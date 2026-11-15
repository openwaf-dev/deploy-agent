//! `DeployCompose`: a Docker Compose application, project `owd-<resource>`, applied by the agent through the Engine
//! API. No Compose client runs next to the Engine.
//!
//! The agent never edits the user's file. A source helper asks Compose for the resolved project (`config --format
//! json`: interpolated with the application's variables, `env_file`s and overrides merged, paths absolute); the
//! agent turns that into a [`Plan`] (the adaptation and what is refused: [`crate::project`]). The services with a
//! `build:` are built from the plan's bake file in a build helper on the rootless builder, each exported as an OCI
//! image layout the agent checks and loads ([`crate::oci`]). The agent then applies the plan as `docker compose up
//! --remove-orphans --wait` did: networks and volumes with Compose's labels, images pulled per `pull_policy`,
//! containers of removed services removed, every service in dependency order (each waiting for its
//! `depends_on` conditions: started, healthy, completed successfully), a service whose configuration changed
//! (any new deployment) recreated, then every service running, and healthy when it has a health check, within
//! [`WAIT_SECS`]. Containers are named and labelled as Compose names and labels them, so a project deployed by
//! an earlier agent (through Compose) is updated in place, and the logs, exec, stop and removal of services keep
//! working.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use bollard::Docker;
use bollard::models::{ContainerSummary, EndpointSettings, NetworkConnectRequest, NetworkCreateRequest};
use bollard::query_parameters::{CreateContainerOptionsBuilder, LogsOptionsBuilder};
use deploy_proto::msg::cause::{
    COMPOSE_EXTERNAL_MISSING, COMPOSE_FILE_MISSING, COMPOSE_IMAGE_NOT_ON_SERVER, COMPOSE_INVALID,
    COMPOSE_NETWORK_CONFLICT, COMPOSE_NO_HEALTHCHECK, COMPOSE_SERVICE_EXITED, COMPOSE_SERVICE_NOT_READY,
    COMPOSE_SERVICE_UNHEALTHY,
};
use deploy_proto::msg::{
    ComposeDeploy, ComposeOutput, ComposeService, ComposeSource, FileMount, LABEL_DEPLOYMENT, LABEL_ENVIRONMENT,
    LogStream, RegistryAuth, Step,
};
use futures_util::StreamExt;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::builder::{Builder, Helper};
use crate::docker::{
    COMPOSE_PROJECT, COMPOSE_SERVICE, File, check_container, client, is_not_found, is_running, labelled, message,
    remove_container, valid_id,
};
use crate::events::{Events, Lines};
use crate::failure::Failure;
use crate::git::{self, Credentials, Repo};
use crate::oci::{Expect, Loaded};
use crate::project::{
    COMPOSE_HASH, COMPOSE_NUMBER, COMPOSE_ONEOFF, Condition, Network, Plan, Pull, Service, Volume, project,
};
use crate::router::{self, Upstream};
use crate::volumes;

/// Largest resolved Compose project read back from the helper.
const MAX_CONFIG_BYTES: usize = 4 << 20;
/// How long the services have to run (or be healthy), dependencies included.
const WAIT_SECS: u64 = 300;
/// How often a container's state is read while waiting for it.
const POLL: Duration = Duration::from_secs(1);
/// Lines of a failed container's log copied into the deployment's log.
const TAIL_LINES: &str = "20";

fn validate(c: &ComposeDeploy) -> Result<(), String> {
    if !valid_id(&c.resource) || !valid_id(&c.deployment) {
        return Err("invalid resource or deployment id".into());
    }
    if !crate::deploy::name_ok(&c.network) {
        return Err("invalid network".into());
    }
    crate::deploy::check_network_name(&c.network)?;
    crate::deploy::check_env(&c.env)?;
    crate::egress::policy(c.egress.as_ref())?;
    router::normalize(&c.routes)?;
    volumes::validate(&c.volumes, &c.files, true)
}

/// Deploys a Compose project. Its log lines, its error and its error's cause never carry the registry credentials
/// it holds.
pub async fn deploy(c: &ComposeDeploy, ev: &Events, cancel: &CancellationToken) -> Result<ComposeOutput, Failure> {
    ev.redact_with(&c.registry_auth);
    deploy_project(c, ev, cancel).await.map_err(|e| e.scrubbed(ev))
}

async fn deploy_project(c: &ComposeDeploy, ev: &Events, cancel: &CancellationToken) -> Result<ComposeOutput, Failure> {
    validate(c)?;
    if !c.registry_auth.is_empty() {
        let hosts: Vec<String> =
            c.registry_auth.iter().map(|a| deploy_proto::registry::server_host(&a.server)).collect();
        ev.system(format!("registry credentials for: {}", hosts.join(", "))).await;
    }
    let d = client()?;
    let project = project(&c.resource);
    crate::deploy::ensure_network(&d, &c.network, c.labels.get(LABEL_ENVIRONMENT).map(String::as_str)).await?;
    volumes::ensure(&d, &c.resource, &c.volumes).await?;
    let previous = crate::docker::app_containers(&d, &c.resource)
        .await?
        .first()
        .and_then(|x| x.labels.as_ref()?.get(LABEL_DEPLOYMENT).cloned());
    let files = volumes::write_files(&c.resource, &c.deployment, &c.files)?;
    ev.step(Step::Fetching).await;
    let r = run(&d, c, &files, ev, cancel).await;
    let (commit, known_hosts, plan) = match r {
        Ok(x) => x,
        Err(e) => {
            // The services that run still use the previous deployment's files.
            volumes::prune_files(&c.resource, previous.as_deref());
            return Err(e);
        }
    };
    ev.step(Step::Switching).await;
    router::switch(&d, &c.resource, &c.network, Upstream::Compose, c.routes.clone(), Some(ev)).await?;
    ev.step(Step::Cleaning).await;
    volumes::prune_files(&c.resource, Some(&c.deployment));
    pulled_sboms(&d, c, &plan, ev, cancel).await;
    let mut services: Vec<ComposeService> = labelled(&d, COMPOSE_PROJECT, &project)
        .await?
        .into_iter()
        .map(|x| ComposeService {
            service: x.labels.as_ref().and_then(|l| l.get(COMPOSE_SERVICE)).cloned().unwrap_or_default(),
            container_id: x.id.unwrap_or_default(),
            image: x.image.unwrap_or_default(),
            state: x.state.map(|s| s.to_string()).unwrap_or_default(),
        })
        .collect();
    services.sort_by(|a, b| a.service.cmp(&b.service));
    for s in &services {
        ev.system(format!("{}: {}", s.service, s.state)).await;
    }
    Ok(ComposeOutput { project, services, commit, known_hosts })
}

/// Resolves the file in a source helper, builds what it builds, and applies the plan.
async fn run(
    d: &Docker,
    c: &ComposeDeploy,
    files: &[(PathBuf, &FileMount)],
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(Option<String>, Vec<String>, Plan), Failure> {
    // Repository content and the Compose file are handled in a helper without the Engine; only the agent's plan
    // reaches the Engine, and only the tree and the plan's bake file reach a build helper.
    let src = Helper::source(d, &c.resource, ev).await?;
    let resolved = resolve(&src, c, files, ev, cancel).await;
    let (plan, commit, known_hosts, inline) = match resolved {
        Ok(x) => x,
        Err(e) => {
            src.remove().await;
            return Err(e);
        }
    };
    let list: Vec<&str> = plan.services.iter().map(|s| s.name.as_str()).collect();
    ev.system(format!("Services: {}", list.join(", "))).await;
    let built = build(d, &src, c, &plan, inline.as_deref(), ev, cancel).await;
    src.remove().await;
    let built = built?;
    ev.step(Step::Starting).await;
    apply(d, &plan, &c.resource, &built, &c.registry_auth, ev, cancel).await?;
    Ok((commit, known_hosts, plan))
}

/// The plan of the project, the commit and new host keys, and the inline file (written into the build helper too:
/// its directory is where relative build contexts resolve).
async fn resolve(
    src: &Helper,
    c: &ComposeDeploy,
    files: &[(PathBuf, &FileMount)],
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(Plan, Option<String>, Vec<String>, Option<String>), Failure> {
    let (file, dir, fetched, known_hosts, inline) = match &c.source {
        ComposeSource::Git { url, reference, auth, ssh, file } => {
            let path = git::inside(file, "Compose file")?;
            if path.is_empty() {
                return Err("the Compose file path is empty".into());
            }
            let repo = Repo {
                url,
                reference,
                creds: Credentials::of(auth.as_ref(), ssh.as_ref()),
                commit: None,
                untrusted: false,
            };
            let cloned = src.clone(&repo, ev, cancel).await?;
            let dir = match path.rsplit_once('/') {
                Some((d, _)) => format!("/src/{d}"),
                None => "/src".to_string(),
            };
            (format!("/src/{path}"), dir, Some(cloned.info()), cloned.known_hosts, None)
        }
        ComposeSource::Inline { content } => {
            src.put(&[File { path: "project/compose.yaml", data: content.as_bytes(), mode: 0o600 }]).await?;
            let (f, d) = ("/owd/project/compose.yaml".to_string(), "/owd/project".to_string());
            (f, d, None, Vec::new(), Some(content.clone()))
        }
    };
    let commit = fetched.as_ref().map(|i| i.sha.clone());
    match fetched {
        Some(info) => ev.step_after_fetch(Step::Building, info).await,
        None => ev.step(Step::Building).await,
    }
    let project = project(&c.resource);
    let cmd: Vec<String> =
        ["docker", "compose", "-p", &project, "-f", &file, "--project-directory", &dir, "config", "--format", "json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    // The application's variables interpolate the file; they reach Compose as its environment, not argv.
    let env: Vec<String> = c.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let (code, out) = src.output(cmd, env, None, MAX_CONFIG_BYTES, ev, cancel).await?;
    if code != 0 {
        let message = format!("the Compose file is invalid (exit code {code})");
        // A file of the repository that is not there, rather than a file Compose refused.
        if let ComposeSource::Git { file: path, .. } = &c.source {
            let test = vec!["test".to_string(), "-f".to_string(), file.clone()];
            if let Ok((1, _)) = src.output(test, Vec::new(), None, 0, ev, cancel).await {
                return Err(Failure::new(COMPOSE_FILE_MISSING, [("path", path.clone())], message));
            }
        }
        return Err(Failure::new(COMPOSE_INVALID, [("exit_code", code.to_string())], message));
    }
    let model: Value = serde_json::from_slice(&out).map_err(|e| format!("docker compose config: {e}"))?;
    let plan = Plan::new(model, c, files)?;
    Ok((plan, commit, known_hosts, inline))
}

/// Builds the services with a `build:` and loads their images (with their SBOMs sent). Returns them by service.
async fn build(
    d: &Docker,
    src: &Helper,
    c: &ComposeDeploy,
    plan: &Plan,
    inline: Option<&str>,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<BTreeMap<String, Loaded>, Failure> {
    let Some((file, targets)) = plan.bake_file() else { return Ok(BTreeMap::new()) };
    let policy = crate::egress::policy(c.egress.as_ref())?;
    let builder = Builder::Trusted;
    let h = Helper::build(d, &c.resource, builder, &c.registry_auth, ev, cancel).await?;
    let r: Result<BTreeMap<String, Loaded>, Failure> = async {
        match inline {
            // Build contexts and Dockerfiles of the services are files of the repository.
            None => h.copy_from(src, "/src", cancel).await?,
            Some(content) => {
                h.put(&[File { path: "project/compose.yaml", data: content.as_bytes(), mode: 0o600 }]).await?;
            }
        }
        ev.system(format!("Building on the rootless BuildKit builder {}", builder.name())).await;
        let names: Vec<&str> = targets.iter().map(String::as_str).collect();
        // The services' Dockerfiles, for a build that cannot read one.
        let dockerfiles: Vec<&str> =
            names.iter().map(|t| file["target"][*t]["dockerfile"].as_str().unwrap_or("Dockerfile")).collect();
        let dockerfiles = dockerfiles.join(", ");
        let egress = crate::egress::Session::start(d, &c.deployment, &policy, ev).await?;
        let built = crate::builder::bake(&h, builder, file, &names, &names, Vec::new(), &egress, ev, cancel).await;
        let denied = egress.finish(ev).await;
        if let Err(failed) = built? {
            let message = format!("the build failed (exit code {})", failed.code);
            return Err(failed.failure(message, "compose", &dockerfiles, &denied, cancel.is_cancelled()));
        }
        let mut built = BTreeMap::new();
        for s in plan.services.iter().filter(|s| s.build.is_some()) {
            let expect = Expect { resource: &c.resource, deployment: &c.deployment };
            let loaded = h.load(&s.name, expect, &s.image, ev, cancel).await?;
            crate::sbom::built(ev, &loaded, Some(&s.name)).await;
            built.insert(s.name.clone(), loaded);
        }
        Ok(built)
    }
    .await;
    h.remove().await;
    r
}

/// Sends the SBOMs of the images the services pulled (best effort; after the switch, so it never delays it).
async fn pulled_sboms(d: &Docker, c: &ComposeDeploy, plan: &Plan, ev: &Events, cancel: &CancellationToken) {
    for s in plan.services.iter().filter(|s| s.build.is_none() && s.replicas > 0) {
        let Ok(image) = d.inspect_image(&s.image).await else { continue };
        let Some(id) = image.id else { continue };
        let auth = deploy_proto::registry::matching(&c.registry_auth, &s.image);
        let pulled = crate::sbom::Pulled { reference: &s.image, auth };
        crate::sbom::of_image(d, &c.resource, &id, &s.image, Some(pulled), Some(&s.name), ev, cancel).await;
    }
}

/// Resolves when `cancel` fires, as an error, or after `t`.
async fn pause(t: Duration, cancel: &CancellationToken) -> Result<(), String> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(crate::CANCELLED.into()),
        _ = tokio::time::sleep(t) => Ok(()),
    }
}

/// Applies `plan` (see the module documentation).
async fn apply(
    d: &Docker,
    plan: &Plan,
    resource: &str,
    built: &BTreeMap<String, Loaded>,
    registry_auth: &[RegistryAuth],
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(), Failure> {
    let deadline = Instant::now() + Duration::from_secs(WAIT_SECS);
    // The networks the services join (`default` only exists when used, as with Compose).
    let used: BTreeSet<String> =
        plan.services.iter().flat_map(|s| s.endpoints(&plan.project, 1)).map(|e| e.network).collect();
    for n in plan.networks.iter().filter(|n| used.contains(n.name.as_str())) {
        ensure_network(d, &plan.project, n).await?;
    }
    for v in &plan.volumes {
        ensure_volume(d, &plan.project, v).await?;
    }
    for s in plan.services.iter().filter(|s| s.build.is_none() && s.replicas > 0) {
        pull(d, s, deploy_proto::registry::matching(registry_auth, &s.image), ev, cancel).await?;
    }
    for s in plan.services.iter().filter(|s| s.replicas > 0) {
        let declared = match d.inspect_image(&s.image).await {
            Ok(i) => i.config.and_then(|c| c.volumes).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        for path in s.anonymous_volumes(&declared) {
            ev.system(volumes::anonymous_warning(Some(&s.name), &path)).await;
        }
    }
    // Every container of the project must be the application's before any changes.
    let existing = labelled(d, COMPOSE_PROJECT, &plan.project).await?;
    for c in &existing {
        check_container(resource, c.names.as_deref().unwrap_or_default(), c.labels.as_ref())?;
    }
    let label = |c: &ContainerSummary, k: &str| c.labels.as_ref().and_then(|l| l.get(k)).cloned().unwrap_or_default();
    for c in &existing {
        let service = label(c, COMPOSE_SERVICE);
        let oneoff = label(c, COMPOSE_ONEOFF) == "True";
        if oneoff || !plan.services.iter().any(|s| s.name == service) {
            ev.system(format!("Removing {}, of no service of the file", name_of(c))).await;
            stop_and_remove(d, c.id.as_deref().unwrap_or_default()).await?;
        }
    }
    let mut ids: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut recreated: BTreeSet<String> = BTreeSet::new();
    for s in &plan.services {
        wait_dependencies(d, s, &ids, deadline, ev, cancel).await?;
        let hash = s.hash();
        // A service whose containers use another's (network stack, volumes, IPC) follows it when it is recreated.
        let follows = s.depends_on.iter().any(|x| recreated.contains(&x.service))
            || matches!(&s.network, crate::project::NetworkMode::Service(x) if recreated.contains(x))
            || s.volumes_from.iter().any(|(x, _)| recreated.contains(x));
        let mut keep: BTreeMap<u64, String> = BTreeMap::new();
        let mine =
            existing.iter().filter(|c| label(c, COMPOSE_SERVICE) == s.name && label(c, COMPOSE_ONEOFF) != "True");
        for c in mine {
            let id = c.id.clone().unwrap_or_default();
            let number: u64 = label(c, COMPOSE_NUMBER).parse().unwrap_or(0);
            let same = !follows
                && label(c, COMPOSE_HASH) == hash
                && (1..=s.replicas).contains(&number)
                && name_of(c) == s.container(&plan.project, number)
                && is_running(c)
                && !keep.contains_key(&number)
                && built.get(&s.name).is_none_or(|b| c.image_id.as_deref() == Some(b.id.as_str()));
            if same {
                keep.insert(number, id);
            } else {
                stop_and_remove(d, &id).await?;
                ev.system(format!("{}: removed", name_of(c))).await;
            }
        }
        let mut created = false;
        for number in 1..=s.replicas {
            if keep.contains_key(&number) {
                continue;
            }
            let id = create(d, plan, s, number, &hash, &ids, cancel).await?;
            ev.system(format!("{}: started", s.container(&plan.project, number))).await;
            keep.insert(number, id);
            created = true;
        }
        if created {
            recreated.insert(s.name.clone());
        }
        ids.insert(s.name.clone(), keep.into_values().collect());
    }
    wait_ready(d, plan, &ids, deadline, ev, cancel).await
}

fn name_of(c: &ContainerSummary) -> String {
    c.names.iter().flatten().next().map(|n| n.trim_start_matches('/').to_string()).unwrap_or_default()
}

/// Creates the project network `n` unless it exists: a bridge named for the firewall's guard, with Compose's
/// labels. An existing one must be the project's. External ones must exist.
async fn ensure_network(d: &Docker, project: &str, n: &Network) -> Result<(), Failure> {
    let existing = match d.inspect_network(&n.name, None).await {
        Ok(x) => Some(x.labels.unwrap_or_default()),
        Err(e) if is_not_found(&e) => None,
        Err(e) => return Err(format!("inspect network {}: {}", n.name, message(&e)).into()),
    };
    if !network_missing(project, n, existing.as_ref())? {
        return Ok(());
    }
    let req = NetworkCreateRequest {
        name: n.name.clone(),
        driver: Some("bridge".into()),
        internal: Some(n.internal),
        enable_ipv6: Some(false),
        options: Some(n.options.clone().into_iter().collect()),
        labels: Some(n.labels.clone().into_iter().collect()),
        ..Default::default()
    };
    match d.create_network(req).await {
        Ok(_) => {}
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 409, .. }) => {}
        Err(e) => return Err(format!("create network {}: {}", n.name, message(&e)).into()),
    }
    Ok(crate::firewall::guard_new_network().await?)
}

/// Whether project network `n` is to be created, given the labels of the network of its name, if one exists. One
/// that exists must be external or the project's; an external one must exist.
fn network_missing(
    project: &str,
    n: &Network,
    existing: Option<&std::collections::HashMap<String, String>>,
) -> Result<bool, Failure> {
    match existing {
        Some(_) if n.external => Ok(false),
        Some(labels) if labels.get(COMPOSE_PROJECT).map(String::as_str) == Some(project) => Ok(false),
        Some(_) => Err(Failure::new(
            COMPOSE_NETWORK_CONFLICT,
            [("network", n.name.clone())],
            format!("network {} exists and is not of the project {project}: refused", n.name),
        )),
        None if n.external => Err(external_missing("network", &n.name)),
        None => Ok(true),
    }
}

fn external_missing(kind: &str, name: &str) -> Failure {
    Failure::new(
        COMPOSE_EXTERNAL_MISSING,
        [("kind", kind.to_string()), ("name", name.to_string())],
        format!("the external {kind} {name} does not exist"),
    )
}

/// Creates the project volume `v` unless it exists (an existing one is used, as Compose does); external ones must
/// exist and not be another resource's ([`volumes::check_external`]).
async fn ensure_volume(d: &Docker, project: &str, v: &Volume) -> Result<(), Failure> {
    match d.inspect_volume(&v.name).await {
        Ok(existing) if v.external => return volumes::check_external(project, &v.name, &existing.labels),
        Ok(_) => return Ok(()),
        Err(e) if is_not_found(&e) && v.external => return Err(external_missing("volume", &v.name)),
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(format!("inspect volume {}: {}", v.name, message(&e)).into()),
    }
    let req = bollard::models::VolumeCreateRequest {
        name: Some(v.name.clone()),
        driver: Some("local".into()),
        driver_opts: Some(v.options.clone().into_iter().collect()),
        labels: Some(v.labels.clone().into_iter().collect()),
        ..Default::default()
    };
    d.create_volume(req).await.map(|_| ()).map_err(|e| format!("create volume {}: {}", v.name, message(&e)).into())
}

/// The image of a service without a build, per its pull policy, with the selected credential for its registry.
async fn pull(
    d: &Docker,
    s: &Service,
    auth: Option<&RegistryAuth>,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(), Failure> {
    if pull_needed(&s.name, &s.image, s.pull, d.inspect_image(&s.image).await.is_ok())? {
        crate::deploy::pull(d, &s.image, auth, s.platform.as_deref(), ev, cancel).await?;
    }
    Ok(())
}

/// Whether `image` of `service` is pulled per its `pull` policy, `present` or not on the server.
fn pull_needed(service: &str, image: &str, pull: Pull, present: bool) -> Result<bool, Failure> {
    match pull {
        Pull::Missing | Pull::Never if present => Ok(false),
        Pull::Never => Err(Failure::new(
            COMPOSE_IMAGE_NOT_ON_SERVER,
            [("service", service.to_string()), ("image", image.to_string())],
            format!("service {service}: the image {image} is not on this server (pull_policy: never)"),
        )),
        Pull::Missing | Pull::Always => Ok(true),
    }
}

async fn stop_and_remove(d: &Docker, id: &str) -> Result<(), String> {
    // The container's own stop signal and grace period.
    match d.stop_container(id, None::<bollard::query_parameters::StopContainerOptions>).await {
        Ok(()) => {}
        Err(e) if is_not_found(&e) => return Ok(()),
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 304, .. }) => {}
        Err(e) => return Err(format!("stop {id}: {}", message(&e))),
    }
    remove_container(d, id).await
}

/// Creates and starts container `number` of `s`: on its first network, connected to the others, with its secrets
/// and configs written in. `ids`: the containers of the services already applied.
async fn create(
    d: &Docker,
    plan: &Plan,
    s: &Service,
    number: u64,
    hash: &str,
    ids: &BTreeMap<String, Vec<String>>,
    cancel: &CancellationToken,
) -> Result<String, String> {
    if cancel.is_cancelled() {
        return Err(crate::CANCELLED.into());
    }
    let name = s.container(&plan.project, number);
    let body = s.container_body(&plan.project, number, hash, &|svc| ids.get(svc).and_then(|v| v.first().cloned()))?;
    let mut opts = CreateContainerOptionsBuilder::default().name(&name);
    if let Some(p) = &s.platform {
        opts = opts.platform(p);
    }
    let id =
        d.create_container(Some(opts.build()), body).await.map_err(|e| format!("create {name}: {}", message(&e)))?.id;
    for e in s.endpoints(&plan.project, number).iter().skip(1) {
        let req = NetworkConnectRequest {
            container: id.clone(),
            endpoint_config: Some(EndpointSettings { aliases: Some(e.aliases.clone()), ..Default::default() }),
        };
        d.connect_network(&e.network, req)
            .await
            .map_err(|err| format!("connect {name} to {}: {}", e.network, message(&err)))?;
    }
    if !s.files.is_empty() {
        let mut b = tar::Builder::new(Vec::new());
        for f in &s.files {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(f.content.len() as u64);
            h.set_mode(f.mode);
            h.set_uid(f.uid);
            h.set_gid(f.gid);
            b.append_data(&mut h, f.target.trim_start_matches('/'), f.content.as_bytes())
                .map_err(|e| format!("{name}: {} {e}", f.target))?;
        }
        let body = b.into_inner().map_err(|e| e.to_string())?;
        let opts = bollard::query_parameters::UploadToContainerOptionsBuilder::default().path("/").build();
        d.upload_to_container(&id, Some(opts), bollard::body_full(body.into()))
            .await
            .map_err(|e| format!("write the secrets and configs of {name}: {}", message(&e)))?;
    }
    d.start_container(&id, None).await.map_err(|e| format!("start {name}: {}", message(&e)))?;
    Ok(id)
}

/// The state of a container, as a waiting step sees it.
#[derive(Debug)]
enum State {
    Starting,
    Ready(bool),
    Failed(Failure),
}

/// Where container `id` (of `service`) stands: running (and healthy, when it has a health check), still starting,
/// or failed.
async fn state(d: &Docker, id: &str, service: &str, completes: bool) -> Result<State, String> {
    let c = d.inspect_container(id, None).await.map_err(|e| format!("inspect {id}: {}", message(&e)))?;
    let name = c.name.unwrap_or_default().trim_start_matches('/').to_string();
    Ok(classify(&c.state.unwrap_or_default(), &name, service, completes))
}

/// Where container `name` of `service` stands, in state `s`. `completes`: it must exit with code 0.
fn classify(s: &bollard::models::ContainerState, name: &str, service: &str, completes: bool) -> State {
    let running = s.running.unwrap_or(false);
    let code = s.exit_code.unwrap_or(-1);
    let exited = || {
        let params = [
            ("service", service.to_string()),
            ("exit_code", code.to_string()),
            ("oom", (s.oom_killed == Some(true)).to_string()),
        ];
        State::Failed(Failure::new(COMPOSE_SERVICE_EXITED, params, format!("{name} exited with code {code}")))
    };
    if completes {
        return match (running, code, s.status.map(|x| x.to_string())) {
            (true, _, _) => State::Starting,
            (false, _, Some(st)) if st == "created" => State::Starting,
            (false, 0, _) => State::Ready(true),
            (false, _, _) => exited(),
        };
    }
    if s.restarting.unwrap_or(false) {
        return if code != 0 { exited() } else { State::Starting };
    }
    if !running {
        return exited();
    }
    match s.health.as_ref().and_then(|h| h.status).map(|h| h.to_string()).as_deref() {
        Some("healthy") => State::Ready(true),
        None | Some("" | "none") => State::Ready(false),
        Some("unhealthy") => State::Failed(Failure::new(
            COMPOSE_SERVICE_UNHEALTHY,
            [("service", service.to_string())],
            format!("{name} is unhealthy"),
        )),
        Some(_) => State::Starting,
    }
}

/// Waits until every container of `ids` (of `service`) is ready, or one fails, or the deadline passes. `completes`:
/// they must exit with code 0 (`service_completed_successfully`).
#[allow(clippy::too_many_arguments)]
async fn wait_for(
    d: &Docker,
    what: &str,
    service: &str,
    ids: &[String],
    completes: bool,
    deadline: Instant,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(), Failure> {
    for id in ids {
        loop {
            match state(d, id, service, completes).await? {
                State::Ready(verified) => {
                    if !verified {
                        pause(Duration::from_millis(1500), cancel).await?;
                        if let State::Failed(f) = state(d, id, service, completes).await? {
                            tail(d, id, ev).await;
                            return Err(f.prefixed(&format!("{what}: ")));
                        }
                    }
                    break;
                }
                State::Failed(f) => {
                    tail(d, id, ev).await;
                    return Err(f.prefixed(&format!("{what}: ")));
                }
                State::Starting if Instant::now() >= deadline => {
                    tail(d, id, ev).await;
                    return Err(not_ready(what, service));
                }
                State::Starting => pause(POLL, cancel).await?,
            }
        }
    }
    Ok(())
}

fn not_ready(what: &str, service: &str) -> Failure {
    Failure::new(
        COMPOSE_SERVICE_NOT_READY,
        [("service", service.to_string()), ("seconds", WAIT_SECS.to_string())],
        format!("{what}: not ready after {WAIT_SECS} s"),
    )
}

/// Waits for the `depends_on` conditions of `s`.
async fn wait_dependencies(
    d: &Docker,
    s: &Service,
    ids: &BTreeMap<String, Vec<String>>,
    deadline: Instant,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(), Failure> {
    for dep in &s.depends_on {
        let list = ids.get(&dep.service).map(Vec::as_slice).unwrap_or_default();
        let what = format!("{} (needed by {})", dep.service, s.name);
        match dep.condition {
            Condition::Started => {}
            Condition::Healthy => {
                for id in list {
                    let c =
                        d.inspect_container(id, None).await.map_err(|e| format!("inspect {id}: {}", message(&e)))?;
                    if c.state.and_then(|st| st.health).is_none() {
                        return Err(Failure::new(
                            COMPOSE_NO_HEALTHCHECK,
                            [("service", dep.service.clone())],
                            format!("{what}: the service has no health check to wait for"),
                        ));
                    }
                }
                ev.system(format!("Waiting for {} to be healthy", dep.service)).await;
                wait_for(d, &what, &dep.service, list, false, deadline, ev, cancel).await?;
            }
            Condition::CompletedSuccessfully => {
                ev.system(format!("Waiting for {} to complete", dep.service)).await;
                wait_for(d, &what, &dep.service, list, true, deadline, ev, cancel).await?;
            }
        }
    }
    Ok(())
}

/// Waits until every service runs (healthy when it has a health check), but those others wait to complete.
async fn wait_ready(
    d: &Docker,
    plan: &Plan,
    ids: &BTreeMap<String, Vec<String>>,
    deadline: Instant,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(), Failure> {
    let completes: BTreeSet<&str> = plan
        .services
        .iter()
        .flat_map(|s| &s.depends_on)
        .filter(|x| x.condition == Condition::CompletedSuccessfully)
        .map(|x| x.service.as_str())
        .collect();
    for s in &plan.services {
        let list = ids.get(&s.name).map(Vec::as_slice).unwrap_or_default();
        let done = completes.contains(s.name.as_str());
        wait_for(d, &format!("service {}", s.name), &s.name, list, done, deadline, ev, cancel).await?;
    }
    Ok(())
}

/// Copies the last lines of a container's log into the deployment's log (why it failed).
async fn tail(d: &Docker, id: &str, ev: &Events) {
    let opts = LogsOptionsBuilder::default().stdout(true).stderr(true).tail(TAIL_LINES).build();
    let mut s = d.logs(id, Some(opts));
    let (mut out, mut err) = (Lines::default(), Lines::default());
    while let Some(Ok(o)) = s.next().await {
        use bollard::container::LogOutput::*;
        let (stream, buf, chunk) = match o {
            StdErr { message } => (LogStream::Stderr, &mut err, message),
            StdOut { message } | Console { message } => (LogStream::Stdout, &mut out, message),
            StdIn { .. } => continue,
        };
        for l in buf.push(&chunk) {
            ev.line(stream, l).await;
        }
    }
}

/// Services of a Compose application by container, for logs and exec (`service` label).
pub fn service_of(c: &bollard::models::ContainerSummary) -> Option<&str> {
    c.labels.as_ref()?.get(COMPOSE_SERVICE).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{ContainerState, ContainerStateStatusEnum, Health, HealthStatusEnum};

    fn failed(s: State) -> Failure {
        match s {
            State::Failed(f) => f,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// A service's container: exited (with Docker's out-of-memory flag), unhealthy, or still starting.
    #[test]
    fn service_states_name_their_cause() {
        let exited = ContainerState {
            status: Some(ContainerStateStatusEnum::EXITED),
            running: Some(false),
            exit_code: Some(137),
            oom_killed: Some(true),
            ..Default::default()
        };
        let f = failed(classify(&exited, "owd-app_1-web-1", "web", false));
        assert_eq!(f.message, "owd-app_1-web-1 exited with code 137");
        let params = ["service", "exit_code", "oom"].map(|p| f.param(p));
        assert_eq!((f.code(), params), (Some(COMPOSE_SERVICE_EXITED), [Some("web"), Some("137"), Some("true")]));
        // A service others wait to complete: code 0 is ready, another code a failure.
        let done = ContainerState { exit_code: Some(0), oom_killed: Some(false), ..exited.clone() };
        assert!(matches!(classify(&done, "c", "init", true), State::Ready(_)));
        assert_eq!(failed(classify(&exited, "c", "init", true)).code(), Some(COMPOSE_SERVICE_EXITED));
        let restarting = ContainerState { restarting: Some(true), exit_code: Some(0), ..exited };
        assert!(matches!(classify(&restarting, "c", "web", false), State::Starting));
        let health = |status| ContainerState {
            running: Some(true),
            health: Some(Health { status: Some(status), ..Default::default() }),
            ..Default::default()
        };
        let f = failed(classify(&health(HealthStatusEnum::UNHEALTHY), "c", "api", false));
        assert_eq!((f.code(), f.param("service")), (Some(COMPOSE_SERVICE_UNHEALTHY), Some("api")));
        assert!(matches!(classify(&health(HealthStatusEnum::STARTING), "c", "api", false), State::Starting));
        assert!(matches!(classify(&health(HealthStatusEnum::HEALTHY), "c", "api", false), State::Ready(_)));
        let f = not_ready("service api", "api");
        assert_eq!((f.code(), f.param("seconds")), (Some(COMPOSE_SERVICE_NOT_READY), Some("300")));
        assert_eq!(f.message, "service api: not ready after 300 s");
    }

    /// Networks the project declares: an existing one must be external or the project's, an external one must
    /// exist; images with `pull_policy: never` must be on the server.
    #[test]
    fn networks_and_images_the_file_names_are_checked() {
        let project = "owd-app_1";
        let net = |external: bool| Network {
            key: "default".into(),
            name: "owd-app_1_default".into(),
            external,
            internal: false,
            labels: Default::default(),
            options: Default::default(),
        };
        let ours = std::collections::HashMap::from([(COMPOSE_PROJECT.to_string(), project.to_string())]);
        let theirs = std::collections::HashMap::new();
        assert_eq!(network_missing(project, &net(false), None), Ok(true));
        assert_eq!(network_missing(project, &net(false), Some(&ours)), Ok(false));
        assert_eq!(network_missing(project, &net(true), Some(&theirs)), Ok(false));
        let f = network_missing(project, &net(false), Some(&theirs)).unwrap_err();
        assert_eq!((f.code(), f.param("network")), (Some(COMPOSE_NETWORK_CONFLICT), Some("owd-app_1_default")));
        let f = network_missing(project, &net(true), None).unwrap_err();
        assert_eq!((f.code(), f.param("kind")), (Some(COMPOSE_EXTERNAL_MISSING), Some("network")));
        assert_eq!(f.message, "the external network owd-app_1_default does not exist");

        assert_eq!(pull_needed("web", "nginx:1", Pull::Missing, true), Ok(false));
        assert_eq!(pull_needed("web", "nginx:1", Pull::Always, true), Ok(true));
        assert_eq!(pull_needed("web", "nginx:1", Pull::Never, true), Ok(false));
        let f = pull_needed("web", "nginx:1", Pull::Never, false).unwrap_err();
        assert_eq!((f.code(), f.param("image")), (Some(COMPOSE_IMAGE_NOT_ON_SERVER), Some("nginx:1")));
    }
}
