//! `DeployApp`: get the image (clone and build, pull, or reuse), then switch the application to a new container.
//!
//! Rolling update, with or without a health check: the image is ready before anything changes, the new container
//! starts next to the current one in the application's other router slot (it publishes nothing: the router owns the
//! host ports), and only once it is healthy (or still running after a few seconds) does the router send new requests
//! to it. The previous container then drains the requests it already has and is stopped and removed. Any failure
//! before the switch removes the new container and leaves the previous one serving, untouched.
//!
//! An application last deployed by a phase-2 agent publishes its port from its own container: that container is
//! stopped right before the router takes the port over, which is the only interruption of the move (as long as a
//! phase-2 switch). If the router cannot take over, it is started again.

use std::collections::HashMap;
use std::time::Duration;

use bollard::Docker;
use bollard::auth::DockerCredentials;
use bollard::models::{
    ContainerCreateBody, ContainerSummary, ContainerUpdateBody, EndpointSettings, HostConfig, HostConfigLogConfig,
    NetworkCreateRequest, NetworkingConfig, RestartPolicy, RestartPolicyNameEnum,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, CreateImageOptionsBuilder, LogsOptionsBuilder, StopContainerOptionsBuilder,
    TagImageOptionsBuilder,
};
use deploy_proto::msg::cause::{
    CONTAINER_EXITED, CONTAINER_NO_ADDRESS, CONTAINER_OOM_KILLED, CONTAINER_PORT_IN_USE, CONTAINER_START_FAILED,
    CONTAINER_STOP_FAILED, DISK_FULL, HEALTH_BAD_STATUS, HEALTH_FAILED, HEALTH_NO_ANSWER, IMAGE_MISSING_ON_SERVER,
    REGISTRY_ACCESS_DENIED, REGISTRY_ANONYMOUS_REFUSED, REGISTRY_CREDENTIAL_REJECTED, REGISTRY_RATE_LIMITED,
    RUNTIME_NOT_LISTENING,
};
use deploy_proto::msg::{
    AppDeploy, BuildPack, BuildSpec, Cause, DEFAULT_DRAIN_SECS, DeployOutput, HealthCheck, LABEL_DEPLOYMENT,
    LABEL_ENVIRONMENT, LABEL_RESOURCE, LogStream, RegistryAuth, Route, Source, Step, UpdateStrategy,
};
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::CANCELLED;
use crate::docker::{
    app_containers, check_image, container_name, is_not_found, is_running, message, pull_reference, remove_container,
    split_tag, valid_id,
};
use crate::events::{Events, Lines};
use crate::failure::Failure;
use crate::git::{self, Credentials, Repo};
use crate::router::{self, Slot, Upstream};
use crate::volumes;

/// Grace period of `docker stop` for the previous container.
const STOP_TIMEOUT_SECS: i32 = 15;
/// Without a health check, a new container must still be running after this long.
const SETTLE: Duration = Duration::from_secs(3);
/// With a health check: one early probe this long after the start, before the scheduled tries, so a container that
/// is ready at once (the usual case) takes traffic without waiting a whole interval. A miss is not counted as a try.
const EARLY_PROBE: Duration = Duration::from_millis(750);
/// While the health check waits for its next try, the container's exit is noticed this often.
const EXIT_POLL: Duration = Duration::from_secs(1);
/// The port check after a deployment without a health check: `GET /` this many times, this far apart, each within
/// [`PORT_TIMEOUT`] (PROTOCOL.md §7, `deploy_app`).
const PORT_TRIES: u32 = 3;
const PORT_INTERVAL: Duration = Duration::from_secs(2);
const PORT_TIMEOUT: Duration = Duration::from_secs(2);
/// Longest drain accepted from the control plane.
const MAX_DRAIN_SECS: u32 = 600;

/// Resolves when `cancel` fires, as an error, or with `f`.
pub async fn cancellable<T, E: From<&'static str>>(
    cancel: &CancellationToken,
    f: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(CANCELLED.into()),
        r = f => r,
    }
}

/// Docker network and alias names.
pub fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Environment variable names and values the Engine accepts.
pub fn check_env<'a>(env: impl IntoIterator<Item = (&'a String, &'a String)>) -> Result<(), String> {
    for (k, v) in env {
        if k.is_empty() || k.contains(['=', '\0']) {
            return Err(format!("invalid environment variable name {k:?}"));
        }
        if v.contains('\0') {
            return Err("environment variable values cannot contain NUL".into());
        }
    }
    Ok(())
}

fn validate(d: &AppDeploy) -> Result<(), String> {
    if !valid_id(&d.resource) || !valid_id(&d.deployment) {
        return Err("invalid resource or deployment id".into());
    }
    if !name_ok(&d.network) || !name_ok(&d.alias) {
        return Err("invalid network or alias".into());
    }
    check_network_name(&d.network)?;
    check_image(&d.resource, &d.run.image_tag)?;
    if let Source::Local { image } = &d.source {
        // A redeployment or rollback reuses one of the application's own images, never another image of the server.
        check_image(&d.resource, image)?;
    }
    if d.run.port == 0 || d.run.publish == Some(0) {
        return Err("invalid port".into());
    }
    check_env(&d.run.env)?;
    if let Some(b) = &d.build {
        crate::egress::policy(b.egress.as_ref())?;
        // Second check after the control plane: untrusted code never gets a secret.
        if b.untrusted && !b.registry_auth.is_empty() {
            return Err("registry credentials are never used by an untrusted build".into());
        }
    }
    if let Some(h) = &d.run.health
        && (!h.path.starts_with('/') || h.path.chars().any(|c| c.is_control() || c.is_whitespace()))
    {
        return Err(format!("invalid health check path {:?}", h.path));
    }
    if d.drain_secs.is_some_and(|s| s > MAX_DRAIN_SECS) {
        return Err(format!("the drain is longer than {MAX_DRAIN_SECS} s"));
    }
    if d.routes.iter().flatten().any(|r| r.service.is_some()) {
        return Err("only Compose applications route to a service".into());
    }
    router::normalize(&routes(d))?;
    volumes::validate(&d.run.volumes, &d.run.files, false)
}

/// The application's routes: as given, or (phase-2 control plane) its published port for every Host.
fn routes(d: &AppDeploy) -> Vec<Route> {
    match &d.routes {
        Some(r) => r.clone(),
        None => d
            .run
            .publish
            .map(|p| Route { listen: Some(p), hosts: Vec::new(), service: None, port: d.run.port, tls: false })
            .into_iter()
            .collect(),
    }
}

/// A phase-2 container publishing a host port itself.
fn publishes(c: &ContainerSummary) -> bool {
    c.ports.iter().flatten().any(|p| p.public_port.is_some())
}

/// Runs a `DeployApp`. Its log lines, its error and its error's cause never carry the registry credentials it holds.
pub async fn run(d: &AppDeploy, ev: &Events, cancel: &CancellationToken) -> Result<DeployOutput, Failure> {
    if let Source::Image { auth: Some(a), .. } = &d.source {
        ev.redact_with(std::slice::from_ref(a));
    }
    if let Some(b) = &d.build {
        ev.redact_with(&b.registry_auth);
    }
    deploy(d, ev, cancel).await.map_err(|e| e.scrubbed(ev))
}

async fn deploy(d: &AppDeploy, ev: &Events, cancel: &CancellationToken) -> Result<DeployOutput, Failure> {
    validate(d)?;
    let docker = crate::docker::client()?;
    let tag = &d.run.image_tag;
    let mut commit = None;
    let mut known_hosts = Vec::new();
    // An image the deployment did not build gets its SBOM once it serves (generating one may take a while):
    // (reference pulled, if pulled).
    let mut sbom_later: Option<Option<String>> = None;
    match &d.source {
        Source::Git { url, reference, auth, ssh, commit: expected } => {
            let spec = d.build.clone().unwrap_or(BuildSpec {
                context: ".".into(),
                dockerfile: "Dockerfile".into(),
                args: Default::default(),
                target: None,
                no_cache: false,
                pack: BuildPack::Dockerfile,
                install_command: None,
                build_command: None,
                start_command: None,
                publish_dir: None,
                spa: false,
                untrusted: false,
                egress: None,
                registry_auth: Vec::new(),
            });
            let repo = Repo {
                url,
                reference,
                creds: Credentials::of(auth.as_ref(), ssh.as_ref()),
                commit: expected.as_deref(),
                untrusted: spec.untrusted,
            };
            ev.step(Step::Fetching).await;
            match spec.pack {
                BuildPack::Dockerfile => {
                    ev.system(format!("Fetching {url} at {reference}")).await;
                    let fetch = git::Fetch {
                        repo,
                        context: &spec.context,
                        dockerfile: &spec.dockerfile,
                        resource: &d.resource,
                        args: spec.args.keys().map(String::as_str).collect(),
                    };
                    let ctx = git::fetch(&docker, fetch, ev, cancel).await?;
                    commit = Some(ctx.commit.clone());
                    known_hosts.clone_from(&ctx.known_hosts);
                    ev.step_after_fetch(Step::Building, ctx.info.clone()).await;
                    let image = crate::builder::build_dockerfile(
                        &docker,
                        &d.resource,
                        &d.deployment,
                        tag,
                        &spec,
                        &ctx,
                        ev,
                        cancel,
                    )
                    .await?;
                    crate::sbom::built(ev, &image, None).await;
                }
                BuildPack::Railpack | BuildPack::Static => {
                    let b = crate::builder::build(&docker, &d.resource, &d.deployment, tag, repo, &spec, ev, cancel)
                        .await?;
                    commit = Some(b.commit);
                    known_hosts = b.known_hosts;
                    crate::sbom::built(ev, &b.image, None).await;
                }
            }
        }
        Source::Image { image, auth } => {
            ev.step(Step::Pulling).await;
            let reference = pull(&docker, image, auth.as_ref(), None, ev, cancel).await?;
            tag_image(&docker, &reference, tag).await?;
            sbom_later = Some(Some(reference));
        }
        Source::Local { image } => {
            ev.step(Step::Pulling).await;
            docker.inspect_image(image).await.map_err(|e| match is_not_found(&e) {
                true => Failure::new(
                    IMAGE_MISSING_ON_SERVER,
                    [("image", image.clone())],
                    format!("image {image} is not on this server"),
                ),
                false => format!("inspect {image}: {}", message(&e)).into(),
            })?;
            ev.system(format!("Using {image}, already on this server")).await;
            if image != tag {
                tag_image(&docker, image, tag).await?;
            }
            sbom_later = Some(None);
        }
    }
    let inspected = docker.inspect_image(tag).await.map_err(|e| format!("inspect {tag}: {}", message(&e)))?;
    let image_id = inspected.id.unwrap_or_default();
    ev.system(format!("Image {tag} ({})", short(&image_id))).await;
    let declared = inspected.config.and_then(|c| c.volumes).unwrap_or_default();
    let mounted: Vec<&str> =
        d.run.volumes.iter().map(|v| v.path.as_str()).chain(d.run.files.iter().map(|f| f.path.as_str())).collect();
    for path in volumes::anonymous_paths(&declared, &mounted) {
        ev.system(volumes::anonymous_warning(None, path)).await;
    }
    if cancel.is_cancelled() {
        return Err(CANCELLED.into());
    }

    let env_label = d.run.labels.get(LABEL_ENVIRONMENT).map(String::as_str);
    ensure_network(&docker, &d.network, env_label).await?;
    volumes::ensure(&docker, &d.resource, &d.run.volumes).await?;
    let name = container_name(&d.resource, &d.deployment);
    let existing = app_containers(&docker, &d.resource).await?;
    let (same, previous): (Vec<ContainerSummary>, Vec<ContainerSummary>) =
        existing.into_iter().partition(|c| c.names.iter().flatten().any(|n| n.trim_start_matches('/') == name));
    // A container left by an earlier attempt of this same deployment is replaced.
    for c in &same {
        remove_container(&docker, c.id.as_deref().unwrap_or_default()).await?;
    }
    let files = volumes::write_files(&d.resource, &d.deployment, &d.run.files)?;
    let running: Vec<&ContainerSummary> = previous.iter().filter(|c| is_running(c)).collect();
    // The new container takes the slot the serving one does not hold.
    let serving = running.iter().find_map(|c| c.labels.as_ref()?.get(router::LABEL_SLOT).and_then(|s| Slot::parse(s)));
    let slot = serving.map_or(Slot::A, Slot::other);

    ev.step(Step::Starting).await;
    let init = engine_has_init(&docker).await;
    if !init {
        ev.system("This server's Docker has no init binary (docker-init): the container runs without an init process")
            .await;
    }
    let new_id = match create(&docker, d, &name, slot, &files, init).await {
        Ok(id) => id,
        Err(e) => {
            volumes::prune_files(&d.resource, current_deployment(&previous).as_deref());
            return Err(e);
        }
    };
    drop(files);
    // Recreate: the running containers stop before the new one starts, so two never use the volumes at once.
    let stopped: Vec<String> = match d.strategy {
        Some(UpdateStrategy::Recreate) => running.iter().filter_map(|c| c.id.clone()).collect(),
        _ => Vec::new(),
    };
    let undo = async |e: Failure| -> Result<DeployOutput, Failure> {
        remove_container(&docker, &new_id).await.ok();
        volumes::prune_files(&d.resource, current_deployment(&previous).as_deref());
        for id in &stopped {
            if let Err(e) = start_again(&docker, id).await {
                ev.system(format!("Could not restart {}: {e}", short(id))).await;
            }
        }
        match (running.is_empty(), stopped.is_empty()) {
            (true, _) => {}
            (false, true) => ev.system("The previous container keeps serving").await,
            (false, false) => ev.system("The previous container was started again").await,
        }
        Err(e)
    };
    for id in &stopped {
        ev.system(format!("Update strategy recreate: stopping the previous container {} first", short(id))).await;
        if let Err(e) = stop(&docker, id).await {
            return undo(Failure::new(CONTAINER_STOP_FAILED, [("detail", e.clone())], e)).await;
        }
    }
    let warning = match start(&docker, d, &new_id, ev, cancel).await {
        Ok(w) => w,
        Err(e) => return undo(e).await,
    };

    // Past this point the deployment completes even if cancelled: the router is about to serve the new container.
    ev.step(Step::Switching).await;
    let legacy: Vec<String> = running.iter().filter(|c| publishes(c)).filter_map(|c| c.id.clone()).collect();
    for id in &legacy {
        ev.system(format!("Moving the application behind the router: stopping {}", short(id))).await;
        if let Err(e) = stop(&docker, id).await {
            return undo(e.into()).await;
        }
    }
    let up = Upstream::Slot { slot };
    if let Err(e) = router::switch(&docker, &d.resource, &d.network, up, routes(d), Some(ev)).await {
        for id in &legacy {
            if let Err(e) = docker.start_container(id, None).await {
                ev.system(format!("Could not restart {}: {}", short(id), message(&e))).await;
            }
        }
        // Where the router publishes its listeners itself (no agent routing), a host port in use fails its start.
        let e = match e.cause {
            None => engine_failure(&e.message, &e.message, d.run.publish, "switching").unwrap_or(e),
            Some(_) => e,
        };
        return undo(e.prefixed("router: ")).await;
    }
    ev.system(format!("{name} is now serving")).await;

    ev.step(Step::Cleaning).await;
    if stopped.is_empty() && running.iter().any(|c| !publishes(c)) {
        // The router moves new requests to the new slot within its settle time; the previous container then only
        // finishes the requests it has.
        tokio::time::sleep(router::SWITCH_SETTLE).await;
        let drain = d.drain_secs.unwrap_or(DEFAULT_DRAIN_SECS);
        ev.system(format!("Draining the previous container for {drain}s")).await;
        tokio::time::sleep(Duration::from_secs(u64::from(drain))).await;
    }
    for c in &previous {
        let id = c.id.as_deref().unwrap_or_default();
        if is_running(c) && !legacy.iter().any(|l| l == id) {
            stop(&docker, id).await.ok();
        }
        remove_container(&docker, id).await?;
        ev.system(format!("Removed the previous container {}", short(id))).await;
    }
    volumes::prune_files(&d.resource, Some(&d.deployment));
    if let Some(reference) = sbom_later {
        let auth = match &d.source {
            Source::Image { auth, .. } => auth.as_ref(),
            _ => None,
        };
        let pulled = reference.as_deref().map(|reference| crate::sbom::Pulled { reference, auth });
        crate::sbom::of_image(&docker, &d.resource, &image_id, tag, pulled, None, ev, cancel).await;
    }
    Ok(DeployOutput { image: tag.clone(), image_id, container_id: new_id, commit, known_hosts, warning })
}

/// The deployment of the newest container, whose files stay.
fn current_deployment(list: &[ContainerSummary]) -> Option<String> {
    list.first().and_then(|c| c.labels.as_ref()?.get(LABEL_DEPLOYMENT).cloned())
}

fn short(id: &str) -> &str {
    let id = id.strip_prefix("sha256:").unwrap_or(id);
    &id[..id.len().min(12)]
}

/// Starts a container this deployment stopped (`recreate`) again; one already running is not an error.
async fn start_again(d: &Docker, id: &str) -> Result<(), String> {
    match d.start_container(id, None).await {
        Ok(()) => Ok(()),
        // 304: already running.
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 304, .. }) => Ok(()),
        Err(e) => Err(message(&e)),
    }
}

async fn stop(d: &Docker, id: &str) -> Result<(), String> {
    let opts = StopContainerOptionsBuilder::default().t(STOP_TIMEOUT_SECS).build();
    match d.stop_container(id, Some(opts)).await {
        Ok(()) => Ok(()),
        Err(e) if is_not_found(&e) => Ok(()),
        // 304: already stopped.
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 304, .. }) => Ok(()),
        Err(e) => Err(format!("stop {}: {}", short(id), message(&e))),
    }
}

fn progress_line(id: Option<&str>, status: &str) -> String {
    match id {
        Some(id) if !id.is_empty() => format!("{id}: {status}"),
        _ => status.to_string(),
    }
}

/// Why a registry refused a pull, as the agent can tell from the error text (Engine or BuildKit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullFailure {
    /// 401 without a credential (or 403 without one: the registry hides private repositories from anonymous pulls).
    Anonymous,
    /// 401 with the credential.
    Rejected,
    /// 403 with the credential.
    Denied,
    RateLimited,
}

impl PullFailure {
    /// The class of an Engine pull error, None when the text says nothing the agent recognizes. A 401 reads
    /// `unauthorized` (the containerd image store), `no basic auth credentials` (the classic store, from a registry
    /// asking for Basic credentials) or `authentication required`.
    pub fn of_engine(text: &str, with_auth: bool) -> Option<PullFailure> {
        let t = text.to_ascii_lowercase();
        if t.contains("toomanyrequests") || t.contains("too many requests") {
            Some(PullFailure::RateLimited)
        } else if ["unauthorized", "no basic auth credentials", "authentication required"].iter().any(|s| t.contains(s))
        {
            Some(if with_auth { PullFailure::Rejected } else { PullFailure::Anonymous })
        } else if t.contains("denied") || t.contains("forbidden") {
            Some(if with_auth { PullFailure::Denied } else { PullFailure::Anonymous })
        } else {
            None
        }
    }

    /// The log text for `image`, pulled with a selected credential for its host when `with_auth`.
    pub fn message(self, image: &str, with_auth: bool) -> String {
        let host = deploy_proto::registry::image_host(image);
        let repo = deploy_proto::registry::image_repo(image);
        match self {
            PullFailure::Anonymous => format!(
                "{host} refused the anonymous pull of {repo} (401): the application selects no credential for {host}"
            ),
            PullFailure::Rejected => format!(
                "{host} rejected the selected credential (401): the username or token is wrong or expired; update it \
                 in the organization's registry credentials"
            ),
            PullFailure::Denied => format!(
                "{host} refused access to {repo} with the selected credential (403): the account cannot read this \
                 repository"
            ),
            PullFailure::RateLimited if host == deploy_proto::registry::DOCKER_HUB && !with_auth => format!(
                "{host} is rate limiting pulls (429); anonymous Docker Hub pulls share this server's limit: select a \
                 Docker Hub credential for this application"
            ),
            PullFailure::RateLimited => format!("{host} is rate limiting pulls (429)"),
        }
    }

    /// The failure for `image`: [`PullFailure::message`] with its `registry.*` cause.
    pub fn failure(self, image: &str, with_auth: bool) -> Failure {
        let host = ("host", deploy_proto::registry::image_host(image));
        let repo = ("repo", deploy_proto::registry::image_repo(image));
        let (code, params) = match self {
            PullFailure::Anonymous => (REGISTRY_ANONYMOUS_REFUSED, vec![host, repo]),
            PullFailure::Rejected => (REGISTRY_CREDENTIAL_REJECTED, vec![host]),
            PullFailure::Denied => (REGISTRY_ACCESS_DENIED, vec![host, repo]),
            PullFailure::RateLimited => (REGISTRY_RATE_LIMITED, vec![host]),
        };
        Failure::new(code, params, self.message(image, with_auth))
    }
}

/// Pulls `image` (for `platform`, when given), its progress in the deployment's log. Returns the reference pulled
/// (with an explicit tag). A refusal the agent recognizes ([`PullFailure`]) is the error, after the Engine's own text
/// as a log line.
pub async fn pull(
    d: &Docker,
    image: &str,
    auth: Option<&RegistryAuth>,
    platform: Option<&str>,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<String, Failure> {
    let reference = pull_reference(image);
    ev.system(format!("Pulling {reference}")).await;
    let creds = auth.map(|a| DockerCredentials {
        username: Some(a.username.clone()),
        password: Some(a.password.clone()),
        serveraddress: Some(a.server.clone()),
        ..Default::default()
    });
    let mut opts = CreateImageOptionsBuilder::default().from_image(&reference);
    if let Some(p) = platform {
        opts = opts.platform(p);
    }
    let failed = async |text: String| -> Result<String, Failure> {
        let text = format!("pull {reference}: {text}");
        match PullFailure::of_engine(&text, auth.is_some()) {
            Some(f) => {
                ev.system(&text).await;
                Err(f.failure(image, auth.is_some()).scrubbed(ev))
            }
            None if text.contains("no space left on device") => {
                Err(Failure::new(DISK_FULL, [("step", "pulling".to_string())], ev.scrub(&text)))
            }
            None => Err(ev.scrub(&text).into()),
        }
    };
    let mut s = d.create_image(Some(opts.build()), None, creds);
    loop {
        let item = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(CANCELLED.into()),
            i = s.next() => i,
        };
        let Some(item) = item else { break };
        let info = match item {
            Ok(i) => i,
            Err(e) => return failed(message(&e)).await,
        };
        if let Some(e) = info.error_detail {
            return failed(e.message.unwrap_or_default()).await;
        }
        // Byte progress of each layer is noise in a deployment log; its state changes are not.
        if let Some(st) = info.status
            && info.progress_detail.is_none_or(|p| p.current.is_none())
        {
            ev.line(LogStream::Stdout, progress_line(info.id.as_deref(), &st)).await;
        }
    }
    Ok(reference)
}

async fn tag_image(d: &Docker, source: &str, target: &str) -> Result<(), String> {
    let (repo, tag) = split_tag(target);
    let opts = TagImageOptionsBuilder::default().repo(repo).tag(tag.unwrap_or("latest")).build();
    d.tag_image(source, Some(opts)).await.map_err(|e| format!("tag {source} as {target}: {}", message(&e)))
}

/// A network applications join: a Deploy network (`owd-…`, covered by the firewall's egress guard), never `host`,
/// Docker's default `bridge` or a network of someone else.
pub fn check_network_name(network: &str) -> Result<(), String> {
    match network.starts_with(crate::firewall::NETWORK_PREFIX) {
        true => Ok(()),
        false => Err(format!("network {network:?} is not a Deploy network (owd-…): refused")),
    }
}

/// Creates the environment's network unless it exists: a bridge named for the firewall's egress guard (`owd+`
/// interfaces) and without IPv6. An existing one must be a bridge network.
pub async fn ensure_network(d: &Docker, network: &str, environment: Option<&str>) -> Result<(), String> {
    check_network_name(network)?;
    match d.inspect_network(network, None).await {
        Ok(n) if n.driver.as_deref() == Some("bridge") => return Ok(()),
        Ok(n) => {
            return Err(format!(
                "network {network} uses the {} driver: Deploy networks are bridge networks",
                n.driver.unwrap_or_default()
            ));
        }
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(format!("inspect network {network}: {}", message(&e))),
    }
    let labels: HashMap<String, String> =
        environment.map(|v| (LABEL_ENVIRONMENT.to_string(), v.to_string())).into_iter().collect();
    let options = HashMap::from([(crate::firewall::BRIDGE_OPTION.to_string(), crate::firewall::bridge_name(network))]);
    let req = NetworkCreateRequest {
        name: network.to_string(),
        driver: Some("bridge".into()),
        labels: Some(labels),
        options: Some(options),
        enable_ipv6: Some(false),
        ..Default::default()
    };
    match d.create_network(req).await {
        Ok(_) => {}
        // Created concurrently by another deployment of the same environment.
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 409, .. }) => {}
        Err(e) => return Err(format!("create network {network}: {}", message(&e))),
    }
    crate::firewall::guard_new_network().await
}

/// Whether the Engine can run containers with its init process (`--init`): it reports the init binary's version,
/// or `N/A` when it has none (some distribution packages ship it apart). Asked once per agent process; a failed
/// question is asked again next time.
async fn engine_has_init(d: &Docker) -> bool {
    static HAS_INIT: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();
    let ask = || async {
        let info = d.info().await.map_err(|e| message(&e))?;
        Ok::<_, String>(info.init_commit.and_then(|c| c.id).is_some_and(|id| !id.is_empty() && id != "N/A"))
    };
    match HAS_INIT.get_or_try_init(ask).await {
        Ok(has) => *has,
        Err(e) => {
            tracing::warn!("docker info: {e}");
            false
        }
    }
}

/// Creates the new container. `init`: Docker's init process runs as PID 1, forwarding signals and reaping the
/// orphaned processes that `exec`s of scheduled tasks leave behind (without it they stay zombies until the
/// container's process limit is reached).
async fn create(
    d: &Docker,
    dep: &AppDeploy,
    name: &str,
    slot: Slot,
    files: &[(std::path::PathBuf, &deploy_proto::msg::FileMount)],
    init: bool,
) -> Result<String, Failure> {
    let r = &dep.run;
    let mut labels: HashMap<String, String> = r.labels.clone().into_iter().collect();
    labels.insert(LABEL_RESOURCE.into(), dep.resource.clone());
    labels.insert(LABEL_DEPLOYMENT.into(), dep.deployment.clone());
    labels.insert(router::LABEL_SLOT.into(), slot.name().into());
    let mut env: Vec<String> = r.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    // The port the router sends traffic to, for applications (Railpack's, the static server) that listen on $PORT.
    if !r.env.contains_key("PORT") {
        env.push(format!("PORT={}", r.port));
    }
    let mounts = volumes::mounts(&dep.resource, &r.volumes, files);
    let body = ContainerCreateBody {
        image: Some(r.image_tag.clone()),
        env: Some(env),
        cmd: r.command.clone(),
        labels: Some(labels),
        exposed_ports: Some(vec![format!("{}/tcp", r.port)]),
        host_config: Some(HostConfig {
            restart_policy: Some(RestartPolicy { name: Some(RestartPolicyNameEnum::NO), maximum_retry_count: None }),
            memory: r.memory_bytes.map(|m| m.min(i64::MAX as u64) as i64),
            nano_cpus: r.cpus.filter(|c| *c > 0.0).map(|c| (c * 1e9) as i64),
            // Rotated logs: an application that logs a lot must not fill the server's disk.
            log_config: Some(HostConfigLogConfig {
                typ: Some("json-file".into()),
                config: Some(HashMap::from([
                    ("max-size".to_string(), "20m".to_string()),
                    ("max-file".to_string(), "5".to_string()),
                ])),
            }),
            mounts: (!mounts.is_empty()).then_some(mounts),
            network_mode: Some(dep.network.clone()),
            init: init.then_some(true),
            ..Default::default()
        }),
        networking_config: Some(NetworkingConfig {
            endpoints_config: Some(HashMap::from([(
                dep.network.clone(),
                // The application's name for its neighbours; its slot alias for the router, which tells the old
                // and the new container apart while both run; its own name.
                EndpointSettings {
                    aliases: Some(vec![dep.alias.clone(), router::slot_alias(&dep.resource, slot), name.to_string()]),
                    ..Default::default()
                },
            )])),
        }),
        ..Default::default()
    };
    let opts = CreateContainerOptionsBuilder::default().name(name).build();
    let c = d.create_container(Some(opts), body).await.map_err(|e| {
        let detail = message(&e);
        start_failure(format!("create {name}: {detail}"), &detail, r.publish)
    })?;
    Ok(c.id)
}

/// What an Engine error says whatever the call: a host port in use (`publish`: the application's published port),
/// or a full disk during `step`.
fn engine_failure(message: &str, detail: &str, publish: Option<u16>, step: &str) -> Option<Failure> {
    let d = detail.to_ascii_lowercase();
    if d.contains("port is already allocated") || d.contains("address already in use") {
        Some(Failure::new(CONTAINER_PORT_IN_USE, publish.map(|p| ("port", p.to_string())), message))
    } else if d.contains("no space left on device") {
        Some(Failure::new(DISK_FULL, [("step", step.to_string())], message))
    } else {
        None
    }
}

/// The failure of creating or starting the new container: [`engine_failure`], else `container.start_failed` with the
/// Engine's message.
fn start_failure(message: String, detail: &str, publish: Option<u16>) -> Failure {
    engine_failure(&message, detail, publish, "starting")
        .unwrap_or_else(|| Failure::new(CONTAINER_START_FAILED, [("detail", detail.to_string())], message))
}

/// Starts the new container and waits until it is healthy. Its log goes to the deployment log meanwhile, so a crash
/// at start-up is visible there. Returns the port check's warning ([`port_check`]).
async fn start(
    d: &Docker,
    dep: &AppDeploy,
    new_id: &str,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<Option<Cause>, Failure> {
    d.start_container(new_id, None).await.map_err(|e| {
        let detail = message(&e);
        start_failure(format!("start: {detail}"), &detail, dep.run.publish)
    })?;
    ev.system(format!("Started {}", short(new_id))).await;
    let follow = tokio::spawn(follow_logs(d.clone(), new_id.to_string(), ev.clone()));
    let r = cancellable(cancel, wait_healthy(d, dep, new_id, ev)).await;
    follow.abort();
    let _ = follow.await;
    let warning = r?;
    // Only a container that passed its checks restarts by itself: one crashing at start-up stays down, with its exit
    // code, while the previous container keeps serving.
    let promote = ContainerUpdateBody {
        restart_policy: Some(RestartPolicy {
            name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
            maximum_retry_count: None,
        }),
        ..Default::default()
    };
    d.update_container(new_id, promote).await.map_err(|e| format!("restart policy: {}", message(&e)))?;
    Ok(warning)
}

async fn follow_logs(d: Docker, id: String, ev: Events) {
    let opts = LogsOptionsBuilder::default().follow(true).stdout(true).stderr(true).build();
    let mut s = d.logs(&id, Some(opts));
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

/// How the new container ended. `start_error`: the init process could not run the command (its own error line),
/// which without init is Docker's start error.
struct Exit {
    code: i64,
    oom: bool,
    start_error: Option<String>,
}

impl Exit {
    /// `container.start_failed` when init could not run the command, else `container.exited`, or
    /// `container.oom_killed`, with `prefix` before the message.
    fn failure(&self, prefix: &str) -> Failure {
        if let Some(detail) = &self.start_error {
            return Failure::new(
                CONTAINER_START_FAILED,
                [("detail", detail.clone())],
                format!("{prefix}the container could not start its command: {detail}"),
            );
        }
        let mut m = format!("{prefix}the container exited with code {}", self.code);
        if self.oom {
            m.push_str(" (out of memory)");
        }
        let code = if self.oom { CONTAINER_OOM_KILLED } else { CONTAINER_EXITED };
        Failure::new(code, [("exit_code", self.code.to_string())], m)
    }
}

/// The error line Docker's init (tini) prints when it cannot run the command (`[FATAL tini (7)] exec /x failed: …`,
/// exit 126 or 127), without its prefix.
fn init_exec_error(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix("[FATAL tini (")?;
    let rest = &rest[rest.find(")] ")? + 3..];
    (rest.starts_with("exec ") && rest.contains(" failed")).then_some(rest)
}

/// How the new container ended, if it is not up.
async fn exited(d: &Docker, id: &str) -> Result<Option<Exit>, String> {
    let c = d.inspect_container(id, None).await.map_err(|e| format!("inspect: {}", message(&e)))?;
    let s = c.state.unwrap_or_default();
    if s.running.unwrap_or(false) {
        return Ok(None);
    }
    let code = s.exit_code.unwrap_or(-1);
    let mut start_error = None;
    let under_init = c.host_config.and_then(|h| h.init) == Some(true);
    if under_init && (code == 126 || code == 127) {
        let opts = LogsOptionsBuilder::default().stdout(true).stderr(true).tail("5").build();
        let mut logs = d.logs(id, Some(opts));
        while let Some(Ok(o)) = logs.next().await {
            let text = String::from_utf8_lossy(&o.into_bytes()).into_owned();
            if let Some(e) = text.lines().find_map(init_exec_error) {
                start_error = Some(e.to_string());
            }
        }
    }
    Ok(Some(Exit { code, oom: s.oom_killed == Some(true), start_error }))
}

/// The container's address on `network`, if it has one.
async fn address(d: &Docker, id: &str, network: &str) -> Result<Option<String>, String> {
    let c = d.inspect_container(id, None).await.map_err(|e| format!("inspect: {}", message(&e)))?;
    Ok(c.network_settings
        .and_then(|n| n.networks)
        .and_then(|mut n| n.remove(network))
        .and_then(|e| e.ip_address)
        .filter(|ip| !ip.is_empty()))
}

/// Waits until the new container is healthy: its health check passes or, without one, it still runs after
/// [`SETTLE`]. Without a health check, returns the port check's warning.
async fn wait_healthy(d: &Docker, dep: &AppDeploy, id: &str, ev: &Events) -> Result<Option<Cause>, Failure> {
    let Some(h) = &dep.run.health else {
        tokio::time::sleep(SETTLE).await;
        if let Some(x) = exited(d, id).await? {
            return Err(x.failure(""));
        }
        return Ok(port_check(d, dep, id, ev).await);
    };
    ev.step(Step::HealthCheck).await;
    let Some(ip) = address(d, id, &dep.network).await? else {
        // A container that already crashed has no address: its exit is the error worth reporting.
        return Err(match exited(d, id).await? {
            Some(x) => x.failure("health check failed: "),
            None => Failure::new(
                CONTAINER_NO_ADDRESS,
                [("network", dep.network.clone())],
                format!("the container has no address on {}", dep.network),
            ),
        });
    };
    probe(d, id, &ip, dep.run.port, h, ev).await.map(|()| None)
}

/// A client for requests to a container: redirects count as an answer (following one would leave the container, to
/// its public HTTPS URL).
pub fn container_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())
}

/// Waits `total`, checking every [`EXIT_POLL`] that the container still runs: its exit is the failure, at once.
async fn wait_running(d: &Docker, id: &str, total: Duration) -> Result<(), Failure> {
    let until = tokio::time::Instant::now() + total;
    loop {
        if let Some(x) = exited(d, id).await? {
            return Err(x.failure("health check failed: "));
        }
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        tokio::time::sleep(left.min(EXIT_POLL)).await;
    }
}

/// The health check: one early probe after [`EARLY_PROBE`] (a miss stays out of the log and the count), then
/// `retries` tries `interval_secs` apart, the first one `interval_secs` after the start as before, so an application
/// gets at least the time it got from earlier agents. The container's exit is checked every [`EXIT_POLL`] meanwhile.
async fn probe(d: &Docker, id: &str, ip: &str, port: u16, h: &HealthCheck, ev: &Events) -> Result<(), Failure> {
    let url = format!("http://{ip}:{port}{}", h.path);
    let client = container_client(Duration::from_secs(u64::from(h.timeout_secs.max(1))))?;
    let tries = h.retries.max(1);
    let interval = Duration::from_secs(u64::from(h.interval_secs.max(1)));
    ev.system(format!("Health check: GET {url} (every {}s, {tries} tries)", h.interval_secs)).await;
    let started = tokio::time::Instant::now();
    wait_running(d, id, EARLY_PROBE).await?;
    if let Ok(r) = client.get(&url).send().await
        && r.status().as_u16() < 400
    {
        ev.system(format!("Health check passed: HTTP {}", r.status().as_u16())).await;
        return Ok(());
    }
    // The last try's outcome: its status, or the kind of its error.
    let mut last: Option<Result<u16, &'static str>> = None;
    for n in 1..=tries {
        // As before: the first try an interval after the start, each next one an interval after the previous one.
        let wait = if n == 1 { interval.saturating_sub(started.elapsed()) } else { interval };
        wait_running(d, id, wait).await?;
        match client.get(&url).send().await {
            Ok(r) if r.status().as_u16() < 400 => {
                ev.system(format!("Health check passed: HTTP {}", r.status().as_u16())).await;
                return Ok(());
            }
            Ok(r) => {
                last = Some(Ok(r.status().as_u16()));
                ev.system(format!("Health check {n}/{tries}: HTTP {}", r.status().as_u16())).await;
            }
            Err(e) => {
                last = Some(Err(error_kind(&e)));
                ev.system(format!("Health check {n}/{tries}: {}", cause(&e))).await;
            }
        }
    }
    let message = format!("health check failed after {tries} tries");
    let tries = ("tries", tries.to_string());
    Err(match last {
        Some(Ok(status)) => {
            Failure::new(HEALTH_BAD_STATUS, [tries, ("path", h.path.clone()), ("status", status.to_string())], message)
        }
        Some(Err(kind)) => Failure::new(
            HEALTH_NO_ANSWER,
            [tries, ("port", port.to_string()), ("path", h.path.clone()), ("error", kind.to_string())],
            message,
        ),
        None => Failure::new(HEALTH_FAILED, [tries], message),
    })
}

/// After a deployment without a health check: `GET /` on the application's port at the new container's address,
/// [`PORT_TRIES`] times [`PORT_INTERVAL`] apart, each within [`PORT_TIMEOUT`]. Any HTTP answer passes. A miss never
/// fails the deployment: it is logged and returned as the warning `runtime.not_listening` (PROTOCOL.md §7).
async fn port_check(d: &Docker, dep: &AppDeploy, id: &str, ev: &Events) -> Option<Cause> {
    let port = dep.run.port;
    let error = match (address(d, id, &dep.network).await, container_client(PORT_TIMEOUT)) {
        (Ok(Some(ip)), Ok(client)) => {
            let url = format!("http://{ip}:{port}/");
            let mut error = "other";
            for n in 0..PORT_TRIES {
                if n > 0 {
                    tokio::time::sleep(PORT_INTERVAL).await;
                }
                match client.get(&url).send().await {
                    Ok(_) => return None,
                    Err(e) => error = error_kind(&e),
                }
            }
            error
        }
        (Ok(None), _) => "no_address",
        _ => "other",
    };
    ev.system(format!(
        "Warning: nothing answered GET / on port {port} of the new container ({error}): it serves anyway, and requests \
         to the application fail until something listens on that port"
    ))
    .await;
    let params = [("port", port.to_string()), ("error", error.to_string())];
    Some(Cause { code: RUNTIME_NOT_LISTENING.into(), params: params.into_iter().map(|(k, v)| (k.into(), v)).collect() })
}

/// How an HTTP request to a container failed, as causes and port probes report it: `refused`, `timeout` or
/// `other`.
pub fn error_kind(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        return "timeout";
    }
    let mut s: Option<&dyn std::error::Error> = Some(e);
    while let Some(err) = s {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            match io.kind() {
                std::io::ErrorKind::ConnectionRefused => return "refused",
                std::io::ErrorKind::TimedOut => return "timeout",
                _ => {}
            }
        }
        s = err.source();
    }
    match cause(e).to_ascii_lowercase().contains("connection refused") {
        true => "refused",
        false => "other",
    }
}

/// The innermost cause of an HTTP error ("connection refused", "operation timed out").
fn cause(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return "timed out".into();
    }
    let mut s: &dyn std::error::Error = e;
    while let Some(next) = s.source() {
        s = next;
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use deploy_proto::msg::RunSpec;

    use super::*;
    #[test]
    fn engine_pull_errors_are_classified() {
        use PullFailure::*;
        let unauthorized = "pull ghcr.io/acme/api:1: Head \"https://ghcr.io/v2/acme/api/manifests/1\": unauthorized";
        assert_eq!(PullFailure::of_engine(unauthorized, false), Some(Anonymous));
        assert_eq!(PullFailure::of_engine(unauthorized, true), Some(Rejected));
        let denied = "pull access denied for acme/x, repository does not exist or may require 'docker login': denied";
        assert_eq!(PullFailure::of_engine(denied, true), Some(Denied));
        assert_eq!(PullFailure::of_engine(denied, false), Some(Anonymous));
        assert_eq!(
            PullFailure::of_engine("toomanyrequests: You have reached your pull rate limit", false),
            Some(RateLimited)
        );
        assert_eq!(PullFailure::of_engine("manifest unknown", true), None);
        // The classic image store, from a registry asking for Basic credentials.
        let basic = "pull 203.0.113.50:5000/e2e/base:1: Head \"http://203.0.113.50:5000/v2/e2e/base/manifests/1\": \
                     no basic auth credentials";
        assert_eq!(PullFailure::of_engine(basic, false), Some(Anonymous));
        assert_eq!(
            Anonymous.message("ghcr.io/acme/api:1", false),
            "ghcr.io refused the anonymous pull of acme/api (401): the application selects no credential for ghcr.io"
        );
        assert!(
            Rejected.message("ghcr.io/acme/api:1", true).starts_with("ghcr.io rejected the selected credential (401)")
        );
        assert!(
            Denied
                .message("ghcr.io/acme/api:1", true)
                .contains("refused access to acme/api with the selected credential (403)")
        );
        assert!(RateLimited.message("redis:7", false).ends_with("select a Docker Hub credential for this application"));
        assert_eq!(RateLimited.message("redis:7", true), "docker.io is rate limiting pulls (429)");
    }

    fn dep(network: &str, image_tag: &str, source: Source) -> AppDeploy {
        AppDeploy {
            resource: "app_01J".into(),
            deployment: "dep_01X".into(),
            network: network.into(),
            alias: "web".into(),
            source,
            build: None,
            run: RunSpec {
                image_tag: image_tag.into(),
                env: Default::default(),
                port: 80,
                publish: None,
                health: None,
                command: None,
                memory_bytes: None,
                cpus: None,
                labels: Default::default(),
                volumes: vec![],
                files: vec![],
            },
            routes: None,
            drain_secs: None,
            strategy: None,
        }
    }

    /// A deployment only joins a Deploy network, and only tags, runs and reuses its application's own images.
    #[test]
    fn deployments_stay_on_deploy_networks_and_their_own_images() {
        let pulled = Source::Image { image: "nginx:1.29".into(), auth: None };
        let tag = "owd/app_01j:dep_01x";
        assert!(validate(&dep("owd-0a1b2c3d4e5f", tag, pulled.clone())).is_ok());
        for network in ["host", "bridge", "none", "traefik", "container:owd-router"] {
            let e = validate(&dep(network, tag, pulled.clone())).unwrap_err();
            assert!(e.contains("network"), "{network}: {e}");
        }
        for t in ["nginx:latest", "owd/app_02:dep_01x", "owd/app_01j"] {
            assert!(validate(&dep("owd-env", t, pulled.clone())).is_err(), "{t}");
        }
        let rollback = Source::Local { image: "owd/app_01j:dep_00w".into() };
        assert!(validate(&dep("owd-env", tag, rollback)).is_ok());
        for image in ["postgres:17", "owd/app_02:dep_00w", "owd/helper:1-docker29.9.3-railpack0.43.0"] {
            let e = validate(&dep("owd-env", tag, Source::Local { image: image.into() })).unwrap_err();
            assert!(e.contains("not in the repository of app_01J"), "{image}: {e}");
        }
    }

    #[test]
    fn an_untrusted_build_with_registry_credentials_is_refused() {
        let git =
            Source::Git { url: "https://x/y".into(), reference: "main".into(), auth: None, ssh: None, commit: None };
        let mut d = dep("owd-env", "owd/app_01j:dep_01x", git);
        let mut b = BuildSpec {
            context: ".".into(),
            dockerfile: "Dockerfile".into(),
            args: Default::default(),
            target: None,
            no_cache: false,
            pack: BuildPack::Dockerfile,
            install_command: None,
            build_command: None,
            start_command: None,
            publish_dir: None,
            spa: false,
            untrusted: false,
            egress: None,
            registry_auth: Vec::new(),
        };
        b.untrusted = true;
        b.registry_auth = vec![RegistryAuth { server: "ghcr.io".into(), username: "u".into(), password: "p".into() }];
        d.build = Some(b.clone());
        assert_eq!(validate(&d).unwrap_err(), "registry credentials are never used by an untrusted build");
        b.untrusted = false;
        d.build = Some(b);
        assert!(validate(&d).is_ok(), "a trusted build may use them");
    }

    /// Engine errors (Docker Engine 28.3.3) name their cause; anything else is the family's fallback, with the
    /// Engine's text.
    #[test]
    fn engine_errors_name_their_cause() {
        use deploy_proto::msg::cause::*;
        let allocated = "failed to set up container networking: driver failed programming external connectivity on \
                         endpoint owd-router (b9d7ee73954a): Bind for 0.0.0.0:28199 failed: port is already allocated";
        let f = start_failure(format!("start: {allocated}"), allocated, Some(28199));
        assert_eq!((f.code(), f.param("port")), (Some(CONTAINER_PORT_IN_USE), Some("28199")));
        assert_eq!(f.message, format!("start: {allocated}"));
        let full = "write /var/lib/docker/containers/1/hostconfig.json: no space left on device";
        let f = start_failure(format!("create x: {full}"), full, None);
        assert_eq!((f.code(), f.param("step")), (Some(DISK_FULL), Some("starting")));
        let missing = "failed to create task for container: failed to create shim task: OCI runtime create failed: \
                       runc create failed: unable to start container process: error during container init: exec: \
                       \"/nonexistent\": stat /nonexistent: no such file or directory: unknown";
        let f = start_failure(format!("start: {missing}"), missing, Some(80));
        assert_eq!((f.code(), f.param("detail")), (Some(CONTAINER_START_FAILED), Some(missing)));
        // Elsewhere (the router's own start) only what the text names: nothing else is a container failure.
        assert_eq!(
            engine_failure("router: x", allocated, Some(1), "switching").unwrap().code(),
            Some(CONTAINER_PORT_IN_USE)
        );
        assert!(engine_failure("router: x", "the router did not answer", Some(1), "switching").is_none());
    }

    /// Under Docker's init a command that cannot run is init's exit (126, 127), named as the start failure it is
    /// without init (tini 0.19 in Docker Engine 29.9.3).
    #[test]
    fn an_init_that_cannot_run_the_command_is_a_start_failure() {
        use deploy_proto::msg::cause::*;
        let line = "[FATAL tini (7)] exec /nonexistent failed: No such file or directory";
        let detail = init_exec_error(line).unwrap();
        assert_eq!(detail, "exec /nonexistent failed: No such file or directory");
        let f = Exit { code: 127, oom: false, start_error: Some(detail.into()) }.failure("health check failed: ");
        assert_eq!((f.code(), f.param("detail")), (Some(CONTAINER_START_FAILED), Some(detail)));
        assert_eq!(init_exec_error("[WARN  tini (7)] Tini is not running as PID 1"), None);
        assert_eq!(init_exec_error("sh: exec /nonexistent failed"), None);
        let f = Exit { code: 127, oom: false, start_error: None }.failure("");
        assert_eq!((f.code(), f.param("exit_code")), (Some(CONTAINER_EXITED), Some("127")));
    }

    /// A refused connection is told apart from other request failures (the kinds of health checks and port probes).
    #[tokio::test]
    async fn refused_connections_are_classified() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let c = container_client(Duration::from_secs(2)).unwrap();
        let e = c.get(format!("http://127.0.0.1:{port}/")).send().await.unwrap_err();
        assert_eq!(error_kind(&e), "refused");
    }
}
