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
use deploy_proto::msg::{
    AppDeploy, BuildPack, BuildSpec, DEFAULT_DRAIN_SECS, DeployOutput, HealthCheck, LABEL_DEPLOYMENT,
    LABEL_ENVIRONMENT, LABEL_RESOURCE, LogStream, RegistryAuth, Route, Source, Step,
};
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::CANCELLED;
use crate::docker::{
    app_containers, check_image, container_name, is_not_found, is_running, message, pull_reference, remove_container,
    split_tag, valid_id,
};
use crate::events::{Events, Lines};
use crate::git::{self, Credentials, Repo};
use crate::router::{self, Slot, Upstream};
use crate::volumes;

/// Grace period of `docker stop` for the previous container.
const STOP_TIMEOUT_SECS: i32 = 15;
/// Without a health check, a new container must still be running after this long.
const SETTLE: Duration = Duration::from_secs(3);
/// Longest drain accepted from the control plane.
const MAX_DRAIN_SECS: u32 = 600;

/// Resolves when `cancel` fires, as an error, or with `f`.
pub async fn cancellable<T>(
    cancel: &CancellationToken,
    f: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
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

pub async fn run(d: &AppDeploy, ev: &Events, cancel: &CancellationToken) -> Result<DeployOutput, String> {
    validate(d)?;
    let docker = crate::docker::client()?;
    let tag = &d.run.image_tag;
    let mut commit = None;
    let mut known_hosts = Vec::new();
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
                    crate::builder::build_dockerfile(&docker, &d.resource, &d.deployment, tag, &spec, &ctx, ev, cancel)
                        .await?;
                }
                BuildPack::Railpack | BuildPack::Static => {
                    let b = crate::builder::build(&docker, &d.resource, &d.deployment, tag, repo, &spec, ev, cancel)
                        .await?;
                    commit = Some(b.commit);
                    known_hosts = b.known_hosts;
                }
            }
        }
        Source::Image { image, auth } => {
            ev.step(Step::Pulling).await;
            let reference = pull(&docker, image, auth.as_ref(), ev, cancel).await?;
            tag_image(&docker, &reference, tag).await?;
        }
        Source::Local { image } => {
            ev.step(Step::Pulling).await;
            docker.inspect_image(image).await.map_err(|e| match is_not_found(&e) {
                true => format!("image {image} is not on this server"),
                false => format!("inspect {image}: {}", message(&e)),
            })?;
            ev.system(format!("Using {image}, already on this server")).await;
            if image != tag {
                tag_image(&docker, image, tag).await?;
            }
        }
    }
    let image_id = docker.inspect_image(tag).await.map_err(|e| format!("inspect {tag}: {}", message(&e)))?.id;
    let image_id = image_id.unwrap_or_default();
    ev.system(format!("Image {tag} ({})", short(&image_id))).await;
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
    let new_id = match create(&docker, d, &name, slot, &files).await {
        Ok(id) => id,
        Err(e) => {
            volumes::prune_files(&d.resource, current_deployment(&previous).as_deref());
            return Err(e);
        }
    };
    drop(files);
    let undo = async |e: String| -> Result<DeployOutput, String> {
        remove_container(&docker, &new_id).await.ok();
        volumes::prune_files(&d.resource, current_deployment(&previous).as_deref());
        if !running.is_empty() {
            ev.system("The previous container keeps serving").await;
        }
        Err(e)
    };
    if let Err(e) = start(&docker, d, &new_id, ev, cancel).await {
        return undo(e).await;
    }

    // Past this point the deployment completes even if cancelled: the router is about to serve the new container.
    ev.step(Step::Switching).await;
    let legacy: Vec<String> = running.iter().filter(|c| publishes(c)).filter_map(|c| c.id.clone()).collect();
    for id in &legacy {
        ev.system(format!("Moving the application behind the router: stopping {}", short(id))).await;
        if let Err(e) = stop(&docker, id).await {
            return undo(e).await;
        }
    }
    let up = Upstream::Slot { slot };
    if let Err(e) = router::switch(&docker, &d.resource, &d.network, up, routes(d), Some(ev)).await {
        for id in &legacy {
            if let Err(e) = docker.start_container(id, None).await {
                ev.system(format!("Could not restart {}: {}", short(id), message(&e))).await;
            }
        }
        return undo(format!("router: {e}")).await;
    }
    ev.system(format!("{name} is now serving")).await;

    ev.step(Step::Cleaning).await;
    if running.iter().any(|c| !publishes(c)) {
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
    Ok(DeployOutput { image: tag.clone(), image_id, container_id: new_id, commit, known_hosts })
}

/// The deployment of the newest container, whose files stay.
fn current_deployment(list: &[ContainerSummary]) -> Option<String> {
    list.first().and_then(|c| c.labels.as_ref()?.get(LABEL_DEPLOYMENT).cloned())
}

fn short(id: &str) -> &str {
    let id = id.strip_prefix("sha256:").unwrap_or(id);
    &id[..id.len().min(12)]
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

async fn pull(
    d: &Docker,
    image: &str,
    auth: Option<&RegistryAuth>,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<String, String> {
    let reference = pull_reference(image);
    ev.system(format!("Pulling {reference}")).await;
    let creds = auth.map(|a| DockerCredentials {
        username: Some(a.username.clone()),
        password: Some(a.password.clone()),
        serveraddress: Some(a.server.clone()),
        ..Default::default()
    });
    let mut s = d.create_image(Some(CreateImageOptionsBuilder::default().from_image(&reference).build()), None, creds);
    loop {
        let item = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(CANCELLED.into()),
            i = s.next() => i,
        };
        let Some(item) = item else { break };
        let info = item.map_err(|e| format!("pull {reference}: {}", message(&e)))?;
        if let Some(e) = info.error_detail {
            return Err(format!("pull {reference}: {}", e.message.unwrap_or_default()));
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

async fn create(
    d: &Docker,
    dep: &AppDeploy,
    name: &str,
    slot: Slot,
    files: &[(std::path::PathBuf, &deploy_proto::msg::FileMount)],
) -> Result<String, String> {
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
    let c = d.create_container(Some(opts), body).await.map_err(|e| format!("create {name}: {}", message(&e)))?;
    Ok(c.id)
}

/// Starts the new container and waits until it is healthy. Its log goes to the deployment log meanwhile, so a crash
/// at start-up is visible there.
async fn start(
    d: &Docker,
    dep: &AppDeploy,
    new_id: &str,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(), String> {
    d.start_container(new_id, None).await.map_err(|e| format!("start: {}", message(&e)))?;
    ev.system(format!("Started {}", short(new_id))).await;
    let follow = tokio::spawn(follow_logs(d.clone(), new_id.to_string(), ev.clone()));
    let r = cancellable(cancel, wait_healthy(d, dep, new_id, ev)).await;
    follow.abort();
    let _ = follow.await;
    r?;
    // Only a container that passed its checks restarts by itself: one crashing at start-up stays down, with its exit
    // code, while the previous container keeps serving.
    let promote = ContainerUpdateBody {
        restart_policy: Some(RestartPolicy {
            name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
            maximum_retry_count: None,
        }),
        ..Default::default()
    };
    d.update_container(new_id, promote).await.map_err(|e| format!("restart policy: {}", message(&e)))
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

/// Why the new container is not up, if it is not.
async fn exited(d: &Docker, id: &str) -> Result<Option<String>, String> {
    let c = d.inspect_container(id, None).await.map_err(|e| format!("inspect: {}", message(&e)))?;
    let s = c.state.unwrap_or_default();
    let down = !s.running.unwrap_or(false);
    Ok(down.then(|| {
        let mut m = format!("the container exited with code {}", s.exit_code.unwrap_or(-1));
        if s.oom_killed == Some(true) {
            m.push_str(" (out of memory)");
        }
        m
    }))
}

async fn wait_healthy(d: &Docker, dep: &AppDeploy, id: &str, ev: &Events) -> Result<(), String> {
    let Some(h) = &dep.run.health else {
        tokio::time::sleep(SETTLE).await;
        return match exited(d, id).await? {
            Some(m) => Err(m),
            None => Ok(()),
        };
    };
    ev.step(Step::HealthCheck).await;
    let c = d.inspect_container(id, None).await.map_err(|e| format!("inspect: {}", message(&e)))?;
    let ip = c
        .network_settings
        .and_then(|n| n.networks)
        .and_then(|mut n| n.remove(&dep.network))
        .and_then(|e| e.ip_address)
        .filter(|ip| !ip.is_empty());
    let Some(ip) = ip else {
        // A container that already crashed has no address: its exit is the error worth reporting.
        return Err(match exited(d, id).await? {
            Some(m) => format!("health check failed: {m}"),
            None => format!("the container has no address on {}", dep.network),
        });
    };
    probe(d, id, &format!("http://{ip}:{}{}", dep.run.port, h.path), h, ev).await
}

async fn probe(d: &Docker, id: &str, url: &str, h: &HealthCheck, ev: &Events) -> Result<(), String> {
    let timeout = Duration::from_secs(u64::from(h.timeout_secs.max(1)));
    // Redirects count as an answer: following one would leave the container (to its public HTTPS URL).
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let tries = h.retries.max(1);
    ev.system(format!("Health check: GET {url} (every {}s, {tries} tries)", h.interval_secs)).await;
    for n in 1..=tries {
        tokio::time::sleep(Duration::from_secs(u64::from(h.interval_secs.max(1)))).await;
        if let Some(m) = exited(d, id).await? {
            return Err(format!("health check failed: {m}"));
        }
        match client.get(url).send().await {
            Ok(r) if r.status().as_u16() < 400 => {
                ev.system(format!("Health check passed: HTTP {}", r.status().as_u16())).await;
                return Ok(());
            }
            Ok(r) => ev.system(format!("Health check {n}/{tries}: HTTP {}", r.status().as_u16())).await,
            Err(e) => ev.system(format!("Health check {n}/{tries}: {}", cause(&e))).await,
        }
    }
    Err(format!("health check failed after {tries} tries"))
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
}
