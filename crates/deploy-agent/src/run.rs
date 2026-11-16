//! One-off containers: a deployment's release command (`AppDeploy::release`, the `releasing` step) and `RunOnce`
//! (manual runs, scheduled tasks in their own container). Each runs a command once in a new container of one of the
//! application's images, with its environment and network, then is removed.
//!
//! The container is never one of the application's: it carries [`LABEL_RUN`] instead of [`LABEL_RESOURCE`] and is
//! named `owd-run-<resource>-<id>`, so no deployment stops or removes it, no status, exec or log stream picks it, and
//! it joins the network under its own name only (no alias of the application or its router slot: it never takes
//! traffic). It runs with Docker's init process, so the orphans of its command are reaped, and without volumes unless
//! the run asks for them.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bollard::Docker;
use bollard::models::{
    ContainerCreateBody, EndpointSettings, HostConfig, HostConfigLogConfig, Mount, NetworkingConfig, RestartPolicy,
    RestartPolicyNameEnum,
};
use bollard::query_parameters::{CreateContainerOptionsBuilder, KillContainerOptionsBuilder, LogsOptionsBuilder};
use deploy_proto::msg::cause::RELEASE_FAILED;
use deploy_proto::msg::{
    AppDeploy, ExecOutput, LABEL_ENVIRONMENT, LABEL_RUN, LABEL_RUN_ID, LogStream, MAX_EXEC_OUTPUT, Release, RunOnceSpec,
};
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::CANCELLED;
use crate::deploy::{check_env, check_network_name, engine_has_init, name_ok};
use crate::docker::{check_image, is_not_found, labelled, message, remove_container, valid_id};
use crate::events::{Events, Lines};
use crate::exec::Tail;
use crate::failure::Failure;
use crate::volumes;

/// Longest run accepted from the control plane (a day, as scheduled tasks).
const MAX_TIMEOUT_SECS: u32 = 86_400;
/// How long a killed container may take to close its log before the agent stops waiting for it.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// Most arguments of a command, and most bytes of them all.
const MAX_ARGS: usize = 64;
const MAX_COMMAND_BYTES: usize = 16 * 1024;

/// Name of a one-off container: `owd-run-<resource>-<id>`, lowercased. Never `owd-<resource>-…`, the names of the
/// application's own containers.
pub fn container_name(resource: &str, id: &str) -> String {
    format!("owd-run-{}-{}", resource.to_ascii_lowercase(), id.to_ascii_lowercase())
}

fn check_command(command: &[String]) -> Result<(), String> {
    if command.is_empty() || command.first().is_some_and(String::is_empty) {
        return Err("the command is empty".into());
    }
    if command.len() > MAX_ARGS || command.iter().map(String::len).sum::<usize>() > MAX_COMMAND_BYTES {
        return Err(format!("the command has more than {MAX_ARGS} arguments or {} KiB", MAX_COMMAND_BYTES / 1024));
    }
    if command.iter().any(|a| a.contains('\0')) {
        return Err("the command contains NUL".into());
    }
    Ok(())
}

fn check_timeout(secs: u32) -> Result<(), String> {
    match secs {
        1..=MAX_TIMEOUT_SECS => Ok(()),
        _ => Err(format!("the timeout must be 1-{MAX_TIMEOUT_SECS} s")),
    }
}

/// The command as a person reads it (arguments with spaces or quotes quoted).
pub fn display(command: &[String]) -> String {
    command
        .iter()
        .map(|a| match a.is_empty() || a.chars().any(|c| c.is_whitespace() || "'\"\\$`".contains(c)) {
            true => format!("{a:?}"),
            false => a.clone(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// What one container runs.
struct OneOff<'a> {
    resource: &'a str,
    id: &'a str,
    image: &'a str,
    network: &'a str,
    command: &'a [String],
    env: Vec<String>,
    mounts: Vec<Mount>,
    memory_bytes: Option<u64>,
    cpus: Option<f64>,
    environment: Option<&'a str>,
    timeout_secs: u32,
}

/// Files of a one-off container: written under its own directory (never pruned by a deployment), removed when this
/// guard drops.
struct Files {
    resource: String,
    id: String,
}

impl Files {
    fn new(resource: &str, id: &str) -> Files {
        Files { resource: resource.to_string(), id: id.to_string() }
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        volumes::remove_run_files(&self.resource, &self.id);
    }
}

/// Runs `o` to its end and removes its container, whatever happened. A cancel kills it and is the error.
async fn one_off(d: &Docker, o: OneOff<'_>, ev: &Events, cancel: &CancellationToken) -> Result<ExecOutput, String> {
    let name = container_name(o.resource, o.id);
    // An earlier attempt of the same run, and containers of this application's runs that ended without being
    // removed (an agent that stopped meanwhile), go first. Another run of the application that is starting stays.
    for c in labelled(d, LABEL_RUN, o.resource).await? {
        let same = c.names.iter().flatten().any(|n| n.trim_start_matches('/') == name);
        let ended = c.state.as_ref().is_some_and(|s| matches!(s.to_string().as_str(), "exited" | "dead"));
        if same || ended {
            remove_container(d, c.id.as_deref().unwrap_or_default()).await?;
        }
    }
    let id = create(d, &o, &name).await?;
    let r = attend(d, &id, &o, ev, cancel).await;
    if let Err(e) = remove_container(d, &id).await {
        ev.system(format!("Could not remove the container {name}: {e}")).await;
    }
    r
}

async fn create(d: &Docker, o: &OneOff<'_>, name: &str) -> Result<String, String> {
    let mut labels =
        HashMap::from([(LABEL_RUN.to_string(), o.resource.to_string()), (LABEL_RUN_ID.into(), o.id.into())]);
    if let Some(env) = o.environment {
        labels.insert(LABEL_ENVIRONMENT.into(), env.into());
    }
    let init = engine_has_init(d).await;
    let body = ContainerCreateBody {
        image: Some(o.image.to_string()),
        env: Some(o.env.clone()),
        cmd: Some(o.command.to_vec()),
        labels: Some(labels),
        host_config: Some(HostConfig {
            restart_policy: Some(RestartPolicy { name: Some(RestartPolicyNameEnum::NO), maximum_retry_count: None }),
            memory: o.memory_bytes.map(|m| m.min(i64::MAX as u64) as i64),
            nano_cpus: o.cpus.filter(|c| *c > 0.0).map(|c| (c * 1e9) as i64),
            log_config: Some(HostConfigLogConfig {
                typ: Some("json-file".into()),
                config: Some(HashMap::from([
                    ("max-size".to_string(), "20m".to_string()),
                    ("max-file".to_string(), "2".to_string()),
                ])),
            }),
            mounts: (!o.mounts.is_empty()).then(|| o.mounts.clone()),
            network_mode: Some(o.network.to_string()),
            init: init.then_some(true),
            ..Default::default()
        }),
        // Its own name only: no alias of the application or of a router slot, so it never receives a request.
        networking_config: Some(NetworkingConfig {
            endpoints_config: Some(HashMap::from([(o.network.to_string(), EndpointSettings::default())])),
        }),
        ..Default::default()
    };
    let opts = CreateContainerOptionsBuilder::default().name(name).build();
    let c = d.create_container(Some(opts), body).await.map_err(|e| format!("create {name}: {}", message(&e)))?;
    Ok(c.id)
}

/// Starts the container and follows its output until it ends, is killed at its timeout, or is cancelled.
async fn attend(
    d: &Docker,
    id: &str,
    o: &OneOff<'_>,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<ExecOutput, String> {
    d.start_container(id, None).await.map_err(|e| format!("start: {}", message(&e)))?;
    let started = Instant::now();
    let opts = LogsOptionsBuilder::default().follow(true).stdout(true).stderr(true).build();
    let mut logs = d.logs(id, Some(opts));
    let deadline = tokio::time::sleep(Duration::from_secs(u64::from(o.timeout_secs)));
    tokio::pin!(deadline);
    let mut grace = Box::pin(tokio::time::sleep(Duration::MAX));
    let mut tail = Tail::new(MAX_EXEC_OUTPUT);
    let (mut out, mut err) = (Lines::default(), Lines::default());
    let mut stopped: Option<&str> = None;
    let kill = async |d: &Docker| {
        let opts = KillContainerOptionsBuilder::default().signal("SIGKILL").build();
        match d.kill_container(id, Some(opts)).await {
            Ok(()) => Ok(()),
            // Already stopped (409) or gone.
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 409, .. }) => Ok(()),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(format!("kill: {}", message(&e))),
        }
    };
    loop {
        let item = tokio::select! {
            biased;
            _ = cancel.cancelled(), if stopped.is_none() => {
                stopped = Some(CANCELLED);
                kill(d).await?;
                grace.as_mut().reset(tokio::time::Instant::now() + KILL_GRACE);
                continue;
            }
            _ = &mut deadline, if stopped.is_none() => {
                stopped = Some("timeout");
                ev.system(format!("Timed out after {}s: killing the container", o.timeout_secs)).await;
                kill(d).await?;
                grace.as_mut().reset(tokio::time::Instant::now() + KILL_GRACE);
                continue;
            }
            _ = &mut grace => break,
            i = logs.next() => i,
        };
        let Some(item) = item else { break };
        use bollard::container::LogOutput::*;
        let (stream, buf, chunk) = match item {
            Ok(StdErr { message }) => (LogStream::Stderr, &mut err, message),
            Ok(StdOut { message } | Console { message }) => (LogStream::Stdout, &mut out, message),
            Ok(StdIn { .. }) => continue,
            // The log stream broke (the container went away): the exit is read below.
            Err(_) => break,
        };
        tail.push(&chunk);
        for l in buf.push(&chunk) {
            ev.line(stream, l).await;
        }
    }
    for (stream, buf) in [(LogStream::Stdout, &mut out), (LogStream::Stderr, &mut err)] {
        if let Some(l) = buf.finish() {
            ev.line(stream, l).await;
        }
    }
    if stopped == Some(CANCELLED) {
        return Err(CANCELLED.into());
    }
    let (exit_code, oom) = exit(d, id).await?;
    if oom {
        ev.system("The container ran out of memory and was killed").await;
    }
    let secs = started.elapsed().as_secs_f64();
    match (stopped, exit_code) {
        (Some(_), _) => {}
        (None, Some(c)) => ev.system(format!("Exited with code {c} after {secs:.1}s")).await,
        (None, None) => ev.system(format!("Ended after {secs:.1}s without an exit code")).await,
    }
    Ok(ExecOutput {
        container_id: id.to_string(),
        exit_code,
        timed_out: stopped.is_some(),
        output: tail.text(),
        truncated: tail.dropped(),
    })
}

/// The container's exit code and whether it was killed for its memory, once it stopped (waiting a little for the
/// Engine to record it after the log closed).
async fn exit(d: &Docker, id: &str) -> Result<(Option<i64>, bool), String> {
    for _ in 0..50 {
        let i = d.inspect_container(id, None).await.map_err(|e| format!("inspect: {}", message(&e)))?;
        let s = i.state.unwrap_or_default();
        if s.running != Some(true) {
            return Ok((s.exit_code, s.oom_killed == Some(true)));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok((None, false))
}

/// The environment of a one-off container: the application's variables, and its `PORT` as its containers get it.
fn environment(env: &std::collections::BTreeMap<String, String>, port: Option<u16>) -> Vec<String> {
    let mut out: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    if let Some(p) = port.filter(|_| !env.contains_key("PORT")) {
        out.push(format!("PORT={p}"));
    }
    out
}

/// The release command of a deployment, in the `releasing` step: the deployment's new image, its variables, files and
/// network, no volume. Its output is the step's log; any exit code but 0, or its timeout, fails the deployment with
/// `release.failed` before anything of the application changed.
pub async fn release(
    d: &Docker,
    dep: &AppDeploy,
    r: &Release,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(), Failure> {
    check_command(&r.command)?;
    check_timeout(r.timeout_secs)?;
    let image = &dep.run.image_tag;
    ev.system(format!("Running the release command in a new container of {image}: {}", display(&r.command))).await;
    let _files = Files::new(&dep.resource, &dep.deployment);
    let written = volumes::write_run_files(&dep.resource, &dep.deployment, &dep.run.files)?;
    let o = OneOff {
        resource: &dep.resource,
        id: &dep.deployment,
        image,
        network: &dep.network,
        command: &r.command,
        env: environment(&dep.run.env, Some(dep.run.port)),
        mounts: volumes::mounts(&dep.resource, &[], &written),
        memory_bytes: dep.run.memory_bytes,
        cpus: dep.run.cpus,
        environment: dep.run.labels.get(LABEL_ENVIRONMENT).map(String::as_str),
        timeout_secs: r.timeout_secs,
    };
    let out = one_off(d, o, ev, cancel).await?;
    match (out.timed_out, out.exit_code) {
        (false, Some(0)) => {
            ev.system("The release command succeeded").await;
            Ok(())
        }
        (true, _) => Err(Failure::new(
            RELEASE_FAILED,
            [("timeout", r.timeout_secs.to_string())],
            format!("the release command did not finish within {}s", r.timeout_secs),
        )),
        (false, Some(c)) => Err(Failure::new(
            RELEASE_FAILED,
            [("exit_code", c.to_string())],
            format!("the release command exited with code {c}"),
        )),
        (false, None) => Err(Failure::new(RELEASE_FAILED, [], "the release command ended without an exit code")),
    }
}

/// The `RunOnce` operation.
pub async fn run_once(spec: &RunOnceSpec, ev: &Events, cancel: &CancellationToken) -> Result<ExecOutput, String> {
    if !valid_id(&spec.resource) || !valid_id(&spec.run) {
        return Err("invalid resource or run id".into());
    }
    check_image(&spec.resource, &spec.image)?;
    if !name_ok(&spec.network) {
        return Err("invalid network".into());
    }
    check_network_name(&spec.network)?;
    check_command(&spec.command)?;
    check_timeout(spec.timeout_secs)?;
    check_env(&spec.env)?;
    volumes::validate(&spec.volumes, &spec.files, false)?;
    let d = crate::docker::client()?;
    d.inspect_image(&spec.image).await.map_err(|e| match is_not_found(&e) {
        true => format!("the image {} is not on this server: deploy the application again", spec.image),
        false => format!("inspect {}: {}", spec.image, message(&e)),
    })?;
    // The volumes must exist already (the application created them): a run never creates one.
    for v in &spec.volumes {
        let name = volumes::volume_name(&spec.resource, &v.name);
        let vol = d.inspect_volume(&name).await.map_err(|e| format!("volume {name}: {}", message(&e)))?;
        crate::docker::check_volume(&spec.resource, &name, Some(&vol.labels))?;
    }
    let _files = Files::new(&spec.resource, &spec.run);
    let written = volumes::write_run_files(&spec.resource, &spec.run, &spec.files)?;
    ev.system(format!("Running in a new container of {}: {}", spec.image, display(&spec.command))).await;
    let o = OneOff {
        resource: &spec.resource,
        id: &spec.run,
        image: &spec.image,
        network: &spec.network,
        command: &spec.command,
        env: environment(&spec.env, None),
        mounts: volumes::mounts(&spec.resource, &spec.volumes, &written),
        memory_bytes: spec.memory_bytes,
        cpus: spec.cpus,
        environment: spec.labels.get(LABEL_ENVIRONMENT).map(String::as_str),
        timeout_secs: spec.timeout_secs,
    };
    one_off(&d, o, ev, cancel).await
}

/// Removes the one-off containers of `resource` (all of them: the application goes), running or not.
pub async fn remove_all(d: &Docker, resource: &str) -> Result<(), String> {
    for c in labelled(d, LABEL_RUN, resource).await? {
        remove_container(d, c.id.as_deref().unwrap_or_default()).await?;
    }
    Ok(())
}

/// At start: every one-off container belongs to a command of an earlier agent process, whose result can no longer be
/// delivered. Removes them (killing those still running) and their files.
pub async fn remove_leftovers() -> Result<usize, String> {
    let d = crate::docker::client()?;
    let filters = HashMap::from([("label".to_string(), vec![LABEL_RUN.to_string()])]);
    let opts = bollard::query_parameters::ListContainersOptionsBuilder::default().all(true).filters(&filters).build();
    let list = d.list_containers(Some(opts)).await.map_err(|e| format!("docker ps: {}", message(&e)))?;
    for c in &list {
        remove_container(&d, c.id.as_deref().unwrap_or_default()).await?;
    }
    volumes::remove_all_run_files();
    Ok(list.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_off_containers_are_never_the_applications() {
        let name = container_name("app_01JABC", "run_01JXYZ");
        assert_eq!(name, "owd-run-app_01jabc-run_01jxyz");
        let labels = HashMap::from([(LABEL_RUN.to_string(), "app_01JABC".to_string())]);
        assert!(crate::docker::check_container("app_01JABC", &[format!("/{name}")], Some(&labels)).is_err());
    }

    #[test]
    fn commands_are_checked() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(check_command(&v(&["npx", "prisma", "migrate", "deploy"])).is_ok());
        assert!(check_command(&[]).is_err());
        assert!(check_command(&v(&[""])).is_err());
        assert!(check_command(&v(&["sh", "-c", "a\0b"])).is_err());
        assert!(check_command(&vec!["x".to_string(); MAX_ARGS + 1]).is_err());
        assert!(
            check_timeout(0).is_err() && check_timeout(MAX_TIMEOUT_SECS + 1).is_err() && check_timeout(300).is_ok()
        );
        assert_eq!(display(&v(&["sh", "-c", "echo hi"])), "sh -c \"echo hi\"");
    }
}
