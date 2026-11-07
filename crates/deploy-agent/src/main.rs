//! `owdeploy-agent`: the OpenWAF Deploy agent on a server (PROTOCOL.md).
//!
//! ```text
//! owdeploy-agent enroll --url https://deploy.openwaf.dev --token-file /root/owde-token [--name web-1]
//! owdeploy-agent run
//! owdeploy-agent firewall-repair   # re-applies the firewall rules if they are missing (CSF post hook)
//! owdeploy-agent csf-hook          # installs that hook when CSF is present
//! owdeploy-agent pin-keys [--control-key KEY] [--update-key KEY] [--release-key KEY]   # by hand (README.md)
//! owdeploy-agent version
//! ```
//!
//! State (identity and pinned control-plane keys) lives in `$OWDEPLOY_AGENT_STATE` (default /var/lib/owdeploy-agent),
//! mode 0700/0600. The agent never opens a port: it dials the control plane and keeps one WebSocket of signed frames.
//!
//! Build limits (environment of the service; an invalid value is logged and the default used, see `builder`):
//! `OWDEPLOY_BUILD_CPUS` (2), `OWDEPLOY_BUILD_MEMORY_MB` (4096, no swap on top), `OWDEPLOY_BUILD_PIDS` (2048) for each
//! BuildKit builder and build helper; `OWDEPLOY_BUILD_CACHE_GB` (10) and `OWDEPLOY_BUILD_CACHE_MAX_AGE_HOURS` (168) for
//! each builder's cache.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use deploy_proto::msg::{
    AgentUpdate, Cancel, Command, CommandResult, ControlKeyRotate, Heartbeat, Hello, Op, Outcome, Ping, Pong, UpdateKey,
};
use deploy_proto::{Direction, Sealer, connect};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_util::sync::CancellationToken;

use crate::events::{Events, Outgoing};
use crate::keys::{Identity, KeyRing};
use crate::update::{Fetched, Poll, Updater};

mod app;
mod builder;
mod compose;
mod deploy;
mod docker;
mod dockerfile;
mod dockerignore;
#[cfg(test)]
mod e2e;
mod events;
mod exec;
mod firewall;
mod git;
mod host;
mod keys;
mod router;
mod update;
mod volumes;

/// Error of a command stopped by a `cancel` frame (or by the end of its session).
pub const CANCELLED: &str = "cancelled";

const HEARTBEAT_EVERY: Duration = Duration::from_secs(30);

fn state_dir() -> PathBuf {
    std::env::var_os("OWDEPLOY_AGENT_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/owdeploy-agent"))
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    o.mode(0o600);
    let mut f = o.open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

#[derive(Deserialize)]
struct EnrollOut {
    server_id: String,
    org_id: String,
    control_public_key: String,
    connect_url: String,
    /// From control planes with an update key.
    #[serde(default)]
    update_public_key: Option<String>,
    /// From control planes with an offline release key: every binary this agent installs must be signed by it.
    #[serde(default)]
    release_public_key: Option<String>,
}

async fn enroll(url: &str, token_file: &str, name: Option<String>) -> Result<(), String> {
    let dir = state_dir();
    if Identity::path(&dir).exists() {
        return Err(format!("{} exists: this server is already enrolled", Identity::path(&dir).display()));
    }
    let token = std::fs::read_to_string(token_file).map_err(|e| format!("{token_file}: {e}"))?.trim().to_string();
    let key = deploy_proto::generate_key();
    let h = host::facts();
    let body = serde_json::json!({
        "token": token, "public_key": deploy_proto::encode_key(&key.verifying_key()), "name": name,
        "hostname": h.hostname, "os": h.os, "arch": h.arch, "kernel": h.kernel, "agent_version": deploy_proto::build_version(),
    });
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/agent/enroll", url.trim_end_matches('/')))
        .json(&body)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("enroll: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        // The API's error message (a refused token, the organization's server quota) rather than its JSON.
        let message = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
            .unwrap_or(text);
        return Err(format!("enroll: HTTP {status}: {message}"));
    }
    let out: EnrollOut = resp.json().await.map_err(|e| format!("enroll: {e}"))?;
    if out.update_public_key.as_deref().is_some_and(|k| deploy_proto::decode_key(k).is_none()) {
        return Err("enroll: the control plane's update key is invalid".into());
    }
    if out.release_public_key.as_deref().is_some_and(|k| deploy_proto::decode_key(k).is_none()) {
        return Err("enroll: the control plane's release key is invalid".into());
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let id = Identity {
        server_id: out.server_id.clone(),
        org_id: out.org_id,
        key: B64.encode(key.to_bytes()),
        control_public_key: out.control_public_key,
        connect_url: out.connect_url,
        control_next_public_key: None,
        update_public_key: out.update_public_key,
        release_public_key: out.release_public_key,
    };
    id.save(&dir)?;
    let _ = std::fs::remove_file(token_file);
    println!("enrolled as {}", out.server_id);
    Ok(())
}

/// Runs until the agent must restart (a new binary installed or a rollback): Ok, and the process exits with
/// [`update::RESTART_EXIT`] for systemd to start the binary again.
async fn run() -> Result<(), String> {
    let dir = state_dir();
    let mut ring = KeyRing::load(&dir)?;
    let key = ring.id.signing_key()?;
    let bin = update::Binary::current().map_err(|e| tracing::warn!("self-update unavailable: {e}")).ok();
    let (fetched_tx, mut fetched) = tokio::sync::mpsc::channel::<Fetched>(4);
    let connect_url = ring.id.connect_url.clone();
    let mut up = Updater::new(dir.clone(), bin.clone(), ring.id.trust()?, &connect_url, fetched_tx);
    if let Some(b) = &bin {
        match update::on_start(&dir, &b.sha256, now())? {
            update::Start::Normal => {}
            update::Start::Probation { deadline, marker } => {
                tracing::info!(
                    "running {} after an update: it must connect within {} s",
                    marker.to_version,
                    deadline - now()
                );
                let confirmed = CancellationToken::new();
                tokio::spawn(watchdog(deadline, b.path.clone(), confirmed.clone()));
                up.on_probation(marker, confirmed);
            }
            update::Start::RollBack(m) => match update::roll_back(&b.path) {
                Ok(()) => {
                    tracing::error!("{} did not connect in time after its installation: rolled back", m.to_version);
                    return Ok(());
                }
                Err(e) => tracing::error!("{} did not connect in time, and cannot roll back: {e}", m.to_version),
            },
            update::Start::Failed(st) => {
                tracing::error!(
                    "the update to {} was rolled back: {}",
                    st.version,
                    st.message.as_deref().unwrap_or("")
                );
                up.report(st);
            }
        }
    }
    // After a reboot the firewall chains are gone; after a crash a Git helper may be left. Neither blocks the agent:
    // the firewall watch below repairs the rules every 30 s and the control plane syncs them after deployments.
    if let Err(e) = firewall::reconcile().await {
        tracing::warn!("firewall: {e}");
    }
    if let Some(b) = &bin {
        match firewall::install_csf_hook(&b.path) {
            Ok(Some(p)) => tracing::info!("firewall: CSF post hook installed in {}", p.display()),
            Ok(None) => {}
            Err(e) => tracing::warn!("firewall: CSF post hook: {e}"),
        }
    }
    tokio::spawn(firewall::watch());
    match git::remove_leftover_helpers().await {
        Ok(0) => {}
        Ok(n) => tracing::info!("removed {n} leftover Git helper containers"),
        Err(e) => tracing::warn!("Git helpers: {e}"),
    }
    let mut failures = 0u32;
    loop {
        match session(&mut ring, &key, &mut up, &mut fetched).await {
            Ok(Flow::Restart) => return Ok(()),
            Ok(Flow::Closed) => failures = 0,
            Err(e) => {
                failures += 1;
                tracing::warn!("connection: {e}");
                if e.contains("401") {
                    tracing::error!("the control plane refused this agent (revoked or unknown); retrying slowly");
                }
            }
        }
        let wait = Duration::from_secs((2u64 << failures.min(6)).min(120)) + Duration::from_millis(jitter_ms());
        tokio::time::sleep(wait).await;
    }
}

/// A newly installed binary that has not connected by `deadline` puts the previous one back and exits.
async fn watchdog(deadline: i64, bin: PathBuf, confirmed: CancellationToken) {
    let wait = Duration::from_secs(u64::try_from(deadline - now()).unwrap_or(0));
    tokio::select! {
        _ = confirmed.cancelled() => {}
        _ = tokio::time::sleep(wait) => match update::roll_back(&bin) {
            Ok(()) => {
                tracing::error!("no connection within {} s of the update: rolled back", update::CONFIRM_WITHIN.as_secs());
                std::process::exit(update::RESTART_EXIT.into());
            }
            Err(e) => tracing::error!("no connection after the update, and cannot roll back: {e}"),
        },
    }
}

/// How a session ended without an error.
enum Flow {
    /// The connection closed: dial again.
    Closed,
    /// A new binary is installed: exit for systemd to start it.
    Restart,
}

fn jitter_ms() -> u64 {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).expect("OS randomness");
    u64::from(u16::from_le_bytes(b)) % 2000
}

async fn session(
    ring: &mut KeyRing,
    key: &SigningKey,
    up: &mut Updater,
    fetched: &mut tokio::sync::mpsc::Receiver<Fetched>,
) -> Result<Flow, String> {
    let id = &ring.id;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).expect("OS randomness");
    let nonce = hex::encode(nonce);
    let ts = now();
    let body = format!("{}\n{nonce}", id.server_id);
    let sig =
        key.sign(&deploy_proto::signing_message(Direction::AgentToControl, 0, ts, connect::KIND, body.as_bytes()));
    let mut req = id.connect_url.as_str().into_client_request().map_err(|e| e.to_string())?;
    let h = req.headers_mut();
    h.insert(connect::HDR_SERVER, id.server_id.parse().map_err(|_| "server id")?);
    h.insert(connect::HDR_TIMESTAMP, ts.to_string().parse().expect("number"));
    h.insert(connect::HDR_NONCE, nonce.parse().expect("hex"));
    h.insert(connect::HDR_SIGNATURE, deploy_proto::encode_signature(&sig).parse().expect("base64"));
    let (ws, _) = tokio_tungstenite::connect_async(req).await.map_err(|e| e.to_string())?;
    tracing::info!(server = %id.server_id, "connected");
    let (mut sink, mut stream) = ws.split();
    let mut sealer = Sealer::new(key.clone(), Direction::AgentToControl);
    let mut opener = ring.opener()?;
    let facts = host::facts();
    let hello = Hello {
        agent_version: deploy_proto::build_version(),
        hostname: facts.hostname,
        os: facts.os,
        arch: facts.arch,
        kernel: facts.kernel,
        docker: docker::info().await.ok(),
        features: deploy_proto::msg::feature::ALL.iter().map(|f| f.to_string()).collect(),
        binary_sha256: up.own_sha256(),
        keys: Some(ring.id.pinned(None)),
    };
    send(&mut sink, &sealer.seal(&hello, now())).await?;
    let mut beat = tokio::time::interval(HEARTBEAT_EVERY);
    beat.tick().await;
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Outgoing>(256);
    let mut running = Running::default();
    let mut verified = false;
    // A binary downloaded during an earlier session installs now, before any command.
    if after_change(up, &running, &mut sink, &mut sealer).await? {
        return Ok(Flow::Restart);
    }
    loop {
        tokio::select! {
            m = stream.next() => {
                let text = match m {
                    Some(Ok(Message::Text(t))) => t,
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                    Some(Ok(Message::Binary(_))) => continue,
                    Some(Ok(Message::Close(_))) | None => return Ok(Flow::Closed),
                    Some(Err(e)) => return Err(e.to_string()),
                };
                let (frame, rotated) = ring.open(&mut opener, text.as_str(), now())?;
                if let Some(keys) = rotated {
                    up.set_trust(ring.id.trust()?);
                    send(&mut sink, &sealer.seal(&keys, now())).await?;
                }
                if !verified {
                    // Both ways work with the pinned key: a binary on probation after an update is confirmed.
                    verified = true;
                    for st in up.connected() {
                        send(&mut sink, &sealer.seal(&st, now())).await?;
                    }
                }
                match frame.kind.as_str() {
                    "command" => {
                        let cmd = match serde_json::from_str::<Command>(&frame.body) {
                            Ok(c) => c,
                            // An operation of a newer control plane: answered, not fatal to the session.
                            Err(e) => {
                                let id = serde_json::from_str::<serde_json::Value>(&frame.body)
                                    .ok()
                                    .and_then(|v| v.get("id")?.as_str().map(str::to_string))
                                    .ok_or("command without an id")?;
                                let outcome = match e.to_string().contains("unknown variant") {
                                    true => Outcome::Unsupported,
                                    false => Outcome::Error { message: format!("invalid command: {e}") },
                                };
                                send(&mut sink, &sealer.seal(&CommandResult { id, outcome }, now())).await?;
                                continue;
                            }
                        };
                        let cancel = CancellationToken::new();
                        running.0.insert(cmd.id.clone(), (cancel.clone(), blocks_update(&cmd.op)));
                        let out = out_tx.clone();
                        tokio::spawn(async move {
                            let (ev, batcher) = Events::start(cmd.id.clone(), out.clone());
                            let outcome = execute(cmd.op, &ev, &cancel).await;
                            // Every event of the command is out before its result.
                            drop(ev);
                            let _ = batcher.await;
                            let _ = out.send(Outgoing::Result(CommandResult { id: cmd.id, outcome })).await;
                        });
                    }
                    "cancel" => {
                        let c: Cancel = frame.decode().map_err(|e| e.to_string())?;
                        if let Some((t, _)) = running.0.get(&c.id) {
                            t.cancel();
                        }
                    }
                    "ping" => {
                        let p: Ping = frame.decode().map_err(|e| e.to_string())?;
                        send(&mut sink, &sealer.seal(&Pong { nonce: p.nonce }, now())).await?;
                    }
                    "agent_update" => match frame.decode::<AgentUpdate>() {
                        Ok(u) => {
                            if let Some(st) = up.offer(u, now()) {
                                send(&mut sink, &sealer.seal(&st, now())).await?;
                            }
                            if after_change(up, &running, &mut sink, &mut sealer).await? {
                                return Ok(Flow::Restart);
                            }
                        }
                        Err(e) => tracing::warn!("update offer: {e}"),
                    },
                    // Key announcements: only in frames the pinned keys opened (see `keys`).
                    "control_key_rotate" => match frame.decode::<ControlKeyRotate>() {
                        Ok(m) => {
                            let keys = ring.rotate(&mut opener, &m);
                            send(&mut sink, &sealer.seal(&keys, now())).await?;
                        }
                        Err(e) => tracing::warn!("control key rotation: {e}"),
                    },
                    "update_key" => match frame.decode::<UpdateKey>() {
                        Ok(m) => {
                            let keys = ring.update_key(&m);
                            up.set_trust(ring.id.trust()?);
                            send(&mut sink, &sealer.seal(&keys, now())).await?;
                        }
                        Err(e) => tracing::warn!("update key: {e}"),
                    },
                    _ => {}
                }
            }
            Some(o) = out_rx.recv() => match o {
                Outgoing::Event(e) => send(&mut sink, &sealer.seal(&e, now())).await?,
                Outgoing::Result(r) => {
                    running.0.remove(&r.id);
                    send(&mut sink, &sealer.seal(&r, now())).await?;
                    if after_change(up, &running, &mut sink, &mut sealer).await? {
                        return Ok(Flow::Restart);
                    }
                }
            },
            Some(f) = fetched.recv() => {
                if let Some(st) = up.fetched(f) {
                    send(&mut sink, &sealer.seal(&st, now())).await?;
                }
                if after_change(up, &running, &mut sink, &mut sealer).await? {
                    return Ok(Flow::Restart);
                }
            }
            _ = beat.tick() => {
                let hb: Heartbeat = host::heartbeat(docker::running().await.unwrap_or(0));
                send(&mut sink, &sealer.seal(&hb, now())).await?;
            }
        }
    }
}

/// Installs a downloaded binary when nothing but log streams runs. True: installed, the agent restarts now.
async fn after_change<S>(up: &mut Updater, running: &Running, sink: &mut S, sealer: &mut Sealer) -> Result<bool, String>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    match up.poll(running.busy(), now()) {
        Poll::Idle => Ok(false),
        Poll::Status(st) => send(sink, &sealer.seal(&st, now())).await.map(|()| false),
        Poll::Restart(st) => {
            tracing::info!("installed {}: restarting", st.version);
            send(sink, &sealer.seal(&st, now())).await?;
            let _ = sink.close().await;
            Ok(true)
        }
    }
}

/// Whether a running command holds back an update: everything but a log stream, which only loses its follower.
fn blocks_update(op: &Op) -> bool {
    !matches!(op, Op::AppLogs { .. })
}

/// Commands of a session by id, with whether each holds back an update. When the session ends their results can no
/// longer be delivered, so they are cancelled: a following log stream stops, a deployment rolls back to the previous
/// container.
#[derive(Default)]
struct Running(HashMap<String, (CancellationToken, bool)>);

impl Running {
    fn busy(&self) -> bool {
        self.0.values().any(|(_, blocks)| *blocks)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.0.values().for_each(|(t, _)| t.cancel());
    }
}

async fn send<S>(sink: &mut S, f: &deploy_proto::Frame) -> Result<(), String>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    sink.send(Message::Text(serde_json::to_string(f).expect("frame").into())).await.map_err(|e| e.to_string())
}

async fn execute(op: Op, ev: &Events, cancel: &CancellationToken) -> Outcome {
    fn value<T: Serialize>(r: Result<T, String>) -> Result<serde_json::Value, String> {
        r.map(|v| serde_json::to_value(v).expect("serializable output"))
    }
    let r = match op {
        // Deployments and log streams watch the token themselves (a deployment restores the previous container
        // before it reports the cancel); short operations are simply abandoned.
        Op::DeployApp(d) => value(deploy::run(&d, ev, cancel).await),
        Op::AppLogs { resource, tail, follow, since, service } => {
            app::logs(&resource, tail, follow, since, service.as_deref(), ev, cancel).await
        }
        Op::DeployCompose(c) => value(compose::deploy(&c, ev, cancel).await),
        Op::Exec(spec) => value(exec::exec(&spec, ev, cancel).await),
        Op::DockerInfo => deploy::cancellable(cancel, async { value(docker::info().await) }).await,
        Op::ContainerList { managed_only } => deploy::cancellable(cancel, docker::containers(managed_only)).await,
        Op::AppAction { resource, action } => {
            deploy::cancellable(cancel, async { value(app::action(&resource, action).await) }).await
        }
        Op::AppStatus { resource } => deploy::cancellable(cancel, async { value(app::status(&resource).await) }).await,
        Op::ImagePrune { resource, keep } => deploy::cancellable(cancel, app::prune(&resource, &keep)).await,
        Op::FirewallSync(rules) => deploy::cancellable(cancel, firewall::sync(&rules)).await,
        // Router changes are not abandoned halfway: a cancel would leave the router between two configurations.
        Op::RouterSync(cfg) => value(router::sync(&cfg).await),
        Op::VolumeRemove { resource, names } => {
            deploy::cancellable(cancel, volumes::remove(&resource, names.as_deref())).await
        }
    };
    match r {
        Ok(output) => Outcome::Ok { output },
        Err(message) => Outcome::Error { message },
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: owdeploy-agent enroll --url URL --token-file PATH [--name NAME] | run | firewall-repair | csf-hook | \
         pin-keys [--control-key KEY] [--update-key KEY] [--release-key KEY] | version"
    );
    ExitCode::from(2)
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("OWDEPLOY_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let r = match args.first().map(String::as_str) {
        Some("enroll") => match (flag("--url"), flag("--token-file")) {
            (Some(u), Some(t)) => enroll(&u, &t, flag("--name")).await,
            _ => return usage(),
        },
        Some("run") => match run().await {
            Ok(()) => return ExitCode::from(update::RESTART_EXIT),
            Err(e) => Err(e),
        },
        Some("firewall-repair") => firewall::reconcile().await.map(|repaired| match repaired.is_empty() {
            true => println!("owdeploy-agent: firewall rules in place"),
            false => println!("owdeploy-agent: firewall repaired: {}", repaired.join("; ")),
        }),
        Some("csf-hook") => std::env::current_exe()
            .map_err(|e| format!("own binary: {e}"))
            .and_then(|bin| firewall::install_csf_hook(&bin))
            .map(|p| match p {
                Some(p) => println!("owdeploy-agent: CSF post hook installed in {}", p.display()),
                None => println!("owdeploy-agent: CSF post hook not needed (no CSF, or already installed)"),
            }),
        // Recovery by hand (README.md): stop the agent, pin, start it again.
        Some("pin-keys") => keys::pin_by_hand(
            &state_dir(),
            flag("--control-key").as_deref(),
            flag("--update-key").as_deref(),
            flag("--release-key").as_deref(),
        )
        .map(|id| {
            println!("owdeploy-agent: control key {}", id.control_public_key);
            println!("owdeploy-agent: update key {}", id.update_public_key.as_deref().unwrap_or("(none)"));
            println!("owdeploy-agent: release key {}", id.release_public_key.as_deref().unwrap_or("(none)"));
            println!("owdeploy-agent: restart the agent to use them (systemctl restart owdeploy-agent)");
        }),
        Some("version") => {
            println!("owdeploy-agent {} (protocol {})", deploy_proto::build_version(), deploy_proto::CONTEXT);
            Ok(())
        }
        _ => return usage(),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A running deployment (or any command but a log stream) holds an update back; a log stream does not.
    #[test]
    fn update_skipped_while_a_deployment_runs() {
        let mut r = Running::default();
        let logs = Op::AppLogs { resource: "app_1".into(), tail: 10, follow: true, since: None, service: None };
        r.0.insert("logs".into(), (CancellationToken::new(), blocks_update(&logs)));
        assert!(!r.busy(), "a following log stream does not hold an update");
        let deploy = Op::DeployCompose(deploy_proto::msg::ComposeDeploy {
            resource: "app_1".into(),
            deployment: "dep_1".into(),
            network: "owd-env".into(),
            source: deploy_proto::msg::ComposeSource::Inline { content: "services: {}".into() },
            env: Default::default(),
            volumes: vec![],
            files: vec![],
            labels: Default::default(),
            routes: vec![],
            no_cache: false,
        });
        r.0.insert("dep".into(), (CancellationToken::new(), blocks_update(&deploy)));
        assert!(r.busy());
        r.0.remove("dep");
        assert!(!r.busy(), "installed once the deployment ended");
    }
}
