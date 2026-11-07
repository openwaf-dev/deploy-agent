//! `owdeploy-agent`: the OpenWAF Deploy agent on a server (PROTOCOL.md).
//!
//! ```text
//! owdeploy-agent enroll --url https://deploy.openwaf.dev --token-file /root/owde-token [--name web-1]
//! owdeploy-agent broker            # root: keys, frame checks, execution (unit owdeploy-agent-broker)
//! owdeploy-agent run               # the relay as owdeploy (unit owdeploy-agent); as root without a broker, the
//!                                  # single process of servers that have not migrated
//! owdeploy-agent migrate-split     # root: installs the broker's and the relay's units, with rollback
//! owdeploy-agent status            # the broker's relay and session
//! owdeploy-agent firewall-repair   # re-applies the firewall rules if they are missing (CSF post hook)
//! owdeploy-agent csf-hook          # installs that hook when CSF is present
//! owdeploy-agent pin-keys [--control-key KEY] [--update-key KEY] [--release-key KEY]   # by hand (README.md)
//! owdeploy-agent capabilities      # what this binary supports (split-privileges)
//! owdeploy-agent build-proxy       # the build egress proxy, in the container the agent runs it in (`egress`)
//! owdeploy-agent version
//! ```
//!
//! State (identity and pinned control-plane keys) lives in `$OWDEPLOY_AGENT_STATE` (default /var/lib/owdeploy-agent),
//! mode 0700/0600, read only by the root process (the broker, or the single process). The agent never opens a port:
//! it dials the control plane and keeps one WebSocket of signed frames. With privileges separated (`split`) that
//! WebSocket is the unprivileged relay's (`relay`), which passes frames to and from the broker (`broker`) over a
//! UNIX socket (`ipc`); the broker alone signs, checks and executes them (`session`).
//!
//! Build limits (environment of the service; an invalid value is logged and the default used, see `builder`):
//! `OWDEPLOY_BUILD_CPUS` (2), `OWDEPLOY_BUILD_MEMORY_MB` (4096, no swap on top), `OWDEPLOY_BUILD_PIDS` (2048) for each
//! BuildKit builder and build helper; `OWDEPLOY_BUILD_CACHE_GB` (10) and `OWDEPLOY_BUILD_CACHE_MAX_AGE_HOURS` (168) for
//! each builder's cache.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use deploy_proto::msg::{Op, Outcome, Privileges};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::events::Events;
use crate::keys::{Identity, KeyRing};
use crate::session::{Agent, Flow};
use crate::update::{Fetched, Updater};

mod app;
mod broker;
mod builder;
mod compose;
mod deploy;
mod docker;
mod dockerfile;
mod dockerignore;
#[cfg(test)]
mod e2e;
mod egress;
mod events;
mod exec;
mod firewall;
mod git;
mod host;
mod ipc;
mod keys;
mod oci;
mod project;
mod proxy;
mod relay;
mod router;
mod sbom;
mod session;
mod split;
mod update;
mod volumes;

/// Error of a command stopped by a `cancel` frame (or by the end of its session).
pub const CANCELLED: &str = "cancelled";

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
    /// The highest agent protocol the control plane speaks; absent from control planes before protocol 2.
    #[serde(default)]
    protocol: Option<u32>,
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
        "protocol": deploy_proto::PROTOCOL_VERSION,
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
        // The highest protocol both speak: no session of an older one from the start.
        protocol: out.protocol.map(|p| p.min(deploy_proto::PROTOCOL_VERSION)).filter(|p| *p >= 2),
    };
    id.save(&dir)?;
    let _ = std::fs::remove_file(token_file);
    println!("enrolled as {}", out.server_id);
    Ok(())
}

/// Loads the agent and sets the host up (both modes): the update probation or rollback of a binary just installed,
/// the firewall rules, the CSF hook, leftover Git helpers. None: this binary rolled back to the previous one, which
/// systemd starts now.
async fn start(privileges: Privileges, fetcher: update::Fetcher) -> Result<Option<Agent>, String> {
    let dir = state_dir();
    let ring = KeyRing::load(&dir)?;
    let bin = update::Binary::current().map_err(|e| tracing::warn!("self-update unavailable: {e}")).ok();
    let (fetched_tx, fetched) = tokio::sync::mpsc::channel::<Fetched>(4);
    let connect_url = ring.id.connect_url.clone();
    let mut up = Updater::new(dir.clone(), bin.clone(), ring.id.trust()?, &connect_url, fetched_tx, fetcher);
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
                    return Ok(None);
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
    Agent::new(ring, up, fetched, privileges).map(Some)
}

/// The single-process agent (servers installed before privilege separation): runs until the agent must restart (a
/// new binary installed or a rollback): Ok, and the process exits with [`update::RESTART_EXIT`] for systemd to start
/// the binary again.
async fn run_legacy() -> Result<(), String> {
    tracing::warn!(
        "running as one root process: privileges are not separated (`owdeploy-agent migrate-split` separates them)"
    );
    let Some(mut agent) = start(Privileges::Legacy, update::Fetcher::Direct).await? else { return Ok(()) };
    let mut failures = 0u32;
    loop {
        match connect_direct(&mut agent).await {
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

/// One session of the single-process agent, over its own WebSocket.
async fn connect_direct(agent: &mut Agent) -> Result<Flow, String> {
    let (headers, handshake) = agent.connect_request();
    let req = session::request(&agent.connect_url(), &headers)?;
    let (ws, answer) = tokio_tungstenite::connect_async(req).await.map_err(|e| e.to_string())?;
    // A v2 session once a pinned control key signed its handshake; v1 only while this agent never used v2.
    let session = agent.accept(handshake, answer.headers())?;
    agent.drive(session, &mut session::WsLink(ws)).await
}

/// `owdeploy-agent broker` (root): the privileged half of a privilege-separated agent.
async fn run_broker() -> Result<(), String> {
    if split::uid() != 0 {
        return Err("the broker runs as root".into());
    }
    let staging = broker::Staging::new(ipc::relay_state_dir().join(ipc::STAGED_FILE));
    let Some(agent) = start(Privileges::Split, update::Fetcher::Relay(staging.clone())).await? else { return Ok(()) };
    broker::run(agent, staging).await
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

fn jitter_ms() -> u64 {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).expect("OS randomness");
    u64::from(u16::from_le_bytes(b)) % 2000
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
        "usage: owdeploy-agent enroll --url URL --token-file PATH [--name NAME] | run | broker | migrate-split | status \
         | firewall-repair | csf-hook | pin-keys [--control-key KEY] [--update-key KEY] [--release-key KEY] | \
         capabilities | build-proxy | version"
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
        // The relay of a broker, or the single root process of a server that has not migrated (`split`).
        Some("run") => {
            let r = match split::run_mode(split::uid(), split::broker_installed()) {
                split::RunMode::Legacy => run_legacy().await,
                split::RunMode::Relay => relay::run(&ipc::socket_path(), &ipc::relay_state_dir()).await,
            };
            match r {
                Ok(()) => return ExitCode::from(update::RESTART_EXIT),
                Err(e) => Err(e),
            }
        }
        Some("broker") => match run_broker().await {
            Ok(()) => return ExitCode::from(update::RESTART_EXIT),
            Err(e) => Err(e),
        },
        Some("migrate-split") => match std::env::current_exe() {
            Ok(bin) => split::migrate(&bin, &state_dir()).await,
            Err(e) => Err(format!("own binary: {e}")),
        },
        Some("status") => split::query(&ipc::socket_path()).await.map(|st| {
            println!("{}", serde_json::to_string_pretty(&st).expect("status"));
        }),
        // Inside the build egress proxy's container (see `egress`): the proxy, and its control client for the agent.
        Some("build-proxy") => proxy::serve().await,
        Some("build-proxy-ctl") => proxy::ctl_client(),
        Some("capabilities") => {
            println!("{}", split::CAPABILITY);
            Ok(())
        }
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
            match split::broker_installed() {
                true => println!(
                    "owdeploy-agent: restart the agent to use them (systemctl restart {} {})",
                    split::BROKER_UNIT,
                    split::RELAY_UNIT
                ),
                false => println!("owdeploy-agent: restart the agent to use them (systemctl restart owdeploy-agent)"),
            }
        }),
        Some("version") => {
            println!("owdeploy-agent {} (protocol {})", deploy_proto::build_version(), deploy_proto::CONTEXT_V2);
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
