//! Build egress: build steps reach the Internet only through the build egress proxy ([`crate::proxy`]), which applies
//! the deployment's policy (`BuildSpec::egress`, `ComposeDeploy::egress`: `open`, `audit` or `allowlist`) and reports
//! where they went.
//!
//! The builders and the build helpers sit on the build network ([`crate::builder::BUILD_NETWORK`]), which Docker
//! creates *internal*: its containers have no route out of it and Docker's resolver forwards no query for them, so
//! direct connections (and DNS lookups of outside names) fail; the agent's firewall also rejects anything that bridge
//! would forward or send to the server. The proxy container ([`CONTAINER`]) is on that network and on [`NETWORK`],
//! an ordinary Deploy network (the egress guard keeps it off private ranges, metadata and the server): it is the one
//! way out. It runs the agent's own static binary (`build-proxy`) as an unprivileged user, without capabilities, on
//! a read-only root file system, from an image the agent builds from that binary ([`IMAGE_REPO`]).
//!
//! Each build gets a random token, registered with its policy: the build steps get the proxy's URL with it as
//! credentials (`HTTP_PROXY`, `HTTPS_PROXY`, lowercase too, and `NO_PROXY` for loopback: Dockerfile and Compose
//! builds as the predefined proxy build arguments, which BuildKit keeps out of the image's history and the cache key;
//! Railpack builds as BuildKit secrets its steps see as environment). Each builder has a token of its own, open, for
//! BuildKit's own traffic (image pulls, Git contexts) and buildx's (registry tokens), set in their containers'
//! environment. Denials are written to the deployment's log as they happen; at the end of the build the agent sends
//! `Event::Egress` (every destination in `audit` and `allowlist` mode, the denied ones in `open` mode) and a summary
//! line. Tools that ignore the proxy variables cannot reach anything and fail.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use bollard::Docker;
use bollard::models::{
    ContainerCreateBody, EndpointSettings, HostConfig, NetworkConnectRequest, RestartPolicy, RestartPolicyNameEnum,
};
use bollard::query_parameters::{BuildImageOptionsBuilder, CreateContainerOptionsBuilder};
use deploy_proto::msg::{BuildEgress, EgressMode, Event};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;

use crate::builder::BUILD_NETWORK;
use crate::docker::{is_not_found, message, remove_container};
use crate::events::Events;
use crate::proxy::{Ctl, PORT, Reply, Report};

/// The proxy's container.
pub const CONTAINER: &str = "owd-build-proxy";
/// The proxy's way out: an ordinary Deploy network, guarded like the others.
pub const NETWORK: &str = "owd-build-egress";
pub const BRIDGE: &str = "owd-builde0";
/// A static Linux build of the agent to run the proxy from, instead of the agent's own binary (development and
/// tests, where the running binary is not one).
const BINARY_ENV: &str = "OWDEPLOY_BUILD_PROXY_BINARY";
/// The proxy's image: `owd/build-proxy:<first 12 hex digits of the binary's SHA-256>`.
pub const IMAGE_REPO: &str = "owd/build-proxy";
/// Label on the proxy's images (older ones are removed when a new one is built).
const LABEL_IMAGE: &str = "dev.openwaf.deploy.build-proxy-image";
/// Label on the proxy's container: its image (a container of another image is replaced).
const LABEL_CONTAINER: &str = "dev.openwaf.deploy.build-proxy";
const BIN_IN_IMAGE: &str = "/owdeploy-agent";
/// The proxy's user and group (`nobody`).
const USER: &str = "65534:65534";
/// The variables that point build tools at the proxy, and those that keep loopback off it.
pub const PROXY_VARS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"];
pub const NO_PROXY_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];
pub const NO_PROXY: &str = "localhost,127.0.0.1,::1";
/// Environment of a Railpack build's bake carrying the proxy settings, read by BuildKit as the values of the secrets
/// named after [`PROXY_VARS`] and [`NO_PROXY_VARS`] (the bake's own process keeps its own proxy variables).
pub const SECRET_ENV_PROXY: &str = "OWD_EGRESS_PROXY";
pub const SECRET_ENV_NO_PROXY: &str = "OWD_EGRESS_NO_PROXY";
/// How long the agent waits for the proxy to answer on its control socket after starting it.
const START_TIMEOUT: Duration = Duration::from_secs(20);
/// Largest control answer read (a report of [`deploy_proto::msg::MAX_EGRESS_ENTRIES`] entries is far below).
const MAX_REPLY: usize = 4 << 20;

static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A random token for the proxy's credentials (16 bytes, hex).
pub fn token() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS randomness");
    hex::encode(b)
}

/// The proxy URL with `token` as credentials, the proxy reached at `host`.
pub fn url(token: &str, host: &str) -> String {
    format!("http://owd:{token}@{host}:{PORT}")
}

/// The environment pointing a process at the proxy through `url`.
pub fn env(url: &str) -> Vec<String> {
    let mut v: Vec<String> = PROXY_VARS.iter().map(|n| format!("{n}={url}")).collect();
    v.extend(NO_PROXY_VARS.iter().map(|n| format!("{n}={NO_PROXY}")));
    v
}

/// The token in an environment made by [`env`] (a builder's), if any.
pub fn token_in(env: &[String]) -> Option<String> {
    let v = env.iter().find_map(|e| e.strip_prefix("HTTPS_PROXY="))?;
    let rest = v.strip_prefix("http://owd:")?;
    let (token, host) = rest.split_once('@')?;
    (crate::proxy::token_ok(token) && host == format!("{CONTAINER}:{PORT}")).then(|| token.to_string())
}

/// The policy of a build: the one sent, or `open` from older control planes. A mode this agent does not know or an
/// invalid allowlist refuses the build.
pub fn policy(p: Option<&BuildEgress>) -> Result<BuildEgress, String> {
    let p = p.cloned().unwrap_or(BuildEgress::OPEN);
    p.rules().map_err(|e| format!("build egress policy: {e}"))?;
    Ok(p)
}

/// Whether an ELF executable is statically linked (no program interpreter). Err: not a 64-bit little-endian ELF.
fn is_static_elf(b: &[u8]) -> Result<bool, String> {
    let bad = || "not a 64-bit little-endian ELF executable".to_string();
    if b.len() < 64 || &b[..4] != b"\x7fELF" || b[4] != 2 || b[5] != 1 {
        return Err(bad());
    }
    let u16_at = |o: usize| b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]));
    let u64_at = |o: usize| b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().expect("8 bytes")));
    let phoff = usize::try_from(u64_at(32).ok_or_else(bad)?).map_err(|_| bad())?;
    let phentsize = usize::from(u16_at(54).ok_or_else(bad)?);
    let phnum = usize::from(u16_at(56).ok_or_else(bad)?);
    for i in 0..phnum {
        let at = phoff.checked_add(i.checked_mul(phentsize).ok_or_else(bad)?).ok_or_else(bad)?;
        let kind = b.get(at..at + 4).ok_or_else(bad)?;
        // PT_INTERP
        if u32::from_le_bytes(kind.try_into().expect("4 bytes")) == 3 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The binary the proxy runs and its image tag, found once.
static BINARY: LazyLock<Result<(PathBuf, String), String>> = LazyLock::new(|| {
    let path = match std::env::var_os(BINARY_ENV).filter(|v| !v.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => std::env::current_exe().map_err(|e| format!("own binary: {e}"))?,
    };
    let data = read_static(&path)?;
    Ok((path, format!("{IMAGE_REPO}:{}", &hex::encode(Sha256::digest(&data))[..12])))
});

/// The content of `path` if it is a static Linux executable.
fn read_static(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    match is_static_elf(&data) {
        Ok(true) => Ok(data),
        Ok(false) | Err(_) => Err(format!(
            "{} is not a static Linux executable: the build egress proxy runs the agent's static (musl) build (set \
             {BINARY_ENV} to one)",
            path.display()
        )),
    }
}

/// Builds the proxy's image from the binary unless it exists, and removes older ones.
async fn ensure_image(d: &Docker, ev: &Events) -> Result<String, String> {
    let (path, tag) = BINARY.as_ref().map_err(Clone::clone)?;
    if d.inspect_image(tag).await.is_ok() {
        return Ok(tag.clone());
    }
    let data = read_static(path)?;
    if !tag.ends_with(&hex::encode(Sha256::digest(&data))[..12]) {
        return Err(format!("{} changed since the agent started", path.display()));
    }
    ev.system(format!("Building the build egress proxy image {tag} (once per agent version)")).await;
    let dockerfile = format!(
        "FROM scratch\nCOPY owdeploy-agent {BIN_IN_IMAGE}\nUSER {USER}\nENTRYPOINT [\"{BIN_IN_IMAGE}\", \"build-proxy\"]\n\
         LABEL {LABEL_IMAGE}=1\n"
    );
    let mut b = tar::Builder::new(Vec::new());
    for (name, body, mode) in [("Dockerfile", dockerfile.as_bytes(), 0o644), ("owdeploy-agent", data.as_slice(), 0o755)]
    {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(mode);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, name, body).map_err(|e| e.to_string())?;
    }
    let body = b.into_inner().map_err(|e| e.to_string())?;
    let opts = BuildImageOptionsBuilder::default().dockerfile("Dockerfile").t(tag).rm(true).forcerm(true);
    let mut s = d.build_image(opts.build(), None, Some(bollard::body_full(body.into())));
    while let Some(item) = s.next().await {
        let info = item.map_err(|e| format!("build the build egress proxy image: {}", message(&e)))?;
        if let Some(e) = info.error_detail {
            return Err(format!("build the build egress proxy image: {}", e.message.unwrap_or_default().trim()));
        }
    }
    let filters = HashMap::from([("label".to_string(), vec![LABEL_IMAGE.to_string()])]);
    let opts = bollard::query_parameters::ListImagesOptionsBuilder::default().filters(&filters).build();
    for i in d.list_images(Some(opts)).await.unwrap_or_default() {
        if !i.repo_tags.iter().any(|t| t == tag) {
            let _ = d.remove_image(&i.id, None::<bollard::query_parameters::RemoveImageOptions>, None).await;
        }
    }
    Ok(tag.clone())
}

/// The proxy's way out: an ordinary bridge without IPv6, its bridge named so the firewall guards it.
async fn ensure_network(d: &Docker) -> Result<(), String> {
    match d.inspect_network(NETWORK, None).await {
        Ok(_) => return Ok(()),
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(format!("inspect network {NETWORK}: {}", message(&e))),
    }
    let req = bollard::models::NetworkCreateRequest {
        name: NETWORK.into(),
        driver: Some("bridge".into()),
        enable_ipv6: Some(false),
        options: Some(HashMap::from([(crate::firewall::BRIDGE_OPTION.to_string(), BRIDGE.to_string())])),
        labels: Some(HashMap::from([(LABEL_CONTAINER.to_string(), "network".to_string())])),
        ..Default::default()
    };
    match d.create_network(req).await {
        Ok(_) => {}
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 409, .. }) => {}
        Err(e) => return Err(format!("create network {NETWORK}: {}", message(&e))),
    }
    crate::firewall::guard_new_network().await
}

/// The proxy's container: [`USER`], no capability, `no-new-privileges`, read-only root file system, its control
/// socket on a memory file system of its own, bounded, restarted with the Engine.
fn container(image: &str) -> ContainerCreateBody {
    let host = HostConfig {
        network_mode: Some(BUILD_NETWORK.into()),
        cap_drop: Some(vec!["ALL".into()]),
        security_opt: Some(vec!["no-new-privileges".into()]),
        readonly_rootfs: Some(true),
        tmpfs: Some(HashMap::from([(
            crate::proxy::CTL_DIR.to_string(),
            "rw,noexec,nosuid,nodev,size=64k,mode=0700,uid=65534,gid=65534".to_string(),
        )])),
        restart_policy: Some(RestartPolicy {
            name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
            maximum_retry_count: None,
        }),
        memory: Some(256 << 20),
        memory_swap: Some(256 << 20),
        pids_limit: Some(256),
        nano_cpus: Some(1_000_000_000),
        init: Some(false),
        ..Default::default()
    };
    ContainerCreateBody {
        image: Some(image.into()),
        user: Some(USER.into()),
        labels: Some(HashMap::from([(LABEL_CONTAINER.to_string(), image.to_string())])),
        host_config: Some(host),
        ..Default::default()
    }
}

/// Makes the proxy usable: both networks, its image, its container running on both (a container of another image,
/// or missing a network, is replaced), answering on its control socket.
pub async fn ensure_proxy(d: &Docker, ev: &Events) -> Result<(), String> {
    let _g = LOCK.lock().await;
    crate::builder::ensure_build_network(d).await?;
    ensure_network(d).await?;
    let image = ensure_image(d, ev).await?;
    let current = match d.inspect_container(CONTAINER, None).await {
        Ok(c) => Some(c),
        Err(e) if is_not_found(&e) => None,
        Err(e) => return Err(format!("inspect {CONTAINER}: {}", message(&e))),
    };
    let fits = current.as_ref().is_some_and(|c| {
        let label = c.config.as_ref().and_then(|c| c.labels.as_ref()?.get(LABEL_CONTAINER).cloned());
        let nets = c.network_settings.as_ref().and_then(|n| n.networks.as_ref());
        label.as_deref() == Some(image.as_str())
            && nets.is_some_and(|n| n.contains_key(BUILD_NETWORK) && n.contains_key(NETWORK))
    });
    let running = fits && current.as_ref().and_then(|c| c.state.as_ref()?.running).unwrap_or(false);
    if !fits {
        if current.is_some() {
            remove_container(d, CONTAINER).await?;
        }
        ev.system(format!("Starting the build egress proxy {CONTAINER}")).await;
        let opts = CreateContainerOptionsBuilder::default().name(CONTAINER).build();
        d.create_container(Some(opts), container(&image))
            .await
            .map_err(|e| format!("create {CONTAINER}: {}", message(&e)))?;
        let connect =
            NetworkConnectRequest { container: CONTAINER.into(), endpoint_config: Some(EndpointSettings::default()) };
        if let Err(e) = d.connect_network(NETWORK, connect).await {
            remove_container(d, CONTAINER).await.ok();
            return Err(format!("connect {CONTAINER} to {NETWORK}: {}", message(&e)));
        }
    }
    if !running {
        d.start_container(CONTAINER, None).await.map_err(|e| format!("start {CONTAINER}: {}", message(&e)))?;
        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        loop {
            match call(d, &Ctl::Ping).await {
                Ok(r) if r == [Reply::Ok] => break,
                r if tokio::time::Instant::now() >= deadline => {
                    let why = match r {
                        Ok(r) => format!("{r:?}"),
                        Err(e) => e,
                    };
                    return Err(format!("the build egress proxy does not answer: {why}"));
                }
                _ => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }
    Ok(())
}

/// Starts `build-proxy-ctl` in the proxy's container with `req` on its standard input.
async fn start_ctl(d: &Docker, req: &Ctl) -> Result<crate::exec::Running, String> {
    let cmd = vec![BIN_IN_IMAGE.to_string(), "build-proxy-ctl".to_string()];
    let stdin = serde_json::to_vec(req).expect("control request");
    crate::exec::start(d, CONTAINER, cmd, Vec::new(), Some(stdin)).await
}

/// One control request and its answers.
async fn call(d: &Docker, req: &Ctl) -> Result<Vec<Reply>, String> {
    let mut r = start_ctl(d, req).await?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    while let Some(item) = r.next().await {
        let (stream, chunk) = item?;
        let buf = if stream == deploy_proto::msg::LogStream::Stderr { &mut err } else { &mut out };
        if buf.len() + chunk.len() > MAX_REPLY {
            return Err("the build egress proxy's answer is too large".into());
        }
        buf.extend_from_slice(&chunk);
    }
    let replies: Vec<Reply> =
        out.split(|b| *b == b'\n').filter(|l| !l.is_empty()).filter_map(|l| serde_json::from_slice(l).ok()).collect();
    if replies.is_empty() {
        let e = String::from_utf8_lossy(&err);
        return Err(format!("the build egress proxy did not answer ({})", e.trim()));
    }
    Ok(replies)
}

async fn expect_ok(d: &Docker, req: &Ctl) -> Result<(), String> {
    match call(d, req).await?.as_slice() {
        [Reply::Ok] => Ok(()),
        [Reply::Error(e)] => Err(format!("build egress proxy: {e}")),
        r => Err(format!("build egress proxy: unexpected answer {r:?}")),
    }
}

/// Registers builder `name`'s own token (open: BuildKit's pulls and buildx's registry tokens). Again before each
/// build: the proxy forgets its registrations when it restarts.
pub async fn register_builder(d: &Docker, name: &str, token: &str) -> Result<(), String> {
    let req =
        Ctl::Register { id: format!("builder:{name}"), token: token.into(), policy: BuildEgress::OPEN, infra: true };
    expect_ok(d, &req).await
}

/// The proxy's address on the build network: build steps reach it without a name lookup.
async fn proxy_address(d: &Docker) -> Result<String, String> {
    let c = d.inspect_container(CONTAINER, None).await.map_err(|e| format!("inspect {CONTAINER}: {}", message(&e)))?;
    c.network_settings
        .and_then(|n| n.networks)
        .and_then(|mut n| n.remove(BUILD_NETWORK))
        .and_then(|e| e.ip_address)
        .filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
        .ok_or_else(|| format!("{CONTAINER} has no address on {BUILD_NETWORK}"))
}

/// One build's registration with the proxy.
pub struct Session {
    d: Docker,
    id: String,
    mode: EgressMode,
    enforced: bool,
    url: String,
    watch: JoinHandle<()>,
}

impl Session {
    /// Registers a build of `deployment` with `policy` (see [`policy`]) and streams its denials into the log.
    pub async fn start(d: &Docker, deployment: &str, policy: &BuildEgress, ev: &Events) -> Result<Session, String> {
        ensure_proxy(d, ev).await?;
        let enforced = crate::builder::build_network_internal(d).await?.unwrap_or(false);
        if !enforced && policy.mode == EgressMode::Allowlist {
            return Err(format!(
                "the build egress allowlist cannot be enforced: the network {BUILD_NETWORK} is not internal"
            ));
        }
        let id = format!("deployment:{deployment}:{}", &token()[..8]);
        let token = token();
        let url = url(&token, &proxy_address(d).await?);
        let req = Ctl::Register { id: id.clone(), token, policy: policy.clone(), infra: false };
        expect_ok(d, &req).await?;
        let mut r = match start_ctl(d, &Ctl::Watch { id: id.clone() }).await {
            Ok(r) => r,
            Err(e) => {
                // Not left registered: its token would keep working until the proxy restarts.
                let _ = call(d, &Ctl::Finish { id }).await;
                return Err(e);
            }
        };
        let log = ev.clone();
        let watch = tokio::spawn(async move {
            let mut lines = crate::events::Lines::default();
            while let Some(Ok((stream, chunk))) = r.next().await {
                if stream == deploy_proto::msg::LogStream::Stderr {
                    continue;
                }
                for l in lines.push(&chunk) {
                    if let Ok(Reply::Denied(x)) = serde_json::from_str::<Reply>(&l) {
                        log.system(format!("Build egress denied: {}:{} ({})", x.host, x.port, x.reason)).await;
                    }
                }
            }
        });
        let what = match policy.mode {
            EgressMode::Allowlist => format!("allowlist of {} destinations", policy.allow.len()),
            m => format!("{m:?}").to_ascii_lowercase(),
        };
        ev.system(format!("Build egress: {what}, through the build egress proxy only")).await;
        Ok(Session { d: d.clone(), id, mode: policy.mode, enforced, url, watch })
    }

    /// The proxy settings as build arguments (Dockerfile and Compose builds: BuildKit's predefined proxy arguments).
    pub fn args(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = PROXY_VARS.iter().map(|n| (n.to_string(), self.url.clone())).collect();
        v.extend(NO_PROXY_VARS.iter().map(|n| (n.to_string(), NO_PROXY.to_string())));
        v
    }

    /// The bake's environment carrying the values of the Railpack secrets ([`SECRET_ENV_PROXY`]).
    pub fn secret_env(&self) -> Vec<String> {
        vec![format!("{SECRET_ENV_PROXY}={}", self.url), format!("{SECRET_ENV_NO_PROXY}={NO_PROXY}")]
    }

    /// Ends the registration: sends what the proxy recorded (`Event::Egress`) and a summary line. Best effort: a
    /// failure is a system line, never the deployment's error.
    pub async fn finish(self, ev: &Events) {
        let r =
            tokio::time::timeout(Duration::from_secs(30), call(&self.d, &Ctl::Finish { id: self.id.clone() })).await;
        // The watch ends with the registration; it is not waited for longer than that.
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut { self.watch }).await;
        let report = match r {
            Ok(Ok(r)) => match r.into_iter().next() {
                Some(Reply::Report(rep)) => rep,
                other => {
                    ev.system(format!("Build egress: no report from the proxy ({other:?})")).await;
                    return;
                }
            },
            Ok(Err(e)) => {
                ev.system(format!("Build egress: no report from the proxy ({e})")).await;
                return;
            }
            Err(_) => {
                ev.system("Build egress: no report from the proxy (timed out)").await;
                return;
            }
        };
        ev.system(summary(self.mode, &report)).await;
        ev.event(Event::Egress {
            mode: self.mode,
            enforced: self.enforced,
            entries: report.entries,
            truncated: report.truncated,
        })
        .await;
    }
}

/// The summary line of a build's egress.
fn summary(mode: EgressMode, r: &Report) -> String {
    let mode = format!("{mode:?}").to_ascii_lowercase();
    let mb = |b: u64| format!("{:.1} MB", b as f64 / 1e6);
    let mut s = format!(
        "Build egress ({mode}): {} connections allowed ({} out, {} in), {} denied",
        r.allowed,
        mb(r.bytes_out),
        mb(r.bytes_in),
        r.denied
    );
    if !r.entries.is_empty() {
        let shown: Vec<String> = r
            .entries
            .iter()
            .take(20)
            .map(|e| match &e.reason {
                Some(why) => format!("{}:{} denied ({why}) ×{}", e.host, e.port, e.count),
                None => format!("{}:{} ×{}", e.host, e.port, e.count),
            })
            .collect();
        s.push_str(&format!("; {}", shown.join(", ")));
        if r.entries.len() > 20 || r.truncated {
            s.push_str(", …");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_tokens_read_back_from_their_environment() {
        let t = token();
        assert!(crate::proxy::token_ok(&t));
        let e = env(&url(&t, CONTAINER));
        assert!(e.contains(&format!("https_proxy=http://owd:{t}@{CONTAINER}:{PORT}")));
        assert!(e.contains(&format!("NO_PROXY={NO_PROXY}")));
        assert_eq!(token_in(&e), Some(t));
        assert_eq!(token_in(&["HTTPS_PROXY=http://owd:x@owd-build-proxy:3128".into()]), None);
        assert_eq!(token_in(&env(&url(&token(), "192.0.2.2"))), None, "a builder's token is for the proxy's name");
    }

    #[test]
    fn only_static_executables_can_run_the_proxy() {
        // A minimal ELF64 header with one program header of `kind` at offset 64.
        let elf = |kind: u32| {
            let mut b = vec![0u8; 64 + 56];
            b[..4].copy_from_slice(b"\x7fELF");
            b[4] = 2;
            b[5] = 1;
            b[32..40].copy_from_slice(&64u64.to_le_bytes());
            b[54..56].copy_from_slice(&56u16.to_le_bytes());
            b[56..58].copy_from_slice(&1u16.to_le_bytes());
            b[64..68].copy_from_slice(&kind.to_le_bytes());
            b
        };
        assert_eq!(is_static_elf(&elf(1)), Ok(true), "PT_LOAD only");
        assert_eq!(is_static_elf(&elf(3)), Ok(false), "PT_INTERP: dynamically linked");
        assert!(is_static_elf(b"#!/bin/sh\n").is_err());
        let mut truncated = elf(1);
        truncated.truncate(66);
        assert!(is_static_elf(&truncated).is_err());
    }

    #[test]
    fn policies_default_to_open_and_unknown_modes_refuse_the_build() {
        assert_eq!(policy(None).unwrap(), BuildEgress::OPEN);
        let unknown: BuildEgress = serde_json::from_value(serde_json::json!({"mode": "strict"})).unwrap();
        assert!(policy(Some(&unknown)).is_err());
        let bad = BuildEgress { mode: EgressMode::Allowlist, allow: vec!["192.0.2.1".into()] };
        assert!(policy(Some(&bad)).unwrap_err().contains("192.0.2.1"));
    }
}
