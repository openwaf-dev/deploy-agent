//! The build egress proxy, `owdeploy-agent build-proxy`: the only way out of the build network. The agent runs it in a
//! container of its own ([`crate::egress`]: unprivileged user, no capability, read-only root file system), on the
//! internal build network (no route out) and on a network with Internet access, whose egress the firewall guards like
//! any Deploy network. It parses traffic of untrusted build steps, so it never runs in the agent's own process.
//!
//! An HTTP proxy: `CONNECT host:port` tunnels (HTTPS and anything else over TCP) and plain HTTP requests in absolute
//! form (`GET http://host/path`, one request per connection: it asks the server to close after its answer). Every
//! request carries credentials (`Proxy-Authorization: Basic`, from the userinfo of the `HTTP_PROXY`/`HTTPS_PROXY`
//! URL build tools are given) whose password is a token the agent registered for one deployment's build, or for a
//! builder's own traffic (BuildKit's image pulls, buildx's registry tokens); it selects the policy
//! ([`BuildEgress`]). Unknown or missing credentials get 407.
//!
//! The decision, per connection: in `allowlist` mode the host must be a name matching an allowed entry (IP addresses
//! are refused); in every mode the name is resolved here, by the proxy, and only public addresses are connected to,
//! never private, shared, loopback, link-local (cloud metadata), multicast or reserved ones (the firewall's ranges,
//! [`crate::firewall::is_blocked`]): a name that resolves only to those is refused, so DNS rebinding cannot reach
//! them. Each registration counts connections and bytes per destination and decision; denials are streamed to the
//! agent as they happen (`watch`) and everything is reported once the build ends (`finish`).
//!
//! The agent drives it through a UNIX socket in the container's memory ([`CTL_SOCKET`], reached with `docker exec …
//! build-proxy-ctl`): one JSON request per connection ([`Ctl`]), answered by JSON lines ([`Reply`]).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use deploy_proto::msg::{
    BuildEgress, EgressDecision, EgressEntry, EgressMode, EgressRule, MAX_EGRESS_ENTRIES, canonical_host,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// The proxy's port, on every address of its container.
pub const PORT: u16 = 3128;
/// The control socket, in a memory file system of the container only its user can enter.
pub const CTL_DIR: &str = "/run/owd-build-proxy";
pub const CTL_SOCKET: &str = "/run/owd-build-proxy/ctl.sock";
/// Largest request head (request line and headers).
const MAX_HEAD: usize = 16 * 1024;
/// Largest control request.
const MAX_CTL: usize = 64 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// A connection on which nothing moves either way for this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_CONNECTIONS: usize = 1024;
/// Registrations at once (builds running on the server, plus one per builder).
const MAX_REGISTRATIONS: usize = 256;
/// Distinct destinations recorded per registration; more are counted in the totals only (`truncated`).
const MAX_RECORDS: usize = 4096;

/// Why a connection was refused (`EgressEntry::reason`).
pub const NOT_ALLOWED: &str = "not_allowed";
pub const IP_LITERAL: &str = "ip_literal";
pub const PRIVATE_ADDRESS: &str = "private_address";
pub const UNRESOLVED: &str = "unresolved";
pub const INVALID: &str = "invalid";

/// The host a client asked for: a name (canonical) or an IP address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Name(String),
    Ip(IpAddr),
}

impl Host {
    /// `name`, `a.b.c.d` or `[v6]`. None for anything else.
    pub fn parse(s: &str) -> Option<Host> {
        if let Some(v6) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            return v6.parse::<std::net::Ipv6Addr>().ok().map(|ip| Host::Ip(IpAddr::V6(ip)));
        }
        if let Ok(ip) = s.parse::<std::net::Ipv4Addr>() {
            return Some(Host::Ip(IpAddr::V4(ip)));
        }
        canonical_host(s).map(Host::Name)
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Name(n) => f.write_str(n),
            Host::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// Where a client wants to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

/// `host:port` (a CONNECT target). Err: the reason it is refused.
pub fn authority(s: &str, default_port: Option<u16>) -> Result<Target, &'static str> {
    let (host, port) = match s.rsplit_once(':') {
        // A bare IPv6 address has colons but no brackets: not an authority.
        Some((h, p)) if !h.contains(':') || h.ends_with(']') => (h, Some(p)),
        _ => (s, None),
    };
    let port = match port {
        Some(p) => p.parse::<u16>().ok().filter(|p| *p > 0).ok_or(INVALID)?,
        None => default_port.ok_or(INVALID)?,
    };
    Ok(Target { host: Host::parse(host).ok_or(INVALID)?, port })
}

/// A policy ready to decide.
#[derive(Debug, Clone)]
pub struct Policy {
    pub mode: EgressMode,
    rules: Vec<EgressRule>,
}

impl Policy {
    pub fn new(p: &BuildEgress) -> Result<Policy, String> {
        let rules = p.rules()?;
        Ok(Policy { mode: p.mode, rules })
    }

    /// Whether every destination is recorded (`audit`, `allowlist`), not only the denied ones.
    fn records_all(&self) -> bool {
        self.mode != EgressMode::Open
    }

    /// The decision before resolution: Err is the reason `t` is refused.
    pub fn check(&self, t: &Target) -> Result<(), &'static str> {
        match (&t.host, self.mode) {
            (_, EgressMode::Unknown) => Err(NOT_ALLOWED),
            (Host::Ip(_), EgressMode::Allowlist) => Err(IP_LITERAL),
            (Host::Name(n), EgressMode::Allowlist) => match self.rules.iter().any(|r| r.matches(n, t.port)) {
                true => Ok(()),
                false => Err(NOT_ALLOWED),
            },
            (Host::Ip(ip), _) if crate::firewall::is_blocked(*ip) => Err(PRIVATE_ADDRESS),
            _ => Ok(()),
        }
    }
}

/// The addresses a connection may use among those a name resolved to: public ones only, IPv4 first (the proxy's
/// networks have no IPv6). Err when none is left: [`PRIVATE_ADDRESS`] if there were some, else [`UNRESOLVED`].
pub fn vet(addrs: impl IntoIterator<Item = SocketAddr>) -> Result<Vec<SocketAddr>, &'static str> {
    let all: Vec<SocketAddr> = addrs.into_iter().collect();
    let mut ok: Vec<SocketAddr> = all.iter().copied().filter(|a| !crate::firewall::is_blocked(a.ip())).collect();
    ok.sort_by_key(|a| a.is_ipv6());
    ok.dedup();
    match (ok.is_empty(), all.is_empty()) {
        (false, _) => Ok(ok),
        (true, false) => Err(PRIVATE_ADDRESS),
        (true, true) => Err(UNRESOLVED),
    }
}

/// The addresses a connection to `t` may use ([`vet`]). A name whose lookup fails (a resolver's transient failure,
/// such as a forwarder giving up on a slow upstream) is looked up once more, within [`RESOLVE_TIMEOUT`] in all.
async fn resolve(t: &Target) -> Result<Vec<SocketAddr>, &'static str> {
    let name = match &t.host {
        Host::Ip(ip) => return vet([SocketAddr::new(*ip, t.port)]),
        Host::Name(n) => n.as_str(),
    };
    let lookup = async {
        for _ in 0..2 {
            if let Ok(addrs) = tokio::net::lookup_host((name, t.port)).await {
                return vet(addrs);
            }
        }
        Err(UNRESOLVED)
    };
    tokio::time::timeout(RESOLVE_TIMEOUT, lookup).await.unwrap_or(Err(UNRESOLVED))
}

/// A denial as streamed to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    pub host: String,
    pub port: u16,
    pub reason: String,
}

/// Counters of one destination and decision.
#[derive(Debug, Clone, Copy, Default)]
struct Counter {
    count: u64,
    bytes_out: u64,
    bytes_in: u64,
}

#[derive(Debug, Default)]
struct Stats {
    /// (host, port, denial reason (None: allowed)) → counters.
    records: HashMap<(String, u16, Option<&'static str>), Counter>,
    truncated: bool,
    allowed: u64,
    denied: u64,
    bytes_out: u64,
    bytes_in: u64,
}

/// What a registration saw, as `finish` reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub mode: Option<EgressMode>,
    /// At most [`MAX_EGRESS_ENTRIES`], most connections first.
    pub entries: Vec<EgressEntry>,
    pub truncated: bool,
    /// Connections allowed and denied, and the bytes of the allowed ones, whatever the mode.
    pub allowed: u64,
    pub denied: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// One token's registration: a deployment's build, or a builder's own traffic (`infra`).
struct Reg {
    id: String,
    policy: Policy,
    infra: bool,
    stats: Mutex<Stats>,
    denials: broadcast::Sender<Denial>,
    finished: CancellationToken,
}

impl Reg {
    fn new(id: String, policy: Policy, infra: bool) -> Reg {
        Reg {
            id,
            policy,
            infra,
            stats: Mutex::default(),
            denials: broadcast::channel(256).0,
            finished: CancellationToken::new(),
        }
    }

    fn stats(&self) -> std::sync::MutexGuard<'_, Stats> {
        self.stats.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Adds one connection (and its bytes) to `host:port` with `denied` (None: allowed).
    fn record(&self, host: &str, port: u16, denied: Option<&'static str>, out: u64, inn: u64) {
        let mut s = self.stats();
        match denied {
            Some(_) => s.denied += 1,
            None => {
                s.allowed += 1;
                s.bytes_out += out;
                s.bytes_in += inn;
            }
        }
        if denied.is_none() && !self.policy.records_all() {
            return;
        }
        let key = (host.to_string(), port, denied);
        let full = s.records.len() >= MAX_RECORDS;
        match s.records.get_mut(&key) {
            Some(c) => {
                c.count += 1;
                c.bytes_out += out;
                c.bytes_in += inn;
            }
            None if full => s.truncated = true,
            None => {
                s.records.insert(key, Counter { count: 1, bytes_out: out, bytes_in: inn });
            }
        }
    }

    fn deny(&self, host: &str, port: u16, reason: &'static str) {
        self.record(host, port, Some(reason), 0, 0);
        if self.infra {
            tracing::warn!("{}: denied {host}:{port} ({reason})", self.id);
        }
        let _ = self.denials.send(Denial { host: host.to_string(), port, reason: reason.to_string() });
    }

    fn report(&self) -> Report {
        let s = self.stats();
        let mut entries: Vec<EgressEntry> = s
            .records
            .iter()
            .map(|((host, port, reason), c)| EgressEntry {
                host: host.clone(),
                port: *port,
                decision: if reason.is_some() { EgressDecision::Denied } else { EgressDecision::Allowed },
                reason: reason.map(str::to_string),
                count: c.count,
                bytes_out: c.bytes_out,
                bytes_in: c.bytes_in,
            })
            .collect();
        entries.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| (&a.host, a.port).cmp(&(&b.host, b.port))));
        let truncated = s.truncated || entries.len() > MAX_EGRESS_ENTRIES;
        entries.truncate(MAX_EGRESS_ENTRIES);
        Report {
            mode: Some(self.policy.mode),
            entries,
            truncated,
            allowed: s.allowed,
            denied: s.denied,
            bytes_out: s.bytes_out,
            bytes_in: s.bytes_in,
        }
    }
}

/// Registrations by token, and the token of each id.
#[derive(Default)]
struct Maps {
    by_token: HashMap<String, Arc<Reg>>,
    by_id: HashMap<String, String>,
}

#[derive(Default, Clone)]
pub struct Registry(Arc<Mutex<Maps>>);

/// A token as the agent makes them: 32 lowercase hexadecimal digits.
pub fn token_ok(t: &str) -> bool {
    t.len() == 32 && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, Maps> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers (or replaces) `id` with `token` and `policy`. Registering an id again with the same token and policy
    /// keeps what it recorded.
    pub fn register(&self, id: &str, token: &str, policy: &BuildEgress, infra: bool) -> Result<(), String> {
        if !token_ok(token) {
            return Err("invalid token".into());
        }
        if id.is_empty() || id.len() > 200 || !id.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("invalid id".into());
        }
        let p = Policy::new(policy)?;
        let mut g = self.lock();
        let Maps { by_token, by_id } = &mut *g;
        if by_token.get(token).is_some_and(|r| r.id != id) {
            return Err("token already registered".into());
        }
        if let Some(old) = by_id.get(id) {
            let same = |r: &Reg| r.policy.mode == p.mode && r.policy.rules == p.rules && r.infra == infra;
            if old == token && by_token.get(token).is_some_and(|r| same(r)) {
                return Ok(());
            }
            if let Some(r) = by_token.remove(old) {
                r.finished.cancel();
            }
        }
        if by_token.len() >= MAX_REGISTRATIONS {
            return Err("too many registrations".into());
        }
        by_token.insert(token.to_string(), Arc::new(Reg::new(id.to_string(), p, infra)));
        by_id.insert(id.to_string(), token.to_string());
        Ok(())
    }

    fn by_token(&self, token: &str) -> Option<Arc<Reg>> {
        self.lock().by_token.get(token).cloned()
    }

    fn by_id(&self, id: &str) -> Option<Arc<Reg>> {
        let g = self.lock();
        g.by_id.get(id).and_then(|t| g.by_token.get(t)).cloned()
    }

    /// Ends `id`: its token stops working, its watchers end, and what it saw is returned.
    pub fn finish(&self, id: &str) -> Option<Report> {
        let reg = {
            let mut g = self.lock();
            let Maps { by_token, by_id } = &mut *g;
            let token = by_id.remove(id)?;
            by_token.remove(&token)?
        };
        reg.finished.cancel();
        Some(reg.report())
    }
}

/// The registration a request's credentials name: the password of `Proxy-Authorization: Basic`.
fn credentials(headers: &[(String, String)]) -> Option<String> {
    let v = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))?.1.trim();
    let (scheme, b64) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (_, password) = text.split_once(':')?;
    Some(password.to_string())
}

/// A request head: method, target, version and headers.
#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

/// Parses a request head (without its final blank line). None for anything malformed.
pub fn parse_head(text: &str) -> Option<Head> {
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, version) = (first.next()?, first.next()?, first.next()?);
    if first.next().is_some()
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
        || target.is_empty()
        || !target.bytes().all(|b| b.is_ascii_graphic())
    {
        return None;
    }
    let mut headers = Vec::new();
    for l in lines {
        let (k, v) = l.split_once(':')?;
        if k.is_empty()
            || !k.bytes().all(|b| b.is_ascii_graphic())
            || v.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return None;
        }
        headers.push((k.to_string(), v.trim().to_string()));
    }
    Some(Head { method: method.into(), target: target.into(), version: version.into(), headers })
}

/// A plain HTTP request's target in absolute form: where it goes and its path (with query).
pub fn absolute(target: &str) -> Result<(Target, String), &'static str> {
    let rest = target.strip_prefix("http://").ok_or(INVALID)?;
    let (auth, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if auth.contains('@') {
        return Err(INVALID);
    }
    let path = if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
    Ok((authority(auth, Some(80))?, path))
}

/// The head sent to the server for a plain HTTP request: origin form, the proxy's own headers and the connection's
/// options dropped, `Connection: close` (one request per connection), the Host header kept or added.
pub fn origin_head(h: &Head, path: &str, host: &str) -> String {
    let hop: Vec<String> = h
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|t| t.trim().to_ascii_lowercase()))
        .collect();
    let mut s = format!("{} {path} {}\r\n", h.method, h.version);
    let mut has_host = false;
    for (k, v) in &h.headers {
        let l = k.to_ascii_lowercase();
        if matches!(l.as_str(), "proxy-authorization" | "proxy-connection" | "connection" | "keep-alive")
            || hop.contains(&l)
        {
            continue;
        }
        has_host |= l == "host";
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_host {
        s.push_str(&format!("Host: {host}\r\n"));
    }
    s.push_str("Connection: close\r\n\r\n");
    s
}

fn answer(status: &str, extra: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Reads a request head: (its text without the blank line, bytes read after it).
async fn read_head(s: &mut TcpStream) -> Result<(String, Vec<u8>), &'static str> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            buf.truncate(i);
            return String::from_utf8(buf).map(|t| (t, rest)).map_err(|_| "400 Bad Request");
        }
        if buf.len() > MAX_HEAD {
            return Err("431 Request Header Fields Too Large");
        }
        let n = s.read(&mut chunk).await.map_err(|_| "")?;
        if n == 0 {
            return Err("");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Copies `r` to `w` until the end of `r`, counting in `n`; then closes `w` for writing. A read that waits longer
/// than [`IDLE_TIMEOUT`] ends it with an error.
async fn pipe(
    mut r: impl AsyncRead + Unpin,
    mut w: impl AsyncWrite + Unpin,
    n: &AtomicU64,
    limit: Option<u64>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    let mut left = limit;
    loop {
        if left == Some(0) {
            return Ok(());
        }
        let want = left.map_or(buf.len(), |l| buf.len().min(usize::try_from(l).unwrap_or(usize::MAX)));
        let k = match tokio::time::timeout(IDLE_TIMEOUT, r.read(&mut buf[..want])).await {
            Ok(r) => r?,
            Err(_) => return Err(std::io::ErrorKind::TimedOut.into()),
        };
        if k == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..k]).await?;
        n.fetch_add(k as u64, Ordering::Relaxed);
        left = left.map(|l| l - k as u64);
    }
}

/// Connects to the first address that answers.
async fn connect(addrs: &[SocketAddr]) -> Option<TcpStream> {
    for a in addrs {
        if let Ok(Ok(s)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
            return Some(s);
        }
    }
    None
}

/// The body length of a plain request: its Content-Length (0 without). Err for chunked bodies (refused: one request
/// per connection needs its length) and invalid lengths.
fn body_length(h: &Head) -> Result<u64, &'static str> {
    if h.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")) {
        return Err("411 Length Required");
    }
    let mut lengths = h.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    match (lengths.next(), lengths.next()) {
        (None, _) => Ok(0),
        (Some((_, v)), None) => v.parse().map_err(|_| "400 Bad Request"),
        _ => Err("400 Bad Request"),
    }
}

async fn handle(registry: Registry, mut client: TcpStream) {
    let (text, rest) = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
        Ok(Ok(x)) => x,
        Ok(Err(status)) if !status.is_empty() => {
            let _ = client.write_all(&answer(status, "", "")).await;
            return;
        }
        _ => return,
    };
    let Some(head) = parse_head(&text) else {
        let _ = client.write_all(&answer("400 Bad Request", "", "")).await;
        return;
    };
    let Some(reg) = credentials(&head.headers).and_then(|t| registry.by_token(&t)) else {
        let body = "build egress proxy: credentials required\n";
        let _ = client
            .write_all(&answer(
                "407 Proxy Authentication Required",
                "Proxy-Authenticate: Basic realm=\"owd-build\"\r\n",
                body,
            ))
            .await;
        return;
    };
    let connect_method = head.method == "CONNECT";
    let parsed = match connect_method {
        true => authority(&head.target, None).map(|t| (t, None)),
        false => absolute(&head.target).map(|(t, p)| (t, Some(p))),
    };
    let (target, path) = match parsed {
        Ok(x) => x,
        Err(reason) => {
            let shown: String = head.target.chars().take(253).collect();
            reg.deny(&shown, 0, reason);
            let _ = client.write_all(&answer("400 Bad Request", "", "build egress proxy: invalid target\n")).await;
            return;
        }
    };
    let host = target.host.to_string();
    let denied = |reason: &'static str| {
        answer("403 Forbidden", "", &format!("build egress: {host}:{} denied ({reason})\n", target.port))
    };
    if let Err(reason) = reg.policy.check(&target) {
        reg.deny(&host, target.port, reason);
        let _ = client.write_all(&denied(reason)).await;
        return;
    }
    let addrs = match resolve(&target).await {
        Ok(a) => a,
        Err(reason) => {
            reg.deny(&host, target.port, reason);
            let _ = client.write_all(&denied(reason)).await;
            return;
        }
    };
    let length = match path.as_ref().map(|_| body_length(&head)).transpose() {
        Ok(l) => l,
        Err(status) => {
            let _ = client.write_all(&answer(status, "", "")).await;
            return;
        }
    };
    let Some(mut upstream) = connect(&addrs).await else {
        reg.record(&host, target.port, None, 0, 0);
        let _ = client.write_all(&answer("502 Bad Gateway", "", "build egress proxy: no answer\n")).await;
        return;
    };
    let (out, inn) = (AtomicU64::new(0), AtomicU64::new(0));
    let start = match &path {
        None => client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await,
        Some(p) => {
            let authority = match target.port {
                80 => host.clone(),
                port => format!(
                    "{}:{port}",
                    match &target.host {
                        Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
                        h => h.to_string(),
                    }
                ),
            };
            upstream.write_all(origin_head(&head, p, &authority).as_bytes()).await
        }
    };
    if start.is_ok() {
        // What the client sent after the head: tunnel bytes, or the start of the request's body (no more than its
        // length: whatever follows would be another request, which this connection does not carry).
        let early: &[u8] = match length {
            Some(l) => &rest[..rest.len().min(usize::try_from(l).unwrap_or(usize::MAX))],
            None => &rest,
        };
        if upstream.write_all(early).await.is_ok() {
            out.fetch_add(early.len() as u64, Ordering::Relaxed);
            let left = length.map(|l| l - early.len() as u64);
            let (cr, cw) = client.split();
            let (ur, uw) = upstream.split();
            let up = pipe(cr, uw, &out, left);
            let down = pipe(ur, cw, &inn, None);
            tokio::pin!(up, down);
            // Either direction failing ends both; one finishing lets the other run to its end.
            tokio::select! {
                r = &mut up => if r.is_ok() { let _ = down.await; },
                r = &mut down => if r.is_ok() && path.is_none() { let _ = up.await; },
            }
        }
    }
    reg.record(&host, target.port, None, out.into_inner(), inn.into_inner());
}

/// A control request (one per connection to [`CTL_SOCKET`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Ctl {
    /// A token for a deployment's build (`infra` false) or a builder's own traffic.
    Register {
        id: String,
        token: String,
        policy: BuildEgress,
        infra: bool,
    },
    /// The denials of `id` as they happen, until it is finished.
    Watch {
        id: String,
    },
    /// Ends `id` and reports what it saw.
    Finish {
        id: String,
    },
    Ping,
}

/// A control answer, one JSON line each.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    Ok,
    Error(String),
    Denied(Denial),
    /// The end of a watch.
    End,
    Report(Report),
}

async fn send(w: &mut (impl AsyncWrite + Unpin), r: &Reply) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(r).expect("reply");
    line.push(b'\n');
    w.write_all(&line).await
}

async fn control(registry: Registry, mut s: UnixStream) -> std::io::Result<()> {
    let mut buf = Vec::new();
    (&mut s).take(MAX_CTL as u64).read_to_end(&mut buf).await?;
    let req = match serde_json::from_slice::<Ctl>(&buf) {
        Ok(r) => r,
        Err(e) => return send(&mut s, &Reply::Error(format!("invalid request: {e}"))).await,
    };
    match req {
        Ctl::Ping => send(&mut s, &Reply::Ok).await,
        Ctl::Register { id, token, policy, infra } => {
            let r = registry.register(&id, &token, &policy, infra);
            send(&mut s, &r.map_or_else(Reply::Error, |()| Reply::Ok)).await
        }
        Ctl::Finish { id } => match registry.finish(&id) {
            Some(report) => send(&mut s, &Reply::Report(report)).await,
            None => send(&mut s, &Reply::Error(format!("{id} is not registered"))).await,
        },
        Ctl::Watch { id } => {
            let Some(reg) = registry.by_id(&id) else {
                return send(&mut s, &Reply::Error(format!("{id} is not registered"))).await;
            };
            let mut rx = reg.denials.subscribe();
            send(&mut s, &Reply::Ok).await?;
            loop {
                tokio::select! {
                    _ = reg.finished.cancelled() => return send(&mut s, &Reply::End).await,
                    d = rx.recv() => match d {
                        Ok(d) => send(&mut s, &Reply::Denied(d)).await?,
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => return send(&mut s, &Reply::End).await,
                    },
                }
            }
        }
    }
}

/// `owdeploy-agent build-proxy`: serves until killed.
pub async fn serve() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let registry = Registry::default();
    let _ = std::fs::remove_file(CTL_SOCKET);
    let ctl = UnixListener::bind(CTL_SOCKET).map_err(|e| format!("{CTL_SOCKET}: {e}"))?;
    std::fs::set_permissions(CTL_SOCKET, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{CTL_SOCKET}: {e}"))?;
    let tcp = TcpListener::bind(("0.0.0.0", PORT)).await.map_err(|e| format!("port {PORT}: {e}"))?;
    tracing::info!("build egress proxy on port {PORT}");
    let r = registry.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = ctl.accept().await {
            let r = r.clone();
            tokio::spawn(async move {
                if let Err(e) = control(r, s).await {
                    tracing::debug!("control: {e}");
                }
            });
        }
    });
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (s, _) = tcp.accept().await.map_err(|e| format!("accept: {e}"))?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(s);
            continue;
        };
        let r = registry.clone();
        tokio::spawn(async move {
            handle(r, s).await;
            drop(permit);
        });
    }
}

/// `owdeploy-agent build-proxy-ctl`: one request from standard input to the control socket, its answer lines to
/// standard output. A short-lived process of its own (`docker exec`), so plain blocking I/O.
pub fn ctl_client() -> Result<(), String> {
    use std::io::{Read, Write};
    let mut req = Vec::new();
    std::io::stdin().take(MAX_CTL as u64).read_to_end(&mut req).map_err(|e| format!("stdin: {e}"))?;
    let mut s = std::os::unix::net::UnixStream::connect(CTL_SOCKET).map_err(|e| format!("{CTL_SOCKET}: {e}"))?;
    s.write_all(&req).map_err(|e| format!("{CTL_SOCKET}: {e}"))?;
    s.shutdown(std::net::Shutdown::Write).map_err(|e| format!("{CTL_SOCKET}: {e}"))?;
    let mut out = std::io::stdout().lock();
    let mut buf = [0u8; 8192];
    loop {
        let n = s.read(&mut buf).map_err(|e| format!("{CTL_SOCKET}: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        out.write_all(&buf[..n]).and_then(|()| out.flush()).map_err(|e| format!("stdout: {e}"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mode: EgressMode, allow: &[&str]) -> Policy {
        Policy::new(&BuildEgress { mode, allow: allow.iter().map(|s| s.to_string()).collect() }).unwrap()
    }

    fn target(s: &str) -> Target {
        authority(s, None).unwrap()
    }

    #[test]
    fn allowlists_match_names_wildcards_and_ports_and_refuse_ip_literals() {
        let p = policy(EgressMode::Allowlist, &["registry.npmjs.org", "*.github.com:443"]);
        assert_eq!(p.check(&target("registry.npmjs.org:443")), Ok(()));
        assert_eq!(p.check(&target("REGISTRY.npmjs.org.:80")), Ok(()), "names compare canonically, any port");
        assert_eq!(p.check(&target("api.github.com:443")), Ok(()));
        assert_eq!(p.check(&target("api.github.com:22")), Err(NOT_ALLOWED), "only its port");
        assert_eq!(p.check(&target("github.com:443")), Err(NOT_ALLOWED), "a wildcard is below the domain only");
        assert_eq!(p.check(&target("npmjs.org.evil.io:443")), Err(NOT_ALLOWED));
        assert_eq!(p.check(&target("203.0.113.7:443")), Err(IP_LITERAL));
        assert_eq!(p.check(&target("[2606:50c0::153]:443")), Err(IP_LITERAL));
        assert_eq!(policy(EgressMode::Allowlist, &[]).check(&target("registry.npmjs.org:443")), Err(NOT_ALLOWED));
        // Open and audit take any public destination, names and addresses, but no private address.
        for mode in [EgressMode::Open, EgressMode::Audit] {
            let p = policy(mode, &[]);
            assert_eq!(p.check(&target("example.com:443")), Ok(()));
            assert_eq!(p.check(&target("198.51.100.20:443")), Ok(()));
            for private in ["10.0.0.1:80", "169.254.169.254:80", "127.0.0.1:22", "[::1]:80", "[fd00:ec2::254]:80"] {
                assert_eq!(p.check(&target(private)), Err(PRIVATE_ADDRESS), "{private}");
            }
        }
        assert!(authority("example.com", None).is_err(), "CONNECT needs a port");
        assert!(authority("::1:443", None).is_err(), "an IPv6 address needs brackets");
        assert!(authority("exa mple.com:443", None).is_err() && authority("a.com:0", None).is_err());
    }

    #[test]
    fn resolution_keeps_public_addresses_only() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(vet([a("10.0.0.5:443"), a("127.0.0.1:443")]), Err(PRIVATE_ADDRESS), "DNS rebinding to private");
        assert_eq!(vet([a("[::ffff:10.0.0.5]:443")]), Err(PRIVATE_ADDRESS), "IPv4-mapped");
        assert_eq!(vet([a("[64:ff9b::a9fe:a9fe]:80")]), Err(PRIVATE_ADDRESS), "metadata behind NAT64");
        assert_eq!(vet([]), Err(UNRESOLVED));
        assert_eq!(
            vet([a("[2606:4700::1]:443"), a("10.1.1.1:443"), a("192.0.2.80:443")]),
            Ok(vec![a("192.0.2.80:443"), a("[2606:4700::1]:443")]),
            "public ones, IPv4 first"
        );
    }

    #[tokio::test]
    async fn names_resolving_to_private_addresses_are_refused_after_resolution() {
        let t = Target { host: Host::Name("localhost".into()), port: 80 };
        assert_eq!(policy(EgressMode::Open, &[]).check(&t), Ok(()), "a name passes before resolution");
        assert_eq!(resolve(&t).await, Err(PRIVATE_ADDRESS));
        let t = Target { host: Host::Name("does-not-exist.invalid".into()), port: 80 };
        assert_eq!(resolve(&t).await, Err(UNRESOLVED));
    }

    #[test]
    fn plain_requests_go_out_in_origin_form_without_the_proxys_headers() {
        let text = "GET http://deb.debian.org/debian/dists?x=1 HTTP/1.1\r\nHost: deb.debian.org\r\n\
                    Proxy-Authorization: Basic b3dkOnNlY3JldA==\r\nProxy-Connection: keep-alive\r\n\
                    Connection: keep-alive, X-Hop\r\nX-Hop: 1\r\nAccept: */*";
        let h = parse_head(text).unwrap();
        let (t, path) = absolute(&h.target).unwrap();
        assert_eq!((t, path.as_str()), (target("deb.debian.org:80"), "/debian/dists?x=1"));
        let out = origin_head(&h, &path, "deb.debian.org");
        assert_eq!(
            out,
            "GET /debian/dists?x=1 HTTP/1.1\r\nHost: deb.debian.org\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(credentials(&h.headers).as_deref(), Some("secret"));
        let (t, path) = absolute("http://[2001:db8::1]:8080?q").unwrap();
        assert_eq!((t.port, path.as_str()), (8080, "/?q"));
        assert!(absolute("https://a.com/").is_err() && absolute("http://user@example.com/").is_err());
        assert!(parse_head("GET http://a.com/ HTTP/2").is_none());
        assert!(parse_head("GET http://a.com/ HTTP/1.1\r\nBad\r\n").is_none());
        let chunked = parse_head("POST http://a.com/ HTTP/1.1\r\nTransfer-Encoding: chunked").unwrap();
        assert!(body_length(&chunked).is_err());
        assert_eq!(body_length(&parse_head("PUT http://a.com/ HTTP/1.1\r\nContent-Length: 12").unwrap()), Ok(12));
    }

    #[test]
    fn tokens_select_their_registration_and_finish_reports_once() {
        let r = Registry::default();
        let (a, b) = ("a".repeat(32), "b".repeat(32));
        r.register(
            "deployment:dep_1",
            &a,
            &BuildEgress { mode: EgressMode::Allowlist, allow: vec!["a.com".into()] },
            false,
        )
        .unwrap();
        r.register("builder:owd-buildkit", &b, &BuildEgress::OPEN, true).unwrap();
        assert!(r.register("x", "short", &BuildEgress::OPEN, false).is_err(), "tokens are 32 hex digits");
        assert!(r.register("deployment:dep_2", &a, &BuildEgress::OPEN, false).is_err(), "one token, one id");
        let bad = BuildEgress { mode: EgressMode::Allowlist, allow: vec!["192.0.2.1".into()] };
        assert!(r.register("deployment:dep_3", &"c".repeat(32), &bad, false).is_err());
        assert!(r.by_token(&"d".repeat(32)).is_none(), "an unknown token selects nothing");
        let reg = r.by_token(&a).unwrap();
        assert_eq!(reg.policy.check(&target("a.com:443")), Ok(()));
        assert_eq!(reg.policy.check(&target("b.com:443")), Err(NOT_ALLOWED));
        assert_eq!(r.by_token(&b).unwrap().policy.check(&target("b.com:443")), Ok(()));
        reg.record("a.com", 443, None, 10, 100);
        reg.record("a.com", 443, None, 5, 50);
        reg.deny("b.com", 443, NOT_ALLOWED);
        let rep = r.finish("deployment:dep_1").unwrap();
        assert_eq!((rep.allowed, rep.denied, rep.bytes_out, rep.bytes_in), (2, 1, 15, 150));
        assert_eq!(rep.entries.len(), 2);
        assert_eq!(rep.entries[0].host, "a.com");
        assert_eq!((rep.entries[0].count, rep.entries[0].bytes_in), (2, 150));
        assert_eq!(rep.entries[1].reason.as_deref(), Some(NOT_ALLOWED));
        assert!(r.by_token(&a).is_none(), "a finished token stops working");
        assert!(r.finish("deployment:dep_1").is_none());
        // Open mode keeps the totals and the denials only.
        let reg = r.by_token(&b).unwrap();
        reg.record("a.com", 443, None, 1, 1);
        reg.deny("10.0.0.1", 80, PRIVATE_ADDRESS);
        let rep = r.finish("builder:owd-buildkit").unwrap();
        assert_eq!((rep.allowed, rep.denied), (1, 1));
        assert_eq!(rep.entries.len(), 1);
        assert_eq!(rep.entries[0].decision, EgressDecision::Denied);
    }

    #[test]
    fn records_are_bounded() {
        let reg = Reg::new("d".into(), policy(EgressMode::Audit, &[]), false);
        for i in 0..MAX_RECORDS + 10 {
            reg.record(&format!("h{i}.example.com"), 443, None, 0, 0);
        }
        let rep = reg.report();
        assert!(rep.truncated);
        assert_eq!(rep.entries.len(), MAX_EGRESS_ENTRIES);
        assert_eq!(rep.allowed, (MAX_RECORDS + 10) as u64);
    }

    /// The proxy end to end on loopback: unknown credentials get 407, a denied CONNECT 403, an allowed one a tunnel
    /// (here to a name resolving to loopback, which the proxy refuses after resolution).
    #[tokio::test]
    async fn the_proxy_answers_per_token() {
        let registry = Registry::default();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let r = registry.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = tcp.accept().await {
                tokio::spawn(handle(r.clone(), s));
            }
        });
        let token = "e".repeat(32);
        registry
            .register(
                "deployment:d",
                &token,
                &BuildEgress { mode: EgressMode::Allowlist, allow: vec!["localhost".into()] },
                false,
            )
            .unwrap();
        let ask = |req: String| async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(req.as_bytes()).await.unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        };
        let auth = |t: &str| base64::engine::general_purpose::STANDARD.encode(format!("owd:{t}"));
        let out = ask("CONNECT example.com:443 HTTP/1.1\r\n\r\n".into()).await;
        assert!(out.starts_with("HTTP/1.1 407"), "{out}");
        let out = ask(format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            auth(&"f".repeat(32))
        ))
        .await;
        assert!(out.starts_with("HTTP/1.1 407"), "an unknown token: {out}");
        let out =
            ask(format!("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", auth(&token)))
                .await;
        assert!(out.starts_with("HTTP/1.1 403") && out.contains("not_allowed"), "{out}");
        let out =
            ask(format!("CONNECT localhost:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", auth(&token))).await;
        assert!(out.starts_with("HTTP/1.1 403") && out.contains("private_address"), "{out}");
        let out =
            ask(format!("GET http://127.0.0.1/ HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", auth(&token))).await;
        assert!(out.starts_with("HTTP/1.1 403") && out.contains("ip_literal"), "{out}");
        let rep = registry.finish("deployment:d").unwrap();
        let reasons: Vec<_> =
            rep.entries.iter().map(|e| (e.host.as_str(), e.reason.clone().unwrap_or_default())).collect();
        assert_eq!(rep.denied, 3);
        assert!(reasons.contains(&("example.com", NOT_ALLOWED.to_string())), "{reasons:?}");
        assert!(reasons.contains(&("localhost", PRIVATE_ADDRESS.to_string())), "{reasons:?}");
        assert!(reasons.contains(&("127.0.0.1", IP_LITERAL.to_string())), "{reasons:?}");
    }
}
