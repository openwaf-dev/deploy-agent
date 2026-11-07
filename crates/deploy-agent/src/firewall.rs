//! The agent's iptables and ip6tables rules (PROTOCOL.md, SECURITY.md): published application ports and the router's
//! listeners reachable only from the OpenWAF edge (`FirewallSync`), and the egress guard of every container on a
//! Deploy network.
//!
//! Docker publishes ports with DNAT in the nat table, so the traffic is forwarded to the container and never crosses
//! INPUT: host firewalls (ufw, CSF) do not see it. Docker sends forwarded traffic through `DOCKER-USER` first and
//! never flushes that chain, so the agent keeps its rules in its own chains, `OWDEPLOY` (jumped to from the top of
//! `DOCKER-USER`) and `OWDEPLOY-SRC`, and replaces them atomically with `iptables-restore --noflush`: rules it did
//! not create, in `DOCKER-USER` or anywhere else, are never touched. `--ctorigdstport` matches the published host
//! port after the DNAT; `--ctstate DNAT` limits the rules to published ports, so a container's own outgoing
//! connections to a remote port in the same range are left alone.
//!
//! The router's listeners are not published by Docker (which cannot add a port to a running container): the agent
//! DNATs each listener port to the router's address itself (`OWDEPLOY-NAT`, jumped to from nat `PREROUTING` for
//! local destinations, and from nat `OUTPUT` except loopback) and accepts that traffic in `OWDEPLOY` after the same
//! source check, so a new listener is a Caddy reload plus one iptables transaction and no listener is interrupted.
//! Before any `FirewallSync` (no edge ranges configured) the listeners are open, as Docker-published ports were.
//!
//! Egress guard. A container on a Deploy network (the environment networks, Compose projects' networks, the build
//! network: Docker networks named `owd-…`) runs code the agent does not trust. What it sends out of its network
//! goes through `OWDEPLOY-EGRESS` (from `OWDEPLOY`): to another Deploy network it is left to Docker's own
//! isolation (its own network passes, others are dropped), a connection to a published port or listener keeps its
//! edge-only source check, DNS to the server's name servers passes (Docker's embedded resolver forwards queries from
//! the container's namespace), and everything else to the private, shared (CGNAT), link-local (cloud metadata),
//! loopback, multicast and reserved ranges, and to the control plane's `deny` list, is rejected; the public
//! Internet stays reachable. What it sends to the server itself (its addresses and the networks' gateways: INPUT,
//! not forwarded) goes through `OWDEPLOY-IN` → `OWDEPLOY-HOST` and is rejected but for those name servers. Networks
//! the agent creates name their bridge `owd<12 hex>`, so `-i owd+` covers each of them from its creation on, with
//! no window before the next check; bridges of older Deploy networks (`br-<id>`) are listed one by one.
//!
//! IPv6 has the same rule sets in ip6tables, without `OWDEPLOY-NAT`: Deploy networks are created without IPv6 (so
//! the router and its listeners are IPv4 only), and the guard of published ports also covers them in `OWDEPLOY-IN`,
//! where an IPv6 connection to a published port arrives when Docker's userland proxy answers it on `[::]`. ip6tables
//! is used where Docker keeps `DOCKER-USER` in it, else (Docker without ip6tables) with the IPv4 backend's flavour
//! when the host has IPv6 at all; a host without IPv6 or ip6tables only gets the IPv4 rules.
//!
//! The rules wanted are the last `FirewallSync` (kept in the state directory), the router's listeners and the Deploy
//! networks. They are checked every [`CHECK_EVERY`], when the router (re)starts and when a network is created or
//! removed, and applied again whenever what iptables lists differs: after a reboot, after `csf -r` (which flushes
//! every chain; `owdeploy-agent firewall-repair` also runs from CSF's post hook), after the router got a new address.
//! When even `DOCKER-USER` is gone (flushed by CSF), it is created again with its jump from `FORWARD`, as Docker
//! does, on the iptables backend Docker was last seen using.
//!
//! A change is one transaction over both families: what iptables lists is kept, each family's single restore input
//! (the agent's chains and rules, the missing jumps, `DOCKER-USER` when it is gone) is checked with `--test` before
//! anything is applied, then applied IPv4 first; when a family fails, it and those already applied are rolled back
//! to what was listed, so a host never keeps half a change or IPv4 and IPv6 rules of different generations.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use deploy_proto::msg::FirewallRules;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use crate::builder::BUILD_BRIDGE;

pub const CHAIN: &str = "OWDEPLOY";
pub const SOURCES: &str = "OWDEPLOY-SRC";
pub const NAT: &str = "OWDEPLOY-NAT";
/// Forwarded traffic leaving a Deploy network (from `OWDEPLOY`).
pub const EGRESS: &str = "OWDEPLOY-EGRESS";
/// The agent's chain at the top of `INPUT`.
pub const INPUT: &str = "OWDEPLOY-IN";
/// Traffic from a Deploy network to the server itself (from `OWDEPLOY-IN`).
pub const HOST: &str = "OWDEPLOY-HOST";
/// Prefix of the bridge interfaces of the networks the agent creates (`owd+` matches all of them).
pub const BRIDGE_PREFIX: &str = "owd";
/// Docker's option naming a bridge network's interface.
pub const BRIDGE_OPTION: &str = "com.docker.network.bridge.name";
/// Name prefix of Deploy networks.
pub const NETWORK_PREFIX: &str = "owd-";
const STATE_FILE: &str = "firewall.json";
/// The iptables binary where `DOCKER-USER` was last found, to recreate it after a flush.
const BACKEND_FILE: &str = "firewall-backend";
/// How often the rules are checked (and repaired).
pub const CHECK_EVERY: Duration = Duration::from_secs(30);

/// Binaries per backend, in order of preference: the backend in use is the one where Docker created `DOCKER-USER`.
/// The IPv6 binaries are at the same positions as their IPv4 flavour.
const V4: [(&str, &str); 3] = [
    ("iptables-nft", "iptables-nft-restore"),
    ("iptables-legacy", "iptables-legacy-restore"),
    ("iptables", "iptables-restore"),
];
const V6: [(&str, &str); 3] = [
    ("ip6tables-nft", "ip6tables-nft-restore"),
    ("ip6tables-legacy", "ip6tables-legacy-restore"),
    ("ip6tables", "ip6tables-restore"),
];

/// Destinations refused to Deploy containers whatever the control plane says: "this network", private, shared
/// (CGNAT), loopback, link-local (cloud metadata at 169.254.169.254), IETF protocol assignments, benchmarking,
/// multicast and reserved.
const BLOCKED_V4: [&str; 11] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
/// The same for IPv6: unspecified, loopback, IPv4-mapped, local-use NAT64, discard, Teredo, documentation, 6to4,
/// unique local (AWS metadata at fd00:ec2::254), link-local and multicast; plus, in [`blocked`], the well-known
/// NAT64 prefix in front of each IPv4 range above.
const BLOCKED_V6: [&str; 11] = [
    "::/128",
    "::1/128",
    "::ffff:0.0.0.0/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/32",
    "2001:db8::/32",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn of(ip: &IpAddr) -> Family {
        if ip.is_ipv4() { Family::V4 } else { Family::V6 }
    }

    fn name(self) -> &'static str {
        match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        }
    }

    fn reject(self) -> &'static str {
        match self {
            Family::V4 => "-j REJECT --reject-with icmp-admin-prohibited",
            Family::V6 => "-j REJECT --reject-with icmp6-adm-prohibited",
        }
    }
}

/// `address/prefix` as its network address, as iptables prints it back.
fn cidr(c: &str) -> Result<(Family, String), String> {
    let (addr, len) = match c.trim().split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (c.trim(), None),
    };
    let ip: IpAddr = addr.parse().map_err(|_| format!("invalid address {c:?}"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len: u8 = match len {
        Some(l) => l.parse().ok().filter(|l| *l <= max).ok_or_else(|| format!("invalid prefix in {c:?}"))?,
        None => max,
    };
    Ok(match ip {
        IpAddr::V4(a) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len)) };
            (Family::V4, format!("{}/{len}", Ipv4Addr::from(u32::from(a) & mask)))
        }
        IpAddr::V6(a) => {
            let mask = if len == 0 { 0 } else { u128::MAX << (128 - u32::from(len)) };
            (Family::V6, format!("{}/{len}", Ipv6Addr::from(u128::from(a) & mask)))
        }
    })
}

/// The destinations always refused in `family`.
pub fn blocked(family: Family) -> Vec<String> {
    match family {
        Family::V4 => BLOCKED_V4.iter().map(|c| c.to_string()).collect(),
        Family::V6 => {
            let mut v: Vec<String> = BLOCKED_V6.iter().map(|c| c.to_string()).collect();
            // 64:ff9b::/96 + an IPv4 address reaches that address through a NAT64 gateway.
            for c in BLOCKED_V4 {
                let (a, l) = c.split_once('/').expect("cidr");
                let a: Ipv4Addr = a.parse().expect("address");
                let l: u8 = l.parse().expect("prefix");
                let nat64 = (0x0064_ff9b_u128 << 96) | u128::from(u32::from(a));
                v.push(format!("{}/{}", Ipv6Addr::from(nat64), 96 + l));
            }
            v
        }
    }
}

/// The ranges of [`blocked`] of both families, parsed once.
static BLOCKED: std::sync::LazyLock<Vec<(IpAddr, u8)>> = std::sync::LazyLock::new(|| {
    [Family::V4, Family::V6]
        .into_iter()
        .flat_map(blocked)
        .map(|c| {
            let (a, l) = c.split_once('/').expect("cidr");
            (a.parse().expect("address"), l.parse().expect("prefix"))
        })
        .collect()
});

/// Whether `ip` is in a range every Deploy container is refused ([`blocked`]): what the build egress proxy never
/// connects to ([`crate::proxy`]).
pub fn is_blocked(ip: IpAddr) -> bool {
    BLOCKED.iter().any(|(net, len)| match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if *len == 0 { 0 } else { u32::MAX << (32 - u32::from(*len)) };
            u32::from(a) & mask == u32::from(*n)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = if *len == 0 { 0 } else { u128::MAX << (128 - u32::from(*len)) };
            u128::from(a) & mask == u128::from(*n)
        }
        _ => false,
    })
}

/// Where the router listens without Docker publishing its ports: its address and listener ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingress {
    pub ip: Ipv4Addr,
    pub ports: Vec<u16>,
}

#[derive(Debug, PartialEq)]
pub struct Plan {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
    pub ports: Vec<u16>,
    pub deny_v4: Vec<String>,
    pub deny_v6: Vec<String>,
}

/// Normalizes the sources and denied destinations (address/prefix, network address, deduplicated) and ports.
/// Anything else is refused: the values end up in an `iptables-restore` script.
pub fn plan(r: &FirewallRules) -> Result<Plan, String> {
    let split = |list: &[String], what: &str| -> Result<(Vec<String>, Vec<String>), String> {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for c in list {
            match cidr(c).map_err(|e| format!("{what}: {e}"))? {
                (Family::V4, n) => v4.push(n),
                (Family::V6, n) => v6.push(n),
            }
        }
        for v in [&mut v4, &mut v6] {
            v.sort();
            v.dedup();
        }
        Ok((v4, v6))
    };
    let (v4, v6) = split(&r.allow, "source")?;
    let (deny_v4, deny_v6) = split(&r.deny, "denied destination")?;
    let mut ports = r.ports.clone();
    if ports.contains(&0) {
        return Err("invalid port 0".into());
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(Plan { v4, v6, ports, deny_v4, deny_v6 })
}

/// What the egress guard covers besides the control plane's rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Guard {
    /// Bridge interfaces of Deploy networks outside `owd+` (networks created before the agent named their
    /// bridges), sorted.
    pub bridges: Vec<String>,
    /// Whether the server has any Deploy network: then the guard is wanted even before a `FirewallSync`.
    pub networks: bool,
    /// The name servers Docker's embedded resolver forwards to (not loopback).
    pub nameservers: Vec<IpAddr>,
}

impl Guard {
    fn interfaces(&self) -> Vec<String> {
        std::iter::once(format!("{BRIDGE_PREFIX}+")).chain(self.bridges.iter().cloned()).collect()
    }
}

/// The interface of a Docker network if it is a Deploy network (named `owd-…`, bridge driver): the bridge Docker
/// was told to create, else its default `br-<first 12 characters of the id>`.
pub fn deploy_bridge(
    name: &str,
    driver: Option<&str>,
    id: &str,
    options: Option<&HashMap<String, String>>,
) -> Option<String> {
    if !name.starts_with(NETWORK_PREFIX) || driver != Some("bridge") {
        return None;
    }
    match options.and_then(|o| o.get(BRIDGE_OPTION)).filter(|b| !b.is_empty()) {
        Some(b) => Some(b.clone()),
        None => Some(format!("br-{}", &id[..id.len().min(12)])),
    }
}

/// Bridge interface the agent gives a Deploy network: `owd` and 12 hex digits of its name's SHA-256 (interface
/// names have at most 15 characters).
pub fn bridge_name(network: &str) -> String {
    use sha2::Digest;
    format!("{BRIDGE_PREFIX}{}", &hex::encode(sha2::Sha256::digest(network.as_bytes()))[..12])
}

/// The `nameserver` lines of a resolv.conf (an IPv6 zone is dropped).
pub fn parse_resolv(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()? == "nameserver").then_some(())?;
            w.next()?.split('%').next()?.parse().ok()
        })
        .collect()
}

/// The upstream name servers of Docker's embedded resolver, as dockerd picks them: the host's resolv.conf, or
/// systemd-resolved's own upstreams when it lists only its loopback stub, and the daemon's `dns` setting. Loopback
/// servers are queried from the host's namespace, never through a container's network: left out.
fn nameservers() -> Vec<IpAddr> {
    let read = |p: &str| std::fs::read_to_string(p).map(|t| parse_resolv(&t)).unwrap_or_default();
    let mut v = read("/etc/resolv.conf");
    if v.iter().all(IpAddr::is_loopback) {
        v.extend(read("/run/systemd/resolve/resolv.conf"));
    }
    if let Ok(t) = std::fs::read_to_string("/etc/docker/daemon.json")
        && let Ok(cfg) = serde_json::from_str::<Value>(&t)
    {
        v.extend(cfg["dns"].as_array().into_iter().flatten().filter_map(|s| s.as_str()?.parse::<IpAddr>().ok()));
    }
    v.retain(|ip| !ip.is_loopback() && !ip.is_unspecified());
    v.sort();
    v.dedup();
    v
}

/// The Deploy networks of the Engine and the name servers.
async fn guard() -> Result<Guard, String> {
    let d = crate::docker::client()?;
    let filters = HashMap::from([("name".to_string(), vec![NETWORK_PREFIX.to_string()])]);
    let opts = bollard::query_parameters::ListNetworksOptionsBuilder::default().filters(&filters).build();
    let list =
        d.list_networks(Some(opts)).await.map_err(|e| format!("docker network ls: {}", crate::docker::message(&e)))?;
    let mut g = Guard { nameservers: nameservers(), ..Default::default() };
    for n in list {
        let (name, id) = (n.name.unwrap_or_default(), n.id.unwrap_or_default());
        if let Some(b) = deploy_bridge(&name, n.driver.as_deref(), &id, n.options.as_ref()) {
            g.networks = true;
            if !b.starts_with(BRIDGE_PREFIX) {
                g.bridges.push(b);
            }
        }
    }
    g.bridges.sort();
    g.bridges.dedup();
    Ok(g)
}

/// The filter table input for `iptables-restore --noflush` (or ip6tables'). Declaring the chains flushes them (or
/// creates them), so the whole set is replaced in one transaction. `sources` None: published ports are not managed
/// (no `FirewallSync` yet), nothing is guarded on them and only the router's listeners are let through. The router's
/// listeners are guarded like the published ports. `deny`: the control plane's refused destinations, of `family`.
pub fn filter_script(
    family: Family,
    sources: Option<&[String]>,
    ports: &[u16],
    ingress: Option<&Ingress>,
    guard: &Guard,
    deny: &[String],
) -> String {
    let mut s = format!("*filter\n:{CHAIN} - [0:0]\n:{SOURCES} - [0:0]\n:{EGRESS} - [0:0]\n:{INPUT} - [0:0]\n");
    s.push_str(&format!(":{HOST} - [0:0]\n"));
    let mut add = |chain: &str, rule: &str| s.push_str(&format!("-A {chain} {rule}\n"));
    add(CHAIN, "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN");
    let mut guarded: Vec<u16> = ports.iter().chain(ingress.iter().flat_map(|i| &i.ports)).copied().collect();
    guarded.sort_unstable();
    guarded.dedup();
    if let Some(sources) = sources {
        for p in &guarded {
            add(CHAIN, &format!("-p tcp -m conntrack --ctstate DNAT --ctorigdstport {p} -j {SOURCES}"));
        }
        for c in sources {
            add(SOURCES, &format!("-s {c} -j RETURN"));
        }
    }
    // Reached only from an allowed source (the others were dropped in `OWDEPLOY-SRC`): Docker's own chains would
    // drop traffic to a port it does not publish.
    if let Some(i) = ingress {
        for p in &i.ports {
            add(CHAIN, &format!("-d {}/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport {p} -j ACCEPT", i.ip));
        }
    }
    let interfaces = guard.interfaces();
    for i in &interfaces {
        add(CHAIN, &format!("-i {i} -j {EGRESS}"));
    }
    // To a Deploy network: Docker's isolation decides (the container's own network passes, others are dropped).
    for o in &interfaces {
        add(EGRESS, &format!("-o {o} -j RETURN"));
    }
    // A published port or router listener: its source check above already decided.
    add(EGRESS, "-m conntrack --ctstate DNAT -j RETURN");
    // The build network leaves through the build egress proxy only (on the same network): nothing of it is forwarded
    // anywhere else, DNS included. Docker already gives that internal network no route out; this holds even if the
    // network were not internal.
    add(EGRESS, &format!("-i {BUILD_BRIDGE} {}", family.reject()));
    let len = if family == Family::V4 { 32 } else { 128 };
    let dns: Vec<String> =
        guard.nameservers.iter().filter(|ip| Family::of(ip) == family).map(|ip| format!("{ip}/{len}")).collect();
    for ns in &dns {
        for proto in ["udp", "tcp"] {
            add(EGRESS, &format!("-d {ns} -p {proto} --dport 53 -j RETURN"));
        }
    }
    for c in deny.iter().cloned().chain(blocked(family)) {
        add(EGRESS, &format!("-d {c} {}", family.reject()));
    }
    add(INPUT, "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN");
    for i in &interfaces {
        add(INPUT, &format!("-i {i} -j {HOST}"));
    }
    // A published port answered by Docker's userland proxy (IPv6 to a container without an IPv6 address) is a
    // local connection: the same source check. Connections from the server itself (loopback) stay open.
    if sources.is_some() {
        for p in &guarded {
            add(INPUT, &format!("! -i lo -p tcp --dport {p} -j {SOURCES}"));
        }
    }
    add(HOST, &format!("-i {BUILD_BRIDGE} {}", family.reject()));
    for ns in &dns {
        for proto in ["udp", "tcp"] {
            add(HOST, &format!("-d {ns} -p {proto} --dport 53 -j RETURN"));
        }
    }
    if family == Family::V6 {
        // Neighbour discovery and path MTU messages.
        add(HOST, "-p ipv6-icmp -j RETURN");
    }
    add(HOST, family.reject());
    add(SOURCES, "-j DROP");
    s.push_str("COMMIT\n");
    s
}

/// The nat table input: each router listener port to the router.
pub fn nat_script(ingress: Option<&Ingress>) -> String {
    let mut s = format!("*nat\n:{NAT} - [0:0]\n");
    if let Some(i) = ingress {
        for p in &i.ports {
            s.push_str(&format!("-A {NAT} -p tcp --dport {p} -j DNAT --to-destination {}:{p}\n", i.ip));
        }
    }
    s.push_str("COMMIT\n");
    s
}

/// A rule the agent adds once to a chain it does not own (at its top).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jump {
    pub table: &'static str,
    pub chain: &'static str,
    pub rule: Vec<&'static str>,
}

fn jumps(family: Family) -> Vec<Jump> {
    let mut j = vec![
        // Docker's own jump; restored when a flush removed it with the chain.
        Jump { table: "filter", chain: "FORWARD", rule: vec!["-j", "DOCKER-USER"] },
        Jump { table: "filter", chain: "DOCKER-USER", rule: vec!["-j", CHAIN] },
        Jump { table: "filter", chain: "INPUT", rule: vec!["-j", INPUT] },
    ];
    if family == Family::V4 {
        j.push(Jump {
            table: "nat",
            chain: "PREROUTING",
            rule: vec!["-m", "addrtype", "--dst-type", "LOCAL", "-j", NAT],
        });
        // Connections from the server itself to one of its addresses (not loopback, which cannot be DNATed to a
        // bridge without changing kernel settings Docker owns).
        j.push(Jump {
            table: "nat",
            chain: "OUTPUT",
            rule: vec!["!", "-d", "127.0.0.0/8", "-m", "addrtype", "--dst-type", "LOCAL", "-j", NAT],
        });
    }
    j
}

/// The options of a rule that identify it, independent of how `iptables -S` prints it (match modules it adds,
/// option order).
fn signature(rule: &str) -> Vec<String> {
    const KEYS: [&str; 12] = [
        "-s",
        "-d",
        "-i",
        "-o",
        "-p",
        "--dport",
        "--ctstate",
        "--ctorigdstport",
        "--dst-type",
        "--to-destination",
        "--reject-with",
        "-j",
    ];
    let mut out = Vec::new();
    let mut negate = false;
    let mut it = rule.split_whitespace();
    while let Some(t) = it.next() {
        if t == "!" {
            negate = true;
            continue;
        }
        if KEYS.contains(&t)
            && let Some(v) = it.next()
        {
            out.push(format!("{}{t} {v}", if negate { "!" } else { "" }));
        }
        negate = false;
    }
    out.sort();
    out
}

/// `-A CHAIN rest` → (CHAIN, rest).
fn appended(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim().strip_prefix("-A ")?;
    Some(rest.split_once(' ').unwrap_or((rest, "")))
}

/// The chains a restore script declares, with their table.
fn declared(script: &str) -> Vec<(String, String)> {
    let mut table = "filter";
    let mut out = Vec::new();
    for l in script.lines() {
        if let Some(t) = l.strip_prefix('*') {
            table = t.trim();
        } else if let Some(c) = l.strip_prefix(':').and_then(|c| c.split_whitespace().next()) {
            out.push((table.to_string(), c.to_string()));
        }
    }
    out
}

/// What differs between the rules wanted (`script`, `jumps`) and those listed (`iptables -S` of the chains
/// concerned). Empty: nothing to repair.
pub fn problems(listing: &str, script: &str, jumps: &[Jump]) -> Vec<String> {
    let mut out = Vec::new();
    let rules_of = |text: &str, chain: &str| -> Vec<Vec<String>> {
        text.lines().filter_map(appended).filter(|(c, _)| *c == chain).map(|(_, r)| signature(r)).collect()
    };
    for (_, chain) in declared(script) {
        if !listing.lines().any(|l| l.trim() == format!("-N {chain}")) {
            out.push(format!("chain {chain} missing"));
        } else if rules_of(listing, &chain) != rules_of(script, &chain) {
            out.push(format!("rules of {chain} differ"));
        }
    }
    for j in jumps {
        if !rules_of(listing, j.chain).contains(&signature(&j.rule.join(" "))) {
            out.push(format!("jump {} → {} missing", j.chain, j.rule.last().copied().unwrap_or_default()));
        }
    }
    out
}

/// Runs a binary (never through a shell): (success, stdout, stderr).
async fn run(bin: &str, args: &[&str], input: Option<&str>) -> Result<(bool, String, String), std::io::Error> {
    let mut c = tokio::process::Command::new(bin);
    c.args(args).stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
    c.stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = c.spawn()?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(text.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    ))
}

/// How the transaction runs iptables: the host's binaries, or a stand-in in the tests.
trait Runner {
    async fn run(
        &self,
        bin: &str,
        args: &[&str],
        input: Option<&str>,
    ) -> Result<(bool, String, String), std::io::Error>;
}

/// The host's iptables binaries.
struct Host;

impl Runner for Host {
    async fn run(
        &self,
        bin: &str,
        args: &[&str],
        input: Option<&str>,
    ) -> Result<(bool, String, String), std::io::Error> {
        run(bin, args, input).await
    }
}

async fn has_docker_user(list: &str) -> bool {
    matches!(run(list, &["-w", "-t", "filter", "-n", "-L", "DOCKER-USER"], None).await, Ok((true, _, _)))
}

async fn detect(candidates: &[(&'static str, &'static str)]) -> Option<(&'static str, &'static str)> {
    for &(list, restore) in candidates {
        if has_docker_user(list).await {
            return Some((list, restore));
        }
    }
    None
}

/// The IPv4 backend: where `DOCKER-USER` is, or (flushed) where it was last seen.
async fn backend_v4() -> Option<(&'static str, &'static str)> {
    let path = crate::state_dir().join(BACKEND_FILE);
    let recorded = std::fs::read_to_string(&path).ok();
    if let Some(b) = detect(&V4).await {
        if recorded.as_deref() != Some(b.0) {
            let _ = crate::write_private(&path, b.0.as_bytes());
        }
        return Some(b);
    }
    let recorded = recorded?;
    let b = V4.into_iter().find(|(list, _)| *list == recorded.trim())?;
    matches!(run(b.0, &["-w", "-t", "filter", "-S", "FORWARD"], None).await, Ok((true, _, _))).then_some(b)
}

/// The IPv6 backend: where Docker keeps `DOCKER-USER` in ip6tables, else (Docker without ip6tables, or a flush)
/// the IPv4 backend's flavour, if the host has IPv6 and that ip6tables works. None: no IPv6 to guard.
async fn backend_v6(v4: &str) -> Option<(&'static str, &'static str)> {
    if !Path::new("/proc/net/if_inet6").exists() {
        return None;
    }
    if let Some(b) = detect(&V6).await {
        return Some(b);
    }
    let b = V6[V4.iter().position(|(list, _)| *list == v4)?];
    matches!(run(b.0, &["-w", "-t", "filter", "-S", "INPUT"], None).await, Ok((true, _, _))).then_some(b)
}

/// Whether the agent can route the router's listeners itself (Docker runs with its iptables integration).
pub async fn available() -> bool {
    backend_v4().await.is_some()
}

/// Chains of the kernel's tables. A restore script never declares them: that would reset their policy.
const BUILT_IN: [&str; 5] = ["INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"];

/// What `iptables -S` printed for one chain the rules concern.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listed {
    table: String,
    chain: String,
    /// None: the chain does not exist.
    text: Option<String>,
}

/// Every chain the rules concern (the agent's chains, and those holding its jumps) as iptables lists them: the
/// snapshot a failed change is rolled back to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Listing(Vec<Listed>);

impl Listing {
    /// The listings of every chain, one after the other (what [`problems`] reads).
    fn text(&self) -> String {
        self.0.iter().filter_map(|l| l.text.as_deref()).collect()
    }

    fn exists(&self, table: &str, chain: &str) -> bool {
        self.0.iter().any(|l| l.table == table && l.chain == chain && l.text.is_some())
    }

    /// The `-A` lines of a chain, as listed.
    fn rules(&self, table: &str, chain: &str) -> Vec<&str> {
        let text = self.0.iter().find(|l| l.table == table && l.chain == chain).and_then(|l| l.text.as_deref());
        text.unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| appended(l).is_some_and(|(c, _)| c == chain))
            .collect()
    }

    fn has(&self, j: &Jump) -> bool {
        let wanted = signature(&j.rule.join(" "));
        self.rules(j.table, j.chain).iter().any(|l| appended(l).is_some_and(|(_, r)| signature(r) == wanted))
    }
}

/// The chains the rules concern, with their table: those the script declares, then those holding a jump.
fn concerned(script: &str, jumps: &[Jump]) -> Vec<(String, String)> {
    let mut chains = declared(script);
    for j in jumps {
        let c = (j.table.to_string(), j.chain.to_string());
        if !chains.contains(&c) {
            chains.push(c);
        }
    }
    chains
}

/// `iptables -S` of every chain the rules concern (a chain iptables does not list does not exist).
async fn listing(r: &impl Runner, list: &str, script: &str, jumps: &[Jump]) -> Result<Listing, String> {
    let mut out = Vec::new();
    for (table, chain) in concerned(script, jumps) {
        let text = match r.run(list, &["-w", "-t", &table, "-S", &chain], None).await {
            Ok((true, text, _)) => Some(text),
            Ok((false, _, _)) => None,
            Err(e) => return Err(format!("{list}: {e}")),
        };
        out.push(Listed { table, chain, text });
    }
    Ok(Listing(out))
}

/// `script` with, per table, the `head` lines added right after its `*table` line and the `tail` lines right before
/// its `COMMIT`, in their order; a table the script has no section for gets its own, after the others.
fn with_lines(script: &str, head: &[(&str, String)], tail: &[(&str, String)]) -> String {
    let of = |lines: &[(&str, String)], table: &str| -> String {
        lines.iter().filter(|(t, _)| *t == table).map(|(_, l)| format!("{l}\n")).collect()
    };
    let mut out = String::new();
    let mut table = None;
    let mut seen = Vec::new();
    for l in script.lines() {
        if l.trim() == "COMMIT"
            && let Some(t) = table
        {
            out.push_str(&of(tail, t));
        }
        out.push_str(&format!("{l}\n"));
        if let Some(t) = l.strip_prefix('*').map(str::trim) {
            out.push_str(&of(head, t));
            table = Some(t);
            seen.push(t);
        }
    }
    for (t, _) in head.iter().chain(tail) {
        if !seen.contains(t) {
            seen.push(t);
            out.push_str(&format!("*{t}\n{}{}COMMIT\n", of(head, t), of(tail, t)));
        }
    }
    out
}

/// The single restore input that brings one family from `before` to the wanted rules: `script` (which declares, so
/// flushes or creates, the agent's chains), `DOCKER-USER` declared when it is gone (never when it exists: declaring
/// flushes it, and it may hold the customer's rules), and each missing jump inserted at the top of its chain, so a
/// broader RETURN or ACCEPT placed by someone else cannot bypass it. Each table's part is one commit.
fn apply_script(script: &str, jumps: &[Jump], before: &Listing) -> String {
    let mut create: Vec<(&str, String)> = Vec::new();
    for j in jumps {
        let decl = format!(":{} - [0:0]", j.chain);
        if !BUILT_IN.contains(&j.chain)
            && !before.exists(j.table, j.chain)
            && !create.contains(&(j.table, decl.clone()))
        {
            create.push((j.table, decl));
        }
    }
    let insert: Vec<(&str, String)> = jumps
        .iter()
        .filter(|j| !before.has(j))
        .map(|j| (j.table, format!("-I {} 1 {}", j.chain, j.rule.join(" "))))
        .collect();
    with_lines(script, &create, &insert)
}

/// The restore input that brings one family back from `now` to `before` (listings of the chains `script` and `jumps`
/// concern). A chain of the agent that exists is declared (flushed) and gets its previous rules back if it existed
/// before, as does any chain that existed and is gone; a jump added since is deleted, one lost since inserted again
/// (both left to the flush in a chain declared here); then chains that did not exist before (the agent's, and
/// `DOCKER-USER` if the change created it) are deleted, once nothing refers to them. Chains of others that existed
/// before keep their rules; built-in chains are never declared. Empty: nothing to undo.
fn rollback_script(before: &Listing, now: &Listing, script: &str, jumps: &[Jump]) -> String {
    let owned = declared(script);
    let mut chains: Vec<(&str, &str)> = Vec::new();
    for l in before.0.iter().chain(&now.0) {
        let c = (l.table.as_str(), l.chain.as_str());
        if !chains.contains(&c) {
            chains.push(c);
        }
    }
    let (mut declare, mut delete, mut insert, mut add, mut remove) = (vec![], vec![], vec![], vec![], vec![]);
    let mut flushed = Vec::new();
    for (t, c) in chains {
        if BUILT_IN.contains(&c) {
            continue;
        }
        let (was, is) = (before.exists(t, c), now.exists(t, c));
        let mine = owned.iter().any(|(ot, oc)| ot == t && oc == c);
        if (is && (mine || !was)) || (was && !is) {
            declare.push((t, format!(":{c} - [0:0]")));
            flushed.push((t, c));
            add.extend(before.rules(t, c).into_iter().map(|r| (t, r.to_string())));
        }
        if is && !was {
            remove.push((t, format!("-X {c}")));
        }
    }
    for j in jumps.iter().filter(|j| !flushed.contains(&(j.table, j.chain))) {
        match (before.has(j), now.has(j)) {
            (false, true) => delete.push((j.table, format!("-D {} {}", j.chain, j.rule.join(" ")))),
            (true, false) => insert.push((j.table, format!("-I {} 1 {}", j.chain, j.rule.join(" ")))),
            _ => {}
        }
    }
    with_lines("", &[], &[declare, delete, insert, add, remove].concat())
}

/// One family's wanted state: its binaries, the restore script of the agent's chains and the jumps to them.
struct Want {
    family: Family,
    list: &'static str,
    restore: &'static str,
    script: String,
    jumps: Vec<Jump>,
}

/// A family the transaction changes: its listing before, and the restore input applying the change.
struct Change<'a> {
    want: &'a Want,
    before: Listing,
    input: String,
}

async fn restore(r: &impl Runner, bin: &str, args: &[&str], input: &str) -> Result<(), String> {
    match r.run(bin, args, Some(input)).await {
        Ok((true, _, _)) => Ok(()),
        Ok((false, _, e)) => Err(format!("{bin}: {e}")),
        Err(e) => Err(format!("{bin}: {e}")),
    }
}

/// Brings every family of `changes` back to its listing from before the transaction, each one attempted whatever
/// happened to the others. iptables-restore commits table by table (legacy and nft alike), so a failed restore may
/// have left part of its change in place: what is listed now is compared, not assumed. Err: the families that could
/// not be.
async fn rollback(r: &impl Runner, changes: &[Change<'_>]) -> Result<(), String> {
    let mut failed = Vec::new();
    for c in changes {
        let w = c.want;
        let undone = async {
            let now = listing(r, w.list, &w.script, &w.jumps).await?;
            let input = rollback_script(&c.before, &now, &w.script, &w.jumps);
            if input.is_empty() {
                return Ok(());
            }
            restore(r, w.restore, &["-w", "--noflush"], &input).await
        }
        .await;
        if let Err(e) = undone {
            tracing::error!("firewall: the {} rules could not be rolled back: {e}", w.family.name());
            failed.push(format!("{}: {e}", w.family.name()));
        }
    }
    match failed.is_empty() {
        true => Ok(()),
        false => Err(failed.join("; ")),
    }
}

/// Brings each family to its wanted state if it differs, as one transaction: what iptables lists is kept, the input
/// of every family that changes is checked with `--test` before any is applied (one refused: nothing applied; the nft
/// backend's dry run checks the syntax and extensions only, not what its kernel accepts), then each family's input
/// (its chains, rules and missing jumps) is applied in one restore, IPv4 first; when one fails, it and those already
/// applied are rolled back, so IPv4 and IPv6 never end up with different generations of the rules. `wanted` false:
/// a family where none of the agent's chains exists is left untouched. Returns what was repaired.
async fn transaction(r: &impl Runner, wants: &[Want], wanted: bool) -> Result<Vec<String>, String> {
    let mut repaired = Vec::new();
    let mut changes = Vec::new();
    for w in wants {
        let before = listing(r, w.list, &w.script, &w.jumps).await?;
        // Nothing wanted and nothing of ours there: a server the agent never configured stays untouched.
        if !wanted && !before.exists("filter", CHAIN) {
            continue;
        }
        let p = problems(&before.text(), &w.script, &w.jumps);
        if p.is_empty() {
            continue;
        }
        repaired.extend(p.into_iter().map(|p| format!("{} {p}", w.family.name())));
        let input = apply_script(&w.script, &w.jumps, &before);
        changes.push(Change { want: w, before, input });
    }
    for c in &changes {
        if let Err(e) = restore(r, c.want.restore, &["-w", "--noflush", "--test"], &c.input).await {
            return Err(format!("{} rules refused by the dry run, nothing applied: {e}", c.want.family.name()));
        }
    }
    for (i, c) in changes.iter().enumerate() {
        if let Err(e) = restore(r, c.want.restore, &["-w", "--noflush"], &c.input).await {
            let families: Vec<&str> = changes[..=i].iter().map(|c| c.want.family.name()).collect();
            let families = families.join(" and ");
            return Err(match rollback(r, &changes[..=i]).await {
                Ok(()) => format!("{} rules not applied ({e}); {families} rolled back", c.want.family.name()),
                Err(u) => format!("{} rules not applied ({e}); rollback failed: {u}", c.want.family.name()),
            });
        }
    }
    Ok(repaired)
}

/// The rules of the last `FirewallSync` (None: never synced, the firewall is not managed).
pub(crate) fn saved_rules() -> Result<Option<FirewallRules>, String> {
    let path = crate::state_dir().join(STATE_FILE);
    match std::fs::read_to_string(&path) {
        Ok(t) => serde_json::from_str(&t).map(Some).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub struct Report {
    pub backend: Option<&'static str>,
    pub ipv6: bool,
    pub guard: Guard,
    pub repaired: Vec<String>,
}

/// Brings iptables and ip6tables to `rules` (None: published ports not managed), the router's `ingress` and the
/// egress guard of the Deploy networks. The caller holds the router lock (`router::LOCK`), so the router's state
/// cannot change meanwhile.
pub(crate) async fn apply_locked(rules: Option<&FirewallRules>, ingress: Option<&Ingress>) -> Result<Report, String> {
    let plan = rules.map(plan).transpose()?;
    let guard = guard().await?;
    let Some(v4) = backend_v4().await else {
        if plan.is_some() || guard.networks {
            return Err("DOCKER-USER chain not found: Docker must run with its iptables integration (and the agent \
                        as root), else neither published ports nor the containers' egress can be guarded"
                .into());
        }
        // Without iptables the router publishes its ports through Docker: nothing to do.
        return Ok(Report { backend: None, ipv6: false, guard, repaired: Vec::new() });
    };
    let wanted = plan.is_some() || ingress.is_some() || guard.networks;
    let ports = plan.as_ref().map(|p| p.ports.as_slice()).unwrap_or_default();
    let (deny_v4, deny_v6) = plan.as_ref().map(|p| (p.deny_v4.as_slice(), p.deny_v6.as_slice())).unwrap_or_default();
    let script = filter_script(Family::V4, plan.as_ref().map(|p| p.v4.as_slice()), ports, ingress, &guard, deny_v4)
        + &nat_script(ingress);
    let mut wants = vec![Want { family: Family::V4, list: v4.0, restore: v4.1, script, jumps: jumps(Family::V4) }];
    let v6 = backend_v6(v4.0).await;
    if let Some((list, restore)) = v6 {
        // No listener is routed over IPv6, but any port the router listens on is guarded like a published one.
        let mut guarded: Vec<u16> = ports.iter().chain(ingress.iter().flat_map(|i| &i.ports)).copied().collect();
        guarded.sort_unstable();
        guarded.dedup();
        let sources = plan.as_ref().map(|p| p.v6.as_slice());
        let script = filter_script(Family::V6, sources, &guarded, None, &guard, deny_v6);
        wants.push(Want { family: Family::V6, list, restore, script, jumps: jumps(Family::V6) });
    }
    let repaired = transaction(&Host, &wants, wanted).await?;
    Ok(Report { backend: Some(v4.0), ipv6: v6.is_some(), guard, repaired })
}

/// `FirewallSync`: the new rules, applied with the router's listeners, then kept for the next checks and starts.
pub async fn sync(r: &FirewallRules) -> Result<Value, String> {
    let p = plan(r)?;
    let _g = crate::router::LOCK.lock().await;
    let ingress = crate::router::ingress().await?;
    let report = apply_locked(Some(r), ingress.as_ref()).await?;
    let path = crate::state_dir().join(STATE_FILE);
    crate::write_private(&path, serde_json::to_string(r).expect("rules").as_bytes())?;
    Ok(json!({
        "applied": true, "backend": report.backend, "ipv6": report.ipv6, "ports": p.ports.len(),
        "router_ports": ingress.map_or(0, |i| i.ports.len()), "denied": p.deny_v4.len() + p.deny_v6.len(),
        "egress_interfaces": report.guard.interfaces(),
    }))
}

/// Checks the rules against the saved ones, the router's listeners and the Deploy networks, and repairs what
/// differs. Returns what was repaired (empty: all in place).
pub async fn reconcile() -> Result<Vec<String>, String> {
    let _g = crate::router::LOCK.lock().await;
    let ingress = crate::router::ingress().await?;
    Ok(apply_locked(saved_rules()?.as_ref(), ingress.as_ref()).await?.repaired)
}

/// Right after the agent created a Deploy network, before any container joins it: the first one of a server is what
/// makes the egress guard wanted, so the rules are put in place now rather than at the next check.
pub async fn guard_new_network() -> Result<(), String> {
    match available().await {
        true => reconcile().await.map(|_| ()).map_err(|e| format!("firewall: {e}")),
        false => Ok(()),
    }
}

/// Every [`CHECK_EVERY`], as soon as the router (re)starts (its address may change) and when a network is created
/// or removed, repairs the rules.
pub async fn watch() {
    let (tx, mut changes) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(docker_changes(tx));
    let mut tick = tokio::time::interval(CHECK_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_error: Option<String> = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            Some(()) = changes.recv() => {}
        }
        match reconcile().await {
            Ok(repaired) => {
                if !repaired.is_empty() {
                    tracing::warn!("firewall: repaired ({})", repaired.join("; "));
                }
                last_error = None;
            }
            Err(e) => {
                if last_error.as_ref() != Some(&e) {
                    tracing::warn!("firewall: {e}");
                }
                last_error = Some(e);
            }
        }
    }
}

/// Signals each start of the router, each network created or removed, and each (re)connection to Docker's event
/// stream (a restarted Docker restarted the router too).
async fn docker_changes(tx: tokio::sync::mpsc::Sender<()>) {
    use futures_util::StreamExt;
    loop {
        if let Ok(d) = crate::docker::client() {
            let router = HashMap::from([
                ("type", vec!["container"]),
                ("container", vec![crate::router::CONTAINER]),
                ("event", vec!["start", "restart"]),
            ]);
            let networks = HashMap::from([("type", vec!["network"]), ("event", vec!["create", "destroy"])]);
            let stream = |f: &HashMap<&str, Vec<&str>>| {
                d.events(Some(bollard::query_parameters::EventsOptionsBuilder::default().filters(f).build()))
            };
            let mut events = futures_util::stream::select(stream(&router), stream(&networks));
            let _ = tx.try_send(());
            while let Some(Ok(_)) = events.next().await {
                let _ = tx.try_send(());
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

const CSF_MARK: &str = "# owdeploy-agent";

/// The CSF post hook with the agent's repair added; None when it is already there.
pub fn csf_hook(existing: Option<&str>, bin: &Path) -> Option<String> {
    let line = format!(
        "{CSF_MARK}: restore the OpenWAF Deploy firewall rules csf just flushed\n\
         [ -x '{b}' ] && '{b}' firewall-repair >/dev/null 2>&1 || true\n",
        b = bin.display()
    );
    match existing {
        Some(t) if t.contains(CSF_MARK) => None,
        Some(t) if t.is_empty() || t.ends_with('\n') => Some(format!("{t}{line}")),
        Some(t) => Some(format!("{t}\n{line}")),
        None => Some(format!("#!/bin/sh\n{line}")),
    }
}

/// When CSF is installed, adds the repair to its post hook (run after every `csf -r`/`csf -s`), which CSF reads from
/// `/usr/local/csf/bin/csfpost.sh`, else `/etc/csf/csfpost.sh`. Returns the file changed.
pub fn install_csf_hook(bin: &Path) -> Result<Option<PathBuf>, String> {
    if !Path::new("/etc/csf").is_dir() {
        return Ok(None);
    }
    if bin.to_string_lossy().contains('\'') {
        return Err(format!("unexpected binary path {}", bin.display()));
    }
    const PATHS: [&str; 2] = ["/usr/local/csf/bin/csfpost.sh", "/etc/csf/csfpost.sh"];
    let target =
        PATHS.iter().map(PathBuf::from).find(|p| p.exists()).unwrap_or_else(|| {
            PathBuf::from(if Path::new("/usr/local/csf/bin").is_dir() { PATHS[0] } else { PATHS[1] })
        });
    let existing = match std::fs::read_to_string(&target) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", target.display())),
    };
    let Some(text) = csf_hook(existing.as_deref(), bin) else { return Ok(None) };
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&target).map(|m| m.permissions().mode() | 0o700).unwrap_or(0o700);
    let tmp = target.with_extension("owdeploy.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &target).map_err(|e| format!("{}: {e}", target.display()))?;
    Ok(Some(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(allow: &[&str], ports: &[u16], deny: &[&str]) -> FirewallRules {
        FirewallRules {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            ports: ports.to_vec(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn plan_normalizes_and_refuses_injection() {
        let r = rules(
            &["10.1.2.3/8", "10.0.0.0/8", "2001:db8::1/32", "192.0.2.7"],
            &[20002, 20001, 20002],
            &["203.0.113.9", "2001:db8:5::7/48"],
        );
        assert_eq!(
            plan(&r).unwrap(),
            Plan {
                v4: vec!["10.0.0.0/8".into(), "192.0.2.7/32".into()],
                v6: vec!["2001:db8::/32".into()],
                ports: vec![20001, 20002],
                deny_v4: vec!["203.0.113.9/32".into()],
                deny_v6: vec!["2001:db8:5::/48".into()],
            }
        );
        for bad in ["10.0.0.0/33", "10.0.0.0/8 -j ACCEPT", "1.2.3.4\n-A INPUT -j ACCEPT", "example.com", ""] {
            assert!(plan(&rules(&[bad], &[], &[])).is_err(), "{bad:?}");
            assert!(plan(&rules(&[], &[], &[bad])).is_err(), "deny {bad:?}");
        }
        assert!(plan(&rules(&[], &[0], &[])).is_err());
        // An older control plane sends no `deny`.
        let old: FirewallRules = serde_json::from_str(r#"{"allow": ["192.0.2.0/24"], "ports": [20001]}"#).unwrap();
        assert!(plan(&old).unwrap().deny_v4.is_empty());
    }

    fn ingress() -> Ingress {
        Ingress { ip: Ipv4Addr::new(172, 18, 0, 2), ports: vec![20002, 20003] }
    }

    fn guard() -> Guard {
        Guard {
            bridges: vec!["br-0123456789ab".into()],
            networks: true,
            nameservers: vec!["192.168.5.2".parse().unwrap(), "fd00::53".parse().unwrap()],
        }
    }

    /// The rules of `chain` in a script, without the `-A CHAIN` prefix.
    fn chain(script: &str, chain: &str) -> Vec<String> {
        script.lines().filter_map(appended).filter(|(c, _)| *c == chain).map(|(_, r)| r.to_string()).collect()
    }

    #[test]
    fn scripts_guard_published_ports_and_route_the_router_listeners() {
        let sources = ["198.51.100.0/24".to_string()];
        let s = filter_script(Family::V4, Some(&sources), &[20001, 20002], Some(&ingress()), &Guard::default(), &[]);
        assert!(s.starts_with(
            "*filter\n:OWDEPLOY - [0:0]\n:OWDEPLOY-SRC - [0:0]\n:OWDEPLOY-EGRESS - [0:0]\n:OWDEPLOY-IN - [0:0]\n\
             :OWDEPLOY-HOST - [0:0]\n"
        ));
        assert!(s.ends_with("-A OWDEPLOY-SRC -j DROP\nCOMMIT\n"));
        assert_eq!(
            chain(&s, CHAIN),
            [
                "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
                "-p tcp -m conntrack --ctstate DNAT --ctorigdstport 20001 -j OWDEPLOY-SRC",
                "-p tcp -m conntrack --ctstate DNAT --ctorigdstport 20002 -j OWDEPLOY-SRC",
                // A router listener is guarded even when the control plane did not list it.
                "-p tcp -m conntrack --ctstate DNAT --ctorigdstport 20003 -j OWDEPLOY-SRC",
                "-d 172.18.0.2/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 20002 -j ACCEPT",
                "-d 172.18.0.2/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 20003 -j ACCEPT",
                "-i owd+ -j OWDEPLOY-EGRESS",
            ]
        );
        assert_eq!(chain(&s, SOURCES), ["-s 198.51.100.0/24 -j RETURN", "-j DROP"]);
        // The same ports answered by Docker's userland proxy (local delivery) get the same check.
        assert_eq!(
            chain(&s, INPUT),
            [
                "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
                "-i owd+ -j OWDEPLOY-HOST",
                "! -i lo -p tcp --dport 20001 -j OWDEPLOY-SRC",
                "! -i lo -p tcp --dport 20002 -j OWDEPLOY-SRC",
                "! -i lo -p tcp --dport 20003 -j OWDEPLOY-SRC",
            ]
        );
        // No sources: published ports are closed to everyone rather than open.
        assert!(
            filter_script(Family::V4, Some(&[]), &[20001], None, &Guard::default(), &[])
                .ends_with("-A OWDEPLOY-SRC -j DROP\nCOMMIT\n")
        );
        // Not managed: nothing guarded, the listeners let through.
        let open = filter_script(Family::V4, None, &[], Some(&ingress()), &Guard::default(), &[]);
        assert!(!open.contains("-j OWDEPLOY-SRC") && open.contains("--ctorigdstport 20003 -j ACCEPT"));
        assert_eq!(
            nat_script(Some(&ingress())),
            "*nat\n:OWDEPLOY-NAT - [0:0]\n\
             -A OWDEPLOY-NAT -p tcp --dport 20002 -j DNAT --to-destination 172.18.0.2:20002\n\
             -A OWDEPLOY-NAT -p tcp --dport 20003 -j DNAT --to-destination 172.18.0.2:20003\nCOMMIT\n"
        );
    }

    /// Deploy containers keep the Internet, their networks and DNS, and lose metadata, private ranges, the
    /// control plane's denied hosts and the server itself, managed or not.
    #[test]
    fn egress_guard_refuses_metadata_private_ranges_and_the_host() {
        let deny = ["203.0.113.9/32".to_string()];
        let s = filter_script(Family::V4, None, &[], None, &guard(), &deny);
        let main = chain(&s, CHAIN);
        assert!(main.contains(&"-i owd+ -j OWDEPLOY-EGRESS".into()));
        assert!(main.contains(&"-i br-0123456789ab -j OWDEPLOY-EGRESS".into()), "an older Deploy network");
        let egress = chain(&s, EGRESS);
        let reject = "-j REJECT --reject-with icmp-admin-prohibited";
        let pos = |r: &str| egress.iter().position(|x| x == r).unwrap_or_else(|| panic!("{r} missing: {egress:#?}"));
        // Order: other Deploy networks and published ports, DNS, then the refusals.
        let dns = pos("-d 192.168.5.2/32 -p udp --dport 53 -j RETURN");
        assert!(pos("-o owd+ -j RETURN") < dns && pos("-o br-0123456789ab -j RETURN") < dns);
        assert!(pos("-m conntrack --ctstate DNAT -j RETURN") < dns);
        assert!(pos("-d 192.168.5.2/32 -p tcp --dport 53 -j RETURN") < pos(&format!("-d 192.168.0.0/16 {reject}")));
        for c in ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10", "127.0.0.0/8", "203.0.113.9/32"] {
            assert!(dns < pos(&format!("-d {c} {reject}")), "{c}");
        }
        assert!(!egress.iter().any(|r| r.contains("fd00::53")), "an IPv6 name server is not in the IPv4 rules");
        assert_eq!(egress.last().unwrap(), &format!("-d 240.0.0.0/4 {reject}"));
        // The build network: nothing forwarded but to Deploy networks (its own: the build egress proxy), not even
        // DNS to the server's name servers; nothing to the server.
        let build = pos(&format!("-i {BUILD_BRIDGE} {reject}"));
        assert!(pos("-o owd+ -j RETURN") < build && build < dns, "{egress:#?}");
        assert_eq!(
            chain(&s, HOST),
            [
                format!("-i {BUILD_BRIDGE} {reject}"),
                "-d 192.168.5.2/32 -p udp --dport 53 -j RETURN".to_string(),
                "-d 192.168.5.2/32 -p tcp --dport 53 -j RETURN".to_string(),
                reject.to_string(),
            ]
        );
        assert_eq!(
            chain(&s, INPUT),
            [
                "-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
                "-i owd+ -j OWDEPLOY-HOST",
                "-i br-0123456789ab -j OWDEPLOY-HOST",
            ]
        );
    }

    /// IPv6 gets the same sets: published ports edge-only (also through the userland proxy), and the egress guard
    /// with IPv6's private, link-local and NAT64-embedded ranges.
    #[test]
    fn ipv6_rules_match_ipv4() {
        let sources = ["2001:db8:e::/48".to_string()];
        let deny = ["2001:db8:c::/48".to_string()];
        let s = filter_script(Family::V6, Some(&sources), &[20001, 20003], None, &guard(), &deny);
        let v4 = filter_script(Family::V4, Some(&[]), &[20001, 20003], None, &guard(), &[]);
        assert_eq!(declared(&s), declared(&v4), "same chains in both families");
        assert!(
            chain(&s, CHAIN)
                .contains(&"-p tcp -m conntrack --ctstate DNAT --ctorigdstport 20003 -j OWDEPLOY-SRC".into())
        );
        assert!(chain(&s, INPUT).contains(&"! -i lo -p tcp --dport 20003 -j OWDEPLOY-SRC".into()));
        assert_eq!(chain(&s, SOURCES), ["-s 2001:db8:e::/48 -j RETURN", "-j DROP"]);
        let egress = chain(&s, EGRESS);
        let reject = "-j REJECT --reject-with icmp6-adm-prohibited";
        for c in [
            "fc00::/7",
            "fe80::/10",
            "::1/128",
            "::ffff:0.0.0.0/96",
            "ff00::/8",
            "2001:db8:c::/48",
            "64:ff9b::a9fe:0/112",
            "64:ff9b::a00:0/104",
            "64:ff9b::c0a8:0/112",
        ] {
            assert!(egress.contains(&format!("-d {c} {reject}")), "{c}: {egress:#?}");
        }
        assert!(egress.contains(&"-d fd00::53/128 -p udp --dport 53 -j RETURN".into()));
        assert!(!egress.iter().any(|r| r.contains("192.168.5.2")));
        assert!(egress.contains(&format!("-i {BUILD_BRIDGE} {reject}")));
        assert_eq!(
            chain(&s, HOST),
            [
                format!("-i {BUILD_BRIDGE} {reject}"),
                "-d fd00::53/128 -p udp --dport 53 -j RETURN".to_string(),
                "-d fd00::53/128 -p tcp --dport 53 -j RETURN".to_string(),
                "-p ipv6-icmp -j RETURN".to_string(),
                reject.to_string(),
            ]
        );
        // Every IPv6 jump the IPv4 rules have, except the IPv4-only listener routing.
        let (j4, j6) = (jumps(Family::V4), jumps(Family::V6));
        assert_eq!(j6, j4.into_iter().filter(|j| j.table == "filter").collect::<Vec<_>>());
    }

    #[test]
    fn blocked_ranges_are_network_addresses() {
        for f in [Family::V4, Family::V6] {
            for c in blocked(f) {
                assert_eq!(cidr(&c).unwrap(), (f, c.clone()), "{c} is printed back by iptables as is");
            }
        }
        assert!(blocked(Family::V4).contains(&"169.254.0.0/16".to_string()));
    }

    /// What the build egress proxy never connects to: the same ranges, address by address.
    #[test]
    fn blocked_addresses_are_those_of_the_ranges() {
        for ip in [
            "10.1.2.3",
            "169.254.169.254",
            "127.0.0.1",
            "100.64.0.1",
            "172.31.255.255",
            "192.168.100.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:192.0.2.1",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(is_blocked(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["192.0.2.1", "198.51.100.20", "172.32.0.1", "100.128.0.1", "2606:4700::1111", "64:ff9b::c000:201"] {
            assert!(!is_blocked(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn deploy_networks_and_their_bridges() {
        let opts = HashMap::from([(BRIDGE_OPTION.to_string(), "owd0123456789ab".to_string())]);
        let id = "0123456789abcdef0123";
        assert_eq!(deploy_bridge("owd-0a1b2c3d4e5f", Some("bridge"), id, None).as_deref(), Some("br-0123456789ab"));
        assert_eq!(
            deploy_bridge("owd-app_1_default", Some("bridge"), id, Some(&opts)).as_deref(),
            Some("owd0123456789ab")
        );
        assert_eq!(deploy_bridge("bridge", Some("bridge"), id, None), None, "Docker's default bridge");
        assert_eq!(deploy_bridge("myapp_default", Some("bridge"), id, None), None, "not a Deploy network");
        assert_eq!(deploy_bridge("owd-lan", Some("macvlan"), id, None), None, "not a bridge");
        let b = bridge_name("owd-0a1b2c3d4e5f");
        assert!(b.len() <= 15 && b.starts_with("owd") && b != bridge_name("owd-0a1b2c3d4e60"), "{b}");
    }

    #[test]
    fn resolv_conf_name_servers() {
        let text = "# generated\nnameserver 127.0.0.53\nnameserver 10.0.0.2\nnameserver fe80::1%eth0\n\
                    options edns0\nnameserver junk\nsearch nameserver\n";
        assert_eq!(
            parse_resolv(text),
            ["127.0.0.53".parse::<IpAddr>().unwrap(), "10.0.0.2".parse().unwrap(), "fe80::1".parse().unwrap()]
        );
    }

    /// What `iptables -S` prints for the chains once `script` and the jumps are applied: chains, then their rules
    /// as iptables writes them back (implicit match modules, its own option order).
    fn listed(script: &str, jumps: &[Jump]) -> String {
        let mut out = String::from("-P FORWARD DROP\n-P INPUT ACCEPT\n-N DOCKER-USER\n-P PREROUTING ACCEPT\n");
        out.push_str("-P OUTPUT ACCEPT\n");
        for (_, c) in declared(script) {
            out.push_str(&format!("-N {c}\n"));
        }
        for j in jumps {
            out.push_str(&format!("-A {} {}\n", j.chain, j.rule.join(" ")));
        }
        for l in script.lines().filter(|l| l.starts_with("-A ")) {
            let l = l
                .replace(" -p tcp --dport", " -p tcp -m tcp --dport")
                .replace(" -p udp --dport", " -p udp -m udp --dport");
            out.push_str(&format!("{l}\n"));
        }
        out.push_str("-A DOCKER-USER -j RETURN\n-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER\n");
        out
    }

    /// The repair is a pure comparison: in place → nothing to do (idempotent, so the 30 s check never churns);
    /// flushed by `csf -r`, a lost jump, a router with a new address, a new older-style Deploy network, an extra
    /// rule → repaired.
    #[test]
    fn repair_detects_flushed_chains_and_lost_jumps_only() {
        let sources = ["198.51.100.0/24".to_string()];
        let script = filter_script(Family::V4, Some(&sources), &[20001], Some(&ingress()), &guard(), &[])
            + &nat_script(Some(&ingress()));
        let j = jumps(Family::V4);
        let healthy = listed(&script, &j);
        assert_eq!(problems(&healthy, &script, &j), Vec::<String>::new());

        let flushed = "-P FORWARD ACCEPT\n-P INPUT ACCEPT\n-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n";
        assert_eq!(
            problems(flushed, &script, &j),
            [
                "chain OWDEPLOY missing",
                "chain OWDEPLOY-SRC missing",
                "chain OWDEPLOY-EGRESS missing",
                "chain OWDEPLOY-IN missing",
                "chain OWDEPLOY-HOST missing",
                "chain OWDEPLOY-NAT missing",
                "jump FORWARD → DOCKER-USER missing",
                "jump DOCKER-USER → OWDEPLOY missing",
                "jump INPUT → OWDEPLOY-IN missing",
                "jump PREROUTING → OWDEPLOY-NAT missing",
                "jump OUTPUT → OWDEPLOY-NAT missing",
            ]
        );
        let no_jump = healthy.replace("-A DOCKER-USER -j OWDEPLOY\n", "");
        assert_eq!(problems(&no_jump, &script, &j), ["jump DOCKER-USER → OWDEPLOY missing"]);
        let no_input = healthy.replace("-A INPUT -j OWDEPLOY-IN\n", "");
        assert_eq!(problems(&no_input, &script, &j), ["jump INPUT → OWDEPLOY-IN missing"]);

        let moved = Ingress { ip: Ipv4Addr::new(172, 18, 0, 3), ..ingress() };
        let now = filter_script(Family::V4, Some(&sources), &[20001], Some(&moved), &guard(), &[])
            + &nat_script(Some(&moved));
        assert_eq!(problems(&healthy, &now, &j), ["rules of OWDEPLOY differ", "rules of OWDEPLOY-NAT differ"]);

        let mut more = guard();
        more.bridges.push("br-fedcba987654".into());
        let now = filter_script(Family::V4, Some(&sources), &[20001], Some(&ingress()), &more, &[])
            + &nat_script(Some(&ingress()));
        assert_eq!(
            problems(&healthy, &now, &j),
            ["rules of OWDEPLOY differ", "rules of OWDEPLOY-EGRESS differ", "rules of OWDEPLOY-IN differ"]
        );

        let extra = format!("{healthy}-A OWDEPLOY-SRC -s 0.0.0.0/0 -j RETURN\n");
        assert_eq!(problems(&extra, &script, &j), ["rules of OWDEPLOY-SRC differ"]);
        let open =
            healthy.replace("-A OWDEPLOY-EGRESS -d 169.254.0.0/16 -j REJECT --reject-with icmp-admin-prohibited\n", "");
        assert_eq!(problems(&open, &script, &j), ["rules of OWDEPLOY-EGRESS differ"], "metadata reopened");

        let s6 = filter_script(Family::V6, Some(&[]), &[20001], None, &guard(), &[]);
        let j6 = jumps(Family::V6);
        assert_eq!(problems(&listed(&s6, &j6), &s6, &j6), Vec::<String>::new());
        assert_eq!(
            problems("-P FORWARD ACCEPT\n-P INPUT ACCEPT\n-N DOCKER-USER\n", &s6, &j6),
            [
                "chain OWDEPLOY missing",
                "chain OWDEPLOY-SRC missing",
                "chain OWDEPLOY-EGRESS missing",
                "chain OWDEPLOY-IN missing",
                "chain OWDEPLOY-HOST missing",
                "jump FORWARD → DOCKER-USER missing",
                "jump DOCKER-USER → OWDEPLOY missing",
                "jump INPUT → OWDEPLOY-IN missing",
            ]
        );
    }

    const FLUSHED: &str = "-P FORWARD ACCEPT\n-P INPUT ACCEPT\n-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n";

    /// What `iptables -S chain` prints out of a whole listing; None when the chain is not there.
    fn chain_listing(text: &str, chain: &str) -> Option<String> {
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| {
                let mut w = l.split_whitespace();
                matches!(w.next(), Some("-N" | "-P" | "-A")) && w.next() == Some(chain)
            })
            .collect();
        lines.iter().any(|l| !l.starts_with("-A ")).then(|| lines.iter().map(|l| format!("{l}\n")).collect())
    }

    /// The listing the transaction takes of a host listing `text`.
    fn snapshot(text: &str, script: &str, jumps: &[Jump]) -> Listing {
        Listing(
            concerned(script, jumps)
                .into_iter()
                .map(|(table, chain)| Listed { text: chain_listing(text, &chain), table, chain })
                .collect(),
        )
    }

    /// The lines of each `*table` section of a restore input, checking that every line lies in one (between its
    /// `*table` and `COMMIT`), as iptables-restore requires.
    fn sections(input: &str) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        let mut open = false;
        for l in input.lines().filter(|l| !l.trim().is_empty()) {
            if let Some(t) = l.strip_prefix('*') {
                assert!(!open, "{t} opened inside another table:\n{input}");
                out.push((t.to_string(), Vec::new()));
                open = true;
            } else if l == "COMMIT" {
                assert!(open, "COMMIT outside a table:\n{input}");
                open = false;
            } else {
                assert!(open, "{l} outside a table:\n{input}");
                out.last_mut().unwrap().1.push(l.to_string());
            }
        }
        assert!(!open, "table not committed:\n{input}");
        out
    }

    fn section(input: &str, table: &str) -> Vec<String> {
        sections(input).into_iter().filter(|(t, _)| t == table).flat_map(|(_, l)| l).collect()
    }

    fn v4_script(ports: &[u16]) -> String {
        let sources = ["198.51.100.0/24".to_string()];
        filter_script(Family::V4, Some(&sources), ports, Some(&ingress()), &guard(), &[])
            + &nat_script(Some(&ingress()))
    }

    fn v6_script(ports: &[u16]) -> String {
        filter_script(Family::V6, Some(&["2001:db8:e::/48".to_string()]), ports, None, &guard(), &[])
    }

    /// After a flush, the one restore input recreates `DOCKER-USER` and every jump, each in its table's commit;
    /// with everything in place it is the agent's chains only, and `DOCKER-USER` (the customer's rules) is never
    /// declared while it exists.
    #[test]
    fn apply_script_carries_the_missing_jumps_and_docker_user() {
        let (script, j) = (v4_script(&[20001]), jumps(Family::V4));
        let input = apply_script(&script, &j, &snapshot(FLUSHED, &script, &j));
        let filter = section(&input, "filter");
        let docker_user = filter.iter().position(|l| l == ":DOCKER-USER - [0:0]").expect(&input);
        let inserts =
            |lines: &[String]| -> Vec<String> { lines.iter().filter(|l| l.starts_with("-I ")).cloned().collect() };
        assert_eq!(
            inserts(&filter),
            ["-I FORWARD 1 -j DOCKER-USER", "-I DOCKER-USER 1 -j OWDEPLOY", "-I INPUT 1 -j OWDEPLOY-IN"]
        );
        // Declarations first, the jumps after every rule of the agent's chains.
        let last_decl = filter.iter().rposition(|l| l.starts_with(':')).unwrap();
        let first_insert = filter.iter().position(|l| l.starts_with("-I ")).unwrap();
        assert!(docker_user <= last_decl && filter.iter().rposition(|l| l.starts_with("-A ")).unwrap() < first_insert);
        assert_eq!(
            inserts(&section(&input, "nat")),
            [
                "-I PREROUTING 1 -m addrtype --dst-type LOCAL -j OWDEPLOY-NAT",
                "-I OUTPUT 1 ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j OWDEPLOY-NAT",
            ]
        );
        // The rest is the script as is.
        let rest: String = input
            .lines()
            .filter(|l| !l.starts_with("-I ") && *l != ":DOCKER-USER - [0:0]")
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(rest, script);

        // In place: the chains are replaced, nothing else (an applied but changed rule set, too).
        let healthy = listed(&script, &j);
        assert_eq!(apply_script(&script, &j, &snapshot(&healthy, &script, &j)), script);
        let changed = v4_script(&[20001, 20004]);
        assert_eq!(apply_script(&changed, &j, &snapshot(&healthy, &changed, &j)), changed);
        // A lost jump: inserted again, `DOCKER-USER` left alone.
        let lost = healthy.replace("-A DOCKER-USER -j OWDEPLOY\n", "");
        let input = apply_script(&script, &j, &snapshot(&lost, &script, &j));
        assert!(!input.contains(":DOCKER-USER"), "{input}");
        assert_eq!(inserts(&section(&input, "filter")), ["-I DOCKER-USER 1 -j OWDEPLOY"]);

        // IPv6 has no nat section.
        let (s6, j6) = (v6_script(&[20001]), jumps(Family::V6));
        let input = apply_script(&s6, &j6, &snapshot(FLUSHED, &s6, &j6));
        assert_eq!(sections(&input).iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(), ["filter"]);
        assert!(input.contains(":DOCKER-USER - [0:0]\n") && input.contains("-I INPUT 1 -j OWDEPLOY-IN\n"));
    }

    /// A recorded call: binary, arguments, standard input.
    type Call = (String, Vec<String>, Option<String>);

    /// iptables for the transaction tests: `-S` answered from the host listing of its binary (`before`, then
    /// `after` once a restore of its family went through), each call recorded, the next restore of each entry of
    /// `refuse` (binary, dry run) failing.
    struct Fake {
        hosts: HashMap<&'static str, (String, String)>,
        refuse: std::cell::RefCell<Vec<(&'static str, bool)>>,
        applied: std::cell::RefCell<Vec<String>>,
        calls: std::cell::RefCell<Vec<Call>>,
    }

    impl Fake {
        fn new(v4: (String, String), v6: (String, String), refuse: Vec<(&'static str, bool)>) -> Fake {
            let hosts = HashMap::from([("iptables", v4), ("ip6tables", v6)]);
            Fake { hosts, refuse: refuse.into(), applied: Default::default(), calls: Default::default() }
        }

        /// The inputs of the restores that were not dry runs, with their binary.
        fn restores(&self) -> Vec<(String, String)> {
            let calls = self.calls.borrow();
            calls
                .iter()
                .filter(|(bin, args, _)| bin.ends_with("-restore") && !args.iter().any(|a| a == "--test"))
                .map(|(bin, _, input)| (bin.clone(), input.clone().unwrap_or_default()))
                .collect()
        }
    }

    impl Runner for Fake {
        async fn run(
            &self,
            bin: &str,
            args: &[&str],
            input: Option<&str>,
        ) -> Result<(bool, String, String), std::io::Error> {
            let call = (bin.to_string(), args.iter().map(|a| a.to_string()).collect(), input.map(str::to_string));
            self.calls.borrow_mut().push(call);
            if let Some(list) = bin.strip_suffix("-restore") {
                let test = args.contains(&"--test");
                let mut refuse = self.refuse.borrow_mut();
                if let Some(i) = refuse.iter().position(|r| *r == (bin, test)) {
                    refuse.remove(i);
                    return Ok((false, String::new(), "line 9 failed".into()));
                }
                if !test {
                    self.applied.borrow_mut().push(list.to_string());
                }
                return Ok((true, String::new(), String::new()));
            }
            let (before, after) = &self.hosts[bin];
            let text = if self.applied.borrow().iter().any(|a| a == bin) { after } else { before };
            Ok(match chain_listing(text, args[args.len() - 1]) {
                Some(t) => (true, t, String::new()),
                None => (false, String::new(), "No chain/target/match by that name.".into()),
            })
        }
    }

    fn wants(s4: String, s6: String) -> Vec<Want> {
        vec![
            Want {
                family: Family::V4,
                list: "iptables",
                restore: "iptables-restore",
                script: s4,
                jumps: jumps(Family::V4),
            },
            Want {
                family: Family::V6,
                list: "ip6tables",
                restore: "ip6tables-restore",
                script: s6,
                jumps: jumps(Family::V6),
            },
        ]
    }

    /// IPv6 refuses its input in the dry run: IPv4, although accepted, is not applied either.
    #[tokio::test]
    async fn a_dry_run_refused_in_one_family_applies_nothing() {
        let (s4, s6) = (v4_script(&[20001]), v6_script(&[20001]));
        let fake = Fake::new(
            (FLUSHED.into(), listed(&s4, &jumps(Family::V4))),
            (FLUSHED.into(), listed(&s6, &jumps(Family::V6))),
            vec![("ip6tables-restore", true)],
        );
        let e = transaction(&fake, &wants(s4, s6), true).await.unwrap_err();
        assert!(
            e.starts_with("IPv6 rules refused by the dry run, nothing applied") && e.contains("line 9 failed"),
            "{e}"
        );
        assert_eq!(fake.restores(), []);
        let calls = fake.calls.borrow();
        let tests: Vec<&str> =
            calls.iter().filter(|(b, _, _)| b.ends_with("-restore")).map(|(b, _, _)| b.as_str()).collect();
        assert_eq!(tests, ["iptables-restore", "ip6tables-restore"], "both dry runs, before anything");
    }

    /// IPv6 fails after IPv4 was applied: both are rolled back to their listing from before, IPv4's new jumps
    /// deleted and its previous rules back.
    #[tokio::test]
    async fn a_failed_family_rolls_back_the_applied_ones() {
        let (j4, j6) = (jumps(Family::V4), jumps(Family::V6));
        let (old4, new4) = (v4_script(&[20001]), v4_script(&[20001, 20004]));
        let (old6, new6) = (v6_script(&[20001]), v6_script(&[20001, 20004]));
        // IPv4 had lost two jumps (and has the customer's rule in DOCKER-USER); IPv6 had the previous rules.
        let before4 =
            listed(&old4, &j4).replace("-A DOCKER-USER -j OWDEPLOY\n", "").replace("-A INPUT -j OWDEPLOY-IN\n", "");
        let fake = Fake::new(
            (before4.clone(), listed(&new4, &j4)),
            (listed(&old6, &j6), listed(&new6, &j6)),
            vec![("ip6tables-restore", false)],
        );
        let e = transaction(&fake, &wants(new4.clone(), new6.clone()), true).await.unwrap_err();
        assert_eq!(
            e, "IPv6 rules not applied (ip6tables-restore: line 9 failed); IPv4 and IPv6 rolled back",
            "the error says what failed and that it was undone"
        );
        let restores = fake.restores();
        let bins: Vec<&str> = restores.iter().map(|(b, _)| b.as_str()).collect();
        assert_eq!(bins, ["iptables-restore", "ip6tables-restore", "iptables-restore", "ip6tables-restore"]);
        assert!(
            restores[0].1.contains("-I DOCKER-USER 1 -j OWDEPLOY\n-I INPUT 1 -j OWDEPLOY-IN\n"),
            "{}",
            restores[0].1
        );

        let rollback4 = &restores[2].1;
        let filter = section(rollback4, "filter");
        assert!(
            filter.contains(&"-D DOCKER-USER -j OWDEPLOY".into()) && filter.contains(&"-D INPUT -j OWDEPLOY-IN".into())
        );
        assert!(!rollback4.contains(":DOCKER-USER") && !rollback4.contains("-X ") && !rollback4.contains("20004"));
        for (_, c) in declared(&old4) {
            let rules = |text: &str| -> Vec<String> {
                text.lines().filter(|l| appended(l).is_some_and(|(x, _)| x == c)).map(str::to_string).collect()
            };
            assert!(rollback4.contains(&format!(":{c} - [0:0]\n")), "{c} flushed");
            assert_eq!(rules(rollback4), rules(&before4), "{c} gets its previous rules back");
        }
        let rollback6 = &restores[3].1;
        assert!(
            !rollback6.contains("-D ") && !rollback6.contains("-X ") && !rollback6.contains("20004"),
            "{rollback6}"
        );
        assert!(rollback6.contains("--ctorigdstport 20001 -j OWDEPLOY-SRC"));
    }

    /// The rollback is a pure difference of two listings.
    #[test]
    fn rollback_script_from_before_and_now() {
        let (script, j) = (v4_script(&[20001]), jumps(Family::V4));
        // The change created everything, `DOCKER-USER` too: all of it goes, the built-in chains keep their policy.
        let created = snapshot(&listed(&script, &j), &script, &j);
        assert_eq!(
            rollback_script(&snapshot(FLUSHED, &script, &j), &created, &script, &j),
            "*filter\n:OWDEPLOY - [0:0]\n:OWDEPLOY-SRC - [0:0]\n:OWDEPLOY-EGRESS - [0:0]\n:OWDEPLOY-IN - [0:0]\n\
             :OWDEPLOY-HOST - [0:0]\n:DOCKER-USER - [0:0]\n-D FORWARD -j DOCKER-USER\n-D INPUT -j OWDEPLOY-IN\n\
             -X OWDEPLOY\n-X OWDEPLOY-SRC\n-X OWDEPLOY-EGRESS\n-X OWDEPLOY-IN\n-X OWDEPLOY-HOST\n-X DOCKER-USER\n\
             COMMIT\n*nat\n:OWDEPLOY-NAT - [0:0]\n-D PREROUTING -m addrtype --dst-type LOCAL -j OWDEPLOY-NAT\n\
             -D OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j OWDEPLOY-NAT\n-X OWDEPLOY-NAT\nCOMMIT\n"
        );
        // Nothing there before or now: nothing to do.
        assert_eq!(rollback_script(&snapshot(FLUSHED, &script, &j), &snapshot(FLUSHED, &script, &j), &script, &j), "");

        // Chains that existed: their previous rules, exactly as listed, and nothing deleted; DOCKER-USER untouched.
        let old = listed(&script, &j);
        let new = v4_script(&[20001, 20004]);
        let input = rollback_script(&snapshot(&old, &new, &j), &snapshot(&listed(&new, &j), &new, &j), &new, &j);
        let lines: Vec<String> = sections(&input).into_iter().flat_map(|(_, l)| l).collect();
        assert!(lines.iter().all(|l| l.starts_with(":OWDEPLOY") || l.starts_with("-A OWDEPLOY")), "{input}");
        let added: Vec<&str> = lines.iter().filter(|l| l.starts_with("-A ")).map(String::as_str).collect();
        let mut was: Vec<&str> = old.lines().filter(|l| l.starts_with("-A OWDEPLOY")).collect();
        let mut added_sorted = added.clone();
        added_sorted.sort_unstable();
        was.sort_unstable();
        assert_eq!(added_sorted, was);
        assert!(added.iter().any(|l| l.contains("-p tcp -m tcp --dport 20001")), "as iptables listed them");

        // A jump lost since (someone else's change meanwhile): inserted again at the top.
        let lost = old.replace("-A INPUT -j OWDEPLOY-IN\n", "");
        let input = rollback_script(&snapshot(&old, &script, &j), &snapshot(&lost, &script, &j), &script, &j);
        assert!(input.contains("-I INPUT 1 -j OWDEPLOY-IN\n"), "{input}");
    }

    #[test]
    fn csf_hook_is_added_once() {
        let bin = Path::new("/usr/local/bin/owdeploy-agent");
        let new = csf_hook(None, bin).unwrap();
        assert!(new.starts_with("#!/bin/sh\n# owdeploy-agent"));
        assert!(new.contains("'/usr/local/bin/owdeploy-agent' firewall-repair"));
        assert_eq!(csf_hook(Some(&new), bin), None);
        let theirs = "#!/bin/sh\niptables -A INPUT -s 192.0.2.1 -j ACCEPT";
        let added = csf_hook(Some(theirs), bin).unwrap();
        assert!(added.starts_with(&format!("{theirs}\n# owdeploy-agent")), "{added}");
        assert_eq!(csf_hook(Some(&added), bin), None);
    }
}
