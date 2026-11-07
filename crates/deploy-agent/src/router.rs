//! The per-server router `owd-router`: one Caddy container (pinned official image) that owns the published host
//! ports. Each application keeps its published port, now a Caddy listener that reverse-proxies to the
//! application's current container on the environment network; a Compose application's domains go to
//! `owd-<app>-<service>`; the preview listener routes previews by Host.
//!
//! The agent keeps the desired routes in its state directory (`router.json`) and pushes the whole Caddy
//! configuration when routes change: written to a volume, then loaded through Caddy's admin API, which listens on
//! loopback inside the router's own network namespace only (reached with `docker exec`). The configuration file in
//! the volume is what Caddy starts from, so a restarted router (or server) serves the last configuration.
//!
//! A deployment's switch does not reload Caddy. A reload replaces every HTTP server and closes their idle
//! keep-alive connections, which races with clients sending their next request on them. Instead, each application
//! has two slots: its containers alternate between the aliases `owd-<app>-a` and `owd-<app>-b`, both upstreams of
//! its routes (first available wins), and whether a slot is available is an active health check answered by the
//! router itself from a one-word file in its volume (`up` or `down`). Switching is writing those files: the new slot
//! is available after its next check and the old one unavailable after its second (one failed check, which a reload
//! can cause, never takes a slot out), requests in flight finish on the old one, and no connection is closed. Reloads
//! happen only when routes change (a new application, a domain, a preview).
//!
//! Docker cannot add a published port to a running container, so the router publishes none: the agent routes each
//! listener port to the router's address itself (`firewall`: DNAT from the host's addresses, accepted after the
//! edge-only source check). A new listener (a new application, an application moving from its phase-2 container to
//! the router, the preview listener) is a configuration reload plus one iptables transaction; no listener is
//! interrupted and the router is never recreated for it. A router created before kept the ports Docker published for
//! it (they keep working, and the agent's DNAT takes precedence for them); it loses them the next time it is created
//! (a new Caddy image). Only where Docker runs without its iptables integration (no `DOCKER-USER`, so no agent
//! firewall either) does the router publish its ports through Docker, and a new port recreates it: a short
//! interruption of every listener. On the server itself, the listeners answer on its addresses but not on loopback.
//!
//! Edge TLS (`feature::EDGE_TLS`): an application's TLS listener (its own port) and the preview TLS listener serve
//! HTTPS with OpenWAF Origin CA certificates and accept only connections presenting the OpenWAF edge's client
//! certificate. The control plane sends the certificates and keys (`RouterConfig::tls`); the agent keeps them in its
//! state directory and in the router's volume, where Caddy reads each at handshake time (see [`render`]), so their
//! renewal never reloads the router.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use bollard::Docker;
use bollard::models::{
    ContainerCreateBody, EndpointSettings, HostConfig, HostConfigLogConfig, Mount, MountType, NetworkConnectRequest,
    NetworkingConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum,
};
use bollard::query_parameters::{CreateContainerOptionsBuilder, StopContainerOptionsBuilder};
use deploy_proto::msg::{Route, RouterConfig, RouterState, RouterTls};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::docker::{
    COMPOSE_PROJECT, app_containers, client, ensure_image, is_not_found, message, remove_container, valid_id,
};
use crate::events::Events;
use crate::firewall::Ingress;

/// Caddy, pinned: the router and the static sites' server.
pub const IMAGE: &str = "caddy:2.11.8-alpine";
pub const CONTAINER: &str = "owd-router";
/// Label on the router container.
pub const LABEL_ROUTER: &str = "dev.openwaf.deploy.router";
/// Label with the slot (`a` or `b`) of an application's container.
pub const LABEL_SLOT: &str = "dev.openwaf.deploy.slot";
/// Volume with the router's configuration and slot files.
const VOLUME: &str = "owd-router";
const CONFIG_DIR: &str = "/etc/owd-router";
const CONFIG_FILE: &str = "/etc/owd-router/caddy.json";
const NEXT_FILE: &str = "/etc/owd-router/caddy.next.json";
const SLOTS_DIR: &str = "/etc/owd-router/slots";
const ADMIN: &str = "localhost:2019";
/// The router's own slot health answers, inside its network namespace.
const SLOT_CHECKS: &str = "127.0.0.1:2020";
/// The router's answers with the TLS certificates (Caddy's certificate manager asks it at each handshake).
const CERT_SOURCE: &str = "127.0.0.1:2021";
/// How often Caddy reads the slot files.
const CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// After writing the slot files, the switch has happened once every upstream was checked again: twice, as a slot
/// becomes unavailable after [`CHECK_FAILS`] failed checks.
pub const SWITCH_SETTLE: Duration = Duration::from_millis(3000);
/// Failed checks that make a slot unavailable. Two, so that the one a reload can fail does not: a new configuration
/// checks its slots while it is provisioned, before a slot-check listener it creates opens, and a reload closes the
/// kept-alive check connection of the configuration it replaces. Caddy cancels that configuration's handlers while
/// its servers still answer; a handler with no available slot then answered 503 without waiting for the next check.
/// Caddy's counters start again with every configuration and whenever a slot changes state.
const CHECK_FAILS: u32 = 2;
const STATE_FILE: &str = "router.json";

/// The current upstream of a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Upstream {
    /// The application's container in this slot (`a` or `b`).
    Slot { slot: Slot },
    /// A Compose application: each route's service, by its alias `owd-<resource>-<service>`.
    Compose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn name(self) -> &'static str {
        match self {
            Slot::A => "a",
            Slot::B => "b",
        }
    }

    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    pub fn parse(s: &str) -> Option<Slot> {
        match s {
            "a" => Some(Slot::A),
            "b" => Some(Slot::B),
            _ => None,
        }
    }
}

/// Network alias of an application's container in `slot`.
pub fn slot_alias(resource: &str, slot: Slot) -> String {
    format!("owd-{}-{}", resource.to_ascii_lowercase(), slot.name())
}

/// Compose service alias on the environment network.
pub fn service_alias(resource: &str, service: &str) -> String {
    format!("owd-{}-{service}", resource.to_ascii_lowercase())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Entry {
    routes: Vec<Route>,
    /// Environment network the upstream is on (the router joins it).
    network: Option<String>,
    /// None: not deployed through the router yet; its routes wait.
    upstream: Option<Upstream>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    preview_port: Option<u16>,
    resources: BTreeMap<String, Entry>,
    /// The configuration the router runs, to skip reloads that would change nothing.
    #[serde(default)]
    applied: Option<Value>,
    /// The preview TLS listener (routes with `listen: None` and `tls`).
    #[serde(default)]
    preview_tls_port: Option<u16>,
    /// What the TLS listeners serve and trust; the certificates and keys themselves are files in the router's volume.
    #[serde(default)]
    tls: Option<Tls>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct Tls {
    /// The edge client CA certificates, base64 DER (Caddy's inline trust pool).
    client_ca: Vec<String>,
    certificates: Vec<Cert>,
}

/// A certificate of a TLS listener, without its PEM (in the file [`cert_file`] of its name).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Cert {
    name: String,
    id: String,
    listen: Option<u16>,
    hosts: Vec<String>,
}

impl State {
    fn load() -> Result<State, String> {
        let p = crate::state_dir().join(STATE_FILE);
        match std::fs::read_to_string(&p) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(format!("{}: {e}", p.display())),
        }
    }

    fn save(&self) -> Result<(), String> {
        let dir = crate::state_dir();
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        crate::write_private(&dir.join(STATE_FILE), serde_json::to_string_pretty(self).expect("state").as_bytes())
    }

    fn active(&self) -> impl Iterator<Item = (&String, &Entry, &str, Upstream)> {
        self.resources.iter().filter_map(|(r, e)| Some((r, e, e.network.as_deref()?, e.upstream?)))
    }

    /// Host ports the router must listen on.
    fn ports(&self) -> BTreeSet<u16> {
        let mut p: BTreeSet<u16> =
            self.active().flat_map(|(_, e, _, _)| e.routes.iter().filter_map(|r| r.listen)).collect();
        p.extend(self.preview_port);
        p.extend(self.preview_tls_port);
        p
    }

    /// The names a TLS listener (`listen`; None: the preview TLS listener) serves, when it can be opened: it has
    /// certificates and the CA of the client certificates it requires. None: it stays closed.
    fn tls_hosts(&self, listen: Option<u16>) -> Option<Vec<String>> {
        let tls = self.tls.as_ref().filter(|t| !t.client_ca.is_empty())?;
        let hosts: Vec<String> =
            tls.certificates.iter().filter(|c| c.listen == listen).flat_map(|c| c.hosts.iter().cloned()).collect();
        (!hosts.is_empty()).then_some(hosts)
    }
}

/// The file of a certificate (chain then key) in the router's volume.
fn cert_file(name: &str) -> String {
    format!("{CONFIG_DIR}/tls-{name}.pem")
}

/// Every router change goes through this lock: deployments of different applications switch one at a time. The
/// firewall takes it too, as its rules follow the router's listeners.
pub(crate) static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

/// A certificate name: exact host names or one-level wildcards (`*.example.com`).
fn cert_host_ok(h: &str) -> bool {
    host_ok(h.strip_prefix("*.").unwrap_or(h))
}

/// Checks routes and normalizes their hosts (lowercase, no trailing dot). The routes of one listener are all TLS or
/// all plain.
pub fn normalize(routes: &[Route]) -> Result<Vec<Route>, String> {
    let mut out = Vec::with_capacity(routes.len());
    let mut seen = BTreeSet::new();
    let mut kinds = BTreeMap::new();
    for r in routes {
        if r.port == 0 || r.listen == Some(0) {
            return Err("invalid route port".into());
        }
        if r.listen.is_none() && r.hosts.is_empty() {
            return Err("a route on the preview listener needs its hosts".into());
        }
        if r.service.as_deref().is_some_and(|s| !valid_id(s)) {
            return Err(format!("invalid service {:?}", r.service.as_deref().unwrap_or_default()));
        }
        if r.listen.is_some() && *kinds.entry(r.listen).or_insert(r.tls) != r.tls {
            return Err(format!("listener {} has both TLS and plain routes", r.listen.unwrap_or_default()));
        }
        let mut hosts = Vec::new();
        for h in &r.hosts {
            let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
            if !host_ok(&h) {
                return Err(format!("invalid host {h:?}"));
            }
            if !seen.insert((r.listen, r.tls, Some(h.clone()))) {
                return Err(format!("host {h} is routed twice"));
            }
            hosts.push(h);
        }
        if hosts.is_empty() && !seen.insert((r.listen, r.tls, None)) {
            return Err(format!("listener {} has two default routes", r.listen.unwrap_or_default()));
        }
        out.push(Route { listen: r.listen, hosts, service: r.service.clone(), port: r.port, tls: r.tls });
    }
    Ok(out)
}

/// Refuses a listener port or a preview host claimed by two resources, a port with both TLS and plain routes, a
/// preview port that is also a listener, or a name served by two certificates.
fn check_conflicts(s: &State) -> Result<(), String> {
    let mut owners: HashMap<(Option<u16>, bool, Option<&str>), &str> = HashMap::new();
    let mut kinds: HashMap<u16, bool> = HashMap::new();
    for (res, e) in &s.resources {
        for r in &e.routes {
            let keys: Vec<(Option<u16>, bool, Option<&str>)> = match r.listen {
                Some(p) => {
                    if *kinds.entry(p).or_insert(r.tls) != r.tls {
                        return Err(format!("port {p} has both TLS and plain routes"));
                    }
                    vec![(Some(p), false, None)]
                }
                None => r.hosts.iter().map(|h| (None, r.tls, Some(h.as_str()))).collect(),
            };
            for k in keys {
                if let Some(other) = owners.insert(k, res)
                    && other != res
                {
                    return Err(match k {
                        (Some(p), _, _) => format!("port {p} is routed to both {other} and {res}"),
                        (_, _, h) => {
                            format!("preview host {} is routed to both {other} and {res}", h.unwrap_or_default())
                        }
                    });
                }
            }
        }
    }
    for p in [s.preview_port, s.preview_tls_port].into_iter().flatten() {
        if let Some(owner) = owners.get(&(Some(p), false, None)) {
            return Err(format!("the preview port {p} is also the port of {owner}"));
        }
    }
    if s.preview_port.is_some() && s.preview_port == s.preview_tls_port {
        return Err("the preview listener and the preview TLS listener need two ports".into());
    }
    let mut names = HashMap::new();
    for c in s.tls.iter().flat_map(|t| &t.certificates) {
        for h in &c.hosts {
            if let Some(other) = names.insert(h.as_str(), c.name.as_str()) {
                return Err(format!("{h} is in two certificates ({other} and {})", c.name));
            }
        }
    }
    Ok(())
}

fn proxy(resource: &str, up: Upstream, r: &Route) -> Option<Value> {
    // A dial that fails (an upstream restarting) is retried for a while instead of answering 502 at once.
    let lb =
        |policy: &str| json!({"selection_policy": {"policy": policy}, "try_duration": "5s", "try_interval": "250ms"});
    Some(match (up, r.service.as_deref()) {
        (Upstream::Compose, Some(svc)) => json!({
            "handler": "reverse_proxy",
            "headers": {"response": {"delete": ["Server"]}},
            "upstreams": [{"dial": format!("{}:{}", service_alias(resource, svc), r.port)}],
            "load_balancing": lb("first"),
        }),
        // A Compose route without its service has nowhere to go.
        (Upstream::Compose, None) => return None,
        (Upstream::Slot { .. }, _) => json!({
            "handler": "reverse_proxy",
            "headers": {"response": {"delete": ["Server"]}},
            "upstreams": [
                {"dial": format!("{}:{}", slot_alias(resource, Slot::A), r.port)},
                {"dial": format!("{}:{}", slot_alias(resource, Slot::B), r.port)},
            ],
            "load_balancing": lb("first"),
            // The slot's availability, from the router's own answer for it (see the module documentation).
            "health_checks": {"active": {
                "upstream": SLOT_CHECKS,
                "uri": "/",
                "headers": {"Host": ["{http.reverse_proxy.active.target_upstream}"]},
                "interval": format!("{}ms", CHECK_INTERVAL.as_millis()),
                "timeout": "2s",
                "passes": 1,
                "fails": CHECK_FAILS,
                "expect_body": "^up$",
            }},
        }),
    })
}

/// Removes the `Via: 1.1 Caddy` that `reverse_proxy` adds to every response it proxies. Its own response header
/// operations act on the upstream's headers before that one is added (they remove the application's `Server`), so
/// only a deferred operation of a `headers` handler, applied as the response is written, removes it.
fn hide_via() -> Value {
    json!({"handler": "headers", "response": {"delete": ["Via"], "deferred": true}})
}

/// Compression of what the application sends uncompressed, as the previous platform's default did: gzip of
/// text, JSON, XML, JavaScript, SVG, fonts and WebAssembly from 512 bytes. Only gzip: the OpenWAF edge asks origins
/// for `br, gzip` and reads the bodies it scans, so zstd would gain nothing there. Responses that already carry a
/// Content-Encoding pass untouched, and `text/event-stream` is not in the list, so server-sent events keep streaming.
fn encode() -> Value {
    json!({
        "handler": "encode",
        "encodings": {"gzip": {}},
        "minimum_length": 512,
        "match": {"headers": {"Content-Type": [
            "text/html*", "text/css*", "text/plain*", "text/xml*", "text/javascript*", "text/csv*", "text/markdown*",
            "text/calendar*", "application/javascript*", "application/json*", "application/ld+json*",
            "application/manifest+json*", "application/xml*", "application/rss+xml*", "application/atom+xml*",
            "application/xhtml+xml*", "application/wasm*", "image/svg+xml*", "image/x-icon*", "font/ttf*", "font/otf*",
            "application/vnd.ms-fontobject*",
        ]}},
    })
}

/// A listener of the rendered configuration: an application's port, or the preview listener (plain or TLS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Listener {
    Port(u16),
    Preview,
    PreviewTls,
}

impl Listener {
    fn of(r: &Route) -> Listener {
        match (r.listen, r.tls) {
            (Some(p), _) => Listener::Port(p),
            (None, false) => Listener::Preview,
            (None, true) => Listener::PreviewTls,
        }
    }
}

/// Ports of the active routes that are TLS listeners.
fn tls_ports(s: &State) -> BTreeSet<u16> {
    s.active().flat_map(|(_, e, _, _)| e.routes.iter().filter(|r| r.tls).filter_map(|r| r.listen)).collect()
}

/// The TLS listeners the configuration opens (those with certificates and the client CA), by port.
fn tls_listeners(s: &State) -> BTreeSet<u16> {
    let mut out: BTreeSet<u16> = tls_ports(s).into_iter().filter(|p| s.tls_hosts(Some(*p)).is_some()).collect();
    out.extend(s.preview_tls_port.filter(|_| s.tls_hosts(None).is_some()));
    out
}

/// The Caddy configuration of the active routes.
///
/// A TLS listener serves the OpenWAF Origin CA certificates of its names and accepts only connections presenting a
/// client certificate of the OpenWAF Edge Client CA (with strict SNI-Host matching, which Caddy enables with client
/// authentication); plain HTTP on it fails the handshake. Caddy gets each certificate at handshake time from the
/// router itself (the `certs` server answers the file of the certificate's name, as the slot checks do), so a
/// renewal is a file replaced by a rename: no reload, no connection closed.
fn render(s: &State) -> Value {
    // Per listener: (host routes, default route).
    let mut listeners: BTreeMap<Listener, (Vec<Value>, Option<Value>)> = BTreeMap::new();
    if s.preview_port.is_some() {
        listeners.entry(Listener::Preview).or_default();
    }
    if s.preview_tls_port.is_some() && s.tls_hosts(None).is_some() {
        listeners.entry(Listener::PreviewTls).or_default();
    }
    let mut slot_checks = Vec::new();
    for (res, e, _, up) in s.active() {
        if matches!(up, Upstream::Slot { .. }) {
            for slot in [Slot::A, Slot::B] {
                let alias = slot_alias(res, slot);
                slot_checks.push(json!({
                    "match": [{"host": [alias]}],
                    "handle": [{"handler": "static_response", "body": format!("{{file.{SLOTS_DIR}/{alias}}}")}],
                    "terminal": true,
                }));
            }
        }
        for r in &e.routes {
            let Some(handler) = proxy(res, up, r) else { continue };
            let l = listeners.entry(Listener::of(r)).or_default();
            if r.hosts.is_empty() {
                l.1 = Some(json!({"handle": [hide_via(), encode(), handler], "terminal": true}));
            } else {
                l.0.push(
                    json!({"match": [{"host": r.hosts}], "handle": [hide_via(), encode(), handler], "terminal": true}),
                );
            }
        }
    }
    let tls = s.tls.as_ref();
    let tls_ports = tls_ports(s);
    let mut servers = serde_json::Map::new();
    for (listener, (mut routes, default)) in listeners {
        let (name, port, tls_hosts) = match listener {
            Listener::Port(p) if tls_ports.contains(&p) => match s.tls_hosts(Some(p)) {
                Some(hosts) => (format!("port-{p}"), p, Some(hosts)),
                // No certificate or no client CA: the listener stays closed rather than open without either.
                None => continue,
            },
            Listener::Port(p) => (format!("port-{p}"), p, None),
            Listener::Preview => match s.preview_port {
                Some(p) => ("preview".to_string(), p, None),
                None => continue,
            },
            Listener::PreviewTls => match (s.preview_tls_port, s.tls_hosts(None)) {
                (Some(p), Some(hosts)) => ("preview-tls".to_string(), p, Some(hosts)),
                _ => continue,
            },
        };
        routes.push(default.unwrap_or_else(|| json!({"handle": [{"handler": "static_response", "status_code": 404}]})));
        let mut server = json!({
            "listen": [format!(":{port}")],
            "routes": routes,
            // The edge terminates the visitors' TLS; Caddy must never try to get certificates for the routed hosts.
            "automatic_https": {"disable": true},
            // Only the OpenWAF edge reaches these ports (firewall), so its X-Forwarded-For is kept and the
            // application sees the real client, as it did when it published its port itself.
            "trusted_proxies": {"source": "static", "ranges": ["0.0.0.0/0", "::/0"]},
        });
        if let (Some(hosts), Some(tls)) = (tls_hosts, tls) {
            server["tls_connection_policies"] = json!([{
                "match": {"sni": hosts},
                "protocol_min": "tls1.2",
                "client_authentication": {
                    "ca": {"provider": "inline", "trusted_ca_certs": tls.client_ca},
                    "mode": "require_and_verify",
                },
            }]);
            // The edge speaks HTTP/1.1 or HTTP/2 over TCP; no QUIC listener (the firewall routes TCP only).
            server["protocols"] = json!(["h1", "h2"]);
        }
        servers.insert(name, server);
    }
    if !slot_checks.is_empty() {
        slot_checks.push(json!({"handle": [{"handler": "static_response", "body": "down"}]}));
        servers.insert(
            "slots".into(),
            json!({"listen": [SLOT_CHECKS], "routes": slot_checks, "automatic_https": {"disable": true}}),
        );
    }
    let mut apps = json!({"http": {"servers": servers}});
    let certs: Vec<&Cert> =
        tls.filter(|t| !t.client_ca.is_empty()).map(|t| t.certificates.iter().collect()).unwrap_or_default();
    if !certs.is_empty() {
        let mut sources: Vec<Value> = certs
            .iter()
            .map(|c| {
                json!({
                    "match": [{"path": [format!("/{}", c.name)]}],
                    "handle": [{"handler": "static_response", "body": format!("{{file.{}}}", cert_file(&c.name))}],
                    "terminal": true,
                })
            })
            .collect();
        sources.push(json!({"handle": [{"handler": "static_response", "status_code": 404}]}));
        apps["http"]["servers"]["certs"] =
            json!({"listen": [CERT_SOURCE], "routes": sources, "automatic_https": {"disable": true}});
        let policies: Vec<Value> = certs
            .iter()
            .map(|c| {
                json!({
                    "subjects": c.hosts,
                    "get_certificate": [{"via": "http", "url": format!("http://{CERT_SOURCE}/{}", c.name)}],
                })
            })
            .collect();
        apps["tls"] = json!({"automation": {"policies": policies}});
    }
    json!({
        "admin": {"listen": ADMIN, "config": {"persist": false}},
        "logging": {"logs": {"default": {"level": "WARN"}}},
        "apps": apps,
    })
}

/// Host ports the router container publishes.
fn bound_ports(c: &bollard::models::ContainerInspectResponse) -> BTreeSet<u16> {
    c.host_config
        .as_ref()
        .and_then(|h| h.port_bindings.as_ref())
        .map(|b| b.keys().filter_map(|k| k.strip_suffix("/tcp")?.parse().ok()).collect())
        .unwrap_or_default()
}

/// The router's IPv4 address: on the network it was created on, else the first of its networks with one.
fn router_ip(c: &bollard::models::ContainerInspectResponse) -> Option<std::net::Ipv4Addr> {
    let nets = c.network_settings.as_ref()?.networks.as_ref()?;
    let ip = |n: &EndpointSettings| n.ip_address.as_deref().and_then(|a| a.parse().ok());
    let primary = c.host_config.as_ref().and_then(|h| h.network_mode.as_deref()).and_then(|m| nets.get(m));
    primary.and_then(ip).or_else(|| {
        let mut names: Vec<&String> = nets.keys().collect();
        names.sort();
        names.into_iter().find_map(|n| ip(&nets[n]))
    })
}

/// What the firewall routes to the running router: its address and listener ports.
async fn ingress_of(d: &Docker, s: &State) -> Result<Option<Ingress>, String> {
    let ports = s.ports();
    if ports.is_empty() {
        return Ok(None);
    }
    let c = match d.inspect_container(CONTAINER, None).await {
        Ok(c) => c,
        Err(e) if is_not_found(&e) => return Ok(None),
        Err(e) => return Err(format!("inspect the router: {}", message(&e))),
    };
    if c.state.as_ref().and_then(|s| s.running) != Some(true) {
        return Ok(None);
    }
    Ok(router_ip(&c).map(|ip| Ingress { ip, ports: ports.into_iter().collect() }))
}

/// [`ingress_of`] the saved state. The caller holds [`LOCK`].
pub(crate) async fn ingress() -> Result<Option<Ingress>, String> {
    let s = State::load()?;
    if s.ports().is_empty() {
        return Ok(None);
    }
    ingress_of(&client()?, &s).await
}

/// What becomes of the router container.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Create,
    Reuse,
    /// Stop it and create it again: an interruption of every listener.
    Recreate,
}

/// `existing`: the router's image and the ports Docker publishes for it. `routed`: the agent routes the listeners
/// itself (iptables available), so ports never force a recreation.
fn plan(existing: Option<(&str, &BTreeSet<u16>)>, ports: &BTreeSet<u16>, routed: bool) -> Plan {
    match existing {
        None => Plan::Create,
        Some((image, _)) if image != IMAGE => Plan::Recreate,
        Some((_, bound)) if routed || bound.is_superset(ports) => Plan::Reuse,
        Some(_) => Plan::Recreate,
    }
}

/// Creates the router; `publish`: Docker publishes the listener ports (no agent routing).
async fn create(d: &Docker, ports: &BTreeSet<u16>, networks: &BTreeSet<String>, publish: bool) -> Result<(), String> {
    let first = networks.iter().next().cloned().unwrap_or_else(|| "bridge".into());
    let published = if publish { ports.clone() } else { BTreeSet::new() };
    let bindings: HashMap<String, Option<Vec<PortBinding>>> = published
        .iter()
        .map(|p| {
            let b = PortBinding { host_ip: Some("0.0.0.0".into()), host_port: Some(p.to_string()) };
            (format!("{p}/tcp"), Some(vec![b]))
        })
        .collect();
    let body = ContainerCreateBody {
        image: Some(IMAGE.into()),
        cmd: Some(vec!["caddy".into(), "run".into(), "--config".into(), CONFIG_FILE.into()]),
        labels: Some(HashMap::from([(LABEL_ROUTER.to_string(), "1".to_string())])),
        exposed_ports: Some(published.iter().map(|p| format!("{p}/tcp")).collect()),
        host_config: Some(HostConfig {
            port_bindings: Some(bindings),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
                maximum_retry_count: None,
            }),
            mounts: Some(vec![Mount {
                typ: Some(MountType::VOLUME),
                source: Some(VOLUME.into()),
                target: Some(CONFIG_DIR.into()),
                ..Default::default()
            }]),
            log_config: Some(HostConfigLogConfig {
                typ: Some("json-file".into()),
                config: Some(HashMap::from([
                    ("max-size".to_string(), "20m".to_string()),
                    ("max-file".to_string(), "3".to_string()),
                ])),
            }),
            network_mode: Some(first.clone()),
            ..Default::default()
        }),
        networking_config: Some(NetworkingConfig {
            endpoints_config: Some(HashMap::from([(first.clone(), EndpointSettings::default())])),
        }),
        ..Default::default()
    };
    let opts = CreateContainerOptionsBuilder::default().name(CONTAINER).build();
    d.create_container(Some(opts), body).await.map_err(|e| format!("create the router: {}", message(&e)))?;
    for n in networks.iter().filter(|n| **n != first) {
        connect(d, n).await?;
    }
    Ok(())
}

async fn connect(d: &Docker, network: &str) -> Result<(), String> {
    let req = NetworkConnectRequest { container: CONTAINER.into(), endpoint_config: None };
    match d.connect_network(network, req).await {
        Ok(()) => Ok(()),
        // Already connected.
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 403 | 409, .. }) => Ok(()),
        Err(e) => Err(format!("connect the router to {network}: {}", message(&e))),
    }
}

/// Runs a command in the router; Err with its output when it fails.
async fn router_exec(d: &Docker, cmd: &[&str]) -> Result<(), String> {
    let mut r = crate::exec::start(d, CONTAINER, cmd.iter().map(|s| s.to_string()).collect(), Vec::new(), None).await?;
    let mut out = Vec::new();
    while let Some(item) = r.next().await {
        out.extend_from_slice(&item?.1);
    }
    match r.exit_code(d).await? {
        Some(0) => Ok(()),
        code => {
            let text = String::from_utf8_lossy(&out);
            let last = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or_default();
            Err(format!("{} failed (exit code {}): {}", cmd.join(" "), code.unwrap_or(-1), last.trim()))
        }
    }
}

async fn write_config(d: &Docker, path: &str, config: &Value) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(config).expect("config");
    let name = path.strip_prefix(CONFIG_DIR).unwrap_or(path).trim_start_matches('/');
    crate::docker::upload(d, CONTAINER, CONFIG_DIR, &[crate::docker::File { path: name, data: &text, mode: 0o600 }])
        .await
}

/// Marks `up` available and `down` not, in one step: each file is replaced by a rename, so a check never reads a
/// half-written file.
async fn write_slots(d: &Docker, up: &str, down: &str) -> Result<(), String> {
    const SCRIPT: &str = r#"set -eu
mkdir -p "$0"
printf up > "$0/$1.tmp"
printf down > "$0/$2.tmp"
mv -f "$0/$1.tmp" "$0/$1"
mv -f "$0/$2.tmp" "$0/$2"
"#;
    router_exec(d, &["sh", "-c", SCRIPT, SLOTS_DIR, up, down]).await
}

/// Waits until Caddy's admin API answers (a fresh router), up to 15 s.
async fn wait_ready(d: &Docker) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let c =
            d.inspect_container(CONTAINER, None).await.map_err(|e| format!("inspect the router: {}", message(&e)))?;
        if c.state.as_ref().and_then(|s| s.running) != Some(true) {
            return Err(format!("the router stopped: {}", router_log_tail(d).await));
        }
        match router_exec(d, &["caddy", "reload", "--config", CONFIG_FILE, "--address", ADMIN]).await {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(format!("the router does not answer: {last}"))
}

async fn router_log_tail(d: &Docker) -> String {
    use futures_util::StreamExt;
    let opts = bollard::query_parameters::LogsOptionsBuilder::default().stdout(true).stderr(true).tail("5").build();
    let mut s = d.logs(CONTAINER, Some(opts));
    let mut text = String::new();
    while let Some(Ok(o)) = s.next().await {
        text.push_str(&String::from_utf8_lossy(&o.into_bytes()));
    }
    text.trim().replace('\n', " | ")
}

/// Brings the router container and its configuration to `s` (and records what it applied in `s`), then the
/// firewall's routing of its listeners.
async fn apply(d: &Docker, s: &mut State, ev: Option<&Events>) -> Result<(), String> {
    let routed = crate::firewall::available().await;
    apply_router(d, s, ev, routed).await?;
    if routed {
        let ingress = ingress_of(d, s).await?;
        let rules = crate::firewall::saved_rules()?;
        crate::firewall::apply_locked(rules.as_ref(), ingress.as_ref()).await.map_err(|e| format!("firewall: {e}"))?;
    }
    Ok(())
}

async fn apply_router(d: &Docker, s: &mut State, ev: Option<&Events>, routed: bool) -> Result<(), String> {
    let ports = s.ports();
    let networks: BTreeSet<String> = s.active().map(|(_, _, n, _)| n.to_string()).collect();
    let config = render(s);
    let existing = match d.inspect_container(CONTAINER, None).await {
        Ok(c) => Some(c),
        Err(e) if is_not_found(&e) => None,
        Err(e) => return Err(format!("inspect the router: {}", message(&e))),
    };
    if existing.is_none() && ports.is_empty() && networks.is_empty() {
        // Nothing routed yet: no router needed.
        s.applied = None;
        return Ok(());
    }
    let bound = existing.as_ref().map(bound_ports).unwrap_or_default();
    let image = existing.as_ref().and_then(|c| c.config.as_ref()?.image.as_deref());
    let plan = plan(existing.as_ref().map(|_| (image.unwrap_or_default(), &bound)), &ports, routed);
    if plan == Plan::Reuse {
        let running = existing.as_ref().and_then(|c| c.state.as_ref()).and_then(|s| s.running) == Some(true);
        if !running {
            d.start_container(CONTAINER, None).await.map_err(|e| format!("start the router: {}", message(&e)))?;
            wait_ready(d).await?;
        }
        for n in &networks {
            connect(d, n).await?;
        }
        if running && s.applied.as_ref() == Some(&config) {
            return Ok(());
        }
        // Loaded from a second file first: a configuration Caddy refuses never becomes the one it starts from.
        write_config(d, NEXT_FILE, &config).await?;
        router_exec(d, &["caddy", "reload", "--config", NEXT_FILE, "--address", ADMIN]).await?;
        router_exec(d, &["mv", "-f", NEXT_FILE, CONFIG_FILE]).await?;
        s.applied = Some(config);
        return Ok(());
    }
    ensure_image(d, IMAGE, ev).await?;
    if plan == Plan::Recreate {
        if let Some(ev) = ev {
            let list: Vec<String> = ports.iter().map(u16::to_string).collect();
            ev.system(format!("Restarting the router to listen on ports {}", list.join(", "))).await;
        }
        let opts = StopContainerOptionsBuilder::default().t(10).build();
        match d.stop_container(CONTAINER, Some(opts)).await {
            Ok(()) => {}
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(format!("stop the router: {}", message(&e))),
        }
        remove_container(d, CONTAINER).await?;
    }
    create(d, &ports, &networks, !routed).await?;
    write_config(d, CONFIG_FILE, &config).await?;
    upload_certs(d, s, false).await?;
    if let Err(e) = d.start_container(CONTAINER, None).await {
        return Err(format!("start the router: {}", message(&e)));
    }
    wait_ready(d).await?;
    s.applied = Some(config);
    Ok(())
}

/// Points `resource`'s routes at `upstream` (a deployment's switch). With a slot, the new slot takes new requests
/// within [`SWITCH_SETTLE`] of the return; the previous one finishes those it has.
pub async fn switch(
    d: &Docker,
    resource: &str,
    network: &str,
    upstream: Upstream,
    routes: Vec<Route>,
    ev: Option<&Events>,
) -> Result<(), String> {
    let routes = normalize(&routes)?;
    let _g = LOCK.lock().await;
    let mut s = State::load()?;
    let e = s.resources.entry(resource.to_string()).or_default();
    e.routes = routes;
    e.network = Some(network.to_string());
    e.upstream = Some(upstream);
    check_conflicts(&s)?;
    if let Upstream::Slot { slot } = upstream {
        // The slot files go first when the router runs (the configuration may already name the slots); a new
        // router gets them right after its start, before any request reaches it.
        let running = d.inspect_container(CONTAINER, None).await.ok().and_then(|c| c.state?.running) == Some(true);
        if running {
            write_slots(d, &slot_alias(resource, slot), &slot_alias(resource, slot.other())).await?;
        }
        apply(d, &mut s, ev).await?;
        if !running {
            write_slots(d, &slot_alias(resource, slot), &slot_alias(resource, slot.other())).await?;
        }
    } else {
        apply(d, &mut s, ev).await?;
    }
    s.save()
}

/// Drops a removed application's routes.
pub async fn forget(resource: &str) -> Result<(), String> {
    let _g = LOCK.lock().await;
    let mut s = State::load()?;
    if s.resources.remove(resource).is_none() {
        return Ok(());
    }
    let d = client()?;
    apply(&d, &mut s, None).await?;
    if s.applied.is_some() {
        let files: Vec<String> =
            [Slot::A, Slot::B].iter().map(|x| format!("{SLOTS_DIR}/{}", slot_alias(resource, *x))).collect();
        router_exec(&d, &["rm", "-f", &files[0], &files[1]]).await?;
    }
    s.save()
}

/// The upstream of a resource deployed before the agent kept (or lost) its router state: its newest running
/// container in a slot (one without is a phase-2 container publishing its port itself, routed after its next
/// deployment), or its Compose project; with the environment network it is on (`owd-…`, not a Compose network).
async fn discover(d: &Docker, resource: &str) -> Result<Option<(String, Upstream)>, String> {
    for c in app_containers(d, resource).await? {
        if !crate::docker::is_running(&c) {
            continue;
        }
        let labels = c.labels.clone().unwrap_or_default();
        let up = match (labels.contains_key(COMPOSE_PROJECT), labels.get(LABEL_SLOT).and_then(|s| Slot::parse(s))) {
            (true, _) => Upstream::Compose,
            (false, Some(slot)) => Upstream::Slot { slot },
            (false, None) => return Ok(None),
        };
        let network = c
            .network_settings
            .as_ref()
            .and_then(|n| n.networks.as_ref())
            .and_then(|n| n.keys().find(|k| k.starts_with("owd-") && !k.contains('_')).cloned());
        let Some(network) = network else { continue };
        return Ok(Some((network, up)));
    }
    Ok(None)
}

/// Where the agent keeps the certificates of the TLS listeners (chain and key, mode 0600), to put them in the router's
/// volume again whenever the router is created.
fn tls_dir() -> std::path::PathBuf {
    crate::state_dir().join("router-tls")
}

const BEGIN_CERT: &str = "-----BEGIN CERTIFICATE-----";
const END_CERT: &str = "-----END CERTIFICATE-----";

/// The certificates of a PEM bundle as base64 DER (what Caddy's inline trust pool takes).
fn ca_der(pem: &str) -> Result<Vec<String>, String> {
    use base64::Engine;
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(i) = rest.find(BEGIN_CERT) {
        let body = &rest[i + BEGIN_CERT.len()..];
        let end = body.find(END_CERT).ok_or("the client CA has an unterminated certificate")?;
        let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|_| "the client CA has a certificate that is not base64".to_string())?;
        out.push(b64);
        rest = &body[end + END_CERT.len()..];
    }
    if out.is_empty() {
        return Err("the client CA has no certificate".into());
    }
    Ok(out)
}

/// Checks the TLS material of a `RouterSync`: what the state keeps, and each certificate's file content.
fn take_tls(t: &RouterTls) -> Result<(Tls, Vec<(String, String)>), String> {
    let client_ca = ca_der(&t.client_ca_pem)?;
    let (mut certificates, mut pems, mut names) = (Vec::new(), Vec::new(), BTreeSet::new());
    for c in &t.certificates {
        let safe = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
        if c.name.is_empty() || c.name.len() > 100 || !c.name.bytes().all(safe) {
            return Err(format!("invalid certificate name {:?}", c.name));
        }
        if !names.insert(c.name.as_str()) {
            return Err(format!("certificate {} is listed twice", c.name));
        }
        if c.listen == Some(0) {
            return Err("invalid certificate listener".into());
        }
        let hosts: Vec<String> = c.hosts.iter().map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase()).collect();
        if hosts.is_empty() || !hosts.iter().all(|h| cert_host_ok(h)) {
            return Err(format!("invalid names in certificate {}", c.name));
        }
        if !c.cert_pem.contains(BEGIN_CERT) || !c.key_pem.contains("PRIVATE KEY-----") {
            return Err(format!("certificate {} needs its PEM chain and key", c.name));
        }
        pems.push((c.name.clone(), format!("{}\n{}\n", c.cert_pem.trim(), c.key_pem.trim())));
        certificates.push(Cert { name: c.name.clone(), id: c.id.clone(), listen: c.listen, hosts });
    }
    Ok((Tls { client_ca, certificates }, pems))
}

/// Keeps exactly `pems` in [`tls_dir`].
fn save_pems(pems: &[(String, String)]) -> Result<(), String> {
    let dir = tls_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (name, pem) in pems {
        crate::write_private(&dir.join(format!("{name}.pem")), pem.as_bytes())?;
    }
    for e in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?.flatten() {
        let file = e.file_name().to_string_lossy().into_owned();
        if !pems.iter().any(|(n, _)| format!("{n}.pem") == file) {
            let _ = std::fs::remove_file(e.path());
        }
    }
    Ok(())
}

/// Puts the certificates of `s` in the router's volume and removes those no longer listed. A running router gets each
/// one replaced by a rename (a handshake never reads half a file); a stopped or new one gets them written directly.
async fn upload_certs(d: &Docker, s: &State, running: bool) -> Result<(), String> {
    let certs = s.tls.as_ref().map(|t| t.certificates.as_slice()).unwrap_or_default();
    let mut files = Vec::with_capacity(certs.len());
    for c in certs {
        let p = tls_dir().join(format!("{}.pem", c.name));
        let pem = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let path = if running { format!(".tls-{}.tmp", c.name) } else { format!("tls-{}.pem", c.name) };
        files.push((path, pem));
    }
    if !files.is_empty() {
        let list: Vec<crate::docker::File> =
            files.iter().map(|(path, data)| crate::docker::File { path, data, mode: 0o600 }).collect();
        crate::docker::upload(d, CONTAINER, CONFIG_DIR, &list).await?;
    }
    if running {
        const SCRIPT: &str = r#"set -eu
d=$0
for n; do mv -f "$d/.tls-$n.tmp" "$d/tls-$n.pem"; done
for f in "$d"/tls-*.pem; do
  [ -e "$f" ] || continue
  b=${f##*/tls-}; b=${b%.pem}; keep=0
  for n; do [ "$n" = "$b" ] && keep=1; done
  [ "$keep" = 1 ] || rm -f "$f"
done
"#;
        let mut cmd = vec!["sh", "-c", SCRIPT, CONFIG_DIR];
        cmd.extend(certs.iter().map(|c| c.name.as_str()));
        router_exec(d, &cmd).await?;
    }
    Ok(())
}

/// `RouterSync`: the whole route table from the control plane.
pub async fn sync(cfg: &RouterConfig) -> Result<RouterState, String> {
    if cfg.preview_port == Some(0) || cfg.preview_tls_port == Some(0) {
        return Err("invalid preview port".into());
    }
    let mut wanted = BTreeMap::new();
    for r in &cfg.resources {
        if !valid_id(&r.resource) {
            return Err(format!("invalid resource id {:?}", r.resource));
        }
        if wanted.insert(r.resource.clone(), normalize(&r.routes)?).is_some() {
            return Err(format!("{} is listed twice", r.resource));
        }
    }
    let (tls, pems) = match &cfg.tls {
        Some(t) => take_tls(t).map(|(tls, pems)| (Some(tls), pems))?,
        None => (None, Vec::new()),
    };
    let d = client()?;
    let _g = LOCK.lock().await;
    let mut s = State::load()?;
    let mut next = State {
        preview_port: cfg.preview_port,
        resources: BTreeMap::new(),
        applied: s.applied.take(),
        preview_tls_port: cfg.preview_tls_port,
        tls,
    };
    let mut discovered = Vec::new();
    for (res, routes) in wanted {
        let mut e = s.resources.remove(&res).unwrap_or_default();
        e.routes = routes;
        if e.upstream.is_none()
            && let Some((network, up)) = discover(&d, &res).await?
        {
            e.network = Some(network);
            e.upstream = Some(up);
            discovered.push((res.clone(), up));
        }
        next.resources.insert(res, e);
    }
    check_conflicts(&next)?;
    // The certificates go first, so a listener the reload opens serves them at once; a renewal is only this step.
    save_pems(&pems)?;
    match d.inspect_container(CONTAINER, None).await {
        Ok(c) => upload_certs(&d, &next, c.state.and_then(|s| s.running) == Some(true)).await?,
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(format!("inspect the router: {}", message(&e))),
    }
    apply(&d, &mut next, None).await?;
    for (res, up) in discovered {
        if let Upstream::Slot { slot } = up {
            write_slots(&d, &slot_alias(&res, slot), &slot_alias(&res, slot.other())).await?;
        }
    }
    next.save()?;
    let tls_listeners: Vec<u16> = tls_listeners(&next).into_iter().collect();
    let certificates = match (&next.tls, next.applied.is_some()) {
        (Some(t), true) => t.certificates.iter().map(|c| c.id.clone()).collect(),
        _ => Vec::new(),
    };
    let mut st = RouterState {
        listeners: next.ports().into_iter().collect(),
        tls_listeners,
        certificates,
        ..Default::default()
    };
    for (r, e) in &next.resources {
        match e.upstream.is_some() && e.network.is_some() {
            true => st.active.push(r.clone()),
            false => st.pending.push(r.clone()),
        }
    }
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(listen: Option<u16>, hosts: &[&str], service: Option<&str>, port: u16) -> Route {
        let hosts = hosts.iter().map(|h| h.to_string()).collect();
        Route { listen, hosts, service: service.map(Into::into), port, tls: false }
    }

    fn tls_route(listen: Option<u16>, hosts: &[&str], port: u16) -> Route {
        Route { tls: true, ..route(listen, hosts, None, port) }
    }

    fn entry(routes: Vec<Route>, up: Option<Upstream>) -> Entry {
        Entry { routes, network: Some("owd-env".into()), upstream: up }
    }

    #[test]
    fn routes_are_normalized_and_checked() {
        let r = normalize(&[route(Some(20001), &["WWW.Example.com."], None, 3000)]).unwrap();
        assert_eq!(r[0].hosts, ["www.example.com"]);
        for bad in [
            vec![route(None, &[], None, 3000)],
            vec![route(Some(0), &[], None, 3000)],
            vec![route(Some(20001), &["a b"], None, 3000)],
            vec![route(Some(20001), &["*.example.com"], None, 3000)],
            vec![route(Some(20001), &[], None, 3000), route(Some(20001), &[], None, 3001)],
            vec![route(Some(20001), &["a.com"], None, 3000), route(Some(20001), &["A.com"], None, 3001)],
            vec![route(Some(20001), &[], Some("../x"), 3000)],
            vec![route(Some(20001), &[], None, 3000), tls_route(Some(20001), &["a.com"], 3000)],
        ] {
            assert!(normalize(&bad).is_err(), "{bad:?}");
        }
        // During a switch a preview's host is on both preview listeners.
        assert!(normalize(&[route(None, &["pr-1.p.com"], None, 80), tls_route(None, &["pr-1.p.com"], 80)]).is_ok());
    }

    #[test]
    fn conflicting_ports_and_preview_hosts_are_refused() {
        let mut s = State::default();
        s.resources.insert("app_a".into(), entry(vec![route(Some(20001), &[], None, 80)], None));
        s.resources.insert("app_b".into(), entry(vec![route(Some(20002), &[], None, 80)], None));
        assert!(check_conflicts(&s).is_ok());
        s.resources.insert("app_c".into(), entry(vec![route(Some(20001), &["x.com"], None, 80)], None));
        assert!(check_conflicts(&s).unwrap_err().contains("port 20001"));
        s.resources.remove("app_c");
        s.resources.insert("app_a-pr1".into(), entry(vec![route(None, &["pr-1.p.com"], None, 80)], None));
        s.resources.insert("app_a-pr2".into(), entry(vec![route(None, &["pr-1.p.com"], None, 80)], None));
        assert!(check_conflicts(&s).unwrap_err().contains("preview host"));
        s.resources.remove("app_a-pr2");
        s.preview_port = Some(20002);
        assert!(check_conflicts(&s).unwrap_err().contains("preview port"));
        s.preview_port = None;
        s.resources.insert("app_d".into(), entry(vec![tls_route(Some(20001), &[], 80)], None));
        assert!(check_conflicts(&s).unwrap_err().contains("both TLS and plain"));
        s.resources.remove("app_d");
        let cert = |name: &str, hosts: &[&str]| Cert {
            name: name.into(),
            id: name.into(),
            listen: Some(20003),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
        };
        s.tls = Some(Tls {
            client_ca: vec!["AA==".into()],
            certificates: vec![cert("a", &["x.com"]), cert("b", &["y.com", "x.com"])],
        });
        assert!(check_conflicts(&s).unwrap_err().contains("two certificates"));
    }

    /// A new listener port never recreates a router whose ports the agent routes itself, including one created
    /// before with ports published by Docker; without agent routing a missing port recreates it, as before.
    #[test]
    fn router_plan_for_a_new_port_shows_no_recreate() {
        let bound: BTreeSet<u16> = [20001].into();
        let ports: BTreeSet<u16> = [20001, 20002].into();
        assert_eq!(plan(Some((IMAGE, &BTreeSet::new())), &ports, true), Plan::Reuse);
        assert_eq!(plan(Some((IMAGE, &bound)), &ports, true), Plan::Reuse, "a migrated router keeps serving");
        assert_eq!(plan(None, &ports, true), Plan::Create);
        assert_eq!(plan(Some(("caddy:2.10.0-alpine", &bound)), &ports, true), Plan::Recreate, "a new image");
        assert_eq!(plan(Some((IMAGE, &bound)), &ports, false), Plan::Recreate);
        assert_eq!(plan(Some((IMAGE, &ports)), &bound, false), Plan::Reuse);
    }

    #[test]
    fn render_routes_active_resources_by_listener_and_host() {
        let mut s = State { preview_port: Some(29999), ..Default::default() };
        let a = Some(Upstream::Slot { slot: Slot::A });
        s.resources.insert("app_A".into(), entry(vec![route(Some(20001), &[], None, 3000)], a));
        s.resources.insert(
            "app_c".into(),
            entry(
                vec![
                    route(Some(20003), &["a.com"], Some("web"), 80),
                    route(Some(20003), &["api.a.com"], Some("api"), 8080),
                ],
                Some(Upstream::Compose),
            ),
        );
        s.resources.insert("app_a-pr4".into(), entry(vec![route(None, &["pr-4.p.com"], None, 3000)], a));
        // Not deployed through the router yet: no listener.
        s.resources.insert("app_old".into(), entry(vec![route(Some(20009), &[], None, 80)], None));
        assert_eq!(s.ports().into_iter().collect::<Vec<_>>(), [20001, 20003, 29999]);
        let c = render(&s);
        let servers = &c["apps"]["http"]["servers"];
        let names: Vec<&String> = servers.as_object().unwrap().keys().collect();
        assert_eq!(names, ["port-20001", "port-20003", "preview", "slots"]);
        let a = &servers["port-20001"];
        assert_eq!(a["listen"], json!([":20001"]));
        assert_eq!(a["routes"][0]["handle"][1]["handler"], "encode", "responses are compressed before proxying");
        let types = a["routes"][0]["handle"][1]["match"]["headers"]["Content-Type"].as_array().unwrap();
        assert!(
            types.iter().any(|t| t == "text/html*")
                && !types.iter().any(|t| t.as_str().unwrap().contains("event-stream"))
        );
        let proxy = &a["routes"][0]["handle"][2];
        assert_eq!(proxy["upstreams"], json!([{"dial": "owd-app_a-a:3000"}, {"dial": "owd-app_a-b:3000"}]));
        assert_eq!(proxy["load_balancing"]["selection_policy"]["policy"], "first");
        assert_eq!(proxy["health_checks"]["active"]["upstream"], "127.0.0.1:2020");
        assert_eq!(a["automatic_https"]["disable"], true);
        let comp = &servers["port-20003"]["routes"];
        assert_eq!(comp[0]["match"][0]["host"], json!(["a.com"]));
        assert_eq!(comp[0]["handle"][2]["upstreams"][0]["dial"], "owd-app_c-web:80");
        assert_eq!(comp[1]["handle"][2]["upstreams"][0]["dial"], "owd-app_c-api:8080");
        assert!(comp[1]["handle"][2].get("health_checks").is_none());
        assert_eq!(comp[2]["handle"][0]["status_code"], 404, "other hosts get a 404");
        let p = &servers["preview"];
        assert_eq!(p["listen"], json!([":29999"]));
        assert_eq!(p["routes"][0]["match"][0]["host"], json!(["pr-4.p.com"]));
        let slots = &servers["slots"];
        assert_eq!(slots["listen"], json!(["127.0.0.1:2020"]));
        assert_eq!(slots["routes"][0]["match"][0]["host"], json!(["owd-app_a-a"]));
        assert_eq!(slots["routes"][0]["handle"][0]["body"], "{file./etc/owd-router/slots/owd-app_a-a}");
        assert_eq!(slots["routes"].as_array().unwrap().last().unwrap()["handle"][0]["body"], "down");
        assert_eq!(c["admin"]["listen"], "localhost:2019");
        // A switch changes no configuration: no reload.
        s.resources.get_mut("app_A").unwrap().upstream = Some(Upstream::Slot { slot: Slot::B });
        assert_eq!(render(&s), c);
    }

    const PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----";

    #[test]
    fn tls_material_is_checked() {
        let c = |name: &str, hosts: &[&str], key: &str| deploy_proto::msg::TlsCertificate {
            name: name.into(),
            id: "id-1".into(),
            listen: Some(20002),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            cert_pem: PEM_CERT.into(),
            key_pem: key.into(),
        };
        let key = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----";
        let two = format!("{PEM_CERT}\n{}", PEM_CERT.replace("AAEC", "AQID"));
        let ok = RouterTls { client_ca_pem: two, certificates: vec![c("app_01-z", &["WWW.A.com.", "*.p.a.com"], key)] };
        let (tls, pems) = take_tls(&ok).unwrap();
        assert_eq!(tls.client_ca, ["AAEC", "AQID"]);
        assert_eq!(tls.certificates[0].hosts, ["www.a.com", "*.p.a.com"]);
        assert!(pems[0].1.contains("PRIVATE KEY") && pems[0].1.starts_with(PEM_CERT));
        for bad in [
            RouterTls { client_ca_pem: "none".into(), ..ok.clone() },
            RouterTls { certificates: vec![c("../x", &["a.com"], key)], ..ok.clone() },
            RouterTls { certificates: vec![c("a", &["a b"], key)], ..ok.clone() },
            RouterTls { certificates: vec![c("a", &["a.com"], "no key")], ..ok.clone() },
            RouterTls { certificates: vec![c("a", &["a.com"], key), c("a", &["b.com"], key)], ..ok.clone() },
        ] {
            assert!(take_tls(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn render_serves_tls_listeners_with_the_edge_client_ca() {
        let a = Some(Upstream::Slot { slot: Slot::A });
        let mut s = State { preview_port: Some(29998), preview_tls_port: Some(29999), ..Default::default() };
        // During the switch: the plain port and the TLS port route the same container.
        s.resources.insert(
            "app_a".into(),
            entry(vec![route(Some(20001), &[], None, 3000), tls_route(Some(20002), &[], 3000)], a),
        );
        s.resources.insert("app_a-pr4".into(), entry(vec![tls_route(None, &["pr-4.p.a.com"], 3000)], a));
        // A TLS listener without a certificate stays closed.
        s.resources.insert("app_b".into(), entry(vec![tls_route(Some(20003), &[], 80)], a));
        let cert = |name: &str, id: &str, listen: Option<u16>, hosts: &[&str]| Cert {
            name: name.into(),
            id: id.into(),
            listen,
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
        };
        s.tls = Some(Tls {
            client_ca: vec!["AAEC".into()],
            certificates: vec![
                cert("app_a-z1", "c1", Some(20002), &["a.com", "www.a.com"]),
                cert("app_a-previews", "c2", None, &["*.p.a.com"]),
            ],
        });
        let c = render(&s);
        let servers = &c["apps"]["http"]["servers"];
        let names: Vec<&String> = servers.as_object().unwrap().keys().collect();
        assert_eq!(names, ["certs", "port-20001", "port-20002", "preview", "preview-tls", "slots"]);
        assert!(servers["port-20001"].get("tls_connection_policies").is_none(), "the plain port stays plain");
        let t = &servers["port-20002"];
        let policy = &t["tls_connection_policies"][0];
        assert_eq!(policy["match"]["sni"], json!(["a.com", "www.a.com"]));
        assert_eq!(policy["client_authentication"]["mode"], "require_and_verify");
        assert_eq!(policy["client_authentication"]["ca"]["trusted_ca_certs"], json!(["AAEC"]));
        assert_eq!(t["protocols"], json!(["h1", "h2"]));
        assert_eq!(t["routes"][0]["handle"][2]["upstreams"][0]["dial"], "owd-app_a-a:3000");
        let p = &servers["preview-tls"];
        assert_eq!(p["listen"], json!([":29999"]));
        assert_eq!(p["tls_connection_policies"][0]["match"]["sni"], json!(["*.p.a.com"]));
        assert_eq!(p["routes"][0]["match"][0]["host"], json!(["pr-4.p.a.com"]));
        assert_eq!(servers["preview"]["routes"].as_array().unwrap().len(), 1, "only the 404");
        let certs = &servers["certs"];
        assert_eq!(certs["listen"], json!(["127.0.0.1:2021"]));
        assert_eq!(certs["routes"][0]["match"][0]["path"], json!(["/app_a-z1"]));
        assert_eq!(certs["routes"][0]["handle"][0]["body"], "{file./etc/owd-router/tls-app_a-z1.pem}");
        assert_eq!(certs["routes"][2]["handle"][0]["status_code"], 404);
        let policies = &c["apps"]["tls"]["automation"]["policies"];
        assert_eq!(policies[1]["subjects"], json!(["*.p.a.com"]));
        assert_eq!(policies[1]["get_certificate"][0]["url"], "http://127.0.0.1:2021/app_a-previews");
        assert_eq!(tls_listeners(&s).into_iter().collect::<Vec<_>>(), [20002, 29999]);
        // A renewal (same names, new ids) changes no configuration: no reload.
        s.tls.as_mut().unwrap().certificates[0].id = "c3".into();
        assert_eq!(render(&s), c);
        // Without the client CA no TLS listener opens.
        s.tls.as_mut().unwrap().client_ca.clear();
        let c = render(&s);
        assert!(c["apps"]["http"]["servers"].get("port-20002").is_none() && c["apps"].get("tls").is_none());
        assert!(tls_listeners(&s).is_empty());
    }
}
