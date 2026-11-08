//! The Compose project as the agent runs it: [`Plan::new`] turns the project `docker compose config` resolved in a
//! source helper (JSON: interpolated with the application's variables, `env_file`s and overrides merged, paths
//! absolute) into a typed plan the agent applies through the Engine API itself ([`crate::compose`]). No Compose
//! client ever runs next to the Engine.
//!
//! Every field of the file is either modelled here, ignored like Compose itself ignores it outside Swarm, or
//! refused: an unknown field, a newer Compose feature, anything that would take a service off the Deploy networks
//! or into the server ([`refuse_escapes`] first, then the allowlist of [`Plan::new`]), is an error naming it. Refused
//! beyond what [`refuse_escapes`] covers: `pid`, `uts`, `userns_mode`, `cgroup_parent`, `runtime`, `isolation`,
//! `storage_opt`, `oom_kill_disable`, `oom_score_adj`, `blkio_config`, `gpus`, `credential_spec`, `annotations`,
//! `external_links`, lifecycle hooks, `use_api_socket`, security options other than `no-new-privileges`, logging
//! drivers other than `json-file`, `local` and `none` (the others send logs from the server's network), IPAM
//! configuration and fixed addresses (a subnet over the server's own routes), container names in another
//! application's `owd-…` namespace, image tags and registry caches of builds, build secrets and SSH.
//!
//! The adaptation is the one Deploy always made: every service gets the resource and deployment labels (and
//! those of the command), the application's variables (they win over the file's), its volumes and files, and
//! joins the environment network with the alias `owd-<resource>-<service>` (the router's upstream) besides its own
//! networks; host `ports:` are dropped, so traffic only arrives through the router; `restart` defaults to
//! `unless-stopped` and logs rotate. Built services get the image `owd/<resource>:<deployment>-<service>`. Labels
//! of the agent's and Compose's namespaces are the agent's; containers, networks and volumes carry Compose's
//! project and service labels, so the agent manages a project deployed by Compose (earlier agents) and the other
//! way round.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use bollard::models::{
    ContainerCreateBody, EndpointSettings, HealthConfig, HostConfig, HostConfigLogConfig, Mount, MountImageOptions,
    MountTmpfsOptions, MountType, MountVolumeOptions, NetworkingConfig, ResourcesUlimits, RestartPolicy,
    RestartPolicyNameEnum,
};

use deploy_proto::msg::{ComposeDeploy, FileMount, LABEL_DEPLOYMENT, LABEL_RESOURCE};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::docker::{COMPOSE_PROJECT, COMPOSE_SERVICE, valid_id};
use crate::router::service_alias;
use crate::volumes::volume_name;

/// Labels Compose puts on its objects, which the agent sets the same way.
pub const COMPOSE_NETWORK: &str = "com.docker.compose.network";
pub const COMPOSE_VOLUME: &str = "com.docker.compose.volume";
pub const COMPOSE_NUMBER: &str = "com.docker.compose.container-number";
pub const COMPOSE_ONEOFF: &str = "com.docker.compose.oneoff";
pub const COMPOSE_HASH: &str = "com.docker.compose.config-hash";
/// Most containers of one service.
const MAX_REPLICAS: u64 = 32;

pub fn project(resource: &str) -> String {
    format!("owd-{}", resource.to_ascii_lowercase())
}

/// A network the project's services join.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Network {
    /// Its key in the file.
    pub key: String,
    /// Its Docker name.
    pub name: String,
    /// One the agent does not create (the environment's, another Deploy network).
    pub external: bool,
    pub internal: bool,
    pub labels: BTreeMap<String, String>,
    pub options: BTreeMap<String, String>,
}

/// A named volume of the project.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Volume {
    pub key: String,
    pub name: String,
    pub external: bool,
    pub labels: BTreeMap<String, String>,
    pub options: BTreeMap<String, String>,
}

/// When a service starts relative to one it depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Condition {
    Started,
    Healthy,
    CompletedSuccessfully,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Dependency {
    pub service: String,
    pub condition: Condition,
}

/// Whether the image of a service without a build is pulled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Pull {
    /// When the Engine does not have it.
    Missing,
    Always,
    Never,
}

/// One network a service joins, with its aliases (the container's name is added when it is created).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Endpoint {
    pub network: String,
    pub aliases: Vec<String>,
}

/// The network stack of a service.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum NetworkMode {
    /// Its own, on these networks (the first one at creation).
    Networks(Vec<Endpoint>),
    None,
    /// The stack of a container of that service.
    Service(String),
}

/// A mount of a service.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum MountSpec {
    /// A named volume (its Docker name) or, without one, an anonymous volume.
    Volume {
        source: Option<String>,
        target: String,
        read_only: bool,
        nocopy: bool,
        subpath: Option<String>,
    },
    Tmpfs {
        target: String,
        size: Option<i64>,
        mode: Option<i64>,
    },
    Image {
        source: String,
        target: String,
        subpath: Option<String>,
    },
    /// A file mount of the application, written by the agent (never a path of the file).
    AgentFile {
        source: String,
        target: String,
    },
}

/// A file put into the container before it starts: a secret or config with `content` or `environment`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Injected {
    pub target: String,
    pub content: String,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Health {
    pub test: Vec<String>,
    pub interval: Option<i64>,
    pub timeout: Option<i64>,
    pub retries: Option<i64>,
    pub start_period: Option<i64>,
    pub start_interval: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Resources {
    pub nano_cpus: Option<i64>,
    pub memory: Option<i64>,
    pub memory_swap: Option<i64>,
    pub memory_reservation: Option<i64>,
    pub pids: Option<i64>,
    pub cpu_shares: Option<i64>,
    pub cpuset: Option<String>,
    pub shm_size: Option<i64>,
    /// name → (soft, hard)
    pub ulimits: BTreeMap<String, (i64, i64)>,
}

/// A service as the agent runs it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Service {
    pub name: String,
    pub image: String,
    /// The bake target of its build ([`crate::builder::bake`]), when it has one.
    pub build: Option<Value>,
    pub pull: Pull,
    pub platform: Option<String>,
    pub replicas: u64,
    pub container_name: Option<String>,
    pub depends_on: Vec<Dependency>,
    pub command: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    pub env: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub healthcheck: Option<Health>,
    /// `no`, `always`, `unless-stopped` or `on-failure`, with its maximum retries.
    pub restart: (String, Option<i64>),
    pub user: Option<String>,
    pub working_dir: Option<String>,
    pub hostname: Option<String>,
    pub domainname: Option<String>,
    pub tty: bool,
    pub stdin_open: bool,
    pub init: Option<bool>,
    pub read_only: bool,
    pub tmpfs: BTreeMap<String, String>,
    pub stop_signal: Option<String>,
    /// Seconds.
    pub stop_grace: Option<i64>,
    pub resources: Resources,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub security_opt: Vec<String>,
    pub sysctls: BTreeMap<String, String>,
    pub extra_hosts: Vec<String>,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub dns_opt: Vec<String>,
    pub group_add: Vec<String>,
    pub expose: Vec<String>,
    pub logging: (String, BTreeMap<String, String>),
    pub network: NetworkMode,
    pub mounts: Vec<MountSpec>,
    /// (service, read-only)
    pub volumes_from: Vec<(String, bool)>,
    /// `private`, `shareable`, `none`, or `service:<name>`.
    pub ipc: Option<String>,
    pub files: Vec<Injected>,
}

impl Service {
    /// The `com.docker.compose.config-hash` of this service: any change of what it runs recreates its containers.
    pub fn hash(&self) -> String {
        hex::encode(Sha256::digest(serde_json::to_vec(self).expect("json")))
    }

    /// The services this one needs to exist first: its dependencies and the services whose containers it uses.
    fn needs(&self) -> BTreeSet<&str> {
        let mut n: BTreeSet<&str> = self.depends_on.iter().map(|d| d.service.as_str()).collect();
        if let NetworkMode::Service(s) = &self.network {
            n.insert(s);
        }
        n.extend(self.volumes_from.iter().map(|(s, _)| s.as_str()));
        if let Some(s) = self.ipc.as_deref().and_then(|i| i.strip_prefix("service:")) {
            n.insert(s);
        }
        n
    }

    /// The name of container `number` (from 1).
    pub fn container(&self, project: &str, number: u64) -> String {
        match &self.container_name {
            Some(n) => n.clone(),
            None => format!("{project}-{}-{number}", self.name),
        }
    }

    /// The endpoints of container `number`: its networks with their aliases and its name (as Compose sets them).
    /// The container is created on the first one and connected to the others before it starts.
    pub fn endpoints(&self, project: &str, number: u64) -> Vec<Endpoint> {
        let NetworkMode::Networks(eps) = &self.network else { return Vec::new() };
        let name = self.container(project, number);
        eps.iter()
            .map(|e| {
                let mut aliases = vec![name.clone()];
                aliases.extend(e.aliases.iter().cloned());
                Endpoint { network: e.network.clone(), aliases }
            })
            .collect()
    }

    /// The Engine's configuration of container `number`, labelled with the service's `hash`. `container_of` names
    /// the first container of another service (`network_mode`, `volumes_from` and `ipc` of `service:`).
    pub fn container_body(
        &self,
        project: &str,
        number: u64,
        hash: &str,
        container_of: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ContainerCreateBody, String> {
        let of = |s: &str| container_of(s).ok_or_else(|| format!("service {}: {s} has no container", self.name));
        let mut labels: HashMap<String, String> = self.labels.clone().into_iter().collect();
        labels.insert(COMPOSE_NUMBER.into(), number.to_string());
        labels.insert(COMPOSE_ONEOFF.into(), "False".into());
        labels.insert(COMPOSE_HASH.into(), hash.into());
        let endpoints = self.endpoints(project, number);
        let network_mode = match &self.network {
            NetworkMode::None => "none".to_string(),
            NetworkMode::Service(s) => format!("container:{}", of(s)?),
            NetworkMode::Networks(_) => endpoints.first().map(|e| e.network.clone()).unwrap_or_else(|| "none".into()),
        };
        let networking_config = endpoints.first().map(|e| NetworkingConfig {
            endpoints_config: Some(HashMap::from([(
                e.network.clone(),
                EndpointSettings { aliases: Some(e.aliases.clone()), ..Default::default() },
            )])),
        });
        let mut volumes_from = Vec::new();
        for (s, ro) in &self.volumes_from {
            volumes_from.push(format!("{}:{}", of(s)?, if *ro { "ro" } else { "rw" }));
        }
        let ipc_mode = match self.ipc.as_deref() {
            Some(i) if i.starts_with("service:") => Some(format!("container:{}", of(&i["service:".len()..])?)),
            i => i.filter(|i| !i.is_empty()).map(str::to_string),
        };
        let mounts: Vec<Mount> = self.mounts.iter().map(mount).collect();
        let r = &self.resources;
        let (restart, retries) = &self.restart;
        let restart_policy = RestartPolicy {
            name: Some(match restart.as_str() {
                "always" => RestartPolicyNameEnum::ALWAYS,
                "unless-stopped" => RestartPolicyNameEnum::UNLESS_STOPPED,
                "on-failure" => RestartPolicyNameEnum::ON_FAILURE,
                _ => RestartPolicyNameEnum::NO,
            }),
            maximum_retry_count: *retries,
        };
        let list = |v: &Vec<String>| (!v.is_empty()).then(|| v.clone());
        let host = HostConfig {
            network_mode: Some(network_mode),
            restart_policy: Some(restart_policy),
            mounts: (!mounts.is_empty()).then_some(mounts),
            volumes_from: (!volumes_from.is_empty()).then_some(volumes_from),
            ipc_mode,
            nano_cpus: r.nano_cpus,
            memory: r.memory,
            memory_swap: r.memory_swap,
            memory_reservation: r.memory_reservation,
            pids_limit: r.pids,
            cpu_shares: r.cpu_shares,
            cpuset_cpus: r.cpuset.clone(),
            shm_size: r.shm_size,
            ulimits: (!r.ulimits.is_empty()).then(|| {
                r.ulimits
                    .iter()
                    .map(|(n, (soft, hard))| ResourcesUlimits {
                        name: Some(n.clone()),
                        soft: Some(*soft),
                        hard: Some(*hard),
                    })
                    .collect()
            }),
            cap_add: list(&self.cap_add),
            cap_drop: list(&self.cap_drop),
            security_opt: list(&self.security_opt),
            sysctls: (!self.sysctls.is_empty()).then(|| self.sysctls.clone().into_iter().collect()),
            extra_hosts: list(&self.extra_hosts),
            dns: list(&self.dns),
            dns_search: list(&self.dns_search),
            dns_options: list(&self.dns_opt),
            group_add: list(&self.group_add),
            init: self.init,
            readonly_rootfs: self.read_only.then_some(true),
            tmpfs: (!self.tmpfs.is_empty()).then(|| self.tmpfs.clone().into_iter().collect()),
            log_config: Some(HostConfigLogConfig {
                typ: Some(self.logging.0.clone()),
                config: Some(self.logging.1.clone().into_iter().collect()),
            }),
            ..Default::default()
        };
        let healthcheck = self.healthcheck.as_ref().map(|h| HealthConfig {
            test: Some(h.test.clone()),
            interval: h.interval,
            timeout: h.timeout,
            retries: h.retries,
            start_period: h.start_period,
            start_interval: h.start_interval,
        });
        Ok(ContainerCreateBody {
            image: Some(self.image.clone()),
            cmd: self.command.clone(),
            entrypoint: self.entrypoint.clone(),
            env: Some(self.env.iter().map(|(k, v)| format!("{k}={v}")).collect()),
            labels: Some(labels),
            healthcheck,
            user: self.user.clone(),
            working_dir: self.working_dir.clone(),
            hostname: self.hostname.clone(),
            domainname: self.domainname.clone(),
            tty: Some(self.tty),
            open_stdin: Some(self.stdin_open),
            exposed_ports: (!self.expose.is_empty()).then(|| self.expose.clone()),
            stop_signal: self.stop_signal.clone(),
            stop_timeout: self.stop_grace,
            host_config: Some(host),
            networking_config,
            ..Default::default()
        })
    }
}

/// The Engine's mount of `m`.
fn mount(m: &MountSpec) -> Mount {
    match m {
        MountSpec::Volume { source, target, read_only, nocopy, subpath } => Mount {
            typ: Some(MountType::VOLUME),
            source: source.clone(),
            target: Some(target.clone()),
            read_only: Some(*read_only),
            volume_options: (*nocopy || subpath.is_some()).then(|| MountVolumeOptions {
                no_copy: Some(*nocopy),
                subpath: subpath.clone(),
                ..Default::default()
            }),
            ..Default::default()
        },
        MountSpec::Tmpfs { target, size, mode } => Mount {
            typ: Some(MountType::TMPFS),
            target: Some(target.clone()),
            tmpfs_options: Some(MountTmpfsOptions { size_bytes: *size, mode: *mode, ..Default::default() }),
            ..Default::default()
        },
        MountSpec::Image { source, target, subpath } => Mount {
            typ: Some(MountType::IMAGE),
            source: Some(source.clone()),
            target: Some(target.clone()),
            image_options: subpath.as_ref().map(|s| MountImageOptions { subpath: Some(s.clone()) }),
            ..Default::default()
        },
        MountSpec::AgentFile { source, target } => Mount {
            typ: Some(MountType::BIND),
            source: Some(source.clone()),
            target: Some(target.clone()),
            read_only: Some(true),
            ..Default::default()
        },
    }
}

/// The project to apply: its networks and volumes, and its services with dependencies first.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub project: String,
    pub networks: Vec<Network>,
    pub volumes: Vec<Volume>,
    pub services: Vec<Service>,
}

/// Capabilities that reach beyond the container (Docker's default set stays available).
const REFUSED_CAPS: [&str; 13] = [
    "ALL",
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_PTRACE",
    "SYS_BOOT",
    "SYS_TIME",
    "DAC_READ_SEARCH",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "BPF",
    "PERFMON",
];
/// Network driver options a Compose file may set; the others change how the network is reached (published
/// ports without NAT, other host addresses) or what the firewall sees.
const NETWORK_OPTIONS: [&str; 2] = ["com.docker.network.driver.mtu", "com.docker.network.bridge.enable_icc"];

/// `external: true` (or the older `external: {name: …}`).
fn is_external(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)) | Some(Value::Object(_)))
}

/// What a Compose project may not ask for: anything that leaves the Deploy networks (and so the firewall's egress
/// guard) or reaches into the server: the host's or another container's namespaces, networks that are not the
/// application's (or not bridges, or with IPv6), privileged mode and capabilities beyond the container, devices,
/// unconfined security profiles, files of the server (bind mounts, local volumes over a host path, file secrets
/// and configs), volumes of other applications, and builds with the host's network or extra privileges.
fn refuse_escapes(model: &Value, resource: &str) -> Result<(), String> {
    let project = project(resource);
    let own = format!("{project}_");
    let empty = Map::new();
    let map = |v: &Value, key: &str| v.get(key).and_then(Value::as_object).unwrap_or(&empty).clone();
    let strings = |v: Option<&Value>| -> Vec<String> {
        v.and_then(Value::as_array).into_iter().flatten().filter_map(|s| s.as_str().map(str::to_string)).collect()
    };
    for (key, n) in &map(model, "networks") {
        let name = n.get("name").and_then(Value::as_str);
        if is_external(n.get("external")) {
            let name = name.unwrap_or(key);
            if !name.starts_with(crate::firewall::NETWORK_PREFIX) {
                return Err(format!("network {key}: the external network {name} is not a Deploy network (owd-…)"));
            }
            continue;
        }
        if let Some(name) = name.filter(|n| !n.starts_with(&own)) {
            return Err(format!("network {key}: its name {name} is refused (an application's networks are {own}…)"));
        }
        match n.get("driver").and_then(Value::as_str) {
            None | Some("bridge") => {}
            Some(d) => return Err(format!("network {key}: the {d} driver is refused (Deploy networks are bridges)")),
        }
        if n.get("enable_ipv6") == Some(&Value::Bool(true)) {
            return Err(format!("network {key}: IPv6 is disabled on Deploy networks"));
        }
        if let Some(o) = map(n, "driver_opts").keys().find(|o| !NETWORK_OPTIONS.contains(&o.as_str())) {
            return Err(format!("network {key}: the driver option {o} is refused"));
        }
    }
    let volumes = map(model, "volumes");
    for (key, v) in &volumes {
        let name = v.get("name").and_then(Value::as_str).unwrap_or(key);
        if is_external(v.get("external")) {
            if !name.starts_with(&format!("{project}-")) && !name.starts_with(&own) {
                return Err(format!("volume {key}: the external volume {name} is not a volume of this application"));
            }
            continue;
        }
        if !name.starts_with(&own) {
            return Err(format!("volume {key}: its name {name} is refused (an application's volumes are {own}…)"));
        }
        if let Some(d) = v.get("driver").and_then(Value::as_str).filter(|d| *d != "local") {
            return Err(format!("volume {key}: the {d} driver is refused"));
        }
        let opts = map(v, "driver_opts");
        let opt = |k: &str| opts.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let host_path = opt("o").split(',').any(|o| matches!(o.trim(), "bind" | "rbind"))
            || matches!(opt("type").as_str(), "none" | "bind")
            || opt("device").starts_with('/');
        if host_path {
            return Err(format!("volume {key}: a volume over a path of the server is refused"));
        }
    }
    for kind in ["secrets", "configs"] {
        if let Some((key, _)) = map(model, kind).iter().find(|(_, s)| s.get("file").is_some()) {
            return Err(format!(
                "{kind} {key}: a file of the server cannot be mounted (use `environment` or `content`, or a file \
                 mount of the application)"
            ));
        }
    }
    let services = map(model, "services");
    for (name, svc) in &services {
        let refused = |what: String| Err(format!("service {name}: {what} is refused"));
        if svc.get("privileged") == Some(&Value::Bool(true)) {
            return refused("privileged mode".into());
        }
        for cap in strings(svc.get("cap_add")) {
            let c = cap.to_ascii_uppercase();
            if REFUSED_CAPS.contains(&c.strip_prefix("CAP_").unwrap_or(&c)) {
                return refused(format!("cap_add {cap}"));
            }
        }
        for key in ["pid", "ipc", "uts", "userns_mode", "cgroup"] {
            if let Some(m) =
                svc.get(key).and_then(Value::as_str).filter(|m| *m == "host" || m.starts_with("container:"))
            {
                return refused(format!("{key}: {m}"));
            }
        }
        match svc.get("network_mode").and_then(Value::as_str) {
            None | Some("none" | "bridge") => {}
            Some(m) if m.strip_prefix("service:").is_some_and(|s| services.contains_key(s)) => {}
            Some(m) => return refused(format!("network_mode {m} (services join the application's networks)")),
        }
        for key in ["devices", "device_cgroup_rules"] {
            if svc.get(key).and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
                return refused(key.into());
            }
        }
        if let Some(o) = strings(svc.get("security_opt")).into_iter().find(|o| {
            let o = o.replace(':', "=");
            o.contains("unconfined") || o == "label=disable"
        }) {
            return refused(format!("security_opt {o}"));
        }
        if let Some(f) = strings(svc.get("volumes_from")).into_iter().find(|f| f.starts_with("container:")) {
            return refused(format!("volumes_from {f}"));
        }
        for m in svc.get("volumes").and_then(Value::as_array).into_iter().flatten() {
            let source = m.get("source").and_then(Value::as_str);
            match m.get("type").and_then(Value::as_str) {
                Some("bind") => {
                    return refused(format!(
                        "the bind mount of {} (files of the server; use a volume or a file mount of the application)",
                        source.unwrap_or_default()
                    ));
                }
                Some("volume") => {
                    if let Some(s) = source.filter(|s| !volumes.contains_key(*s)) {
                        return refused(format!("the volume {s}, not declared by the file"));
                    }
                }
                Some("tmpfs" | "image") => {}
                t => return refused(format!("a mount of type {}", t.unwrap_or("(none)"))),
            }
        }
        if let Some(b) = svc.get("build").and_then(Value::as_object) {
            if let Some(n) = b.get("network").and_then(Value::as_str).filter(|n| !matches!(*n, "default" | "none")) {
                return refused(format!("build network {n}"));
            }
            if b.get("privileged") == Some(&Value::Bool(true)) {
                return refused("a privileged build".into());
            }
            if let Some(e) = strings(b.get("entitlements")).first() {
                return refused(format!("the build entitlement {e}"));
            }
        }
    }
    Ok(())
}

/// Keys of a service: modelled, or ignored as Compose ignores them outside Swarm (`deploy` parts aside). Anything
/// else is refused.
const SERVICE_KEYS: [&str; 61] = [
    "image",
    "build",
    "command",
    "entrypoint",
    "environment",
    "labels",
    "healthcheck",
    "restart",
    "depends_on",
    "deploy",
    "user",
    "working_dir",
    "hostname",
    "domainname",
    "tty",
    "stdin_open",
    "init",
    "read_only",
    "tmpfs",
    "stop_signal",
    "stop_grace_period",
    "mem_limit",
    "memswap_limit",
    "mem_reservation",
    "cpus",
    "cpu_shares",
    "cpuset",
    "pids_limit",
    "shm_size",
    "ulimits",
    "cap_add",
    "cap_drop",
    "security_opt",
    "sysctls",
    "extra_hosts",
    "dns",
    "dns_search",
    "dns_opt",
    "group_add",
    "expose",
    "logging",
    "networks",
    "network_mode",
    "volumes",
    "volumes_from",
    "ipc",
    "secrets",
    "configs",
    "container_name",
    "pull_policy",
    "platform",
    "scale",
    "privileged",
    "links",
    // Dropped: traffic arrives through the router only.
    "ports",
    // What `config` already applied, or what only the Compose CLI uses.
    "env_file",
    "label_file",
    "profiles",
    "attach",
    "develop",
    // Empty lists Compose writes (anything in them is refused by `refuse_escapes`).
    "devices",
];

/// Keys of a service's `build`.
const BUILD_KEYS: [&str; 10] = [
    "context",
    "dockerfile",
    "dockerfile_inline",
    "args",
    "target",
    "labels",
    "network",
    "no_cache",
    "pull",
    "additional_contexts",
];

fn text(v: &Value, what: &str) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err(format!("{what}: expected a string")),
    }
}

fn opt_text(v: Option<&Value>, what: &str) -> Result<Option<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(v) => text(v, what).map(Some),
    }
}

/// A list of strings (a single string is a one-item list).
fn texts(v: Option<&Value>, what: &str) -> Result<Vec<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => a.iter().map(|x| text(x, what)).collect(),
        Some(v) => Ok(vec![text(v, what)?]),
    }
}

fn boolean(v: Option<&Value>, what: &str) -> Result<Option<bool>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(Value::String(s)) if s == "true" || s == "false" => Ok(Some(s == "true")),
        _ => Err(format!("{what}: expected true or false")),
    }
}

fn integer(v: Option<&Value>, what: &str) -> Result<Option<i64>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_i64().map(Some).ok_or_else(|| format!("{what}: expected a whole number")),
        Some(Value::String(s)) => s.trim().parse().map(Some).map_err(|_| format!("{what}: expected a whole number")),
        _ => Err(format!("{what}: expected a whole number")),
    }
}

fn float(v: Option<&Value>, what: &str) -> Result<Option<f64>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_f64().map(Some).ok_or_else(|| format!("{what}: expected a number")),
        Some(Value::String(s)) => s.trim().parse().map(Some).map_err(|_| format!("{what}: expected a number")),
        _ => Err(format!("{what}: expected a number")),
    }
}

/// A size in bytes: a number, or digits with a unit (b, k, m, g, with or without b; powers of 1024).
fn bytes(v: Option<&Value>, what: &str) -> Result<Option<i64>, String> {
    let s = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => return n.as_i64().map(Some).ok_or_else(|| format!("{what}: expected a size")),
        Some(Value::String(s)) => s.trim().to_ascii_lowercase(),
        _ => return Err(format!("{what}: expected a size")),
    };
    let digits = s.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(s.len());
    let n: f64 = s[..digits].parse().map_err(|_| format!("{what}: {s:?} is not a size"))?;
    let unit = match &s[digits..] {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        _ => return Err(format!("{what}: {s:?} is not a size")),
    };
    Ok(Some((n * unit as f64) as i64))
}

/// A Go duration (`1m30s`, `500ms`) in nanoseconds.
fn duration(v: Option<&Value>, what: &str) -> Result<Option<i64>, String> {
    let s = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => return n.as_i64().map(Some).ok_or_else(|| format!("{what}: expected a duration")),
        Some(Value::String(s)) => s.trim().to_string(),
        _ => return Err(format!("{what}: expected a duration")),
    };
    let bad = || format!("{what}: {s:?} is not a duration");
    let mut rest = s.as_str();
    let mut total = 0f64;
    if rest == "0" {
        return Ok(Some(0));
    }
    while !rest.is_empty() {
        let n = rest.find(|c: char| !c.is_ascii_digit() && c != '.').ok_or_else(bad)?;
        let value: f64 = rest[..n].parse().map_err(|_| bad())?;
        rest = &rest[n..];
        let u = rest.find(|c: char| c.is_ascii_digit()).unwrap_or(rest.len());
        let unit = match &rest[..u] {
            "ns" => 1.0,
            "us" | "µs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            _ => return Err(bad()),
        };
        total += value * unit;
        rest = &rest[u..];
    }
    Ok(Some(total as i64))
}

/// A map of strings: an object (null values dropped) or a list of `KEY=VALUE` (`KEY` alone dropped).
fn strings_map(v: Option<&Value>, what: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    match v {
        None | Some(Value::Null) => {}
        Some(Value::Object(m)) => {
            for (k, v) in m {
                if let Some(v) = opt_text(Some(v), what)? {
                    out.insert(k.clone(), v);
                }
            }
        }
        Some(Value::Array(a)) => {
            for x in a {
                if let Some((k, v)) = text(x, what)?.split_once('=') {
                    out.insert(k.to_string(), v.to_string());
                }
            }
        }
        _ => return Err(format!("{what}: expected a map")),
    }
    Ok(out)
}

/// Refuses keys of `m` beyond `allowed` (extensions `x-…` aside).
fn only(m: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), String> {
    match m.keys().find(|k| !k.starts_with("x-") && !allowed.contains(&k.as_str())) {
        Some(k) => Err(format!("{what}: `{k}` is not supported by Deploy")),
        None => Ok(()),
    }
}

fn object<'a>(v: Option<&'a Value>, what: &str) -> Result<Option<&'a Map<String, Value>>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        _ => Err(format!("{what}: expected a map")),
    }
}

/// A path of the repository or inline project in the helpers (`/src`, `/owd/project`), without `..`.
fn project_path(p: &str) -> bool {
    let inside = ["/src", "/owd/project"].iter().any(|r| p == *r || p.starts_with(&format!("{r}/")));
    inside && !p.split('/').any(|c| c == "..")
}

/// A build context the builder may fetch itself: a public Git or HTTP(S) URL.
fn remote_context(p: &str) -> bool {
    p.starts_with("https://") || p.starts_with("http://") || p.starts_with("git://")
}

/// Undoes the escaping `docker compose config` applies so its output can be loaded again: every `$` of a value is
/// written `$$`. The values run as given (`up` unescaped them too).
fn unescape(v: &mut Value) {
    match v {
        Value::String(s) if s.contains("$$") => *s = s.replace("$$", "$"),
        Value::Array(a) => a.iter_mut().for_each(unescape),
        Value::Object(m) => m.values_mut().for_each(unescape),
        _ => {}
    }
}

impl Plan {
    /// The plan of `model` (the resolved project) for the deployment `c`, with the application's written files
    /// (host path, file).
    pub fn new(mut model: Value, c: &ComposeDeploy, files: &[(PathBuf, &FileMount)]) -> Result<Plan, String> {
        let project = project(&c.resource);
        unescape(&mut model);
        refuse_escapes(&model, &c.resource)?;
        let root = model.as_object().ok_or("the Compose project is not an object")?;
        only(root, &["name", "services", "networks", "volumes", "secrets", "configs"], "the Compose file")?;
        let services = object(root.get("services"), "services")?.ok_or("the Compose file has no services")?;
        for n in services.keys() {
            if !valid_id(n) {
                return Err(format!("service name {n:?}: use letters, digits, '-' and '_'"));
            }
        }
        let networks = networks(root, &project, c)?;
        let volumes = volumes(root, &project, c)?;
        let secrets = secret_sources(root, "secrets", c)?;
        let configs = secret_sources(root, "configs", c)?;
        let mut list = Vec::new();
        for (name, svc) in services {
            let svc = svc.as_object().ok_or_else(|| format!("service {name} is not an object"))?;
            let ctx = Context { project: &project, c, services, networks: &networks, volumes: &volumes, files };
            list.push(service(name, svc, &ctx, &secrets, &configs)?);
        }
        for m in
            c.volumes.iter().filter_map(|v| v.service.as_ref()).chain(c.files.iter().filter_map(|f| f.service.as_ref()))
        {
            if !services.contains_key(m) {
                return Err(format!("a mount names the service {m}, which the Compose file does not have"));
            }
        }
        for r in &c.routes {
            let s = r.service.as_deref().ok_or("each route of a Compose application names its service")?;
            let routed = list.iter().any(|x| x.name == s && matches!(x.network, NetworkMode::Networks(_)));
            if !routed {
                return Err(format!("the route to {s}: no such service with its own network"));
            }
        }
        let services = order(list)?;
        Ok(Plan { project, networks, volumes, services })
    }

    /// The bake file of the services with a build: one target per service, named after it.
    pub fn bake_file(&self) -> Option<(Value, Vec<String>)> {
        let targets: Map<String, Value> =
            self.services.iter().filter_map(|s| Some((s.name.clone(), s.build.clone()?))).collect();
        let names: Vec<String> = targets.keys().cloned().collect();
        (!names.is_empty()).then(|| (json!({"target": targets}), names))
    }
}

/// What a service's parsing needs from the rest of the project.
struct Context<'a> {
    project: &'a str,
    c: &'a ComposeDeploy,
    services: &'a Map<String, Value>,
    networks: &'a [Network],
    volumes: &'a [Volume],
    files: &'a [(PathBuf, &'a FileMount)],
}

/// The project's networks: the file's (its own bridges, named for the firewall's `owd+` guard, without IPv6; or
/// external Deploy networks), then the environment's.
fn networks(root: &Map<String, Value>, project: &str, c: &ComposeDeploy) -> Result<Vec<Network>, String> {
    let mut out = Vec::new();
    let declared = object(root.get("networks"), "networks")?.cloned().unwrap_or_default();
    let mut keys: BTreeSet<String> = declared.keys().cloned().collect();
    // Services without `networks` join `default`, which Compose declares only when used.
    keys.insert("default".into());
    for key in keys {
        let empty = Map::new();
        let n = match declared.get(&key) {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(m)) => m,
            Some(_) => return Err(format!("network {key} is not a map")),
        };
        let what = format!("network {key}");
        only(
            n,
            &["name", "driver", "driver_opts", "external", "labels", "internal", "attachable", "enable_ipv6", "ipam"],
            &what,
        )?;
        if let Some(ipam) = object(n.get("ipam"), &what)? {
            let configured = ipam.iter().any(|(k, v)| match k.as_str() {
                "driver" => v.as_str().is_some_and(|d| d != "default"),
                _ => !v.is_null() && v != &json!([]) && v != &json!({}),
            });
            if configured {
                return Err(format!("{what}: IPAM configuration is not supported by Deploy (addresses are Docker's)"));
            }
        }
        let external = is_external(n.get("external"));
        let name = match opt_text(n.get("name"), &what)? {
            Some(name) => name,
            None if external => key.clone(),
            None => format!("{project}_{key}"),
        };
        let mut labels = strings_map(n.get("labels"), &what)?;
        let mut options = strings_map(n.get("driver_opts"), &what)?;
        if !external {
            labels.retain(|k, _| !reserved_label(k));
            labels.insert(COMPOSE_PROJECT.into(), project.into());
            labels.insert(COMPOSE_NETWORK.into(), key.clone());
            options.insert(crate::firewall::BRIDGE_OPTION.into(), crate::firewall::bridge_name(&name));
        }
        let internal = boolean(n.get("internal"), &what)?.unwrap_or(false);
        out.push(Network { key, name, external, internal, labels, options });
    }
    out.push(Network {
        key: String::new(),
        name: c.network.clone(),
        external: true,
        internal: false,
        labels: BTreeMap::new(),
        options: BTreeMap::new(),
    });
    Ok(out)
}

/// The project's volumes and the application's (external, created by the agent beforehand).
fn volumes(root: &Map<String, Value>, project: &str, c: &ComposeDeploy) -> Result<Vec<Volume>, String> {
    let mut out = Vec::new();
    for (key, v) in object(root.get("volumes"), "volumes")?.into_iter().flatten() {
        let empty = Map::new();
        let v = match v {
            Value::Null => &empty,
            Value::Object(m) => m,
            _ => return Err(format!("volume {key} is not a map")),
        };
        let what = format!("volume {key}");
        only(v, &["name", "driver", "driver_opts", "external", "labels"], &what)?;
        let external = is_external(v.get("external"));
        let name = opt_text(v.get("name"), &what)?.unwrap_or_else(|| format!("{project}_{key}"));
        let mut labels = strings_map(v.get("labels"), &what)?;
        if !external {
            labels.retain(|k, _| !reserved_label(k));
            labels.insert(COMPOSE_PROJECT.into(), project.into());
            labels.insert(COMPOSE_VOLUME.into(), key.clone());
        }
        let options = strings_map(v.get("driver_opts"), &what)?;
        out.push(Volume { key: key.clone(), name, external, labels, options });
    }
    for v in &c.volumes {
        let name = volume_name(&c.resource, &v.name);
        out.push(Volume {
            key: String::new(),
            name,
            external: true,
            labels: BTreeMap::new(),
            options: BTreeMap::new(),
        });
    }
    Ok(out)
}

/// Contents of the file's secrets or configs: `content`, or `environment` (a variable of the application).
fn secret_sources(
    root: &Map<String, Value>,
    kind: &str,
    c: &ComposeDeploy,
) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for (key, s) in object(root.get(kind), kind)?.into_iter().flatten() {
        let what = format!("{kind} {key}");
        let s = s.as_object().ok_or_else(|| format!("{what} is not a map"))?;
        only(s, &["name", "content", "environment"], &what)?;
        let content = match (opt_text(s.get("content"), &what)?, opt_text(s.get("environment"), &what)?) {
            (Some(content), _) => content,
            (None, Some(var)) => c
                .env
                .get(&var)
                .cloned()
                .ok_or_else(|| format!("{what}: the variable {var} is not one of the application's"))?,
            (None, None) => return Err(format!("{what}: only `content` and `environment` are supported by Deploy")),
        };
        out.insert(key.clone(), content);
    }
    Ok(out)
}

/// Labels only the agent sets: its own namespace and Compose's.
fn reserved_label(k: &str) -> bool {
    k.starts_with("dev.openwaf.deploy.") || k.starts_with("com.docker.compose.")
}

fn service(
    name: &str,
    svc: &Map<String, Value>,
    x: &Context<'_>,
    secrets: &BTreeMap<String, String>,
    configs: &BTreeMap<String, String>,
) -> Result<Service, String> {
    let what = format!("service {name}");
    only(svc, &SERVICE_KEYS, &what)?;
    let c = x.c;
    let field = |k: &str| format!("{what}: {k}");
    if svc.get("devices").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
        return Err(format!("{what}: devices are refused"));
    }

    // Image and build.
    let build = match object(svc.get("build"), &field("build"))? {
        Some(b) => Some(build_target(name, b, x)?),
        None => None,
    };
    let image = match &build {
        // Built images live in the application's repository, like a Dockerfile application's (prune, remove),
        // whatever the file names them: a build never replaces an image of someone else.
        Some(_) => format!(
            "owd/{}:{}-{}",
            c.resource.to_ascii_lowercase(),
            c.deployment.to_ascii_lowercase(),
            name.to_ascii_lowercase()
        ),
        None => opt_text(svc.get("image"), &field("image"))?.ok_or_else(|| format!("{what} has no image"))?,
    };
    let pull = match opt_text(svc.get("pull_policy"), &field("pull_policy"))?.as_deref() {
        None | Some("missing" | "if_not_present" | "build" | "daily" | "weekly") => Pull::Missing,
        Some(p) if p.starts_with("every_") => Pull::Missing,
        Some("always") => Pull::Always,
        Some("never") => Pull::Never,
        Some(p) => return Err(format!("{what}: the pull policy {p} is not supported")),
    };
    let platform = opt_text(svc.get("platform"), &field("platform"))?;

    // Replicas and restart (`deploy` is Swarm's, but Compose applies these parts of it).
    let deploy = object(svc.get("deploy"), &field("deploy"))?.cloned().unwrap_or_default();
    only(
        &deploy,
        &[
            "replicas",
            "resources",
            "restart_policy",
            "mode",
            "placement",
            "update_config",
            "rollback_config",
            "endpoint_mode",
            "labels",
        ],
        &field("deploy"),
    )?;
    if let Some(m) = opt_text(deploy.get("mode"), &field("deploy.mode"))?.filter(|m| m != "replicated") {
        return Err(format!("{what}: the deploy mode {m} is not supported"));
    }
    let replicas = match (
        integer(svc.get("scale"), &field("scale"))?,
        integer(deploy.get("replicas"), &field("deploy.replicas"))?,
    ) {
        (Some(n), _) | (None, Some(n)) => n,
        (None, None) => 1,
    };
    if !(0..=MAX_REPLICAS as i64).contains(&replicas) {
        return Err(format!("{what}: from 0 to {MAX_REPLICAS} replicas"));
    }
    let restart = match opt_text(svc.get("restart"), &field("restart"))? {
        Some(r) => restart_policy(&r).ok_or_else(|| format!("{what}: invalid restart policy {r:?}"))?,
        None => match object(deploy.get("restart_policy"), &field("deploy.restart_policy"))? {
            Some(p) => {
                only(p, &["condition", "max_attempts", "delay", "window"], &field("deploy.restart_policy"))?;
                let max = integer(p.get("max_attempts"), &field("deploy.restart_policy.max_attempts"))?;
                match opt_text(p.get("condition"), &field("deploy.restart_policy.condition"))?.as_deref() {
                    Some("none") => ("no".to_string(), None),
                    Some("on-failure") => ("on-failure".to_string(), max),
                    None | Some("any") => ("always".to_string(), None),
                    Some(o) => return Err(format!("{what}: invalid restart condition {o:?}")),
                }
            }
            None => ("unless-stopped".to_string(), None),
        },
    };

    // Resources.
    let mut res = Resources::default();
    if let Some(r) = object(deploy.get("resources"), &field("deploy.resources"))? {
        only(r, &["limits", "reservations"], &field("deploy.resources"))?;
        if let Some(l) = object(r.get("limits"), &field("deploy.resources.limits"))? {
            only(l, &["cpus", "memory", "pids"], &field("deploy.resources.limits"))?;
            res.nano_cpus = float(l.get("cpus"), &field("limits.cpus"))?.map(|c| (c * 1e9) as i64);
            res.memory = bytes(l.get("memory"), &field("limits.memory"))?;
            res.pids = integer(l.get("pids"), &field("limits.pids"))?;
        }
        if let Some(l) = object(r.get("reservations"), &field("deploy.resources.reservations"))? {
            only(l, &["cpus", "memory"], &field("deploy.resources.reservations"))?;
            res.memory_reservation = bytes(l.get("memory"), &field("reservations.memory"))?;
        }
    }
    let or = |a: Option<i64>, b: Option<i64>| a.or(b);
    res.nano_cpus = or(float(svc.get("cpus"), &field("cpus"))?.map(|c| (c * 1e9) as i64), res.nano_cpus);
    res.memory = or(bytes(svc.get("mem_limit"), &field("mem_limit"))?, res.memory);
    res.memory_swap = bytes(svc.get("memswap_limit"), &field("memswap_limit"))?;
    res.memory_reservation = or(bytes(svc.get("mem_reservation"), &field("mem_reservation"))?, res.memory_reservation);
    res.pids = or(integer(svc.get("pids_limit"), &field("pids_limit"))?, res.pids);
    res.cpu_shares = integer(svc.get("cpu_shares"), &field("cpu_shares"))?;
    res.cpuset = opt_text(svc.get("cpuset"), &field("cpuset"))?;
    res.shm_size = bytes(svc.get("shm_size"), &field("shm_size"))?;
    for (k, v) in object(svc.get("ulimits"), &field("ulimits"))?.into_iter().flatten() {
        let l = match v {
            Value::Object(o) => {
                let soft = integer(o.get("soft"), &field("ulimits"))?;
                let hard = integer(o.get("hard"), &field("ulimits"))?;
                (soft.or(hard).unwrap_or(0), hard.or(soft).unwrap_or(0))
            }
            v => {
                let n = integer(Some(v), &field("ulimits"))?.unwrap_or(0);
                (n, n)
            }
        };
        res.ulimits.insert(k.clone(), l);
    }

    // Environment and labels: the application's win, the agent's namespaces are its own.
    let mut env = strings_map(svc.get("environment"), &field("environment"))?;
    env.extend(c.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    let mut labels = strings_map(svc.get("labels"), &field("labels"))?;
    labels.retain(|k, _| !reserved_label(k));
    labels.extend(c.labels.iter().map(|(k, v)| (k.clone(), v.clone())));
    labels.insert(LABEL_RESOURCE.into(), c.resource.clone());
    labels.insert(LABEL_DEPLOYMENT.into(), c.deployment.clone());
    labels.insert(COMPOSE_PROJECT.into(), x.project.into());
    labels.insert(COMPOSE_SERVICE.into(), name.into());

    let healthcheck = match object(svc.get("healthcheck"), &field("healthcheck"))? {
        None => None,
        Some(h) => {
            only(
                h,
                &["test", "interval", "timeout", "retries", "start_period", "start_interval", "disable"],
                &field("healthcheck"),
            )?;
            let test = match boolean(h.get("disable"), &field("healthcheck.disable"))? {
                Some(true) => vec!["NONE".to_string()],
                _ => match h.get("test") {
                    Some(Value::String(s)) => vec!["CMD-SHELL".to_string(), s.clone()],
                    t => texts(t, &field("healthcheck.test"))?,
                },
            };
            Some(Health {
                test,
                interval: duration(h.get("interval"), &field("healthcheck.interval"))?,
                timeout: duration(h.get("timeout"), &field("healthcheck.timeout"))?,
                retries: integer(h.get("retries"), &field("healthcheck.retries"))?,
                start_period: duration(h.get("start_period"), &field("healthcheck.start_period"))?,
                start_interval: duration(h.get("start_interval"), &field("healthcheck.start_interval"))?,
            })
        }
    };

    // Dependencies.
    let mut depends_on = Vec::new();
    for (dep, d) in object(svc.get("depends_on"), &field("depends_on"))?.into_iter().flatten() {
        let empty = Map::new();
        let d = d.as_object().unwrap_or(&empty);
        only(d, &["condition", "required", "restart"], &field("depends_on"))?;
        let required = boolean(d.get("required"), &field("depends_on.required"))?.unwrap_or(true);
        if !x.services.contains_key(dep) {
            if required {
                return Err(format!("{what} depends on {dep}, which the file does not have"));
            }
            continue;
        }
        let condition = match opt_text(d.get("condition"), &field("depends_on.condition"))?.as_deref() {
            None | Some("service_started") => Condition::Started,
            Some("service_healthy") => Condition::Healthy,
            Some("service_completed_successfully") => Condition::CompletedSuccessfully,
            Some(o) => return Err(format!("{what}: the dependency condition {o} is not supported")),
        };
        depends_on.push(Dependency { service: dep.clone(), condition });
    }
    for l in texts(svc.get("links"), &field("links"))? {
        let (target, alias) = l.split_once(':').unwrap_or((&l, &l));
        if target != alias {
            return Err(format!("{what}: the link alias {alias} is not supported (services reach each other by name)"));
        }
        if !depends_on.iter().any(|d| d.service == target) {
            depends_on.push(Dependency { service: target.to_string(), condition: Condition::Started });
        }
    }

    // Networks.
    let network = match opt_text(svc.get("network_mode"), &field("network_mode"))?.as_deref() {
        Some("none") => NetworkMode::None,
        Some(m) if m.starts_with("service:") => NetworkMode::Service(m["service:".len()..].to_string()),
        _ => {
            let mut endpoints = Vec::new();
            let joined: Vec<(String, Option<Map<String, Value>>)> = match svc.get("networks") {
                None | Some(Value::Null) => vec![("default".into(), None)],
                Some(Value::Array(a)) => {
                    a.iter().map(|n| Ok((text(n, &field("networks"))?, None))).collect::<Result<_, String>>()?
                }
                Some(Value::Object(m)) => m
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), object(Some(v), &field("networks"))?.cloned())))
                    .collect::<Result<_, String>>()?,
                Some(_) => return Err(format!("{what}: invalid networks")),
            };
            let mut ordered = Vec::new();
            for (key, cfg) in joined {
                let net = x
                    .networks
                    .iter()
                    .find(|n| !n.key.is_empty() && n.key == key)
                    .ok_or_else(|| format!("{what} joins the network {key}, which the file does not declare"))?;
                let cfg = cfg.unwrap_or_default();
                only(&cfg, &["aliases", "priority"], &format!("{what}: network {key}"))?;
                let priority = integer(cfg.get("priority"), &field("networks.priority"))?.unwrap_or(0);
                let mut aliases = vec![name.to_string()];
                aliases.extend(texts(cfg.get("aliases"), &field("networks.aliases"))?);
                ordered.push((-priority, key, Endpoint { network: net.name.clone(), aliases }));
            }
            ordered.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
            endpoints.extend(ordered.into_iter().map(|(_, _, e)| e));
            // The environment network, where the router reaches the service by its Deploy alias only (a service
            // name there would answer for another application's service of the same name).
            endpoints.push(Endpoint { network: c.network.clone(), aliases: vec![service_alias(&c.resource, name)] });
            NetworkMode::Networks(endpoints)
        }
    };

    // Mounts.
    let mut mounts = Vec::new();
    for m in svc.get("volumes").and_then(Value::as_array).into_iter().flatten() {
        let m = m.as_object().ok_or_else(|| format!("{what}: invalid volumes"))?;
        only(
            m,
            &["type", "source", "target", "read_only", "volume", "tmpfs", "image", "consistency"],
            &field("volumes"),
        )?;
        let target =
            opt_text(m.get("target"), &field("volumes"))?.ok_or_else(|| format!("{what}: a mount without target"))?;
        let read_only = boolean(m.get("read_only"), &field("volumes.read_only"))?.unwrap_or(false);
        let source = opt_text(m.get("source"), &field("volumes.source"))?;
        mounts.push(match m.get("type").and_then(Value::as_str) {
            Some("volume") => {
                let o = object(m.get("volume"), &field("volumes.volume"))?.cloned().unwrap_or_default();
                only(&o, &["nocopy", "subpath"], &field("volumes.volume"))?;
                let source =
                    match source {
                        Some(key) => {
                            Some(x.volumes.iter().find(|v| v.key == key).map(|v| v.name.clone()).ok_or_else(|| {
                                format!("{what}: the volume {key}, not declared by the file, is refused")
                            })?)
                        }
                        None => None,
                    };
                MountSpec::Volume {
                    source,
                    target,
                    read_only,
                    nocopy: boolean(o.get("nocopy"), &field("volumes.volume.nocopy"))?.unwrap_or(false),
                    subpath: opt_text(o.get("subpath"), &field("volumes.volume.subpath"))?,
                }
            }
            Some("tmpfs") => {
                let o = object(m.get("tmpfs"), &field("volumes.tmpfs"))?.cloned().unwrap_or_default();
                only(&o, &["size", "mode"], &field("volumes.tmpfs"))?;
                MountSpec::Tmpfs {
                    target,
                    size: bytes(o.get("size"), &field("volumes.tmpfs.size"))?,
                    mode: integer(o.get("mode"), &field("volumes.tmpfs.mode"))?,
                }
            }
            Some("image") => {
                let o = object(m.get("image"), &field("volumes.image"))?.cloned().unwrap_or_default();
                only(&o, &["subpath"], &field("volumes.image"))?;
                MountSpec::Image {
                    source: source.ok_or_else(|| format!("{what}: an image mount without image"))?,
                    target,
                    subpath: opt_text(o.get("subpath"), &field("volumes.image.subpath"))?,
                }
            }
            t => return Err(format!("{what}: a mount of type {} is refused", t.unwrap_or("(none)"))),
        });
    }
    for v in c.volumes.iter().filter(|v| v.service.as_deref() == Some(name)) {
        mounts.push(MountSpec::Volume {
            source: Some(volume_name(&c.resource, &v.name)),
            target: v.path.clone(),
            read_only: false,
            nocopy: false,
            subpath: None,
        });
    }
    for (p, f) in x.files.iter().filter(|(_, f)| f.service.as_deref() == Some(name)) {
        mounts.push(MountSpec::AgentFile { source: p.to_string_lossy().into_owned(), target: f.path.clone() });
    }
    let mut volumes_from = Vec::new();
    for v in texts(svc.get("volumes_from"), &field("volumes_from"))? {
        let v = v.strip_prefix("service:").unwrap_or(&v);
        let (s, mode) = v.split_once(':').unwrap_or((v, "rw"));
        if !x.services.contains_key(s) {
            return Err(format!("{what}: volumes_from {s}, which the file does not have"));
        }
        volumes_from.push((s.to_string(), mode == "ro"));
    }
    let mut tmpfs = BTreeMap::new();
    for t in texts(svc.get("tmpfs"), &field("tmpfs"))? {
        let (path, opts) = t.split_once(':').unwrap_or((&t, ""));
        tmpfs.insert(path.to_string(), opts.to_string());
    }

    // Secrets and configs, written into the container before it starts.
    let mut injected = Vec::new();
    for (kind, sources, base) in [("secrets", secrets, "/run/secrets/"), ("configs", configs, "/")] {
        for s in svc.get(kind).and_then(Value::as_array).into_iter().flatten() {
            let (source, o) = match s {
                Value::String(s) => (s.clone(), Map::new()),
                Value::Object(o) => {
                    only(o, &["source", "target", "uid", "gid", "mode"], &field(kind))?;
                    (opt_text(o.get("source"), &field(kind))?.unwrap_or_default(), o.clone())
                }
                _ => return Err(format!("{what}: invalid {kind}")),
            };
            let content = sources.get(&source).ok_or_else(|| format!("{what}: {kind} {source} is not declared"))?;
            let target = opt_text(o.get("target"), &field(kind))?.unwrap_or_else(|| source.clone());
            let target = if target.starts_with('/') { target } else { format!("{base}{target}") };
            let mode = match o.get("mode") {
                Some(Value::String(m)) => u32::from_str_radix(m.trim_start_matches("0o"), 8)
                    .map_err(|_| format!("{what}: invalid {kind} mode {m:?}"))?,
                m => integer(m, &field(kind))?.unwrap_or(0o444) as u32,
            };
            let id = |k: &str| integer(o.get(k), &field(kind)).map(|v| v.unwrap_or(0).max(0) as u64);
            injected.push(Injected {
                target,
                content: content.clone(),
                mode: mode & 0o777,
                uid: id("uid")?,
                gid: id("gid")?,
            });
        }
    }

    let logging = match object(svc.get("logging"), &field("logging"))? {
        Some(l) => {
            only(l, &["driver", "options"], &field("logging"))?;
            let driver = opt_text(l.get("driver"), &field("logging.driver"))?.unwrap_or_else(|| "json-file".into());
            if !matches!(driver.as_str(), "json-file" | "local" | "none") {
                return Err(format!(
                    "{what}: the logging driver {driver} is refused (json-file, local or none: the others send logs \
                     from the server)"
                ));
            }
            (driver, strings_map(l.get("options"), &field("logging.options"))?)
        }
        None => {
            ("json-file".into(), BTreeMap::from([("max-size".into(), "20m".into()), ("max-file".into(), "5".into())]))
        }
    };

    let security_opt = texts(svc.get("security_opt"), &field("security_opt"))?;
    if let Some(o) = security_opt.iter().find(|o| {
        !matches!(
            o.replace('=', ":").as_str(),
            "no-new-privileges" | "no-new-privileges:true" | "no-new-privileges:false"
        )
    }) {
        return Err(format!("{what}: security_opt {o} is refused (only no-new-privileges)"));
    }
    let ipc = opt_text(svc.get("ipc"), &field("ipc"))?;
    if let Some(i) = &ipc {
        let ok = matches!(i.as_str(), "private" | "shareable" | "none" | "")
            || i.strip_prefix("service:").is_some_and(|s| x.services.contains_key(s));
        if !ok {
            return Err(format!("{what}: ipc {i} is refused"));
        }
    }
    let container_name = opt_text(svc.get("container_name"), &field("container_name"))?;
    if let Some(n) = &container_name {
        let own = format!("{}-", x.project);
        let valid = !n.is_empty()
            && n.len() <= 128
            && n.starts_with(|ch: char| ch.is_ascii_alphanumeric())
            && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
        if !valid || (n.starts_with("owd-") && !n.starts_with(&own)) {
            return Err(format!("{what}: the container name {n} is refused (names owd-… are Deploy's)"));
        }
        if replicas > 1 {
            return Err(format!("{what}: a container name with more than one replica"));
        }
    }
    let mut expose = Vec::new();
    for e in texts(svc.get("expose"), &field("expose"))? {
        let (ports, proto) = e.split_once('/').unwrap_or((&e, "tcp"));
        let (a, b) = ports.split_once('-').unwrap_or((ports, ports));
        let (a, b): (u16, u16) = match (a.parse(), b.parse()) {
            (Ok(a), Ok(b)) if a <= b && b - a < 1024 => (a, b),
            _ => return Err(format!("{what}: invalid expose {e:?}")),
        };
        expose.extend((a..=b).map(|p| format!("{p}/{proto}")));
    }
    let stop_grace = duration(svc.get("stop_grace_period"), &field("stop_grace_period"))?.map(|ns| ns / 1_000_000_000);
    let entrypoint = match svc.get("entrypoint") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) if a.is_empty() => Some(vec![String::new()]),
        e => Some(texts(e, &field("entrypoint"))?),
    };
    let command = match svc.get("command") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(vec!["/bin/sh".into(), "-c".into(), s.clone()]),
        e => Some(texts(e, &field("command"))?),
    };
    let extra_hosts = texts(svc.get("extra_hosts"), &field("extra_hosts"))?
        .into_iter()
        .map(|h| match h.split_once('=') {
            Some((host, ip)) => format!("{host}:{ip}"),
            None => h,
        })
        .collect();

    Ok(Service {
        name: name.to_string(),
        image,
        build,
        pull,
        platform,
        replicas: replicas as u64,
        container_name,
        depends_on,
        command,
        entrypoint,
        env,
        labels,
        healthcheck,
        restart,
        user: opt_text(svc.get("user"), &field("user"))?,
        working_dir: opt_text(svc.get("working_dir"), &field("working_dir"))?,
        hostname: opt_text(svc.get("hostname"), &field("hostname"))?,
        domainname: opt_text(svc.get("domainname"), &field("domainname"))?,
        tty: boolean(svc.get("tty"), &field("tty"))?.unwrap_or(false),
        stdin_open: boolean(svc.get("stdin_open"), &field("stdin_open"))?.unwrap_or(false),
        init: boolean(svc.get("init"), &field("init"))?,
        read_only: boolean(svc.get("read_only"), &field("read_only"))?.unwrap_or(false),
        tmpfs,
        stop_signal: opt_text(svc.get("stop_signal"), &field("stop_signal"))?,
        stop_grace,
        resources: res,
        cap_add: texts(svc.get("cap_add"), &field("cap_add"))?,
        cap_drop: texts(svc.get("cap_drop"), &field("cap_drop"))?,
        security_opt,
        sysctls: strings_map(svc.get("sysctls"), &field("sysctls"))?,
        extra_hosts,
        dns: texts(svc.get("dns"), &field("dns"))?,
        dns_search: texts(svc.get("dns_search"), &field("dns_search"))?,
        dns_opt: texts(svc.get("dns_opt"), &field("dns_opt"))?,
        group_add: texts(svc.get("group_add"), &field("group_add"))?,
        expose,
        logging,
        network,
        mounts,
        volumes_from,
        ipc,
        files: injected,
    })
}

/// `no`, `always`, `unless-stopped`, `on-failure[:N]`.
fn restart_policy(r: &str) -> Option<(String, Option<i64>)> {
    match r.split_once(':') {
        Some(("on-failure", n)) => Some(("on-failure".into(), Some(n.parse().ok()?))),
        None if matches!(r, "no" | "always" | "unless-stopped" | "on-failure") => Some((r.to_string(), None)),
        _ => None,
    }
}

/// The bake target of a service's build: its context and Dockerfile in the copied repository (or inline project),
/// its arguments, target and labels, nothing else.
fn build_target(name: &str, b: &Map<String, Value>, x: &Context<'_>) -> Result<Value, String> {
    let what = format!("service {name}: build");
    only(b, &BUILD_KEYS, &what)?;
    let c = x.c;
    let context = opt_text(b.get("context"), &what)?.unwrap_or_else(|| ".".into());
    if !project_path(&context) && !remote_context(&context) {
        return Err(format!("{what}: the context {context} is refused (the repository's, or a public URL)"));
    }
    let mut t = json!({"context": context});
    if let Some(df) = opt_text(b.get("dockerfile"), &what)? {
        let ok = match df.starts_with('/') {
            true => project_path(&df),
            false => !df.split('/').any(|p| p == ".."),
        };
        if !ok {
            return Err(format!("{what}: the Dockerfile {df} is outside the repository"));
        }
        t["dockerfile"] = df.into();
    }
    if let Some(inline) = opt_text(b.get("dockerfile_inline"), &what)? {
        t["dockerfile-inline"] = inline.into();
    }
    t["args"] = json!(strings_map(b.get("args"), &what)?);
    if let Some(target) = opt_text(b.get("target"), &what)? {
        t["target"] = target.into();
    }
    let mut labels = strings_map(b.get("labels"), &what)?;
    labels.retain(|k, _| !reserved_label(k));
    labels.insert(LABEL_RESOURCE.into(), c.resource.clone());
    labels.insert(LABEL_DEPLOYMENT.into(), c.deployment.clone());
    t["labels"] = json!(labels);
    t["no-cache"] = (c.no_cache || boolean(b.get("no_cache"), &what)?.unwrap_or(false)).into();
    if let Some(p) = boolean(b.get("pull"), &what)? {
        t["pull"] = p.into();
    }
    if opt_text(b.get("network"), &what)?.as_deref() == Some("none") {
        t["network"] = "none".into();
    }
    let mut contexts = Map::new();
    for (k, v) in strings_map(b.get("additional_contexts"), &what)? {
        let v = match v.strip_prefix("service:") {
            Some(s) if x.services.contains_key(s) => format!("target:{s}"),
            Some(s) => {
                return Err(format!("{what}: the context {k} names the service {s}, which the file does not have"));
            }
            None if project_path(&v) || remote_context(&v) || v.starts_with("docker-image://") => v,
            None => return Err(format!("{what}: the context {k} ({v}) is refused")),
        };
        contexts.insert(k, v.into());
    }
    if !contexts.is_empty() {
        t["contexts"] = Value::Object(contexts);
    }
    Ok(t)
}

/// The services with every service before those that need it ([`Service::needs`]); a cycle is refused.
fn order(services: Vec<Service>) -> Result<Vec<Service>, String> {
    let names: BTreeSet<String> = services.iter().map(|s| s.name.clone()).collect();
    for s in &services {
        if let Some(n) = s.needs().into_iter().find(|n| !names.contains(*n)) {
            return Err(format!("service {} needs {n}, which the file does not have", s.name));
        }
    }
    let mut left: BTreeMap<String, Service> = services.into_iter().map(|s| (s.name.clone(), s)).collect();
    let mut out: Vec<Service> = Vec::new();
    while !left.is_empty() {
        let ready: Vec<String> = left
            .values()
            .filter(|s| s.needs().iter().all(|n| out.iter().any(|o| o.name == *n)))
            .map(|s| s.name.clone())
            .collect();
        if ready.is_empty() {
            let stuck: Vec<&str> = left.keys().map(String::as_str).collect();
            return Err(format!("the services {} depend on each other in a cycle", stuck.join(", ")));
        }
        for n in ready {
            out.push(left.remove(&n).expect("listed"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deploy_proto::msg::{ComposeSource, LABEL_ENVIRONMENT, Route, VolumeMount};

    fn spec() -> ComposeDeploy {
        ComposeDeploy {
            resource: "app_01C".into(),
            deployment: "dep_01X".into(),
            network: "owd-env".into(),
            source: ComposeSource::Inline { content: String::new() },
            env: BTreeMap::from([("GREETING".to_string(), "hi".to_string())]),
            volumes: vec![VolumeMount { name: "data".into(), path: "/data".into(), service: Some("db".into()) }],
            files: vec![],
            labels: BTreeMap::from([(LABEL_ENVIRONMENT.to_string(), "env".to_string())]),
            routes: vec![Route {
                listen: Some(20001),
                hosts: vec!["a.com".into()],
                service: Some("web".into()),
                port: 80,
                tls: false,
            }],
            no_cache: false,
            egress: None,
            registry_auth: Vec::new(),
        }
    }

    fn svc<'a>(p: &'a Plan, name: &str) -> &'a Service {
        p.services.iter().find(|s| s.name == name).unwrap()
    }

    #[test]
    fn plan_routes_through_the_environment_network_without_host_ports() {
        let model = json!({
            "name": "x",
            "services": {
                "web": {"image": "nginx", "ports": [{"target": 80, "published": "8080"}], "environment": {"GREETING": "file"},
                        "networks": {"default": null}, "labels": {"dev.openwaf.deploy.resource": "app_other", "com.docker.compose.project": "x", "keep": "me"}},
                "db": {"build": {"context": "/src/db"}, "image": "postgres:17", "restart": "always",
                       "networks": ["default", "back"]},
                "side": {"image": "busybox", "network_mode": "service:web"},
                "worker": {"image": "busybox", "network_mode": "bridge"}
            },
            "networks": {"default": {"name": "owd-app_01c_default", "ipam": {}}, "back": {}}
        });
        let files = [(
            PathBuf::from("/state/files/app_01c/dep_01x/0"),
            &FileMount { path: "/etc/x".into(), content: "x".into(), service: Some("web".into()) },
        )];
        let mut c = spec();
        c.files = vec![files[0].1.clone()];
        let p = Plan::new(model, &c, &files).unwrap();
        assert_eq!(p.project, "owd-app_01c");
        let web = svc(&p, "web");
        assert_eq!(web.env["GREETING"], "hi", "the application's variables win");
        assert_eq!(web.labels[LABEL_RESOURCE], "app_01C", "the agent's labels are its own");
        assert_eq!(web.labels[COMPOSE_PROJECT], "owd-app_01c");
        assert_eq!(web.labels[COMPOSE_SERVICE], "web");
        assert_eq!(web.labels[LABEL_ENVIRONMENT], "env");
        assert_eq!(web.labels["keep"], "me");
        assert_eq!(web.restart, ("unless-stopped".to_string(), None));
        assert_eq!(web.logging.0, "json-file");
        let NetworkMode::Networks(eps) = &web.network else { panic!() };
        assert_eq!(eps[0], Endpoint { network: "owd-app_01c_default".into(), aliases: vec!["web".into()] });
        assert_eq!(eps[1], Endpoint { network: "owd-env".into(), aliases: vec!["owd-app_01c-web".into()] });
        assert_eq!(
            web.mounts,
            [MountSpec::AgentFile { source: "/state/files/app_01c/dep_01x/0".into(), target: "/etc/x".into() }]
        );
        let db = svc(&p, "db");
        assert_eq!(db.restart, ("always".to_string(), None));
        assert_eq!(db.image, "owd/app_01c:dep_01x-db", "a build never replaces another image");
        assert_eq!(db.build.as_ref().unwrap()["labels"][LABEL_RESOURCE], "app_01C");
        assert_eq!(db.build.as_ref().unwrap()["context"], "/src/db");
        let NetworkMode::Networks(eps) = &db.network else { panic!() };
        let nets: Vec<&str> = eps.iter().map(|e| e.network.as_str()).collect();
        assert_eq!(nets, ["owd-app_01c_back", "owd-app_01c_default", "owd-env"]);
        assert_eq!(
            db.mounts,
            [MountSpec::Volume {
                source: Some("owd-app_01c-data".into()),
                target: "/data".into(),
                read_only: false,
                nocopy: false,
                subpath: None
            }]
        );
        assert_eq!(svc(&p, "side").network, NetworkMode::Service("web".into()), "shares web's network stack");
        let NetworkMode::Networks(eps) = &svc(&p, "worker").network else {
            panic!("Docker's default bridge is not a Deploy network")
        };
        assert_eq!(eps[0].network, "owd-app_01c_default");
        // The project's networks get bridges the firewall's `owd+` rules cover, and the project's labels.
        for (key, name) in [("default", "owd-app_01c_default"), ("back", "owd-app_01c_back")] {
            let n = p.networks.iter().find(|n| n.key == key).unwrap();
            assert_eq!(n.name, name);
            assert!(!n.external);
            assert_eq!(n.options[crate::firewall::BRIDGE_OPTION], crate::firewall::bridge_name(name));
            assert_eq!(n.labels[COMPOSE_PROJECT], "owd-app_01c");
            assert_eq!(n.labels[COMPOSE_NETWORK], key);
        }
        assert!(p.networks.iter().any(|n| n.name == "owd-env" && n.external));
        assert!(p.volumes.iter().any(|v| v.name == "owd-app_01c-data" && v.external));
        let (bake, targets) = p.bake_file().unwrap();
        assert_eq!(targets, ["db"]);
        assert_eq!(bake["target"]["db"]["context"], "/src/db");
        // Every deployment recreates the services (its labels change), and a same plan hashes the same.
        let mut c2 = spec();
        c2.deployment = "dep_02".into();
        let model = json!({"services": {"web": {"image": "nginx"}, "db": {"image": "postgres"}}});
        let a = Plan::new(model.clone(), &spec(), &[]).unwrap();
        assert_eq!(svc(&a, "web").hash(), svc(&Plan::new(model.clone(), &spec(), &[]).unwrap(), "web").hash());
        assert_ne!(svc(&a, "web").hash(), svc(&Plan::new(model, &c2, &[]).unwrap(), "web").hash());
    }

    #[test]
    fn dependencies_start_first_with_their_conditions_and_cycles_are_refused() {
        let mut c = spec();
        c.volumes.clear();
        c.routes.clear();
        let model = json!({"services": {
            "web": {"image": "x", "depends_on": {"api": {"condition": "service_healthy", "required": true},
                                                 "gone": {"condition": "service_started", "required": false}}},
            "api": {"image": "x", "depends_on": {"migrate": {"condition": "service_completed_successfully"}, "db": {}}},
            "migrate": {"image": "x", "depends_on": {"db": {"condition": "service_healthy"}}},
            "db": {"image": "x", "healthcheck": {"test": ["CMD-SHELL", "pg_isready"], "interval": "1m30s", "timeout": "500ms"}},
            "cache": {"image": "x", "network_mode": "service:db"},
            "logs": {"image": "x", "volumes_from": ["api:ro"], "ipc": "service:cache"},
        }});
        let p = Plan::new(model, &c, &[]).unwrap();
        let order: Vec<&str> = p.services.iter().map(|s| s.name.as_str()).collect();
        let pos = |n: &str| order.iter().position(|x| *x == n).unwrap();
        for (before, after) in [
            ("db", "migrate"),
            ("migrate", "api"),
            ("db", "api"),
            ("api", "web"),
            ("db", "cache"),
            ("api", "logs"),
            ("cache", "logs"),
        ] {
            assert!(pos(before) < pos(after), "{before} before {after}: {order:?}");
        }
        assert_eq!(
            svc(&p, "web").depends_on,
            [Dependency { service: "api".into(), condition: Condition::Healthy }],
            "an optional dependency the file lacks is skipped"
        );
        assert_eq!(
            svc(&p, "api").depends_on[1],
            Dependency { service: "migrate".into(), condition: Condition::CompletedSuccessfully }
        );
        let h = svc(&p, "db").healthcheck.clone().unwrap();
        assert_eq!((h.interval, h.timeout), (Some(90_000_000_000), Some(500_000_000)));
        assert_eq!(svc(&p, "logs").volumes_from, [("api".to_string(), true)]);

        let cycle = json!({"services": {"a": {"image": "x", "depends_on": {"b": {}}}, "b": {"image": "x", "network_mode": "service:a"}}});
        assert!(Plan::new(cycle, &c, &[]).unwrap_err().contains("cycle"));
        let missing = json!({"services": {"a": {"image": "x", "depends_on": {"b": {"required": true}}}}});
        assert!(Plan::new(missing, &c, &[]).unwrap_err().contains("depends on b"));
    }

    /// Fields the agent does not model are refused by name, never silently dropped or passed on.
    #[test]
    fn unmodelled_fields_are_refused() {
        let mut c = spec();
        c.volumes.clear();
        let refused = |svc: Value, root: Value, needle: &str| {
            let mut m = json!({"services": {"web": {"image": "nginx"}, "db": svc}});
            for (k, v) in root.as_object().unwrap() {
                m[k] = v.clone();
            }
            let e = Plan::new(m.clone(), &c, &[]).err().unwrap_or_else(|| panic!("accepted: {m}"));
            assert!(e.contains(needle), "{e} (wanted {needle})");
        };
        let none = json!({});
        for (key, value) in [
            ("pid", json!("service:web")),
            ("uts", json!("private")),
            ("runtime", json!("runc")),
            ("cgroup_parent", json!("/x")),
            ("oom_kill_disable", json!(true)),
            ("gpus", json!("all")),
            ("annotations", json!({"a": "b"})),
            ("external_links", json!(["other"])),
            ("post_start", json!([{"command": "x"}])),
            ("use_api_socket", json!(true)),
            ("storage_opt", json!({"size": "1G"})),
        ] {
            refused(json!({"image": "x", key: value}), none.clone(), &format!("`{key}`"));
        }
        refused(json!({"image": "x", "security_opt": ["apparmor=custom"]}), none.clone(), "security_opt");
        refused(
            json!({"image": "x", "logging": {"driver": "syslog", "options": {"syslog-address": "udp://192.0.2.1:514"}}}),
            none.clone(),
            "syslog",
        );
        refused(
            json!({"image": "x", "networks": {"default": {"ipv4_address": "192.0.2.5"}}}),
            none.clone(),
            "`ipv4_address`",
        );
        refused(
            json!({"image": "x"}),
            json!({"networks": {"default": {"ipam": {"config": [{"subnet": "198.51.100.0/24"}]}}}}),
            "IPAM",
        );
        refused(json!({"image": "x", "container_name": "owd-router"}), none.clone(), "container name");
        refused(json!({"image": "x", "container_name": "owd-app_02-db"}), none.clone(), "container name");
        refused(
            json!({"image": "x", "deploy": {"resources": {"reservations": {"devices": [{"capabilities": ["gpu"]}]}}}}),
            none.clone(),
            "`devices`",
        );
        refused(json!({"image": "x", "deploy": {"mode": "global"}}), none.clone(), "global");
        refused(json!({"build": {"context": "/src", "tags": ["caddy:2"]}}), none.clone(), "`tags`");
        refused(json!({"build": {"context": "/src", "secrets": ["s"]}}), none.clone(), "`secrets`");
        refused(json!({"build": {"context": "/src", "cache_to": ["type=registry"]}}), none.clone(), "`cache_to`");
        refused(json!({"build": {"context": "/etc"}}), none.clone(), "context /etc");
        refused(json!({"build": {"context": "/src/../etc"}}), none.clone(), "context");
        refused(
            json!({"build": {"context": "/src", "dockerfile": "/etc/passwd"}}),
            none.clone(),
            "outside the repository",
        );
        refused(
            json!({"build": {"context": "/src", "additional_contexts": {"x": "/var/lib"}}}),
            none.clone(),
            "context x",
        );
        refused(
            json!({"image": "x", "secrets": ["s"]}),
            json!({"secrets": {"s": {"environment": "NOT_SET"}}}),
            "NOT_SET",
        );
        refused(json!({"image": "x"}), json!({"models": {}}), "`models`");
        // Still refused as before the plan: escapes from the Deploy networks or into the server.
        refused(json!({"image": "x", "privileged": true}), none.clone(), "privileged");
        refused(json!({"image": "x", "network_mode": "host"}), none.clone(), "network_mode host");
        let bind = json!({"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"});
        refused(json!({"image": "x", "volumes": [bind]}), none.clone(), "/var/run/docker.sock");
        // What is modelled passes.
        let ok = json!({"image": "x", "container_name": "owd-app_01c-db", "user": "1000:1000", "read_only": true,
            "tmpfs": ["/run", "/tmp:size=64m"], "cap_add": ["NET_BIND_SERVICE"], "security_opt": ["no-new-privileges:true"],
            "sysctls": {"net.core.somaxconn": "1024"}, "extra_hosts": ["a.test=203.0.113.4"], "stop_grace_period": "1m30s",
            "mem_limit": "268435456", "cpus": 1, "deploy": {"resources": {"limits": {"pids": 100}}, "placement": {}},
            "ulimits": {"nofile": {"soft": 1024, "hard": 2048}}, "secrets": [{"source": "s", "target": "/run/s", "mode": "0400"}],
            "configs": [{"source": "c", "target": "/etc/c"}], "expose": ["5432"], "x-custom": 1});
        let root = json!({"secrets": {"s": {"environment": "GREETING"}}, "configs": {"c": {"content": "hello"}}});
        let mut m = json!({"services": {"web": {"image": "nginx"}, "db": ok}});
        for (k, v) in root.as_object().unwrap() {
            m[k] = v.clone();
        }
        let p = Plan::new(m, &c, &[]).unwrap();
        let db = svc(&p, "db");
        assert_eq!(
            db.files,
            [
                Injected { target: "/run/s".into(), content: "hi".into(), mode: 0o400, uid: 0, gid: 0 },
                Injected { target: "/etc/c".into(), content: "hello".into(), mode: 0o444, uid: 0, gid: 0 },
            ]
        );
        assert_eq!(
            (db.resources.memory, db.resources.nano_cpus, db.resources.pids),
            (Some(268_435_456), Some(1_000_000_000), Some(100))
        );
        assert_eq!(db.extra_hosts, ["a.test:203.0.113.4"]);
        assert_eq!(db.stop_grace, Some(90));
        assert_eq!(db.container(&p.project, 1), "owd-app_01c-db");
        assert_eq!(svc(&p, "web").container(&p.project, 2), "owd-app_01c-web-2");
    }

    #[test]
    fn routes_and_mounts_name_services_of_the_file() {
        let model = json!({"services": {"web": {"image": "nginx"}}});
        let mut c = spec();
        assert!(Plan::new(model.clone(), &c, &[]).unwrap_err().contains("service db"));
        c.volumes.clear();
        c.routes[0].service = Some("api".into());
        assert!(Plan::new(model.clone(), &c, &[]).unwrap_err().contains("api"));
        c.routes[0].service = Some("web".into());
        assert!(Plan::new(model, &c, &[]).is_ok());
        let none = json!({"services": {"web": {"image": "nginx", "network_mode": "none"}}});
        assert!(Plan::new(none, &c, &[]).unwrap_err().contains("no such service with its own network"));
    }

    #[test]
    fn values_parse_as_compose_writes_them() {
        // `config` writes every literal `$` as `$$` (here: `$$HOME`, `$$$$` and `$${FOO}` in the file).
        let mut c = spec();
        c.volumes.clear();
        c.routes.clear();
        let model = json!({"services": {"a": {"image": "x", "command": ["sh", "-c", "echo $$HOME bar $$$$"],
            "environment": {"X": "p$$w"}, "labels": {"l": "$${FOO}"}}}});
        let p = Plan::new(model, &c, &[]).unwrap();
        let a = svc(&p, "a");
        assert_eq!(a.command.as_deref().unwrap()[2], "echo $HOME bar $$");
        assert_eq!(a.env["X"], "p$w");
        assert_eq!(a.labels["l"], "${FOO}");
        assert_eq!(duration(Some(&json!("1h2m3.5s")), "d"), Ok(Some(3_723_500_000_000)));
        assert_eq!(duration(Some(&json!("0")), "d"), Ok(Some(0)));
        assert!(duration(Some(&json!("5 minutes")), "d").is_err());
        assert_eq!(bytes(Some(&json!("64m")), "b"), Ok(Some(64 << 20)));
        assert_eq!(bytes(Some(&json!("1.5g")), "b"), Ok(Some(3 << 29)));
        assert_eq!(bytes(Some(&json!(1024)), "b"), Ok(Some(1024)));
        assert!(bytes(Some(&json!("12x")), "b").is_err());
        assert_eq!(restart_policy("on-failure:3"), Some(("on-failure".into(), Some(3))));
        assert_eq!(restart_policy("sometimes"), None);
    }
}
