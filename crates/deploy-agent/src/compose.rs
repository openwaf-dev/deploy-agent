//! `DeployCompose`: a Docker Compose application, run by `docker compose -p owd-<resource>` in the builder helper.
//!
//! The agent never edits the user's file. It asks Compose for the resolved project (`config --format json`:
//! interpolated with the application's variables, `env_file`s and overrides merged, paths absolute) and adapts that:
//! every service gets the resource and deployment labels, the application's variables, its volumes and files, and
//! joins the environment network as `owd-<resource>-<service>` (the router's upstream); host `ports:` are dropped,
//! so traffic only arrives through the router. That adapted project is what `docker compose up` runs.
//!
//! The clone and `config` run in a source helper without the Engine's socket; the build helper, which holds it, only
//! gets the cloned tree and the adapted project.

use std::collections::BTreeSet;
use std::path::PathBuf;

use deploy_proto::msg::{
    ComposeDeploy, ComposeOutput, ComposeService, ComposeSource, FileMount, LABEL_DEPLOYMENT, LABEL_ENVIRONMENT,
    LABEL_RESOURCE, Step,
};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use crate::builder::Helper;
use crate::docker::{COMPOSE_PROJECT, COMPOSE_SERVICE, File, client, labelled, valid_id};
use crate::events::Events;
use crate::git::{self, Credentials, Repo};
use crate::router::{self, Upstream, service_alias};
use crate::volumes::{self, volume_name};

/// Largest resolved Compose project read back from the helper.
const MAX_CONFIG_BYTES: usize = 4 << 20;
/// How long `up --wait` waits for the services to run (or be healthy).
const WAIT_SECS: u32 = 300;

pub fn project(resource: &str) -> String {
    format!("owd-{}", resource.to_ascii_lowercase())
}

/// Key of the environment network in the adapted project.
const ENV_NETWORK: &str = "owd_environment";

/// Builds the services with a `build:` on the rootless builder (see [`crate::builder`]).
const BUILD_SCRIPT: &str = r#"set -eu
if [ "$OWD_NO_CACHE" = 1 ]; then set -- --no-cache; else set --; fi
docker compose -p "$OWD_PROJECT" -f /owd/compose.json --progress plain build --builder "$OWD_BUILDER" "$@"
"#;

const UP_SCRIPT: &str = r#"set -eu
docker compose -p "$OWD_PROJECT" -f /owd/compose.json --progress plain up -d --no-build --remove-orphans \
  --wait --wait-timeout "$OWD_WAIT"
"#;

/// Adapts the resolved project. Returns it with its service names. What would take a service out of the
/// firewall's reach or into the server's is refused first ([`refuse_escapes`]).
pub fn adapt(
    mut model: Value,
    c: &ComposeDeploy,
    files: &[(PathBuf, &FileMount)],
) -> Result<(Value, BTreeSet<String>), String> {
    let project = project(&c.resource);
    refuse_escapes(&model, &c.resource)?;
    let root = model.as_object_mut().ok_or("the Compose project is not an object")?;
    root.insert("name".into(), json!(project));
    let services = root.get_mut("services").and_then(Value::as_object_mut).ok_or("the Compose file has no services")?;
    let names: BTreeSet<String> = services.keys().cloned().collect();
    for n in &names {
        if !valid_id(n) {
            return Err(format!("service name {n:?}: use letters, digits, '-' and '_'"));
        }
    }
    let mut joined = BTreeSet::new();
    let mut referenced = BTreeSet::new();
    for (name, svc) in services.iter_mut() {
        let svc = svc.as_object_mut().ok_or_else(|| format!("service {name} is not an object"))?;
        // Traffic arrives through the router only.
        svc.remove("ports");
        let labels = object(svc, "labels")?;
        for (k, v) in &c.labels {
            labels.insert(k.clone(), json!(v));
        }
        labels.insert(LABEL_RESOURCE.into(), json!(c.resource));
        labels.insert(LABEL_DEPLOYMENT.into(), json!(c.deployment));
        let env = object(svc, "environment")?;
        for (k, v) in &c.env {
            env.insert(k.clone(), json!(v));
        }
        svc.entry("restart").or_insert(json!("unless-stopped"));
        svc.entry("logging").or_insert(json!({"driver": "json-file", "options": {"max-size": "20m", "max-file": "5"}}));
        if let Some(build) = svc.get_mut("build").and_then(Value::as_object_mut) {
            let l = build.entry("labels").or_insert(json!({}));
            if let Some(l) = l.as_object_mut() {
                l.insert(LABEL_RESOURCE.into(), json!(c.resource));
                l.insert(LABEL_DEPLOYMENT.into(), json!(c.deployment));
            }
            // Built images live in the application's repository, like a Dockerfile application's (prune, remove),
            // whatever the file names them: a build never replaces an image of someone else.
            svc.insert(
                "image".into(),
                json!(format!(
                    "owd/{}:{}-{}",
                    c.resource.to_ascii_lowercase(),
                    c.deployment.to_ascii_lowercase(),
                    name.to_ascii_lowercase()
                )),
            );
        }
        // Docker's default bridge is not a Deploy network: such a service joins the application's networks.
        if svc.get("network_mode").and_then(Value::as_str) == Some("bridge") {
            svc.remove("network_mode");
        }
        // A service sharing another's network stack (or none) cannot join a network.
        let own_network = svc.get("network_mode").is_none_or(Value::is_null);
        if own_network {
            let nets = match svc.remove("networks") {
                None | Some(Value::Null) => json!({"default": null}),
                Some(Value::Array(list)) => Value::Object(
                    list.into_iter().filter_map(|n| Some((n.as_str()?.to_string(), Value::Null))).collect(),
                ),
                Some(v) => v,
            };
            let mut nets = match nets {
                Value::Object(m) => m,
                _ => return Err(format!("service {name}: invalid networks")),
            };
            for key in nets.keys() {
                referenced.insert(key.clone());
            }
            nets.insert(ENV_NETWORK.into(), json!({"aliases": [service_alias(&c.resource, name)]}));
            svc.insert("networks".into(), Value::Object(nets));
            joined.insert(name.clone());
        }
        let mounts = svc.entry("volumes").or_insert(json!([]));
        let mounts = mounts.as_array_mut().ok_or_else(|| format!("service {name}: invalid volumes"))?;
        for v in c.volumes.iter().filter(|v| v.service.as_deref() == Some(name)) {
            mounts.push(json!({"type": "volume", "source": volume_name(&c.resource, &v.name), "target": v.path}));
        }
        for (p, f) in files.iter().filter(|(_, f)| f.service.as_deref() == Some(name)) {
            mounts.push(json!({"type": "bind", "source": p.to_string_lossy(), "target": f.path, "read_only": true}));
        }
    }
    for m in
        c.volumes.iter().filter_map(|v| v.service.as_ref()).chain(c.files.iter().filter_map(|f| f.service.as_ref()))
    {
        if !names.contains(m) {
            return Err(format!("a mount names the service {m}, which the Compose file does not have"));
        }
    }
    for r in &c.routes {
        let s = r.service.as_deref().ok_or("each route of a Compose application names its service")?;
        if !joined.contains(s) {
            return Err(format!("the route to {s}: no such service with its own network"));
        }
    }
    let nets = object(root, "networks")?;
    // The project's own networks (those Compose creates): bridges named for the firewall's `owd+` guard from
    // their creation on, without IPv6.
    for key in referenced {
        nets.entry(key.clone()).or_insert_with(|| json!({}));
    }
    for (key, n) in nets.iter_mut() {
        if n.is_null() {
            *n = json!({});
        }
        let n = n.as_object_mut().ok_or_else(|| format!("network {key} is not a map"))?;
        if is_external(n.get("external")) {
            continue;
        }
        let name = n.get("name").and_then(Value::as_str).map_or_else(|| format!("{project}_{key}"), str::to_string);
        let opts = object(n, "driver_opts")?;
        opts.insert(crate::firewall::BRIDGE_OPTION.into(), json!(crate::firewall::bridge_name(&name)));
        n.insert("name".into(), json!(name));
        n.insert("driver".into(), json!("bridge"));
        n.insert("enable_ipv6".into(), json!(false));
    }
    nets.insert(ENV_NETWORK.into(), json!({"name": c.network, "external": true}));
    let vols = object(root, "volumes")?;
    for v in &c.volumes {
        let n = volume_name(&c.resource, &v.name);
        vols.insert(n.clone(), json!({"name": n, "external": true}));
    }
    Ok((model, names))
}

/// The map at `key` (created empty when missing or null).
fn object<'a>(m: &'a mut Map<String, Value>, key: &str) -> Result<&'a mut Map<String, Value>, String> {
    let v = m.entry(key).or_insert(json!({}));
    if v.is_null() {
        *v = json!({});
    }
    v.as_object_mut().ok_or_else(|| format!("{key} is not a map"))
}

/// `external: true` (or the older `external: {name: …}`).
fn is_external(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)) | Some(Value::Object(_)))
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

fn validate(c: &ComposeDeploy) -> Result<(), String> {
    if !valid_id(&c.resource) || !valid_id(&c.deployment) {
        return Err("invalid resource or deployment id".into());
    }
    if !crate::deploy::name_ok(&c.network) {
        return Err("invalid network".into());
    }
    crate::deploy::check_network_name(&c.network)?;
    crate::deploy::check_env(&c.env)?;
    router::normalize(&c.routes)?;
    volumes::validate(&c.volumes, &c.files, true)
}

pub async fn deploy(c: &ComposeDeploy, ev: &Events, cancel: &CancellationToken) -> Result<ComposeOutput, String> {
    validate(c)?;
    let d = client()?;
    let project = project(&c.resource);
    crate::deploy::ensure_network(&d, &c.network, c.labels.get(LABEL_ENVIRONMENT).map(String::as_str)).await?;
    volumes::ensure(&d, &c.resource, &c.volumes).await?;
    let previous = crate::docker::app_containers(&d, &c.resource)
        .await?
        .first()
        .and_then(|x| x.labels.as_ref()?.get(LABEL_DEPLOYMENT).cloned());
    let files = volumes::write_files(&c.resource, &c.deployment, &c.files)?;
    ev.step(Step::Fetching).await;
    // Repository content and the Compose file are handled in a helper without the Engine's socket; the helper with
    // it only gets the cloned tree and the project the agent checked.
    let src = match Helper::source(&d, &c.resource, ev).await {
        Ok(s) => s,
        Err(e) => {
            volumes::prune_files(&c.resource, previous.as_deref());
            return Err(e);
        }
    };
    let h = match Helper::start(&d, &c.resource, ev).await {
        Ok(h) => h,
        Err(e) => {
            src.remove().await;
            volumes::prune_files(&c.resource, previous.as_deref());
            return Err(e);
        }
    };
    let r = run(&src, &h, c, &project, &files, ev, cancel).await;
    src.remove().await;
    h.remove().await;
    let (commit, known_hosts) = match r {
        Ok(x) => x,
        Err(e) => {
            // The services that run still use the previous deployment's files.
            volumes::prune_files(&c.resource, previous.as_deref());
            return Err(e);
        }
    };
    ev.step(Step::Switching).await;
    router::switch(&d, &c.resource, &c.network, Upstream::Compose, c.routes.clone(), Some(ev)).await?;
    ev.step(Step::Cleaning).await;
    volumes::prune_files(&c.resource, Some(&c.deployment));
    let mut services: Vec<ComposeService> = labelled(&d, COMPOSE_PROJECT, &project)
        .await?
        .into_iter()
        .map(|x| ComposeService {
            service: x.labels.as_ref().and_then(|l| l.get(COMPOSE_SERVICE)).cloned().unwrap_or_default(),
            container_id: x.id.unwrap_or_default(),
            image: x.image.unwrap_or_default(),
            state: x.state.map(|s| s.to_string()).unwrap_or_default(),
        })
        .collect();
    services.sort_by(|a, b| a.service.cmp(&b.service));
    for s in &services {
        ev.system(format!("{}: {}", s.service, s.state)).await;
    }
    Ok(ComposeOutput { project, services, commit, known_hosts })
}

async fn run(
    src: &Helper,
    h: &Helper,
    c: &ComposeDeploy,
    project: &str,
    files: &[(PathBuf, &FileMount)],
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(Option<String>, Vec<String>), String> {
    let (file, dir, fetched, known_hosts) = match &c.source {
        ComposeSource::Git { url, reference, auth, ssh, file } => {
            let path = git::inside(file, "Compose file")?;
            if path.is_empty() {
                return Err("the Compose file path is empty".into());
            }
            let repo = Repo {
                url,
                reference,
                creds: Credentials::of(auth.as_ref(), ssh.as_ref()),
                commit: None,
                untrusted: false,
            };
            let cloned = src.clone(&repo, ev, cancel).await?;
            let dir = match path.rsplit_once('/') {
                Some((d, _)) => format!("/src/{d}"),
                None => "/src".to_string(),
            };
            (format!("/src/{path}"), dir, Some(cloned.info()), cloned.known_hosts)
        }
        ComposeSource::Inline { content } => {
            let file = [File { path: "project/compose.yaml", data: content.as_bytes(), mode: 0o600 }];
            src.put(&file).await?;
            // The project's directory, which relative build contexts (`dockerfile_inline`) resolve to.
            h.put(&file).await?;
            ("/owd/project/compose.yaml".to_string(), "/owd/project".to_string(), None, Vec::new())
        }
    };
    let commit = fetched.as_ref().map(|i| i.sha.clone());
    match fetched {
        Some(info) => ev.step_after_fetch(Step::Building, info).await,
        None => ev.step(Step::Building).await,
    }
    let cmd: Vec<String> =
        ["docker", "compose", "-p", project, "-f", &file, "--project-directory", &dir, "config", "--format", "json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    // The application's variables interpolate the file; they reach Compose as its environment, not argv.
    let env: Vec<String> = c.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let (code, out) = src.output(cmd, env, MAX_CONFIG_BYTES, ev, cancel).await?;
    if code != 0 {
        return Err(format!("the Compose file is invalid (exit code {code})"));
    }
    let model: Value = serde_json::from_slice(&out).map_err(|e| format!("docker compose config: {e}"))?;
    let (model, services) = adapt(model, c, files)?;
    if matches!(c.source, ComposeSource::Git { .. }) {
        // Build contexts and Dockerfiles of the services are files of the repository.
        h.copy_from(src, "/src", cancel).await?;
    }
    src.remove().await;
    let list: Vec<&str> = services.iter().map(String::as_str).collect();
    ev.system(format!("Services: {}", list.join(", "))).await;
    let text = serde_json::to_vec_pretty(&model).expect("project");
    h.put(&[File { path: "compose.json", data: &text, mode: 0o600 }]).await?;
    let base = vec![format!("OWD_PROJECT={project}"), format!("OWD_NO_CACHE={}", u8::from(c.no_cache))];
    if model["services"].as_object().is_some_and(|s| s.values().any(|s| s.get("build").is_some())) {
        let builder = crate::builder::Builder::Trusted;
        crate::builder::ensure_builder(h, builder, ev, cancel).await?;
        ev.system(format!("Building on the rootless BuildKit builder {}", builder.name())).await;
        let mut env = base.clone();
        env.push(format!("OWD_BUILDER={}", builder.name()));
        let code = h.sh(BUILD_SCRIPT, env, ev, cancel, &mut |_, _| true).await?;
        crate::builder::prune_cache(h, builder, ev, cancel).await;
        if code != 0 {
            return Err(format!("docker compose build failed (exit code {code})"));
        }
    }
    ev.step(Step::Starting).await;
    let mut env = base;
    env.push(format!("OWD_WAIT={WAIT_SECS}"));
    let code = h.sh(UP_SCRIPT, env, ev, cancel, &mut |_, _| true).await?;
    if code != 0 {
        return Err(format!("docker compose up failed (exit code {code})"));
    }
    Ok((commit, known_hosts))
}

/// Services of a Compose application by container, for logs and exec (`service` label).
pub fn service_of(c: &bollard::models::ContainerSummary) -> Option<&str> {
    c.labels.as_ref()?.get(COMPOSE_SERVICE).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deploy_proto::msg::{Route, VolumeMount};
    use std::collections::BTreeMap;

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
        }
    }

    #[test]
    fn adapt_routes_through_the_environment_network_without_host_ports() {
        let model = json!({
            "name": "x",
            "services": {
                "web": {"image": "nginx", "ports": [{"target": 80, "published": "8080"}], "environment": {"GREETING": "file"},
                        "networks": {"default": null}},
                "db": {"build": {"context": "/src/db"}, "image": "postgres:17", "restart": "always",
                       "networks": ["default", "back"]},
                "side": {"image": "busybox", "network_mode": "service:web"},
                "worker": {"image": "busybox", "network_mode": "bridge"}
            },
            "networks": {"default": {"name": "owd-app_01c_default"}, "back": {}}
        });
        let (m, names) = adapt(model, &spec(), &[]).unwrap();
        assert_eq!(names.into_iter().collect::<Vec<_>>(), ["db", "side", "web", "worker"]);
        assert_eq!(m["name"], "owd-app_01c");
        let web = &m["services"]["web"];
        assert!(web.get("ports").is_none());
        assert_eq!(web["environment"]["GREETING"], "hi", "the application's variables win");
        assert_eq!(web["labels"][LABEL_RESOURCE], "app_01C");
        assert_eq!(web["labels"][LABEL_ENVIRONMENT], "env");
        assert_eq!(web["networks"][ENV_NETWORK]["aliases"], json!(["owd-app_01c-web"]));
        assert!(web["networks"].as_object().unwrap().contains_key("default"));
        assert_eq!(web["restart"], "unless-stopped");
        let db = &m["services"]["db"];
        assert_eq!(db["restart"], "always");
        assert_eq!(db["image"], "owd/app_01c:dep_01x-db", "a build never replaces another image");
        assert_eq!(db["build"]["labels"][LABEL_RESOURCE], "app_01C");
        assert!(db["networks"].as_object().unwrap().contains_key("back"));
        assert_eq!(db["volumes"], json!([{"type": "volume", "source": "owd-app_01c-data", "target": "/data"}]));
        assert!(m["services"]["side"].get("networks").is_none(), "shares web's network stack");
        let worker = &m["services"]["worker"];
        assert!(worker.get("network_mode").is_none(), "Docker's default bridge is not a Deploy network");
        assert!(worker["networks"].as_object().unwrap().contains_key("default"));
        assert_eq!(m["networks"][ENV_NETWORK], json!({"name": "owd-env", "external": true}));
        assert_eq!(m["volumes"]["owd-app_01c-data"], json!({"name": "owd-app_01c-data", "external": true}));
        // The project's networks get bridges the firewall's `owd+` rules cover, and no IPv6.
        for (key, name) in [("default", "owd-app_01c_default"), ("back", "owd-app_01c_back")] {
            let n = &m["networks"][key];
            assert_eq!(n["name"], name);
            assert_eq!(n["enable_ipv6"], false);
            assert_eq!(n["driver"], "bridge");
            assert_eq!(n["driver_opts"][crate::firewall::BRIDGE_OPTION], crate::firewall::bridge_name(name));
        }
    }

    /// A Compose file cannot take a service off the Deploy networks, into the server's namespaces or files, or
    /// to another application's volumes.
    #[test]
    fn adapt_refuses_escapes() {
        let mut c = spec();
        c.volumes.clear();
        let with = |svc: Value, root: Value| {
            let mut m = json!({"services": {"web": {"image": "nginx"}, "db": svc}});
            for (k, v) in root.as_object().unwrap() {
                m[k] = v.clone();
            }
            adapt(m, &c, &[])
        };
        let ok = |svc: Value, root: Value| with(svc, root).map(|_| ()).map_err(|e| e.to_string());
        let refused = |svc: Value, root: Value, needle: &str| {
            let e = with(svc.clone(), root.clone()).err().unwrap_or_else(|| panic!("accepted: {svc} {root}"));
            assert!(e.contains(needle), "{e} (wanted {needle})");
        };
        let none = json!({});
        assert_eq!(ok(json!({"image": "postgres"}), none.clone()), Ok(()));
        refused(json!({"image": "x", "network_mode": "host"}), none.clone(), "network_mode host");
        refused(json!({"image": "x", "network_mode": "container:owd-router"}), none.clone(), "container:owd-router");
        refused(json!({"image": "x", "network_mode": "service:nope"}), none.clone(), "service:nope");
        assert_eq!(ok(json!({"image": "x", "network_mode": "service:web"}), none.clone()), Ok(()));
        refused(json!({"image": "x", "privileged": true}), none.clone(), "privileged");
        for cap in ["SYS_ADMIN", "cap_net_admin", "ALL"] {
            refused(json!({"image": "x", "cap_add": [cap]}), none.clone(), "cap_add");
        }
        assert_eq!(ok(json!({"image": "x", "cap_add": ["NET_BIND_SERVICE"]}), none.clone()), Ok(()));
        refused(json!({"image": "x", "pid": "host"}), none.clone(), "pid: host");
        refused(json!({"image": "x", "ipc": "host"}), none.clone(), "ipc: host");
        refused(json!({"image": "x", "userns_mode": "host"}), none.clone(), "userns_mode");
        refused(
            json!({"image": "x", "devices": [{"source": "/dev/kvm", "target": "/dev/kvm"}]}),
            none.clone(),
            "devices",
        );
        refused(json!({"image": "x", "security_opt": ["seccomp:unconfined"]}), none.clone(), "security_opt");
        refused(json!({"image": "x", "security_opt": ["label=disable"]}), none.clone(), "security_opt");
        refused(json!({"image": "x", "volumes_from": ["container:other"]}), none.clone(), "volumes_from");
        let bind = json!({"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"});
        refused(json!({"image": "x", "volumes": [bind]}), none.clone(), "/var/run/docker.sock");
        refused(json!({"image": "x", "build": {"context": "/src", "network": "host"}}), none.clone(), "build network");
        refused(
            json!({"image": "x", "build": {"context": "/src", "entitlements": ["network.host"]}}),
            none.clone(),
            "entitlement",
        );
        // Networks: the application's own bridges, or Deploy networks.
        let uses = |net: &str| json!({"image": "x", "networks": {net: null}});
        refused(uses("lan"), json!({"networks": {"lan": {"driver": "macvlan"}}}), "macvlan");
        refused(uses("lan"), json!({"networks": {"lan": {"name": "shared"}}}), "shared");
        refused(
            uses("lan"),
            json!({"networks": {"lan": {"external": true, "name": "bridge"}}}),
            "not a Deploy network",
        );
        refused(uses("lan"), json!({"networks": {"lan": {"enable_ipv6": true}}}), "IPv6");
        let routed =
            json!({"networks": {"lan": {"driver_opts": {"com.docker.network.bridge.gateway_mode_ipv4": "routed"}}}});
        refused(uses("lan"), routed, "gateway_mode_ipv4");
        assert_eq!(
            ok(uses("lan"), json!({"networks": {"lan": {"external": true, "name": "owd-0a1b2c3d4e5f"}}})),
            Ok(())
        );
        // Volumes: the project's own, or the application's.
        let mounts = |src: &str| json!({"image": "x", "volumes": [{"type": "volume", "source": src, "target": "/d"}]});
        assert_eq!(ok(mounts("pg"), json!({"volumes": {"pg": {"name": "owd-app_01c_pg"}}})), Ok(()));
        refused(mounts("pg"), json!({"volumes": {"pg": {"name": "owd-router"}}}), "owd-router");
        refused(
            mounts("pg"),
            json!({"volumes": {"pg": {"external": true, "name": "owd-app_02-data"}}}),
            "not a volume of",
        );
        let host = json!({"volumes": {"pg": {"name": "owd-app_01c_pg", "driver_opts": {"type": "none", "o": "bind", "device": "/etc"}}}});
        refused(mounts("pg"), host, "path of the server");
        refused(json!({"image": "x"}), json!({"secrets": {"s": {"file": "/etc/shadow"}}}), "secrets s");
        assert_eq!(ok(json!({"image": "x"}), json!({"configs": {"c": {"content": "x"}}})), Ok(()));
    }

    #[test]
    fn adapt_refuses_routes_and_mounts_to_unknown_services() {
        let model = json!({"services": {"web": {"image": "nginx"}}});
        let mut c = spec();
        assert!(adapt(model.clone(), &c, &[]).unwrap_err().contains("service db"));
        c.volumes.clear();
        c.routes[0].service = Some("api".into());
        assert!(adapt(model.clone(), &c, &[]).unwrap_err().contains("api"));
        c.routes[0].service = Some("web".into());
        assert!(adapt(model, &c, &[]).is_ok());
    }
}
