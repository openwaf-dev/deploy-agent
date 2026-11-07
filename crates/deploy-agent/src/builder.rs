//! The builder helpers: throwaway containers with the Docker CLI (BuildKit through buildx, Compose) and Railpack, for
//! builds the Engine API alone cannot run (the helper-container model). The server needs no build tool: the agent
//! builds the helper image itself, once, from pinned and checksummed releases.
//!
//! Helpers live for one deployment: created idle, the agent runs each step in them with `docker exec` and removes
//! them at the end, on failure and on cancel alike. Removing one kills the step running in it, which closes its
//! BuildKit session and stops the build. Repository content is handled first in a source helper ([`Role::Source`]:
//! no Engine socket, no capability, `no-new-privileges`): the clone, Railpack's plan, Compose's resolution. Its
//! /src (and the plan) is then copied, Engine to Engine, into the build helper ([`Role::Docker`]), which holds the
//! Engine's socket and only runs `docker buildx` and `docker compose` on that, and the source helper is removed.
//!
//! Resources are bounded ([`Limits`], from the agent's environment): `OWDEPLOY_BUILD_CPUS` (default 2),
//! `OWDEPLOY_BUILD_MEMORY_MB` (4096, no swap on top) and `OWDEPLOY_BUILD_PIDS` (2048) for each builder and each
//! helper; `OWDEPLOY_BUILD_CACHE_GB` (10) and `OWDEPLOY_BUILD_CACHE_MAX_AGE_HOURS` (168) for each builder's cache,
//! which its daemon garbage-collects and the agent prunes after every build.
//!
//! Every build that runs code of the repository (Dockerfile, Compose, Railpack) runs on a rootless BuildKit daemon,
//! never on the Engine's builder: [`BUILDKIT_IMAGE`] (pinned by digest) in an agent-owned container, without host
//! mounts (its state is a named volume), without privileges (only `SETUID`/`SETGID` for its user namespace helpers;
//! seccomp and AppArmor unconfined, and an unmasked /proc, which BuildKit's own sandbox needs), as an unprivileged
//! user: build steps are root only inside a user namespace mapped to unprivileged host ids. buildx reaches it with
//! its `remote` driver through `docker exec` (no listening socket), and the result is loaded into the Engine. The
//! builders sit on their own network, [`BUILD_NETWORK`] (bridge `owd-build0`): build steps share the builder's
//! network namespace, so the agent's firewall keeps builds off private ranges, cloud metadata and the host, like
//! every `owd*` bridge, while the public internet (package registries) stays reachable. Untrusted code (pull
//! requests from forks) builds on a second builder with its own state, so it never shares a cache (cache mounts
//! included) with the application's own builds. Static sites are packaged on the Engine: their Dockerfile is the
//! agent's and runs nothing from the repository.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock, Mutex};

use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig, Mount, MountType};
use bollard::query_parameters::{
    BuildImageOptionsBuilder, CreateContainerOptionsBuilder, DownloadFromContainerOptionsBuilder,
    UploadToContainerOptionsBuilder,
};
use deploy_proto::msg::{BuildPack, BuildSpec, LABEL_DEPLOYMENT, LABEL_RESOURCE, LogStream, Step};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::docker::{LABEL_HELPER, ensure_image, message, remove_container, upload};
use crate::events::Events;
use crate::exec;
use crate::git::{self, Cloned, Repo, SECRETS_TMPFS};

const DOCKER_CLI_IMAGE: &str = "docker:29.9.3-cli";
const RAILPACK_VERSION: &str = "0.43.0";
/// The mise release Railpack 0.43.0 pins (core/mise/version.txt); installed where Railpack looks for it, so a
/// build never downloads it.
const MISE_VERSION: &str = "2026.10.14";
/// BuildKit frontend that turns a Railpack plan into an image, same version as the CLI that wrote the plan.
pub const RAILPACK_FRONTEND: &str = "ghcr.io/railwayapp/railpack-frontend:v0.43.0";
/// Static sites are served by the router's Caddy, so a server keeps one web server image.
pub const STATIC_SERVER_IMAGE: &str = crate::router::IMAGE;
/// Tag of the helper image: changes with any pinned version, so an upgraded agent builds its own.
pub const IMAGE: &str = "owd/helper:1-docker29.9.3-railpack0.43.0";
/// Label on the helper image, so it is never mistaken for an application's.
const LABEL_HELPER_IMAGE: &str = "dev.openwaf.deploy.helper-image";
/// The Engine's socket on the server, given to the helper.
const DOCKER_SOCKET: &str = "/var/run/docker.sock";
/// The rootless BuildKit daemon of every build, pinned by digest (the multi-platform index of the tag).
pub const BUILDKIT_IMAGE: &str =
    "moby/buildkit:v0.34.2-rootless@sha256:c8252268760e1baba80780d63d738ef9f260fb7c7c0973c78494cb9ddd99eda1";
/// Network of the builders; build traffic leaves through its bridge, [`BUILD_BRIDGE`].
pub const BUILD_NETWORK: &str = "owd-build";
pub const BUILD_BRIDGE: &str = "owd-build0";
/// Label on a builder container: its configuration revision (a builder of another revision is replaced).
const LABEL_BUILDER: &str = "dev.openwaf.deploy.builder";
const BUILDER_REVISION: &str = "rootless-1";
/// Label on a builder container: its resource limits and cache settings ([`Limits::builder_settings`]). A builder
/// with other settings is recreated on its cache volume, which stays.
const LABEL_BUILDER_SETTINGS: &str = "dev.openwaf.deploy.builder-settings";
/// The builders' BuildKit configuration (cache garbage collection), written by the agent before the daemon starts.
const BUILDKITD_CONFIG: &str = "/etc/buildkit/buildkitd.toml";
/// Where the rootless image keeps BuildKit's state (its cache).
const BUILDKIT_STATE: &str = "/home/user/.local/share/buildkit";
/// The privileged buildx builder earlier agents ran Railpack builds on, removed with its cache.
const LEGACY_CONTAINER: &str = "buildx_buildkit_owd-buildkit0";
const LEGACY_VOLUME: &str = "buildx_buildkit_owd-buildkit0_state";
/// The builders' AppArmor profile: unconfined, but allowed to create user namespaces, which kernels restricting
/// unprivileged ones to AppArmor-confined programs (`kernel.apparmor_restrict_unprivileged_userns`, Ubuntu 23.10
/// and later) refuse to unconfined containers. Loaded by the agent when needed.
const APPARMOR_PROFILE: &str = "owd-buildkit";
const APPARMOR_POLICY: &str =
    "abi <abi/4.0>,\ninclude <tunables/global>\n\nprofile owd-buildkit flags=(unconfined) {\n  userns,\n}\n";
/// One builder change at a time: concurrent deployments would race to create its container.
static BUILDER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Resource limits of the containers that clone and build (each builder, each helper) and the bounds of each
/// builder's cache, from the agent's environment, read once ([`limits`]). An invalid value is logged and replaced by
/// its default rather than stopping the agent: a typo in the service's environment must not take every deployment of
/// the server down with it, and the defaults are safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// CPU time, in billionths of a CPU (`OWDEPLOY_BUILD_CPUS`, default 2, fractions allowed).
    pub nano_cpus: i64,
    /// Memory in bytes, and the same for memory plus swap, so no swap on top (`OWDEPLOY_BUILD_MEMORY_MB`, MiB,
    /// default 4096).
    pub memory: i64,
    /// Processes and threads (`OWDEPLOY_BUILD_PIDS`, default 2048).
    pub pids: i64,
    /// Build cache a builder keeps, in bytes (`OWDEPLOY_BUILD_CACHE_GB`, GiB, default 10).
    pub cache: i64,
    /// Build cache unused for longer than this many hours is dropped (`OWDEPLOY_BUILD_CACHE_MAX_AGE_HOURS`, default
    /// 168: a week).
    pub cache_max_age_hours: i64,
}

impl Limits {
    /// Limits from `var` (the environment, in [`limits`]), with a warning for each value set but invalid.
    fn parse(var: impl Fn(&str) -> Option<String>) -> (Limits, Vec<String>) {
        let mut warnings = Vec::new();
        // (name, default, smallest, largest, whole numbers only)
        let mut get = |name: &str, default: f64, min: f64, max: f64, whole: bool| -> f64 {
            let Some(raw) = var(name).filter(|v| !v.trim().is_empty()) else { return default };
            match raw.trim().parse::<f64>() {
                Ok(v) if v.is_finite() && (min..=max).contains(&v) && (!whole || v.fract() == 0.0) => v,
                _ => {
                    let kind = if whole { "a whole number" } else { "a number" };
                    warnings.push(format!("{name}={raw:?} is not {kind} from {min} to {max}: using {default}"));
                    default
                }
            }
        };
        const MIB: f64 = 1024.0 * 1024.0;
        let limits = Limits {
            // The Engine's smallest CPU quota is 0.01.
            nano_cpus: (get("OWDEPLOY_BUILD_CPUS", 2.0, 0.01, 1024.0, false) * 1e9).round() as i64,
            memory: (get("OWDEPLOY_BUILD_MEMORY_MB", 4096.0, 256.0, 16.0 * MIB, true) * MIB) as i64,
            pids: get("OWDEPLOY_BUILD_PIDS", 2048.0, 64.0, 4_194_304.0, true) as i64,
            cache: (get("OWDEPLOY_BUILD_CACHE_GB", 10.0, 1.0, 65_536.0, true) * 1024.0 * MIB) as i64,
            cache_max_age_hours: get("OWDEPLOY_BUILD_CACHE_MAX_AGE_HOURS", 168.0, 1.0, 87_600.0, true) as i64,
        };
        (limits, warnings)
    }

    /// Puts the CPU, memory (swap included) and process limits on a container.
    pub fn apply(&self, h: &mut HostConfig) {
        h.nano_cpus = Some(self.nano_cpus);
        h.memory = Some(self.memory);
        h.memory_swap = Some(self.memory);
        h.pids_limit = Some(self.pids);
    }

    /// Everything of a builder these limits decide, as its [`LABEL_BUILDER_SETTINGS`] label.
    fn builder_settings(&self) -> String {
        format!(
            "cpus={} memory={} pids={} cache={} max-age={}h",
            self.nano_cpus, self.memory, self.pids, self.cache, self.cache_max_age_hours
        )
    }

    /// The builders' BuildKit configuration: the daemon garbage-collects its own cache, first what no build used
    /// for the maximum age, then the least recently used down to the size cap. `maxUsedSpace` and
    /// `keepDuration` are the current names (the older `keepBytes`/`gckeepstorage` are deprecated).
    fn buildkitd_config(&self) -> String {
        format!(
            "# Written by the deploy agent: garbage collection of this builder's cache.\n[worker.oci]\n  gc = true\n\n  \
             [[worker.oci.gcpolicy]]\n    all = true\n    keepDuration = \"{}h\"\n\n  [[worker.oci.gcpolicy]]\n    \
             all = true\n    maxUsedSpace = {}\n",
            self.cache_max_age_hours, self.cache
        )
    }
}

/// The agent's [`Limits`], read from its environment on first use (warnings go to its log).
static LIMITS: LazyLock<Limits> = LazyLock::new(|| {
    let (limits, warnings) = Limits::parse(|name| std::env::var(name).ok());
    for w in warnings {
        tracing::warn!("{w}");
    }
    limits
});

pub fn limits() -> &'static Limits {
    &LIMITS
}

/// Host configuration of a container that handles repository content without the Engine's socket (the clone,
/// Railpack's plan, Compose's resolution): the secrets tmpfs of [`git::SCRIPT`], no capability (root in it is
/// an ordinary user towards files it does not own, and cannot gain any privilege back through setuid binaries),
/// and the build [`limits`].
pub fn source_host_config() -> HostConfig {
    let mut h = HostConfig {
        tmpfs: Some([(SECRETS_TMPFS.0.to_string(), SECRETS_TMPFS.1.to_string())].into()),
        cap_drop: Some(vec!["ALL".into()]),
        security_opt: Some(vec!["no-new-privileges".into()]),
        ..Default::default()
    };
    limits().apply(&mut h);
    h
}

/// A rootless BuildKit builder: the container (also its buildx builder name) and its state volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builder {
    /// The application's own builds.
    Trusted,
    /// Untrusted code: pull requests from forks.
    Untrusted,
}

impl Builder {
    pub fn of(untrusted: bool) -> Builder {
        if untrusted { Builder::Untrusted } else { Builder::Trusted }
    }

    pub fn name(self) -> &'static str {
        match self {
            Builder::Trusted => "owd-buildkit",
            Builder::Untrusted => "owd-buildkit-untrusted",
        }
    }

    fn volume(self) -> &'static str {
        match self {
            Builder::Trusted => "owd-buildkit-state",
            Builder::Untrusted => "owd-buildkit-untrusted-state",
        }
    }
}

/// Registers a builder in a helper (buildx keeps builders in the client's configuration, which dies with each
/// helper) and waits until it answers.
const BUILDER_SCRIPT: &str = r#"set -eu
docker buildx inspect "$OWD_BUILDER" >/dev/null 2>&1 || \
  docker buildx create --name "$OWD_BUILDER" --driver remote "docker-container://$OWD_BUILDER" >/dev/null
docker buildx inspect --bootstrap "$OWD_BUILDER" >/dev/null
"#;

/// Release assets per architecture of the Docker host: (Railpack archive, SHA-256), (mise archive, SHA-256).
fn assets(arch: &str) -> Result<[(String, &'static str); 2], String> {
    let (rp, rp_sum, mise, mise_sum) = match arch {
        "aarch64" | "arm64" => (
            "arm64-unknown-linux-musl",
            "732ece14eb4f4676a43ebba19431f954edf7b130acb76159ef0f2ff86ac42ac9",
            "linux-arm64-musl",
            "2b661edd0ba55d4f9fac940d0e108c79893bb30642ac5b532a677b49fa7cb8b3",
        ),
        "x86_64" | "amd64" => (
            "x86_64-unknown-linux-musl",
            "248a8f60f36854aabed6124113631078a802de3461660855fc4de9c26065c1fb",
            "linux-x64-musl",
            "d2ce450af6abc290d153723f790546d836428aa60f8b61d4a3d2c1dacde5d6c5",
        ),
        a => return Err(format!("no build helper for the {a} architecture")),
    };
    Ok([
        (
            format!(
                "https://github.com/railwayapp/railpack/releases/download/v{RAILPACK_VERSION}/railpack-v{RAILPACK_VERSION}-{rp}.tar.gz"
            ),
            rp_sum,
        ),
        (
            format!("https://github.com/jdx/mise/releases/download/v{MISE_VERSION}/mise-v{MISE_VERSION}-{mise}.tar.xz"),
            mise_sum,
        ),
    ])
}

/// The helper image's Dockerfile: the Docker CLI image plus Railpack and mise, each checked against its SHA-256.
fn dockerfile(arch: &str) -> Result<String, String> {
    let [(rp, rp_sum), (mise, mise_sum)] = assets(arch)?;
    Ok(format!(
        "FROM {DOCKER_CLI_IMAGE}\n\
         RUN set -eu; \\\n  \
           wget -q -O /tmp/railpack.tgz '{rp}'; \\\n  \
           echo '{rp_sum}  /tmp/railpack.tgz' | sha256sum -c -; \\\n  \
           tar -xzf /tmp/railpack.tgz -C /usr/local/bin railpack; \\\n  \
           wget -q -O /tmp/mise.txz '{mise}'; \\\n  \
           echo '{mise_sum}  /tmp/mise.txz' | sha256sum -c -; \\\n  \
           mkdir -p /tmp/railpack/mise /tmp/mise; \\\n  \
           tar -xJf /tmp/mise.txz -C /tmp/mise; \\\n  \
           mv /tmp/mise/mise/bin/mise /tmp/railpack/mise/mise-{MISE_VERSION}; \\\n  \
           rm -rf /tmp/railpack.tgz /tmp/mise.txz /tmp/mise; \\\n  \
           railpack --version\n\
         LABEL {LABEL_HELPER_IMAGE}=1\n"
    ))
}

/// One helper image build at a time: concurrent deployments would otherwise each build it.
static IMAGE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn ensure_image_built(d: &Docker, ev: &Events) -> Result<(), String> {
    let _g = IMAGE_LOCK.lock().await;
    if d.inspect_image(IMAGE).await.is_ok() {
        return Ok(());
    }
    let arch = d.info().await.map_err(|e| format!("docker info: {}", message(&e)))?.architecture.unwrap_or_default();
    ev.system(format!("Building the build helper image {IMAGE} (once per server)")).await;
    let text = dockerfile(&arch)?;
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(text.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(tar::EntryType::Regular);
    b.append_data(&mut h, "Dockerfile", text.as_bytes()).map_err(|e| e.to_string())?;
    let body = b.into_inner().map_err(|e| e.to_string())?;
    let opts =
        BuildImageOptionsBuilder::default().dockerfile("Dockerfile").t(IMAGE).rm(true).forcerm(true).pull("true");
    let mut s = d.build_image(opts.build(), None, Some(bollard::body_full(body.into())));
    while let Some(item) = s.next().await {
        let info = item.map_err(|e| format!("build helper image: {}", message(&e)))?;
        if let Some(e) = info.error_detail {
            return Err(format!("build helper image: {}", e.message.unwrap_or_default().trim()));
        }
    }
    Ok(())
}

/// What a helper container is for. Both run the helper image without capabilities, `no-new-privileges` and the build
/// [`limits`]; only the second holds the Engine's socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Repository content: the clone, Railpack's plan, Compose's resolution. No Engine socket.
    Source,
    /// `docker buildx` and `docker compose` against the builders and the Engine, on what a source container
    /// produced. Never clones.
    Docker,
}

/// The container of a helper with `role` for `resource`.
fn helper_container(role: Role, resource: &str) -> ContainerCreateBody {
    let mut host = source_host_config();
    host.init = Some(true);
    if role == Role::Docker {
        host.mounts = Some(vec![Mount {
            typ: Some(MountType::BIND),
            source: Some(DOCKER_SOCKET.into()),
            target: Some(DOCKER_SOCKET.into()),
            ..Default::default()
        }]);
    }
    ContainerCreateBody {
        image: Some(IMAGE.into()),
        // Idle until removed; each step is an exec. `sleep` outlives any build (24 h).
        entrypoint: Some(vec!["sleep".into(), "86400".into()]),
        // The same label for both roles: `git::remove_leftover_helpers` finds them all.
        labels: Some(HashMap::from([(LABEL_HELPER.to_string(), resource.to_string())])),
        host_config: Some(host),
        ..Default::default()
    }
}

/// A running helper container, removed by [`Helper::remove`].
pub struct Helper {
    pub id: String,
    role: Role,
    d: Docker,
}

impl Helper {
    /// The helper with the Engine's socket.
    pub async fn start(d: &Docker, resource: &str, ev: &Events) -> Result<Helper, String> {
        Helper::create(d, resource, Role::Docker, ev).await
    }

    /// A helper for repository content, without the Engine's socket.
    pub async fn source(d: &Docker, resource: &str, ev: &Events) -> Result<Helper, String> {
        Helper::create(d, resource, Role::Source, ev).await
    }

    async fn create(d: &Docker, resource: &str, role: Role, ev: &Events) -> Result<Helper, String> {
        ensure_image_built(d, ev).await?;
        let what = match role {
            Role::Source => "source helper",
            Role::Docker => "build helper",
        };
        let created = d
            .create_container(Some(CreateContainerOptionsBuilder::default().build()), helper_container(role, resource))
            .await
            .map_err(|e| format!("create the {what}: {}", message(&e)))?;
        let h = Helper { id: created.id, role, d: d.clone() };
        if let Err(e) = d.start_container(&h.id, None).await {
            h.remove().await;
            return Err(format!("start the {what}: {}", message(&e)));
        }
        Ok(h)
    }

    /// Removes the container and whatever runs in it; removing it again is harmless.
    pub async fn remove(&self) {
        remove_container(&self.d, &self.id).await.ok();
    }

    /// Runs a shell script with `env`; its output goes to the deployment log. Returns the exit code.
    pub async fn sh(
        &self,
        script: &str,
        env: Vec<String>,
        ev: &Events,
        cancel: &CancellationToken,
        keep: &mut (dyn FnMut(LogStream, &str) -> bool + Send),
    ) -> Result<i64, String> {
        let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
        let r = exec::start(&self.d, &self.id, cmd, env, None).await?;
        exec::pump(&self.d, r, ev, cancel, keep).await
    }

    /// Runs a command and returns its standard output (at most `cap` bytes); standard error goes to the log.
    pub async fn output(
        &self,
        cmd: Vec<String>,
        env: Vec<String>,
        cap: usize,
        ev: &Events,
        cancel: &CancellationToken,
    ) -> Result<(i64, Vec<u8>), String> {
        let mut r = exec::start(&self.d, &self.id, cmd, env, None).await?;
        let mut out = Vec::new();
        let mut err = crate::events::Lines::default();
        loop {
            let item = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(crate::CANCELLED.into()),
                i = r.next() => i,
            };
            let Some(item) = item else { break };
            match item? {
                (LogStream::Stderr, chunk) => {
                    for l in err.push(&chunk) {
                        ev.line(LogStream::Stderr, l).await;
                    }
                }
                (_, chunk) => {
                    if out.len() + chunk.len() > cap {
                        return Err(format!("output larger than {} KiB", cap / 1024));
                    }
                    out.extend_from_slice(&chunk);
                }
            }
        }
        if let Some(l) = err.finish() {
            ev.line(LogStream::Stderr, l).await;
        }
        Ok((r.exit_code(&self.d).await?.unwrap_or(-1), out))
    }

    /// Clones the repository into /src (the clone script of [`git::SCRIPT`], secrets through stdin). Only in a
    /// source helper: repository content never meets the Engine's socket before the agent has checked it.
    pub async fn clone(&self, repo: &Repo<'_>, ev: &Events, cancel: &CancellationToken) -> Result<Cloned, String> {
        if self.role != Role::Source {
            return Err("the clone runs in a source helper, never next to the Engine's socket".into());
        }
        let mut clone = git::prepare(repo)?;
        ev.system(format!("Fetching {} at {}", repo.url, repo.reference)).await;
        let stdin = std::mem::take(&mut clone.stdin);
        let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), git::SCRIPT.to_string()];
        let r = exec::start(&self.d, &self.id, cmd, clone.env.clone(), Some(stdin)).await?;
        let mut cloned = Cloned::default();
        let code = exec::pump(&self.d, r, ev, cancel, &mut |s, l| s == LogStream::Stderr || !cloned.marker(l)).await?;
        let commit = cloned.commit(code)?;
        ev.system(format!("Checked out commit {commit}")).await;
        for k in &cloned.known_hosts {
            ev.system(format!("Accepted the host key on first use: {k}")).await;
        }
        Ok(cloned)
    }

    /// Copies directory `path` (absolute) of helper `from` to the same path here: the Engine's archive of it streams
    /// straight into an upload, without a file on the server.
    pub async fn copy_from(&self, from: &Helper, path: &str, cancel: &CancellationToken) -> Result<(), String> {
        // The upload only sees an I/O error when the download fails; keep the Engine's message for the log.
        let failed: Arc<Mutex<Option<String>>> = Arc::default();
        let seen = failed.clone();
        let archive = self
            .d
            .download_from_container(&from.id, Some(DownloadFromContainerOptionsBuilder::default().path(path).build()))
            .map(move |chunk| {
                chunk.map_err(|e| {
                    let m = message(&e);
                    *seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(m.clone());
                    std::io::Error::other(m)
                })
            });
        // The archive's entries are under the directory's own name: unpacked at its parent.
        let parent = match path.rsplit_once('/') {
            Some(("", _)) | None => "/",
            Some((p, _)) => p,
        };
        let opts = UploadToContainerOptionsBuilder::default().path(parent).build();
        let upload = self.d.upload_to_container(&self.id, Some(opts), bollard::body_try_stream(archive));
        let r = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(crate::CANCELLED.into()),
            r = upload => r,
        };
        r.map_err(|e| match failed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take() {
            Some(m) => format!("copy {path} out of the source helper: {m}"),
            None => format!("copy {path} into the build helper: {}", message(&e)),
        })
    }

    /// Writes files under /owd in the helper.
    pub async fn put(&self, files: &[crate::docker::File<'_>]) -> Result<(), String> {
        upload(&self.d, &self.id, "/", &[crate::docker::File { path: "owd/.keep", data: b"", mode: 0o600 }]).await?;
        upload(&self.d, &self.id, "/owd", files).await
    }

    /// Unpacks a build context archive into /ctx in the helper.
    async fn put_context(&self, archive: &std::path::Path) -> Result<(), String> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o755);
        h.set_size(0);
        b.append_data(&mut h, "ctx/", std::io::empty()).map_err(|e| e.to_string())?;
        let dir = b.into_inner().map_err(|e| e.to_string())?;
        let opts = |p: &str| UploadToContainerOptionsBuilder::default().path(p).build();
        self.d
            .upload_to_container(&self.id, Some(opts("/")), bollard::body_full(dir.into()))
            .await
            .map_err(|e| format!("copy into the build helper: {}", message(&e)))?;
        let file = tokio::fs::File::open(archive).await.map_err(|e| format!("build context: {e}"))?;
        let body = bollard::body_try_stream(tokio_util::io::ReaderStream::new(file));
        self.d
            .upload_to_container(&self.id, Some(opts("/ctx")), body)
            .await
            .map_err(|e| format!("copy the build context into the build helper: {}", message(&e)))
    }
}

/// A Dockerfile build, from the context [`git::fetch`] packed: a bake file (written into the helper, so build
/// argument values are neither in argv nor in the environment, whatever their names) on the rootless builder,
/// loaded into the Engine.
const DOCKERFILE_SCRIPT: &str = r#"set -eu
cd /
docker buildx bake --builder "$OWD_BUILDER" --progress plain --provenance=false -f /owd/bake.json
"#;

/// The bake file of a Dockerfile build of `ctx` into `tag`.
fn bake_file(spec: &BuildSpec, dockerfile: &str, tag: &str, resource: &str, deployment: &str) -> serde_json::Value {
    let mut target = serde_json::json!({
        "context": "/ctx",
        "dockerfile": dockerfile,
        "args": spec.args,
        "labels": {LABEL_RESOURCE: resource, LABEL_DEPLOYMENT: deployment},
        "tags": [tag],
        "no-cache": spec.no_cache,
        "output": ["type=docker"],
    });
    if let Some(t) = &spec.target {
        target["target"] = t.as_str().into();
    }
    serde_json::json!({"target": {"default": target}})
}

/// Builds the repository's Dockerfile from `ctx` into `tag` on the rootless builder ([`Builder::of`] the spec).
#[allow(clippy::too_many_arguments)]
pub async fn build_dockerfile(
    d: &Docker,
    resource: &str,
    deployment: &str,
    tag: &str,
    spec: &BuildSpec,
    ctx: &git::Context,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let h = Helper::start(d, resource, ev).await?;
    let r = async {
        let builder = Builder::of(spec.untrusted);
        ensure_builder(&h, builder, ev, cancel).await?;
        h.put_context(&ctx.tar).await?;
        let bake = serde_json::to_vec(&bake_file(spec, &ctx.dockerfile, tag, resource, deployment)).expect("json");
        h.put(&[crate::docker::File { path: "bake.json", data: &bake, mode: 0o600 }]).await?;
        ev.system(format!("Building on the rootless BuildKit builder {}", builder.name())).await;
        let code = h
            .sh(DOCKERFILE_SCRIPT, vec![format!("OWD_BUILDER={}", builder.name())], ev, cancel, &mut |_, _| true)
            .await?;
        prune_cache(&h, builder, ev, cancel).await;
        if code != 0 {
            return Err(format!("build failed (exit code {code})"));
        }
        Ok(())
    }
    .await;
    h.remove().await;
    r
}

/// Railpack's plan, in the source helper: detection and overrides, from the repository, written to /owd. Build
/// variables reach Railpack as environment, never in argv.
const PREPARE_SCRIPT: &str = r#"set -eu
mkdir -p /owd
cd "/src/$OWD_CONTEXT"
set --
for n in $OWD_ENV_NAMES; do set -- "$@" --env "$n"; done
railpack prepare . --plan-out /owd/railpack-plan.json --info-out /owd/railpack-info.json "$@"
"#;

/// Railpack's build step, in the build helper: build the plan [`PREPARE_SCRIPT`] wrote on the rootless builder and
/// load the image into the Engine. Build variables reach BuildKit as secrets, never in argv. Railpack's frontend
/// ignores `--label`, so a second, metadata-only build on top of its image (on the Engine: nothing to merge or run
/// there) adds the resource and deployment labels (image pruning and removal find an application's images by them).
const RAILPACK_SCRIPT: &str = r#"set -eu
cd "/src/$OWD_CONTEXT"
set --
for n in $OWD_ENV_NAMES; do set -- "$@" --secret "id=$n,env=$n"; done
if [ "$OWD_NO_CACHE" = 1 ]; then set -- "$@" --no-cache; fi
docker buildx build --builder "$OWD_BUILDER" --progress plain \
  --build-arg "BUILDKIT_SYNTAX=$OWD_FRONTEND" \
  --build-arg "cache-key=$OWD_CACHE_KEY" \
  --build-arg "secrets-hash=$OWD_SECRETS_HASH" \
  -f /owd/railpack-plan.json -t "$OWD_IMAGE-railpack" --load "$@" .
mkdir -p /owd/empty
printf 'FROM %s\n' "$OWD_IMAGE-railpack" | docker buildx build --progress plain \
  --label "$OWD_LABEL_RESOURCE" --label "$OWD_LABEL_DEPLOYMENT" -t "$OWD_IMAGE" --load -f - /owd/empty
docker image rm "$OWD_IMAGE-railpack" >/dev/null
"#;

/// Bounds a builder's cache after a build: what no build used for the maximum age, then the least recently used
/// beyond the size cap (`--max-used-space`; `--keep-storage` is deprecated). The daemon's own garbage collection
/// ([`Limits::buildkitd_config`]) does the same in the background; this makes the bound hold right after each
/// build. Records a running build uses are never pruned. Errors only: the lists of what went stay out of the log.
const PRUNE_SCRIPT: &str = r#"set -eu
exec 2>&1 >/dev/null
docker buildx prune --builder "$OWD_BUILDER" --force --all --filter "until=$OWD_CACHE_MAX_AGE"
docker buildx prune --builder "$OWD_BUILDER" --force --all --max-used-space "$OWD_CACHE_BYTES"
"#;

/// The environment of [`PRUNE_SCRIPT`] for builder `b`.
fn prune_env(b: Builder, l: &Limits) -> Vec<String> {
    vec![
        format!("OWD_BUILDER={}", b.name()),
        format!("OWD_CACHE_MAX_AGE={}h", l.cache_max_age_hours),
        format!("OWD_CACHE_BYTES={}", l.cache),
    ]
}

/// Runs [`PRUNE_SCRIPT`] for builder `b` from helper `h`, after a build that ended (successfully or not). Best
/// effort: a failure becomes a system line of the deployment, never its error; after a cancel nothing is logged.
pub async fn prune_cache(h: &Helper, b: Builder, ev: &Events, cancel: &CancellationToken) {
    let cmd = vec!["/bin/sh".to_string(), "-c".to_string(), PRUNE_SCRIPT.to_string()];
    let failure = match h.output(cmd, prune_env(b, limits()), 64 * 1024, ev, cancel).await {
        Ok((0, _)) => return,
        Ok((code, out)) => {
            let out = String::from_utf8_lossy(&out);
            let last = out.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or_default().trim().to_string();
            format!("exit code {code}: {last}")
        }
        Err(_) if cancel.is_cancelled() => return,
        Err(e) => e,
    };
    ev.system(format!("Could not prune the cache of the BuildKit builder {} ({failure})", b.name())).await;
}

/// Makes rootless builder `b` usable from helper `h`: its network exists, its container runs the pinned image with
/// the current configuration, and buildx in the helper knows it. A builder of another image, revision or security
/// options, and the privileged builder of earlier agents, are replaced, cache included; a builder with other limits
/// or cache settings is recreated on the same cache ([`fit`]).
pub async fn ensure_builder(h: &Helper, b: Builder, ev: &Events, cancel: &CancellationToken) -> Result<(), String> {
    let _g = BUILDER_LOCK.lock().await;
    let d = &h.d;
    if d.inspect_container(LEGACY_CONTAINER, None).await.is_ok() {
        ev.system("Removing the privileged BuildKit builder of earlier agents").await;
        remove_container(d, LEGACY_CONTAINER).await?;
        remove_volume(d, LEGACY_VOLUME).await?;
    }
    let security = security_options().await?;
    let limits = limits();
    let current = match d.inspect_container(b.name(), None).await {
        Ok(c) => Some(c),
        Err(e) if crate::docker::is_not_found(&e) => None,
        Err(e) => return Err(format!("inspect {}: {}", b.name(), message(&e))),
    };
    let current = match current.map(|c| (fit(&c, &security, limits), c)) {
        Some((Fit::Current, c)) => Some(c),
        Some((Fit::Recreate, _)) => {
            ev.system(format!(
                "Recreating the BuildKit builder {} with the current limits (its cache stays)",
                b.name()
            ))
            .await;
            remove_container(d, b.name()).await?;
            None
        }
        Some((Fit::Replace, _)) => {
            ev.system(format!("Replacing the BuildKit builder {} ({BUILDKIT_IMAGE})", b.name())).await;
            remove_container(d, b.name()).await?;
            remove_volume(d, b.volume()).await?;
            None
        }
        None => None,
    };
    let running = match current {
        Some(c) => c.state.and_then(|s| s.running).unwrap_or(false),
        None => {
            ensure_image(d, BUILDKIT_IMAGE, Some(ev)).await?;
            ensure_build_network(d).await?;
            ev.system(format!("Creating the rootless BuildKit builder {} (once per server)", b.name())).await;
            let opts = CreateContainerOptionsBuilder::default().name(b.name()).build();
            d.create_container(Some(opts), builder_container(b, security, limits))
                .await
                .map_err(|e| format!("create the BuildKit builder {}: {}", b.name(), message(&e)))?;
            let config = limits.buildkitd_config();
            let file = crate::docker::File {
                path: BUILDKITD_CONFIG.trim_start_matches('/'),
                data: config.as_bytes(),
                mode: 0o644,
            };
            if let Err(e) = upload(d, b.name(), "/", &[file]).await {
                // Not left half made: the next deployment creates it again.
                remove_container(d, b.name()).await.ok();
                return Err(format!("configure the BuildKit builder {}: {e}", b.name()));
            }
            false
        }
    };
    if !running {
        d.start_container(b.name(), None)
            .await
            .map_err(|e| format!("start the BuildKit builder {}: {}", b.name(), message(&e)))?;
    }
    let code = h.sh(BUILDER_SCRIPT, vec![format!("OWD_BUILDER={}", b.name())], ev, cancel, &mut |_, _| true).await?;
    if code != 0 {
        return Err(format!("the BuildKit builder {} does not answer (exit code {code})", b.name()));
    }
    Ok(())
}

/// The daemon's arguments: its configuration file ([`Limits::buildkitd_config`]), after the image's entrypoint
/// (`rootlesskit buildkitd`).
fn builder_cmd() -> Vec<String> {
    vec!["--config".into(), BUILDKITD_CONFIG.into()]
}

/// The container of builder `b`. Every builder gets the whole [`Limits`]: the builds running on it share them.
fn builder_container(b: Builder, security: Vec<String>, limits: &Limits) -> ContainerCreateBody {
    let mut host = HostConfig {
        network_mode: Some(BUILD_NETWORK.into()),
        // No host path: its state is a named volume.
        mounts: Some(vec![Mount {
            typ: Some(MountType::VOLUME),
            source: Some(b.volume().into()),
            target: Some(BUILDKIT_STATE.into()),
            ..Default::default()
        }]),
        // newuidmap and newgidmap (setuid) map the build's user namespace; nothing else is needed.
        cap_drop: Some(vec!["ALL".into()]),
        cap_add: Some(vec!["SETUID".into(), "SETGID".into()]),
        security_opt: Some(security),
        // No masked or read-only /proc paths (the CLI's `systempaths=unconfined`): BuildKit mounts a /proc of
        // its own for each step, which the kernel refuses under a partly masked one.
        masked_paths: Some(Vec::new()),
        readonly_paths: Some(Vec::new()),
        ..Default::default()
    };
    limits.apply(&mut host);
    ContainerCreateBody {
        image: Some(BUILDKIT_IMAGE.into()),
        cmd: Some(builder_cmd()),
        labels: Some(HashMap::from([
            (LABEL_BUILDER.to_string(), BUILDER_REVISION.to_string()),
            (LABEL_BUILDER_SETTINGS.to_string(), limits.builder_settings()),
        ])),
        host_config: Some(host),
        ..Default::default()
    }
}

/// How an existing builder container compares with the one [`builder_container`] makes now.
#[derive(Debug, PartialEq, Eq)]
enum Fit {
    Current,
    /// Other limits or cache settings: a new container on the same cache volume.
    Recreate,
    /// Another image, revision or security options: the cache was written by another configuration and goes too.
    Replace,
}

fn fit(c: &bollard::models::ContainerInspectResponse, security: &[String], limits: &Limits) -> Fit {
    let config = c.config.as_ref();
    let label = |k: &str| config.and_then(|c| c.labels.as_ref()?.get(k)).map(String::as_str);
    if config.and_then(|c| c.image.as_deref()) != Some(BUILDKIT_IMAGE)
        || label(LABEL_BUILDER) != Some(BUILDER_REVISION)
        || c.host_config.as_ref().and_then(|h| h.security_opt.as_deref()) != Some(security)
    {
        return Fit::Replace;
    }
    if label(LABEL_BUILDER_SETTINGS) != Some(limits.builder_settings().as_str())
        || config.and_then(|c| c.cmd.as_deref()) != Some(builder_cmd().as_slice())
    {
        return Fit::Recreate;
    }
    Fit::Current
}

async fn remove_volume(d: &Docker, name: &str) -> Result<(), String> {
    match d.remove_volume(name, None::<bollard::query_parameters::RemoveVolumeOptions>).await {
        Ok(()) => Ok(()),
        Err(e) if crate::docker::is_not_found(&e) => Ok(()),
        Err(e) => Err(format!("remove volume {name}: {}", message(&e))),
    }
}

/// The builders' network, without IPv6, its bridge named so the firewall recognizes it.
async fn ensure_build_network(d: &Docker) -> Result<(), String> {
    match d.inspect_network(BUILD_NETWORK, None).await {
        Ok(_) => return Ok(()),
        Err(e) if crate::docker::is_not_found(&e) => {}
        Err(e) => return Err(format!("inspect network {BUILD_NETWORK}: {}", message(&e))),
    }
    let req = bollard::models::NetworkCreateRequest {
        name: BUILD_NETWORK.into(),
        driver: Some("bridge".into()),
        enable_ipv6: Some(false),
        options: Some(HashMap::from([("com.docker.network.bridge.name".to_string(), BUILD_BRIDGE.to_string())])),
        labels: Some(HashMap::from([(LABEL_BUILDER.to_string(), "network".to_string())])),
        ..Default::default()
    };
    match d.create_network(req).await {
        Ok(_) => {}
        // Created concurrently.
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 409, .. }) => {}
        Err(e) => return Err(format!("create network {BUILD_NETWORK}: {}", message(&e))),
    }
    crate::firewall::guard_new_network().await
}

/// Security options of the builders. Rootless BuildKit sandboxes each build step in user, mount and PID namespaces
/// of its own, which Docker's default seccomp and AppArmor profiles and its masked /proc paths forbid. With AppArmor
/// restricting unprivileged user namespaces, the agent's profile [`APPARMOR_PROFILE`] (loaded now when missing).
async fn security_options() -> Result<Vec<String>, String> {
    let mut opts = vec!["seccomp=unconfined".to_string()];
    let read = |p: &str| std::fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default();
    if read("/sys/module/apparmor/parameters/enabled") != "Y" {
        return Ok(opts);
    }
    if read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") != "1" {
        opts.push("apparmor=unconfined".into());
        return Ok(opts);
    }
    let loaded = read("/sys/kernel/security/apparmor/profiles")
        .lines()
        .any(|l| l.split_once(" (").is_some_and(|(name, _)| name == APPARMOR_PROFILE));
    if !loaded {
        load_apparmor_profile().await?;
    }
    opts.push(format!("apparmor={APPARMOR_PROFILE}"));
    Ok(opts)
}

async fn load_apparmor_profile() -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let mut last = String::new();
    for bin in ["apparmor_parser", "/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"] {
        let child = tokio::process::Command::new(bin)
            .arg("-r")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                last = format!("{bin}: {e}");
                continue;
            }
        };
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(APPARMOR_POLICY.as_bytes()).await.map_err(|e| format!("{bin}: {e}"))?;
        drop(stdin);
        let out = child.wait_with_output().await.map_err(|e| format!("{bin}: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        return Err(format!(
            "load the AppArmor profile {APPARMOR_PROFILE} the rootless builder needs: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Err(format!(
        "AppArmor restricts unprivileged user namespaces and apparmor_parser is missing ({last}): install apparmor \
         so the agent can load the profile {APPARMOR_PROFILE} the rootless builder needs"
    ))
}

/// A static site: the files of the publish directory (in the context, or in the image Railpack built) behind Caddy.
/// With a Railpack build, the context is empty: the files come from that image, removed afterwards.
const STATIC_SCRIPT: &str = r#"set -eu
if [ "$OWD_NO_CACHE" = 1 ]; then set -- --no-cache; else set --; fi
if [ -n "${OWD_BUILT:-}" ]; then ctx=/owd/empty; else ctx="/src/$OWD_CONTEXT"; fi
docker buildx build --progress plain --label "$OWD_LABEL_RESOURCE" --label "$OWD_LABEL_DEPLOYMENT" \
  -f /owd/static.Dockerfile -t "$OWD_IMAGE" --load "$@" "$ctx"
if [ -n "${OWD_BUILT:-}" ]; then docker image rm "$OWD_BUILT" >/dev/null; fi
"#;

/// Names a Railpack build cannot take from the user: the helper's own variables and what its tools depend on.
fn reserved(name: &str) -> bool {
    name.starts_with("OWD_")
        || name.starts_with("BUILDKIT_")
        || name.starts_with("BUILDX_")
        || name.starts_with("DOCKER_")
        || name.starts_with("MISE_")
        || ["PATH", "HOME", "HOSTNAME", "PWD", "SHELL", "USER", "IFS"].contains(&name)
}

fn env_name_ok(n: &str) -> bool {
    !n.is_empty()
        && !n.starts_with(|c: char| c.is_ascii_digit())
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The Caddyfile of a static site: files of /srv on `$PORT`, compressed, with an optional single-page fallback.
pub fn caddyfile(spa: bool) -> String {
    let fallback = if spa { "\ttry_files {path} {path}/ /index.html\n" } else { "" };
    format!(
        "{{\n\tadmin off\n\tauto_https off\n\tpersist_config off\n}}\n\n:{{$PORT:80}} {{\n\troot * /srv\n\tencode zstd gzip\n{fallback}\tfile_server\n}}\n"
    )
}

/// The static site's Dockerfile. Without a build, `site` is a directory of the context; with one, of the image
/// Railpack built (its application lives in /app).
pub fn static_dockerfile(site: &str, built: Option<&str>, spa: bool) -> String {
    let (stage, from) = match built {
        Some(image) => (format!("FROM {image} AS site\n"), format!("--from=site /app/{site}")),
        None => (String::new(), site.to_string()),
    };
    let from = from.trim_end_matches('/');
    let from = if from.is_empty() { "." } else { from };
    format!(
        "{stage}FROM {STATIC_SERVER_IMAGE}\nCOPY <<'OWD' /etc/caddy/Caddyfile\n{}OWD\nCOPY {from}/ /srv/\n",
        caddyfile(spa)
    )
}

pub struct Built {
    pub commit: String,
    pub known_hosts: Vec<String>,
}

/// A Railpack or static image for `tag` from the repository.
#[allow(clippy::too_many_arguments)]
pub async fn build(
    d: &Docker,
    resource: &str,
    deployment: &str,
    tag: &str,
    repo: Repo<'_>,
    spec: &BuildSpec,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<Built, String> {
    let context = git::inside(&spec.context, "build context")?;
    let site = git::inside(spec.publish_dir.as_deref().unwrap_or("."), "publish directory")?;
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in &spec.args {
        if !env_name_ok(k) || reserved(k) {
            return Err(format!("build variable {k:?} cannot be used in a Railpack build"));
        }
        if v.contains('\0') {
            return Err("build variable values cannot contain NUL".into());
        }
        vars.insert(k.clone(), v.clone());
    }
    for (name, v) in [
        ("RAILPACK_INSTALL_CMD", &spec.install_command),
        ("RAILPACK_BUILD_CMD", &spec.build_command),
        ("RAILPACK_START_CMD", &spec.start_command),
    ] {
        if let Some(v) = v.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            if v.contains('\0') {
                return Err(format!("{name} contains NUL"));
            }
            vars.insert(name.into(), v.into());
        }
    }
    ensure_image(d, crate::router::IMAGE, Some(ev)).await?;
    let src = Helper::source(d, resource, ev).await?;
    let mut helper = None;
    let r = run(d, &src, &mut helper, resource, deployment, tag, repo, spec, &context, &site, vars, ev, cancel).await;
    // Both go on success, failure and cancel alike.
    src.remove().await;
    if let Some(h) = helper {
        h.remove().await;
    }
    r
}

/// Clones and plans in the source helper `src`, then copies the result into a helper with the Engine's socket
/// (kept in `helper`, for its owner to remove) that builds it.
#[allow(clippy::too_many_arguments)]
async fn run(
    d: &Docker,
    src: &Helper,
    helper: &mut Option<Helper>,
    resource: &str,
    deployment: &str,
    tag: &str,
    repo: Repo<'_>,
    spec: &BuildSpec,
    context: &str,
    site: &str,
    vars: BTreeMap<String, String>,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<Built, String> {
    let cloned = src.clone(&repo, ev, cancel).await?;
    ev.step_after_fetch(Step::Building, cloned.info()).await;
    let commit = cloned.commit.clone().unwrap_or_default();
    let common = vec![
        format!("OWD_CONTEXT={context}"),
        format!("OWD_NO_CACHE={}", u8::from(spec.no_cache)),
        format!("OWD_LABEL_RESOURCE={LABEL_RESOURCE}={resource}"),
        format!("OWD_LABEL_DEPLOYMENT={LABEL_DEPLOYMENT}={deployment}"),
    ];
    let railpack =
        spec.pack == BuildPack::Railpack || spec.build_command.as_deref().is_some_and(|c| !c.trim().is_empty());
    let built = format!("{tag}-build");
    let builder = Builder::of(spec.untrusted);
    let names = format!("OWD_ENV_NAMES={}", vars.keys().cloned().collect::<Vec<_>>().join(" "));
    if railpack {
        ev.system(format!(
            "Building with Railpack {RAILPACK_VERSION} on the rootless BuildKit builder {}",
            builder.name()
        ))
        .await;
        let mut env = vec![format!("OWD_CONTEXT={context}"), names.clone()];
        env.extend(vars.iter().map(|(k, v)| format!("{k}={v}")));
        let code = src.sh(PREPARE_SCRIPT, env, ev, cancel, &mut |_, _| true).await?;
        if code != 0 {
            return Err(format!("Railpack could not plan the build (exit code {code})"));
        }
    }
    // Only what the source helper produced reaches the helper with the Engine's socket.
    let h = &*helper.insert(Helper::start(d, resource, ev).await?);
    h.copy_from(src, "/src", cancel).await?;
    if railpack {
        h.copy_from(src, "/owd", cancel).await?;
    }
    src.remove().await;
    if railpack {
        ensure_builder(h, builder, ev, cancel).await?;
        let mut hash = Sha256::new();
        for (k, v) in &vars {
            hash.update(k.as_bytes());
            hash.update([0]);
            hash.update(v.as_bytes());
            hash.update([0]);
        }
        let mut env = common.clone();
        env.extend([
            names,
            format!("OWD_FRONTEND={RAILPACK_FRONTEND}"),
            format!("OWD_BUILDER={}", builder.name()),
            format!("OWD_CACHE_KEY={}", resource.to_ascii_lowercase()),
            format!("OWD_SECRETS_HASH={}", hex::encode(hash.finalize())),
            format!("OWD_IMAGE={}", if spec.pack == BuildPack::Static { &built } else { tag }),
        ]);
        env.extend(vars.iter().map(|(k, v)| format!("{k}={v}")));
        let code = h.sh(RAILPACK_SCRIPT, env, ev, cancel, &mut |_, _| true).await?;
        prune_cache(h, builder, ev, cancel).await;
        if code != 0 {
            return Err(format!("Railpack build failed (exit code {code})"));
        }
    }
    if spec.pack == BuildPack::Static {
        ev.system(format!("Packaging the static site from {}", if site.is_empty() { "." } else { site })).await;
        let dockerfile = static_dockerfile(site, railpack.then_some(built.as_str()), spec.spa);
        h.put(&[
            crate::docker::File { path: "static.Dockerfile", data: dockerfile.as_bytes(), mode: 0o644 },
            // The repository's .git never ends up in the served files.
            crate::docker::File { path: "static.Dockerfile.dockerignore", data: b".git\n", mode: 0o644 },
            crate::docker::File { path: "empty/.keep", data: b"", mode: 0o644 },
        ])
        .await?;
        let mut env = common;
        env.push(format!("OWD_IMAGE={tag}"));
        if railpack {
            env.push(format!("OWD_BUILT={built}"));
        }
        let code = h.sh(STATIC_SCRIPT, env, ev, cancel, &mut |_, _| true).await?;
        if code != 0 {
            return Err(format!("static site build failed (exit code {code})"));
        }
    }
    Ok(Built { commit, known_hosts: cloned.known_hosts })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_image_pins_versions_and_checksums_per_architecture() {
        let arm = dockerfile("aarch64").unwrap();
        assert!(arm.starts_with("FROM docker:29.9.3-cli\n"));
        assert!(arm.contains("railpack-v0.43.0-arm64-unknown-linux-musl.tar.gz"));
        assert!(arm.contains("732ece14eb4f4676a43ebba19431f954edf7b130acb76159ef0f2ff86ac42ac9  /tmp/railpack.tgz"));
        assert!(arm.contains("/tmp/railpack/mise/mise-2026.10.14"));
        let x86 = dockerfile("x86_64").unwrap();
        assert!(x86.contains("mise-v2026.10.14-linux-x64-musl.tar.xz"));
        assert!(x86.contains("d2ce450af6abc290d153723f790546d836428aa60f8b61d4a3d2c1dacde5d6c5  /tmp/mise.txz"));
        assert!(dockerfile("riscv64").is_err());
    }

    #[test]
    fn static_sites_copy_the_publish_directory() {
        let plain = static_dockerfile("", None, false);
        assert!(plain.starts_with(&format!("FROM {STATIC_SERVER_IMAGE}\n")));
        assert!(plain.ends_with("COPY ./ /srv/\n"), "{plain}");
        assert!(!plain.contains("try_files"));
        let built = static_dockerfile("dist", Some("owd/app_1:dep_1-build"), true);
        assert!(built.starts_with("FROM owd/app_1:dep_1-build AS site\n"), "{built}");
        assert!(built.ends_with("COPY --from=site /app/dist/ /srv/\n"), "{built}");
        assert!(built.contains("try_files {path} {path}/ /index.html"));
        assert!(caddyfile(false).contains(":{$PORT:80} {"));
    }

    #[test]
    fn railpack_variables_cannot_steer_the_helper() {
        for n in ["PATH", "OWD_IMAGE", "DOCKER_HOST", "BUILDKIT_SYNTAX", "MISE_DATA_DIR"] {
            assert!(reserved(n), "{n}");
        }
        assert!(!reserved("NODE_ENV") && !reserved("RAILPACK_NODE_VERSION"));
        assert!(env_name_ok("NODE_ENV") && !env_name_ok("A B") && !env_name_ok("1A") && !env_name_ok("A;B"));
    }

    #[test]
    fn dockerfile_builds_take_any_argument_name_from_the_bake_file() {
        let spec = BuildSpec {
            context: ".".into(),
            dockerfile: "docker/Dockerfile".into(),
            args: [("PATH".to_string(), "/x".to_string()), ("TOKEN".to_string(), "v".to_string())].into(),
            target: Some("prod".into()),
            no_cache: true,
            pack: BuildPack::Dockerfile,
            install_command: None,
            build_command: None,
            start_command: None,
            publish_dir: None,
            spa: false,
            untrusted: false,
        };
        let b = bake_file(&spec, "docker/Dockerfile", "owd/app_1:dep_1", "app_1", "dep_1");
        let t = &b["target"]["default"];
        assert_eq!(t["args"], serde_json::json!({"PATH": "/x", "TOKEN": "v"}));
        assert_eq!(
            (t["dockerfile"].as_str(), t["target"].as_str(), t["no-cache"].as_bool()),
            (Some("docker/Dockerfile"), Some("prod"), Some(true))
        );
        assert_eq!(t["labels"][LABEL_RESOURCE], "app_1");
        assert_eq!(t["output"], serde_json::json!(["type=docker"]));
        let b = bake_file(&BuildSpec { target: None, ..spec }, "Dockerfile", "t", "r", "d");
        assert!(b["target"]["default"].get("target").is_none());
    }

    fn limits(vars: &[(&str, &str)]) -> (Limits, Vec<String>) {
        let vars: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Limits::parse(|name| vars.get(name).cloned())
    }

    const MIB: i64 = 1024 * 1024;

    #[test]
    fn limits_default_take_valid_values_and_replace_invalid_ones() {
        let defaults = Limits {
            nano_cpus: 2_000_000_000,
            memory: 4096 * MIB,
            pids: 2048,
            cache: 10 * 1024 * MIB,
            cache_max_age_hours: 168,
        };
        assert_eq!(limits(&[]), (defaults.clone(), vec![]));
        assert_eq!(limits(&[("OWDEPLOY_BUILD_CPUS", " "), ("OWDEPLOY_BUILD_PIDS", "")]), (defaults.clone(), vec![]));
        let (l, w) = limits(&[
            ("OWDEPLOY_BUILD_CPUS", "1.5"),
            ("OWDEPLOY_BUILD_MEMORY_MB", "512"),
            ("OWDEPLOY_BUILD_PIDS", "300"),
            ("OWDEPLOY_BUILD_CACHE_GB", "3"),
            ("OWDEPLOY_BUILD_CACHE_MAX_AGE_HOURS", " 24 "),
        ]);
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(
            l,
            Limits {
                nano_cpus: 1_500_000_000,
                memory: 512 * MIB,
                pids: 300,
                cache: 3 * 1024 * MIB,
                cache_max_age_hours: 24
            }
        );
        // Each invalid value falls back to its own default, with a warning naming it; the others still apply.
        for (name, bad) in [
            ("OWDEPLOY_BUILD_CPUS", "two"),
            ("OWDEPLOY_BUILD_CPUS", "0"),
            ("OWDEPLOY_BUILD_CPUS", "-1"),
            ("OWDEPLOY_BUILD_CPUS", "NaN"),
            ("OWDEPLOY_BUILD_CPUS", "inf"),
            ("OWDEPLOY_BUILD_MEMORY_MB", "4g"),
            ("OWDEPLOY_BUILD_MEMORY_MB", "64"),
            ("OWDEPLOY_BUILD_MEMORY_MB", "1024.5"),
            ("OWDEPLOY_BUILD_PIDS", "0"),
            ("OWDEPLOY_BUILD_CACHE_GB", "0"),
            ("OWDEPLOY_BUILD_CACHE_MAX_AGE_HOURS", "1e9"),
        ] {
            let valid = if name == "OWDEPLOY_BUILD_PIDS" {
                ("OWDEPLOY_BUILD_CPUS", "3")
            } else {
                ("OWDEPLOY_BUILD_PIDS", "100")
            };
            let (l, w) = limits(&[(name, bad), valid]);
            let expected = limits(&[valid]).0;
            assert_eq!(l, expected, "{name}={bad}");
            assert_eq!(w.len(), 1, "{name}={bad}: {w:?}");
            assert!(w[0].starts_with(&format!("{name}=")), "{w:?}");
        }
    }

    fn assert_limits(h: &HostConfig, l: &Limits) {
        assert_eq!(
            (h.nano_cpus, h.memory, h.memory_swap, h.pids_limit),
            (Some(l.nano_cpus), Some(l.memory), Some(l.memory), Some(l.pids)),
            "no swap beyond the memory limit"
        );
    }

    #[test]
    fn builders_mount_no_host_path_and_keep_only_their_namespace_capabilities() {
        let (l, _) = limits(&[("OWDEPLOY_BUILD_CPUS", "0.5")]);
        for b in [Builder::Trusted, Builder::Untrusted] {
            let c = builder_container(b, vec!["seccomp=unconfined".into()], &l);
            assert_eq!(c.cmd, Some(vec!["--config".to_string(), BUILDKITD_CONFIG.to_string()]));
            let h = c.host_config.unwrap();
            assert!(h.binds.is_none() && h.privileged.is_none() && h.devices.is_none());
            let mounts = h.mounts.as_ref().unwrap();
            assert_eq!(mounts.len(), 1);
            assert_eq!((mounts[0].typ, mounts[0].source.as_deref()), (Some(MountType::VOLUME), Some(b.volume())));
            assert_eq!(
                (h.cap_drop.clone().unwrap(), h.cap_add.clone().unwrap()),
                (vec!["ALL".to_string()], vec!["SETUID".to_string(), "SETGID".to_string()])
            );
            assert_eq!(h.network_mode.as_deref(), Some(BUILD_NETWORK));
            assert_limits(&h, &l);
        }
        assert_ne!(Builder::Trusted.volume(), Builder::Untrusted.volume(), "untrusted code never shares a cache");
    }

    #[test]
    fn only_the_docker_helper_gets_the_socket_and_no_helper_gets_privileges() {
        let l = super::limits();
        for role in [Role::Source, Role::Docker] {
            let c = helper_container(role, "app_1");
            assert_eq!(c.labels.unwrap().get(LABEL_HELPER).map(String::as_str), Some("app_1"), "found as a leftover");
            let h = c.host_config.unwrap();
            assert!(h.binds.is_none() && h.privileged.is_none() && h.devices.is_none() && h.cap_add.is_none());
            assert_eq!(h.cap_drop.as_deref(), Some(["ALL".to_string()].as_slice()));
            assert_eq!(h.security_opt.as_deref(), Some(["no-new-privileges".to_string()].as_slice()));
            assert!(h.tmpfs.as_ref().unwrap().contains_key(SECRETS_TMPFS.0), "the clone's secrets stay in memory");
            assert_limits(&h, l);
            let mounts = h.mounts.unwrap_or_default();
            let sockets = mounts.iter().filter(|m| m.source.as_deref() == Some(DOCKER_SOCKET)).count();
            assert_eq!(sockets, usize::from(role == Role::Docker), "{role:?}");
            assert_eq!(mounts.len(), sockets, "{role:?}: no other mount");
        }
    }

    #[test]
    fn a_builder_with_other_limits_keeps_its_cache_and_another_configuration_drops_it() {
        let security = vec!["seccomp=unconfined".to_string()];
        let l = limits(&[]).0;
        let inspect = |body: ContainerCreateBody| bollard::models::ContainerInspectResponse {
            config: Some(bollard::models::ContainerConfig {
                image: body.image,
                labels: body.labels,
                cmd: body.cmd,
                ..Default::default()
            }),
            host_config: body.host_config,
            ..Default::default()
        };
        let made = |l: &Limits| inspect(builder_container(Builder::Trusted, security.clone(), l));
        assert_eq!(fit(&made(&l), &security, &l), Fit::Current);
        for other in [
            limits(&[("OWDEPLOY_BUILD_CPUS", "4")]).0,
            limits(&[("OWDEPLOY_BUILD_MEMORY_MB", "8192")]).0,
            limits(&[("OWDEPLOY_BUILD_PIDS", "100")]).0,
            limits(&[("OWDEPLOY_BUILD_CACHE_GB", "20")]).0,
            limits(&[("OWDEPLOY_BUILD_CACHE_MAX_AGE_HOURS", "24")]).0,
        ] {
            assert_eq!(fit(&made(&other), &security, &l), Fit::Recreate, "{other:?}");
        }
        // A builder of an earlier agent: no limits, no configuration file, same image and revision.
        let mut earlier = made(&l);
        let config = earlier.config.as_mut().unwrap();
        config.cmd = None;
        config.labels.as_mut().unwrap().remove(LABEL_BUILDER_SETTINGS);
        assert_eq!(fit(&earlier, &security, &l), Fit::Recreate);

        let mut revision = made(&l);
        revision.config.as_mut().unwrap().labels.as_mut().unwrap().insert(LABEL_BUILDER.into(), "rootless-0".into());
        assert_eq!(fit(&revision, &security, &l), Fit::Replace);
        let mut image = made(&l);
        image.config.as_mut().unwrap().image = Some("moby/buildkit:v0.1-rootless".into());
        assert_eq!(fit(&image, &security, &l), Fit::Replace);
        let apparmor = vec!["seccomp=unconfined".to_string(), "apparmor=unconfined".to_string()];
        assert_eq!(fit(&made(&l), &apparmor, &l), Fit::Replace);
        assert_eq!(fit(&made(&limits(&[("OWDEPLOY_BUILD_CPUS", "4")]).0), &apparmor, &l), Fit::Replace);
    }
}
