//! The builder helpers: throwaway containers with the Docker CLI (BuildKit through buildx, Compose's resolution),
//! Railpack and syft, for builds the Engine API alone cannot run (the helper-container model). The server needs no
//! build tool: the agent builds the helper image itself, once, from pinned and checksummed releases.
//!
//! Helpers live for one deployment: created idle, the agent runs each step in them with `docker exec` and removes
//! them at the end, on failure and on cancel alike. Removing one kills the step running in it, which closes its
//! BuildKit session and stops the build. No helper has the Engine's socket: only the agent process talks to the
//! Engine. Repository content is handled first in a source helper ([`Role::Source`]: no capability,
//! `no-new-privileges`): the clone, Railpack's plan, Compose's resolution. Its /src (and the plan) is then copied,
//! Engine to Engine, into a build helper ([`Role::Build`]), which reaches one builder's BuildKit and nothing else,
//! and the source helper is removed. Builds export OCI image layouts into the build helper, which the agent checks
//! and loads into the Engine itself ([`crate::oci`]).
//!
//! Resources are bounded ([`Limits`], from the agent's environment): `OWDEPLOY_BUILD_CPUS` (default 2),
//! `OWDEPLOY_BUILD_MEMORY_MB` (4096, no swap on top) and `OWDEPLOY_BUILD_PIDS` (2048) for each builder and each
//! helper; `OWDEPLOY_BUILD_CACHE_GB` (10) and `OWDEPLOY_BUILD_CACHE_MAX_AGE_HOURS` (168) for each builder's cache,
//! which its daemon garbage-collects and the agent prunes after every build.
//!
//! Every build (Dockerfile, Compose, Railpack, static sites) runs on a rootless BuildKit daemon, never on the
//! Engine's builder: [`BUILDKIT_IMAGE`] (pinned by digest) in an agent-owned container, without host mounts (its
//! state is a named volume), without privileges (only `SETUID`/`SETGID` for its user namespace helpers; seccomp and
//! AppArmor unconfined, and an unmasked /proc, which BuildKit's own sandbox needs), as an unprivileged user: build
//! steps are root only inside a user namespace mapped to unprivileged host ids. It listens on a unix socket in a
//! memory-backed volume of its own ([`Builder::socket_volume`]), mounted only into the builder and the build helpers
//! that use it (which join the socket's group, the image's unprivileged user's); buildx reaches it with its `remote`
//! driver. The builders and build helpers sit on their own network, [`BUILD_NETWORK`] (bridge [`BUILD_BRIDGE`]),
//! which is internal: build steps share the builder's network namespace and have no way out but the build egress
//! proxy on the same network ([`crate::egress`]), which applies the deployment's egress policy and never connects to
//! private ranges, cloud metadata or the server. Untrusted code (pull requests from forks) builds on a second
//! builder with its own state and socket, so it never shares a cache (cache mounts included) with the application's
//! own builds.
//!
//! Every image built gets an SPDX SBOM attestation from BuildKit's generator ([`SBOM_SCANNER`], pinned by digest),
//! which the agent sends with the deployment ([`crate::sbom`]).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock, Mutex};

use bollard::Docker;
use bollard::models::{ContainerCreateBody, HostConfig, Mount, MountType};
use bollard::query_parameters::{
    BuildImageOptionsBuilder, CreateContainerOptionsBuilder, DownloadFromContainerOptionsBuilder,
    UploadToContainerOptionsBuilder,
};
use deploy_proto::msg::{BuildEgress, BuildPack, BuildSpec, LABEL_DEPLOYMENT, LABEL_RESOURCE, LogStream, Step};
use futures_util::StreamExt;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::docker::{File, LABEL_HELPER, ensure_image, message, remove_container, upload};
use crate::events::Events;
use crate::exec;
use crate::git::{self, Cloned, Repo, SECRETS_TMPFS};
use crate::oci::{self, Expect, Loaded};

const DOCKER_CLI_IMAGE: &str = "docker:29.9.3-cli";
const RAILPACK_VERSION: &str = "0.43.0";
/// The mise release Railpack 0.43.0 pins (core/mise/version.txt); installed where Railpack looks for it, so a
/// build never downloads it.
const MISE_VERSION: &str = "2026.10.14";
/// The SBOM generator for images without an SBOM attestation (pulled ones): the release BuildKit's generator
/// [`SBOM_SCANNER`] embeds.
pub const SYFT_VERSION: &str = "1.51.0";
/// BuildKit frontend that turns a Railpack plan into an image, same version as the CLI that wrote the plan.
pub const RAILPACK_FRONTEND: &str = "ghcr.io/railwayapp/railpack-frontend:v0.43.0";
/// Static sites are served by the router's Caddy, so a server keeps one web server image.
pub const STATIC_SERVER_IMAGE: &str = crate::router::IMAGE;
/// Tag of the helper image: changes with any pinned version, so an upgraded agent builds its own.
pub const IMAGE: &str = "owd/helper:2-docker29.9.3-railpack0.43.0-syft1.51.0";
/// Label on the helper image, so it is never mistaken for an application's.
const LABEL_HELPER_IMAGE: &str = "dev.openwaf.deploy.helper-image";
/// The rootless BuildKit daemon of every build, pinned by digest (the multi-platform index of the tag).
pub const BUILDKIT_IMAGE: &str =
    "moby/buildkit:v0.34.2-rootless@sha256:c8252268760e1baba80780d63d738ef9f260fb7c7c0973c78494cb9ddd99eda1";
/// BuildKit's SBOM generator for `--sbom` attestations, pinned by digest (the multi-platform index of `stable-1`).
pub const SBOM_SCANNER: &str =
    "docker/buildkit-syft-scanner:stable-1@sha256:873a7458c3c8ac8e32c7b796c10e1600b07b963d2aa000a72a2d97aaaa2d6315";
/// Where a builder's socket volume is mounted, in the builder and in its build helpers.
const BUILDKIT_SOCKET_DIR: &str = "/run/owd-buildkit";
/// The address BuildKit listens on, in [`BUILDKIT_SOCKET_DIR`].
const BUILDKIT_ADDR: &str = "unix:///run/owd-buildkit/buildkitd.sock";
/// User and group ids of the rootless BuildKit image's user: the socket's owner and group (mode 0660, in a
/// directory of mode 0750). Build helpers join the group; nothing else on the server can reach the socket.
const BUILDKIT_ID: &str = "1000";
/// Where builds write the OCI image layouts the agent loads, in the build helper.
const OUT: &str = "/owd/out";
/// Network of the builders, the build helpers and the build egress proxy: internal (no route out, no outside name
/// resolved for its containers), so the proxy is the only way out ([`crate::egress`]). The firewall also refuses
/// anything its bridge, [`BUILD_BRIDGE`], would forward or send to the server.
pub const BUILD_NETWORK: &str = "owd-build-internal";
pub const BUILD_BRIDGE: &str = "owd-buildi0";
/// The builders' network of earlier agents (not internal), removed once no container uses it.
const LEGACY_BUILD_NETWORK: &str = "owd-build";
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

/// Host configuration of a container that handles repository content (the clone, Railpack's plan, Compose's
/// resolution, builds) or images (the SBOM generator): the secrets tmpfs of [`git::SCRIPT`], no capability (root in
/// it is an ordinary user towards files it does not own, and cannot gain any privilege back through setuid
/// binaries), and the build [`limits`].
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

/// A rootless BuildKit builder: the container (also its buildx builder name), its state volume and its socket
/// volume.
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

    /// The volume holding the builder's socket: memory (tmpfs), owned by the image's user, shared with the build
    /// helpers of this builder only.
    pub fn socket_volume(self) -> &'static str {
        match self {
            Builder::Trusted => "owd-buildkit-sock",
            Builder::Untrusted => "owd-buildkit-untrusted-sock",
        }
    }
}

/// Registers a builder in a build helper (buildx keeps builders in the client's configuration, which dies with each
/// helper) and waits until its daemon answers on its socket (it may have just started).
const BUILDER_SCRIPT: &str = r#"set -eu
docker buildx create --name "$OWD_BUILDER" --driver remote "$OWD_ADDR" >/dev/null
i=0
until docker buildx inspect --bootstrap "$OWD_BUILDER" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then exec docker buildx inspect --bootstrap "$OWD_BUILDER" >/dev/null; fi
  sleep 1
done
"#;

/// Release assets per architecture of the Docker host: (Railpack archive, SHA-256), (mise archive, SHA-256), (syft
/// archive, SHA-256).
fn assets(arch: &str) -> Result<[(String, &'static str); 3], String> {
    let (rp, rp_sum, mise, mise_sum, syft, syft_sum) = match arch {
        "aarch64" | "arm64" => (
            "arm64-unknown-linux-musl",
            "732ece14eb4f4676a43ebba19431f954edf7b130acb76159ef0f2ff86ac42ac9",
            "linux-arm64-musl",
            "2b661edd0ba55d4f9fac940d0e108c79893bb30642ac5b532a677b49fa7cb8b3",
            "linux_arm64",
            "6c0466811541ea03add5213a60a1562f0851e4c0b0ecfdee1a694a9455285900",
        ),
        "x86_64" | "amd64" => (
            "x86_64-unknown-linux-musl",
            "248a8f60f36854aabed6124113631078a802de3461660855fc4de9c26065c1fb",
            "linux-x64-musl",
            "d2ce450af6abc290d153723f790546d836428aa60f8b61d4a3d2c1dacde5d6c5",
            "linux_amd64",
            "2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f",
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
        (
            format!(
                "https://github.com/anchore/syft/releases/download/v{SYFT_VERSION}/syft_{SYFT_VERSION}_{syft}.tar.gz"
            ),
            syft_sum,
        ),
    ])
}

/// The helper image's Dockerfile: the Docker CLI image plus Railpack, mise and syft, each checked against its
/// SHA-256.
fn dockerfile(arch: &str) -> Result<String, String> {
    let [(rp, rp_sum), (mise, mise_sum), (syft, syft_sum)] = assets(arch)?;
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
           wget -q -O /tmp/syft.tgz '{syft}'; \\\n  \
           echo '{syft_sum}  /tmp/syft.tgz' | sha256sum -c -; \\\n  \
           tar -xzf /tmp/syft.tgz -C /usr/local/bin syft; \\\n  \
           rm -rf /tmp/railpack.tgz /tmp/mise.txz /tmp/mise /tmp/syft.tgz; \\\n  \
           railpack --version; \\\n  \
           syft version\n\
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
    // Helper images of earlier agents go (one still used by a helper stays until the next build).
    let filters = HashMap::from([("label".to_string(), vec![LABEL_HELPER_IMAGE.to_string()])]);
    let opts = bollard::query_parameters::ListImagesOptionsBuilder::default().filters(&filters).build();
    for i in d.list_images(Some(opts)).await.unwrap_or_default() {
        if !i.repo_tags.iter().any(|t| t == IMAGE) {
            let _ = d.remove_image(&i.id, None::<bollard::query_parameters::RemoveImageOptions>, None).await;
        }
    }
    Ok(())
}

/// What a helper container is for. Each runs the helper image without capabilities, `no-new-privileges` and the
/// build [`limits`]; none has the Engine's socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Repository content: the clone, Railpack's plan, Compose's resolution; registry lookups of SBOM attestations.
    /// On Docker's default bridge (Git servers may be private ones the build network would refuse).
    Source,
    /// `docker buildx` against one builder, through its socket volume, on what a source helper produced. On the
    /// build network (buildx fetches registry tokens for BuildKit, through the build egress proxy with its builder's
    /// token, set in its environment). Never clones.
    Build(Builder),
    /// The SBOM generator, on an image the agent exported from the Engine. No network.
    Scan,
}

/// The container of a helper with `role` for `resource`, with `env` (a build helper's proxy settings).
fn helper_container(role: Role, resource: &str, env: Vec<String>) -> ContainerCreateBody {
    let mut host = source_host_config();
    host.init = Some(true);
    match role {
        Role::Source => {}
        Role::Build(b) => {
            host.network_mode = Some(BUILD_NETWORK.into());
            host.mounts = Some(vec![Mount {
                typ: Some(MountType::VOLUME),
                source: Some(b.socket_volume().into()),
                target: Some(BUILDKIT_SOCKET_DIR.into()),
                ..Default::default()
            }]);
            host.group_add = Some(vec![BUILDKIT_ID.into()]);
        }
        Role::Scan => host.network_mode = Some("none".into()),
    }
    ContainerCreateBody {
        image: Some(IMAGE.into()),
        env: (!env.is_empty()).then_some(env),
        // Idle until removed; each step is an exec. `sleep` outlives any build (24 h).
        entrypoint: Some(vec!["sleep".into(), "86400".into()]),
        // The same label for every role: `git::remove_leftover_helpers` finds them all.
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
    /// A build helper for builder `b`: the build egress proxy and the builder are made usable first
    /// ([`crate::egress::ensure_proxy`], [`ensure_builder`]), the builder's own token registered with the proxy, then
    /// buildx in the helper knows the builder.
    pub async fn build(
        d: &Docker,
        resource: &str,
        b: Builder,
        ev: &Events,
        cancel: &CancellationToken,
    ) -> Result<Helper, String> {
        crate::egress::ensure_proxy(d, ev).await?;
        let token = ensure_builder(d, b, ev).await?;
        crate::egress::register_builder(d, b.name(), &token).await?;
        let proxy = crate::egress::env(&crate::egress::url(&token, crate::egress::CONTAINER));
        let h = Helper::create(d, resource, Role::Build(b), proxy, ev).await?;
        let env = vec![format!("OWD_BUILDER={}", b.name()), format!("OWD_ADDR={BUILDKIT_ADDR}")];
        match h.sh(BUILDER_SCRIPT, env, ev, cancel, &mut |_, _| true).await {
            Ok(0) => Ok(h),
            r => {
                h.remove().await;
                Err(match r {
                    Ok(code) => format!("the BuildKit builder {} does not answer (exit code {code})", b.name()),
                    Err(e) => e,
                })
            }
        }
    }

    /// A helper for repository content.
    pub async fn source(d: &Docker, resource: &str, ev: &Events) -> Result<Helper, String> {
        Helper::create(d, resource, Role::Source, Vec::new(), ev).await
    }

    /// A helper for the SBOM generator, without network.
    pub async fn scan(d: &Docker, resource: &str, ev: &Events) -> Result<Helper, String> {
        Helper::create(d, resource, Role::Scan, Vec::new(), ev).await
    }

    async fn create(d: &Docker, resource: &str, role: Role, env: Vec<String>, ev: &Events) -> Result<Helper, String> {
        ensure_image_built(d, ev).await?;
        let what = match role {
            Role::Source => "source helper",
            Role::Build(_) => "build helper",
            Role::Scan => "SBOM helper",
        };
        let created = d
            .create_container(
                Some(CreateContainerOptionsBuilder::default().build()),
                helper_container(role, resource, env),
            )
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
    /// `stdin`, when given, is written to the command, then closed and wiped (see [`exec::start`]).
    pub async fn output(
        &self,
        cmd: Vec<String>,
        env: Vec<String>,
        stdin: Option<Vec<u8>>,
        cap: usize,
        ev: &Events,
        cancel: &CancellationToken,
    ) -> Result<(i64, Vec<u8>), String> {
        let mut r = exec::start(&self.d, &self.id, cmd, env, stdin).await?;
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
    /// source helper: repository content reaches a build helper only through the agent's copy.
    pub async fn clone(&self, repo: &Repo<'_>, ev: &Events, cancel: &CancellationToken) -> Result<Cloned, String> {
        if self.role != Role::Source {
            return Err("the clone runs in a source helper".into());
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
        let file = tokio::fs::File::open(archive).await.map_err(|e| format!("build context: {e}"))?;
        let body = tokio_util::io::ReaderStream::new(file);
        self.unpack("ctx", body, &CancellationToken::new())
            .await
            .map_err(|e| format!("copy the build context into the build helper: {e}"))
    }

    /// Unpacks the tar archive `archive` into the directory `/<dir>` (created here) of the helper.
    pub async fn unpack<S, E>(&self, dir: &str, archive: S, cancel: &CancellationToken) -> Result<(), String>
    where
        S: futures_util::Stream<Item = Result<bytes::Bytes, E>> + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o755);
        h.set_size(0);
        b.append_data(&mut h, format!("{dir}/"), std::io::empty()).map_err(|e| e.to_string())?;
        let made = b.into_inner().map_err(|e| e.to_string())?;
        let opts = |p: &str| UploadToContainerOptionsBuilder::default().path(p).build();
        self.d
            .upload_to_container(&self.id, Some(opts("/")), bollard::body_full(made.into()))
            .await
            .map_err(|e| message(&e))?;
        let body = bollard::body_try_stream(archive.map(|r| r.map_err(std::io::Error::other)));
        let upload = self.d.upload_to_container(&self.id, Some(opts(&format!("/{dir}"))), body);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(crate::CANCELLED.into()),
            r = upload => r.map_err(|e| message(&e)),
        }
    }

    /// Checks and loads the image layout bake target `target` exported ([`OUT`]) as `tag` ([`oci::load`]).
    pub async fn load(
        &self,
        target: &str,
        expect: Expect<'_>,
        tag: &str,
        ev: &Events,
        cancel: &CancellationToken,
    ) -> Result<Loaded, String> {
        let loaded = oci::load(&self.d, &self.id, &format!("{OUT}/{target}"), expect, tag, cancel).await?;
        ev.system(format!("Checked and loaded {tag} ({})", loaded.id)).await;
        Ok(loaded)
    }
}

/// Runs `/owd/bake.json` in a build helper: the targets of `OWD_TARGETS` (and those they use), provenance off (an
/// SBOM attestation is set per target by [`export`]).
const BAKE_SCRIPT: &str = r#"set -eu
cd /
docker buildx bake --builder "$OWD_BUILDER" --progress plain --provenance=false -f /owd/bake.json $OWD_TARGETS
"#;

/// Makes bake target `name` export its image as an OCI image layout into [`OUT`] for the agent to load, with
/// BuildKit's SBOM attestation when `sbom`.
fn export(target: &mut Value, name: &str, sbom: bool) {
    target["output"] = json!([format!("type=oci,tar=false,dest={OUT}/{name}")]);
    target["attest"] = match sbom {
        true => json!([format!("type=sbom,generator={SBOM_SCANNER}")]),
        false => json!([]),
    };
}

/// Whether a build log line names the SBOM generator in the summary of a failed step (` > … buildkit-syft-scanner
/// …`).
fn scanner_failed(line: &str) -> bool {
    line.trim_start().starts_with("> ") && line.contains("buildkit-syft-scanner")
}

/// Builds `targets` of the bake file `file` on builder `b` from build helper `h`; each name of `exported` is a
/// target whose image the agent loads afterwards ([`Helper::load`]). The file goes into the helper, so build
/// arguments are neither in argv nor in the environment, whatever their names; `env` is the build's environment
/// (secrets the file names). Every target gets the build egress proxy of `egress` as BuildKit's predefined proxy
/// arguments (in place of the user's own), and the environment carries it for Railpack's secrets
/// ([`crate::egress::Session::secret_env`]). The builder's cache is pruned afterwards ([`prune_cache`]).
///
/// BuildKit fails a build whose SBOM generator cannot run (its image cannot be pulled, say): such a build runs
/// again without the attestation, so an SBOM never fails a deployment. Returns whether the attestations were made,
/// or the build's exit code when it failed.
#[allow(clippy::too_many_arguments)]
pub async fn bake(
    h: &Helper,
    b: Builder,
    mut file: Value,
    targets: &[&str],
    exported: &[&str],
    env: Vec<String>,
    egress: &crate::egress::Session,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<Result<bool, i64>, String> {
    let mut env = env;
    env.extend(egress.secret_env());
    env.push(format!("OWD_BUILDER={}", b.name()));
    env.push(format!("OWD_TARGETS={}", targets.join(" ")));
    let replaced = proxy_args(&mut file, &egress.args());
    if !replaced.is_empty() {
        ev.system(format!(
            "Build arguments {} are set by the agent: build steps reach the Internet through the build egress proxy",
            replaced.join(", ")
        ))
        .await;
    }
    let mut outcome = Err(-1);
    for sbom in [true, false] {
        for t in exported {
            export(&mut file["target"][*t], t, sbom);
        }
        let data = serde_json::to_vec(&file).expect("json");
        h.put(&[File { path: "bake.json", data: &data, mode: 0o600 }]).await?;
        let mut scanner = false;
        let code = h
            .sh(BAKE_SCRIPT, env.clone(), ev, cancel, &mut |_, l| {
                scanner |= scanner_failed(l);
                true
            })
            .await?;
        outcome = if code == 0 { Ok(sbom) } else { Err(code) };
        if code == 0 || !sbom || !scanner {
            break;
        }
        ev.system("BuildKit could not run its SBOM generator: building again without the SBOM attestation").await;
    }
    prune_cache(h, b, ev, cancel).await;
    Ok(outcome)
}

/// Sets `args` on every target of the bake file; returns the names some target had set otherwise.
fn proxy_args(file: &mut Value, args: &[(String, String)]) -> Vec<String> {
    let mut replaced = std::collections::BTreeSet::new();
    if let Some(targets) = file["target"].as_object_mut() {
        for t in targets.values_mut() {
            if !t["args"].is_object() {
                t["args"] = json!({});
            }
            let a = t["args"].as_object_mut().expect("an object");
            for (k, v) in args {
                if a.insert(k.clone(), v.as_str().into()).is_some_and(|old| old != v.as_str()) {
                    replaced.insert(k.clone());
                }
            }
        }
    }
    replaced.into_iter().collect()
}

/// The bake file of a Dockerfile build of the context in /ctx: one target, `image`.
fn dockerfile_bake(spec: &BuildSpec, dockerfile: &str, resource: &str, deployment: &str) -> Value {
    let mut target = json!({
        "context": "/ctx",
        "dockerfile": dockerfile,
        "args": spec.args,
        "labels": {LABEL_RESOURCE: resource, LABEL_DEPLOYMENT: deployment},
        "no-cache": spec.no_cache,
    });
    if let Some(t) = &spec.target {
        target["target"] = t.as_str().into();
    }
    json!({"target": {"image": target}})
}

/// Builds the repository's Dockerfile from `ctx` on the rootless builder ([`Builder::of`] the spec) and loads it as
/// `tag`.
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
) -> Result<Loaded, String> {
    let policy = crate::egress::policy(spec.egress.as_ref())?;
    let builder = Builder::of(spec.untrusted);
    let h = Helper::build(d, resource, builder, ev, cancel).await?;
    let r = async {
        h.put_context(&ctx.tar).await?;
        ev.system(format!("Building on the rootless BuildKit builder {}", builder.name())).await;
        let egress = crate::egress::Session::start(d, deployment, &policy, ev).await?;
        let file = dockerfile_bake(spec, &ctx.dockerfile, resource, deployment);
        let built = bake(&h, builder, file, &["image"], &["image"], Vec::new(), &egress, ev, cancel).await;
        egress.finish(ev).await;
        if let Err(code) = built? {
            return Err(format!("build failed (exit code {code})"));
        }
        h.load("image", Expect { resource, deployment }, tag, ev, cancel).await
    }
    .await;
    h.remove().await;
    r
}

/// Railpack's plan, in the source helper: detection and overrides, from the repository, written to /owd. Build
/// variables reach Railpack as environment, never in argv. The proxy variables are declared with a placeholder
/// (Railpack lists every variable it is given as a secret its steps see as environment): their values, the build
/// egress proxy's, only exist at build time ([`railpack_target`]).
const PREPARE_SCRIPT: &str = r#"set -eu
mkdir -p /owd
cd "/src/$OWD_CONTEXT"
set --
for n in $OWD_ENV_NAMES; do set -- "$@" --env "$n"; done
for n in $OWD_EGRESS_NAMES; do set -- "$@" --env "$n=build-egress-proxy"; done
railpack prepare . --plan-out /owd/railpack-plan.json --info-out /owd/railpack-info.json "$@"
"#;

/// What Railpack builds, in the build helper: the plan [`PREPARE_SCRIPT`] wrote, through Railpack's frontend
/// (target `railpack`, kept in BuildKit). Build variables reach BuildKit as secrets from the build's environment,
/// never in argv; so do the build egress proxy's settings ([`crate::egress::Session::secret_env`]), which stay out of
/// the secrets hash (a new token per build would otherwise invalidate every cached step). Railpack's frontend ignores
/// labels, so the image the agent loads is a metadata-only build on top of it (target `image`, see [`run`]), which
/// adds the resource and deployment labels (image pruning and removal find an application's images by them).
fn railpack_target(context: &str, vars: &BTreeMap<String, String>, resource: &str, no_cache: bool) -> Value {
    let mut hash = Sha256::new();
    for (k, v) in vars {
        hash.update(k.as_bytes());
        hash.update([0]);
        hash.update(v.as_bytes());
        hash.update([0]);
    }
    let mut secrets: Vec<String> = vars.keys().map(|n| format!("id={n},env={n}")).collect();
    secrets.extend(crate::egress::PROXY_VARS.iter().map(|n| format!("id={n},env={}", crate::egress::SECRET_ENV_PROXY)));
    secrets.extend(
        crate::egress::NO_PROXY_VARS.iter().map(|n| format!("id={n},env={}", crate::egress::SECRET_ENV_NO_PROXY)),
    );
    json!({
        "context": format!("/src/{context}"),
        "dockerfile": "/owd/railpack-plan.json",
        "args": {
            "BUILDKIT_SYNTAX": RAILPACK_FRONTEND,
            "cache-key": resource.to_ascii_lowercase(),
            "secrets-hash": hex::encode(hash.finalize()),
        },
        "secret": secrets,
        "no-cache": no_cache,
        "output": ["type=cacheonly"],
    })
}

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
    let failure = match h.output(cmd, prune_env(b, limits()), None, 64 * 1024, ev, cancel).await {
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

/// Makes rootless builder `b` usable: its network and socket volume exist, and its container runs the pinned image
/// with the current configuration. A builder of another image, revision or security options, and the privileged
/// builder of earlier agents, are replaced, cache included; a builder with other limits, cache settings, daemon
/// arguments, network or without its build egress proxy settings is recreated on the same cache ([`fit`]). Returns
/// the builder's own token for the build egress proxy (read back from its environment, or new).
async fn ensure_builder(d: &Docker, b: Builder, ev: &Events) -> Result<String, String> {
    let _g = BUILDER_LOCK.lock().await;
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
        Some((Fit::Current(token), c)) => Some((token, c)),
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
    let (token, running) = match current {
        Some((token, c)) => (token, c.state.and_then(|s| s.running).unwrap_or(false)),
        None => {
            ensure_image(d, BUILDKIT_IMAGE, Some(ev)).await?;
            ensure_build_network(d).await?;
            ensure_socket_volume(d, b).await?;
            ev.system(format!("Creating the rootless BuildKit builder {} (once per server)", b.name())).await;
            let token = crate::egress::token();
            let opts = CreateContainerOptionsBuilder::default().name(b.name()).build();
            d.create_container(Some(opts), builder_container(b, security, limits, &token))
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
            // The network of earlier builders goes once nothing uses it (best effort: a build helper of an earlier
            // agent may still be on it).
            let _ = d.remove_network(LEGACY_BUILD_NETWORK).await;
            (token, false)
        }
    };
    if !running {
        d.start_container(b.name(), None)
            .await
            .map_err(|e| format!("start the BuildKit builder {}: {}", b.name(), message(&e)))?;
    }
    Ok(token)
}

/// The volume of builder `b`'s socket: a tmpfs owned by the image's user and group, mode 0750 (see
/// [`BUILDKIT_ID`]). An existing one with other options is refused rather than used.
async fn ensure_socket_volume(d: &Docker, b: Builder) -> Result<(), String> {
    let name = b.socket_volume();
    let options = HashMap::from([
        ("type".to_string(), "tmpfs".to_string()),
        ("device".to_string(), "tmpfs".to_string()),
        ("o".to_string(), format!("uid={BUILDKIT_ID},gid={BUILDKIT_ID},mode=0750,size=1m,nosuid,nodev,noexec")),
    ]);
    match d.inspect_volume(name).await {
        Ok(v) if v.options == options => return Ok(()),
        Ok(_) => return Err(format!("volume {name} exists with other options than the builder's socket volume")),
        Err(e) if crate::docker::is_not_found(&e) => {}
        Err(e) => return Err(format!("inspect volume {name}: {}", message(&e))),
    }
    let req = bollard::models::VolumeCreateRequest {
        name: Some(name.into()),
        driver: Some("local".into()),
        driver_opts: Some(options),
        labels: Some(HashMap::from([(LABEL_BUILDER.to_string(), "socket".to_string())])),
        ..Default::default()
    };
    d.create_volume(req).await.map(|_| ()).map_err(|e| format!("create volume {name}: {}", message(&e)))
}

/// The daemon's arguments, after the image's entrypoint (`rootlesskit buildkitd`): its socket in the socket volume
/// and its configuration file ([`Limits::buildkitd_config`]).
fn builder_cmd() -> Vec<String> {
    vec!["--addr".into(), BUILDKIT_ADDR.into(), "--config".into(), BUILDKITD_CONFIG.into()]
}

/// The container of builder `b`. Every builder gets the whole [`Limits`]: the builds running on it share them.
/// BuildKit's own traffic (image pulls, remote contexts) goes through the build egress proxy with `token`.
fn builder_container(b: Builder, security: Vec<String>, limits: &Limits, token: &str) -> ContainerCreateBody {
    let mut host = HostConfig {
        network_mode: Some(BUILD_NETWORK.into()),
        // No host path: its state and its socket are named volumes.
        mounts: Some(vec![
            Mount {
                typ: Some(MountType::VOLUME),
                source: Some(b.volume().into()),
                target: Some(BUILDKIT_STATE.into()),
                ..Default::default()
            },
            Mount {
                typ: Some(MountType::VOLUME),
                source: Some(b.socket_volume().into()),
                target: Some(BUILDKIT_SOCKET_DIR.into()),
                ..Default::default()
            },
        ]),
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
        env: Some(crate::egress::env(&crate::egress::url(token, crate::egress::CONTAINER))),
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
    /// As wanted, with its build egress proxy token.
    Current(String),
    /// Other limits, cache settings, network, or no proxy settings: a new container on the same cache volume.
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
    let token = config.and_then(|c| crate::egress::token_in(c.env.as_deref().unwrap_or_default()));
    match token {
        Some(token)
            if label(LABEL_BUILDER_SETTINGS) == Some(limits.builder_settings().as_str())
                && config.and_then(|c| c.cmd.as_deref()) == Some(builder_cmd().as_slice())
                && c.host_config.as_ref().and_then(|h| h.network_mode.as_deref()) == Some(BUILD_NETWORK) =>
        {
            Fit::Current(token)
        }
        _ => Fit::Recreate,
    }
}

async fn remove_volume(d: &Docker, name: &str) -> Result<(), String> {
    match d.remove_volume(name, None::<bollard::query_parameters::RemoveVolumeOptions>).await {
        Ok(()) => Ok(()),
        Err(e) if crate::docker::is_not_found(&e) => Ok(()),
        Err(e) => Err(format!("remove volume {name}: {}", message(&e))),
    }
}

/// The network of the builders, the build helpers and the build egress proxy: internal (see [`BUILD_NETWORK`]),
/// without IPv6, its bridge named so the firewall recognizes it. An existing one that is not internal is refused.
pub(crate) async fn ensure_build_network(d: &Docker) -> Result<(), String> {
    match build_network_internal(d).await? {
        Some(true) => return Ok(()),
        Some(false) => return Err(format!("the network {BUILD_NETWORK} exists but is not internal: remove it")),
        None => {}
    }
    let req = bollard::models::NetworkCreateRequest {
        name: BUILD_NETWORK.into(),
        driver: Some("bridge".into()),
        internal: Some(true),
        enable_ipv6: Some(false),
        options: Some(HashMap::from([(crate::firewall::BRIDGE_OPTION.to_string(), BUILD_BRIDGE.to_string())])),
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

/// Whether the build network is internal (Docker gives its containers no route out); None when it does not exist.
pub(crate) async fn build_network_internal(d: &Docker) -> Result<Option<bool>, String> {
    match d.inspect_network(BUILD_NETWORK, None).await {
        Ok(n) => Ok(Some(n.internal == Some(true))),
        Err(e) if crate::docker::is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("inspect network {BUILD_NETWORK}: {}", message(&e))),
    }
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

/// Names a Railpack build cannot take from the user: the helper's own variables and what its tools depend on.
fn reserved(name: &str) -> bool {
    name.starts_with("OWD_")
        || name.starts_with("BUILDKIT_")
        || name.starts_with("BUILDX_")
        || name.starts_with("DOCKER_")
        || name.starts_with("MISE_")
        || ["PATH", "HOME", "HOSTNAME", "PWD", "SHELL", "USER", "IFS"].contains(&name)
}

/// The proxy variables, which the agent sets to the build egress proxy ([`crate::egress`]).
fn egress_name(name: &str) -> bool {
    crate::egress::PROXY_VARS.contains(&name) || crate::egress::NO_PROXY_VARS.contains(&name)
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

/// The static site's Dockerfile. Without a build, `site` is a directory of the context; with one (`built`), of the
/// image Railpack built (its application lives in /app), the bake target named context `railpack`.
pub fn static_dockerfile(site: &str, built: bool, spa: bool) -> String {
    let (stage, from) = match built {
        true => ("FROM railpack AS site\n".to_string(), format!("--from=site /app/{site}")),
        false => (String::new(), site.to_string()),
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
    pub image: Loaded,
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
    let policy = crate::egress::policy(spec.egress.as_ref())?;
    let context = git::inside(&spec.context, "build context")?;
    let site = git::inside(spec.publish_dir.as_deref().unwrap_or("."), "publish directory")?;
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    let mut ignored = Vec::new();
    for (k, v) in &spec.args {
        if !env_name_ok(k) || reserved(k) {
            return Err(format!("build variable {k:?} cannot be used in a Railpack build"));
        }
        if v.contains('\0') {
            return Err("build variable values cannot contain NUL".into());
        }
        if egress_name(k) {
            ignored.push(k.as_str());
            continue;
        }
        vars.insert(k.clone(), v.clone());
    }
    if !ignored.is_empty() {
        ev.system(format!(
            "Build variables {} are set by the agent: build steps reach the Internet through the build egress proxy",
            ignored.join(", ")
        ))
        .await;
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
    let src = Helper::source(d, resource, ev).await?;
    let mut helper = None;
    let r =
        run(d, &src, &mut helper, resource, deployment, tag, repo, spec, &policy, &context, &site, vars, ev, cancel)
            .await;
    // Both go on success, failure and cancel alike.
    src.remove().await;
    if let Some(h) = helper {
        h.remove().await;
    }
    r
}

/// Clones and plans in the source helper `src`, then copies the result into a build helper (kept in `helper`, for
/// its owner to remove) that builds it, and loads the image.
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
    policy: &BuildEgress,
    context: &str,
    site: &str,
    vars: BTreeMap<String, String>,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<Built, String> {
    let cloned = src.clone(&repo, ev, cancel).await?;
    ev.step_after_fetch(Step::Building, cloned.info()).await;
    let commit = cloned.commit.clone().unwrap_or_default();
    let railpack =
        spec.pack == BuildPack::Railpack || spec.build_command.as_deref().is_some_and(|c| !c.trim().is_empty());
    let builder = Builder::of(spec.untrusted);
    if railpack {
        ev.system(format!(
            "Building with Railpack {RAILPACK_VERSION} on the rootless BuildKit builder {}",
            builder.name()
        ))
        .await;
        let names = format!("OWD_ENV_NAMES={}", vars.keys().cloned().collect::<Vec<_>>().join(" "));
        let egress_names: Vec<&str> =
            crate::egress::PROXY_VARS.iter().chain(&crate::egress::NO_PROXY_VARS).copied().collect();
        let mut env =
            vec![format!("OWD_CONTEXT={context}"), names, format!("OWD_EGRESS_NAMES={}", egress_names.join(" "))];
        env.extend(vars.iter().map(|(k, v)| format!("{k}={v}")));
        let code = src.sh(PREPARE_SCRIPT, env, ev, cancel, &mut |_, _| true).await?;
        if code != 0 {
            return Err(format!("Railpack could not plan the build (exit code {code})"));
        }
    }
    // Only what the source helper produced reaches the build helper.
    let h = &*helper.insert(Helper::build(d, resource, builder, ev, cancel).await?);
    h.copy_from(src, "/src", cancel).await?;
    if railpack {
        h.copy_from(src, "/owd", cancel).await?;
    }
    src.remove().await;
    let labels = json!({LABEL_RESOURCE: resource, LABEL_DEPLOYMENT: deployment});
    let mut targets = Map::new();
    let mut files = vec![File { path: "empty/.keep", data: b"", mode: 0o644 }];
    let dockerfile;
    if railpack {
        targets.insert("railpack".into(), railpack_target(context, &vars, resource, spec.no_cache));
    }
    let mut image = if spec.pack == BuildPack::Static {
        ev.system(format!("Packaging the static site from {}", if site.is_empty() { "." } else { site })).await;
        dockerfile = static_dockerfile(site, railpack, spec.spa);
        files.push(File { path: "static.Dockerfile", data: dockerfile.as_bytes(), mode: 0o644 });
        // The repository's .git never ends up in the served files.
        files.push(File { path: "static.Dockerfile.dockerignore", data: b".git\n", mode: 0o644 });
        let ctx = if railpack { "/owd/empty".to_string() } else { format!("/src/{context}") };
        json!({"context": ctx, "dockerfile": "/owd/static.Dockerfile"})
    } else {
        json!({"context": "/owd/empty", "dockerfile-inline": "FROM railpack\n"})
    };
    image["labels"] = labels;
    image["no-cache"] = spec.no_cache.into();
    if railpack {
        image["contexts"] = json!({"railpack": "target:railpack"});
    }
    targets.insert("image".into(), image);
    h.put(&files).await?;
    let env = vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let egress = crate::egress::Session::start(d, deployment, policy, ev).await?;
    let built = bake(h, builder, json!({"target": targets}), &["image"], &["image"], env, &egress, ev, cancel).await;
    egress.finish(ev).await;
    if let Err(code) = built? {
        return Err(match railpack {
            true => format!("Railpack build failed (exit code {code})"),
            false => format!("static site build failed (exit code {code})"),
        });
    }
    let image = h.load("image", Expect { resource, deployment }, tag, ev, cancel).await?;
    Ok(Built { commit, known_hosts: cloned.known_hosts, image })
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
        assert!(arm.contains("syft_1.51.0_linux_arm64.tar.gz"));
        assert!(arm.contains("6c0466811541ea03add5213a60a1562f0851e4c0b0ecfdee1a694a9455285900  /tmp/syft.tgz"));
        assert!(x86.contains("2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f  /tmp/syft.tgz"));
        assert!(dockerfile("riscv64").is_err());
    }

    #[test]
    fn static_sites_copy_the_publish_directory() {
        let plain = static_dockerfile("", false, false);
        assert!(plain.starts_with(&format!("FROM {STATIC_SERVER_IMAGE}\n")));
        assert!(plain.ends_with("COPY ./ /srv/\n"), "{plain}");
        assert!(!plain.contains("try_files"));
        let built = static_dockerfile("dist", true, true);
        assert!(built.starts_with("FROM railpack AS site\n"), "{built}");
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
    fn dockerfile_builds_take_any_argument_name_from_the_bake_file_and_export_a_layout_with_its_sbom() {
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
            egress: None,
        };
        let mut b = dockerfile_bake(&spec, "docker/Dockerfile", "app_1", "dep_1");
        let t = &mut b["target"]["image"];
        assert_eq!(t["args"], json!({"PATH": "/x", "TOKEN": "v"}));
        assert_eq!(
            (t["dockerfile"].as_str(), t["target"].as_str(), t["no-cache"].as_bool()),
            (Some("docker/Dockerfile"), Some("prod"), Some(true))
        );
        assert_eq!(t["labels"][LABEL_RESOURCE], "app_1");
        assert!(t.get("tags").is_none(), "the build names no image: the agent tags what it loaded");
        export(t, "image", true);
        assert_eq!(t["output"], json!(["type=oci,tar=false,dest=/owd/out/image"]), "never into the Engine");
        assert_eq!(t["attest"], json!([format!("type=sbom,generator={SBOM_SCANNER}")]));
        assert!(SBOM_SCANNER.contains("@sha256:"), "the generator is pinned");
        export(t, "image", false);
        assert_eq!(t["attest"], json!([]));
        let b = dockerfile_bake(&BuildSpec { target: None, ..spec }, "Dockerfile", "r", "d");
        assert!(b["target"]["image"].get("target").is_none());
    }

    /// Every target of a bake file gets the build egress proxy as BuildKit's predefined proxy arguments, over the
    /// user's own values (reported), with its other arguments kept.
    #[test]
    fn every_bake_target_gets_the_proxy_arguments() {
        let mut file = json!({"target": {
            "web": {"context": "/src", "args": {"HTTP_PROXY": "http://corp:3128", "TOKEN": "v"}},
            "worker": {"context": "/src/worker"},
            "same": {"args": {"NO_PROXY": NO_PROXY_VALUE}},
        }});
        let args: Vec<(String, String)> = [("HTTP_PROXY", "http://owd:t@192.0.2.2:3128"), ("NO_PROXY", NO_PROXY_VALUE)]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(proxy_args(&mut file, &args), ["HTTP_PROXY"], "only a different value counts as replaced");
        for t in ["web", "worker", "same"] {
            assert_eq!(file["target"][t]["args"]["HTTP_PROXY"], "http://owd:t@192.0.2.2:3128", "{t}");
            assert_eq!(file["target"][t]["args"]["NO_PROXY"], NO_PROXY_VALUE, "{t}");
        }
        assert_eq!(file["target"]["web"]["args"]["TOKEN"], "v");
    }

    const NO_PROXY_VALUE: &str = crate::egress::NO_PROXY;

    #[test]
    fn a_failed_sbom_generator_is_told_apart_from_a_failed_build() {
        assert!(scanner_failed(
            " > resolve image config for docker-image://docker.io/docker/buildkit-syft-scanner@sha256:1:"
        ));
        assert!(scanner_failed(
            " > [linux/arm64] generating sbom using docker.io/docker/buildkit-syft-scanner:stable-1:"
        ));
        assert!(!scanner_failed(
            "#2 resolve image config for docker-image://docker.io/docker/buildkit-syft-scanner:stable-1"
        ));
        assert!(!scanner_failed(" > [2/2] RUN npm ci:"));
    }

    #[test]
    fn railpack_builds_keep_variables_out_of_the_bake_file() {
        let vars = BTreeMap::from([("NODE_ENV".to_string(), "production".to_string())]);
        let t = railpack_target("web", &vars, "App_1", false);
        assert_eq!(t["context"], "/src/web");
        let secrets: Vec<&str> = t["secret"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
        assert_eq!(secrets[0], "id=NODE_ENV,env=NODE_ENV");
        // The proxy's settings reach the steps as secrets read from the bake's environment, never from its own
        // proxy variables, and stay out of the secrets hash (a new token per build keeps the cache).
        assert!(secrets.contains(&"id=HTTPS_PROXY,env=OWD_EGRESS_PROXY"));
        assert!(secrets.contains(&"id=no_proxy,env=OWD_EGRESS_NO_PROXY"));
        assert_eq!(secrets.len(), 7);
        assert_eq!(t["args"]["BUILDKIT_SYNTAX"], RAILPACK_FRONTEND);
        assert_eq!(t["args"]["cache-key"], "app_1");
        assert!(!t.to_string().contains("production"), "values reach BuildKit as secrets only");
        assert_eq!(t["output"], json!(["type=cacheonly"]), "only the labelled image is exported");
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
            let token = crate::egress::token();
            let c = builder_container(b, vec!["seccomp=unconfined".into()], &l, &token);
            assert_eq!(
                crate::egress::token_in(c.env.as_deref().unwrap()),
                Some(token),
                "its pulls go through the proxy"
            );
            assert_eq!(
                c.cmd,
                Some(vec!["--addr".into(), BUILDKIT_ADDR.into(), "--config".into(), BUILDKITD_CONFIG.into()])
            );
            let h = c.host_config.unwrap();
            assert!(h.binds.is_none() && h.privileged.is_none() && h.devices.is_none());
            let mounts: Vec<_> =
                h.mounts.iter().flatten().map(|m| (m.typ, m.source.as_deref(), m.target.as_deref())).collect();
            assert_eq!(
                mounts,
                [
                    (Some(MountType::VOLUME), Some(b.volume()), Some(BUILDKIT_STATE)),
                    (Some(MountType::VOLUME), Some(b.socket_volume()), Some(BUILDKIT_SOCKET_DIR))
                ]
            );
            assert_eq!(
                (h.cap_drop.clone().unwrap(), h.cap_add.clone().unwrap()),
                (vec!["ALL".to_string()], vec!["SETUID".to_string(), "SETGID".to_string()])
            );
            assert_eq!(h.network_mode.as_deref(), Some(BUILD_NETWORK));
            assert_limits(&h, &l);
        }
        assert_ne!(Builder::Trusted.volume(), Builder::Untrusted.volume(), "untrusted code never shares a cache");
        assert_ne!(Builder::Trusted.socket_volume(), Builder::Untrusted.socket_volume());
    }

    /// No helper has the Engine's socket or a host path; a build helper reaches its own builder's socket only.
    #[test]
    fn no_helper_gets_the_engine_or_privileges() {
        let l = super::limits();
        for role in [Role::Source, Role::Build(Builder::Trusted), Role::Build(Builder::Untrusted), Role::Scan] {
            let c = helper_container(role, "app_1", Vec::new());
            assert_eq!(c.labels.unwrap().get(LABEL_HELPER).map(String::as_str), Some("app_1"), "found as a leftover");
            let h = c.host_config.unwrap();
            assert!(h.binds.is_none() && h.privileged.is_none() && h.devices.is_none() && h.cap_add.is_none());
            assert_eq!(h.cap_drop.as_deref(), Some(["ALL".to_string()].as_slice()));
            assert_eq!(h.security_opt.as_deref(), Some(["no-new-privileges".to_string()].as_slice()));
            assert!(h.tmpfs.as_ref().unwrap().contains_key(SECRETS_TMPFS.0), "the clone's secrets stay in memory");
            assert_limits(&h, l);
            let mounts: Vec<_> = h.mounts.iter().flatten().map(|m| (m.typ, m.source.clone())).collect();
            match role {
                Role::Build(b) => {
                    assert_eq!(mounts, [(Some(MountType::VOLUME), Some(b.socket_volume().to_string()))]);
                    assert_eq!(h.network_mode.as_deref(), Some(BUILD_NETWORK));
                    assert_eq!(h.group_add, Some(vec![BUILDKIT_ID.to_string()]));
                }
                Role::Scan => {
                    assert!(mounts.is_empty());
                    assert_eq!(h.network_mode.as_deref(), Some("none"));
                }
                Role::Source => assert!(mounts.is_empty() && h.network_mode.is_none() && h.group_add.is_none()),
            }
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
                env: body.env,
                ..Default::default()
            }),
            host_config: body.host_config,
            ..Default::default()
        };
        let token = crate::egress::token();
        let made = |l: &Limits| inspect(builder_container(Builder::Trusted, security.clone(), l, &token));
        assert_eq!(fit(&made(&l), &security, &l), Fit::Current(token.clone()), "its token is read back");
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
        // One of an agent before the build egress proxy: direct egress on the old network, no proxy settings.
        let mut direct = made(&l);
        direct.config.as_mut().unwrap().env = None;
        assert_eq!(fit(&direct, &security, &l), Fit::Recreate);
        let mut legacy_network = made(&l);
        legacy_network.host_config.as_mut().unwrap().network_mode = Some(LEGACY_BUILD_NETWORK.into());
        assert_eq!(fit(&legacy_network, &security, &l), Fit::Recreate);

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
