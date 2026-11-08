//! Messages carried in frames. Each has a fixed `kind`; unknown kinds are ignored by both sides so either can be
//! upgraded first.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The `kind` of a message in its frame.
pub trait Kind {
    const KIND: &'static str;
}

macro_rules! kind {
    ($t:ty, $k:literal) => {
        impl Kind for $t {
            const KIND: &'static str = $k;
        }
    };
}

/// The agent's first frame after connecting in v1; its second in v2, after [`SessionProof`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub agent_version: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub kernel: String,
    /// None when Docker is not installed or not reachable.
    pub docker: Option<DockerInfo>,
    /// Operations beyond phase 2 this agent understands ([`feature::ALL`]). Empty for a phase-2 agent, which closes
    /// its session on an operation it cannot decode: the control plane sends newer operations only when listed here.
    #[serde(default)]
    pub features: Vec<String>,
    /// SHA-256 (hex) of the agent's own binary, which the control plane compares with the binary it serves. None from
    /// agents before [`feature::SELF_UPDATE`].
    #[serde(default)]
    pub binary_sha256: Option<String>,
    /// The keys the agent pinned. None from agents before [`feature::UPDATE_KEY`].
    #[serde(default)]
    pub keys: Option<PinnedKeys>,
    /// How the agent's processes are privileged. None from agents before privilege separation, which all run as one
    /// root process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Privileges>,
}

/// How an agent's processes are privileged, as reported in [`Hello::privileges`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privileges {
    /// Privilege-separated: an unprivileged relay carries the connection (TLS, WebSocket, the control plane's
    /// input) and holds no secret; a root broker holds the keys, checks every frame and executes.
    Split,
    /// One root process does everything (servers installed before privilege separation that have not migrated).
    Legacy,
    /// A value of a newer agent.
    #[serde(other)]
    Unknown,
}

/// Features of a phase-3 agent, as announced in [`Hello::features`].
pub mod feature {
    /// `RouterSync`, `DeployApp::routes` and rolling updates through the per-server router.
    pub const ROUTER: &str = "router";
    /// `BuildSpec::pack` railpack and static.
    pub const BUILD_PACKS: &str = "build_packs";
    /// `DeployCompose`.
    pub const COMPOSE: &str = "compose";
    /// `Source::Git::ssh` (deploy keys).
    pub const SSH_GIT: &str = "ssh_git";
    /// `RunSpec::volumes`, `RunSpec::files`, `VolumeRemove`.
    pub const VOLUMES: &str = "volumes";
    /// `Exec`.
    pub const EXEC: &str = "exec";
    /// `AgentUpdate` (and the agent's `UpdateStatus` answers).
    pub const SELF_UPDATE: &str = "self_update";
    /// `UpdateKey`, v2 offers (`AgentUpdate::expires_at`, signed by the pinned update key once there is one),
    /// anti-downgrade, `Hello::keys` and `PinnedKeys`.
    pub const UPDATE_KEY: &str = "update_key";
    /// `ControlKeyRotate`.
    pub const CONTROL_KEY_ROTATION: &str = "control_key_rotation";
    /// `Route::tls`, `RouterConfig::tls` and `RouterConfig::preview_tls_port`: listeners serving HTTPS with an OpenWAF
    /// Origin CA certificate that require the OpenWAF edge's client certificate (`RouterState` reports them).
    pub const EDGE_TLS: &str = "edge_tls";
    /// Builds run on rootless BuildKit builders (`BuildSpec::untrusted`, `Source::Git::commit`).
    pub const ISOLATED_BUILDS: &str = "isolated_builds";
    /// `Event::Sbom`: the agent sends the software bill of materials of each image it deploys.
    pub const SBOM: &str = "sbom";
    /// `BuildSpec::egress`, `ComposeDeploy::egress` and `Event::Egress`: build steps reach the Internet only through
    /// the agent's build egress proxy, which applies the deployment's [`super::BuildEgress`] policy and reports the
    /// destinations.
    pub const BUILD_EGRESS: &str = "build_egress";
    /// `ComposeDeploy::registry_auth` and `BuildSpec::registry_auth`: credentials matched per image for Compose pulls,
    /// SBOM lookups and BuildKit's base image pulls.
    pub const REGISTRY_AUTH: &str = "registry_auth";
    pub const ALL: [&str; 14] = [
        ROUTER,
        BUILD_PACKS,
        COMPOSE,
        SSH_GIT,
        VOLUMES,
        EXEC,
        SELF_UPDATE,
        UPDATE_KEY,
        CONTROL_KEY_ROTATION,
        EDGE_TLS,
        ISOLATED_BUILDS,
        SBOM,
        BUILD_EGRESS,
        REGISTRY_AUTH,
    ];
}
kind!(Hello, "hello");

/// Agent → control, the agent's first frame of a v2 session ([`crate::session`]): its key's signature (base64) of the
/// handshake transcript as `agent-to-control`. The control plane closes a v2 session whose first frame is anything
/// else or does not verify. v1 sessions never carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProof {
    pub signature: String,
}
kind!(SessionProof, "session_proof");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DockerInfo {
    pub version: String,
    pub api_version: String,
    pub containers_running: u64,
    pub containers_total: u64,
    pub images: u64,
}

/// Periodic state of the server (every 30 s).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub uptime_secs: u64,
    pub load1: f64,
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_avail_bytes: u64,
    pub containers_running: u64,
}
kind!(Heartbeat, "heartbeat");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    pub nonce: u64,
}
kind!(Ping, "ping");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pong {
    pub nonce: u64,
}
kind!(Pong, "pong");

/// Control → agent, only to agents announcing [`feature::SELF_UPDATE`]: the control plane serves another agent
/// binary for this agent's target at `/v1/agent/binary/{target}`. `signature` covers the binary ([`crate::update`]):
/// v1 by the control key over `(target, version, sha256)`; v2 (with `expires_at`, agents announcing
/// [`feature::UPDATE_KEY`]) by the update key, or the control key while the agent pinned no update key, also over
/// `allow_downgrade` and `expires_at`. The agent downloads it from the control plane's own base URL, installs it only
/// between deployments and restarts; it rolls back to the previous binary if the new one does not connect in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentUpdate {
    pub target: String,
    pub version: String,
    pub sha256: String,
    pub signature: String,
    /// Asked by an administrator: also retried after an earlier failed attempt of the same binary (an automatic
    /// offer of a binary that once failed to connect is declined).
    #[serde(default)]
    pub force: bool,
    /// v2, with `force`: install even when `version` is not newer than the running one (an administrator's audited
    /// downgrade). Without it the agent refuses such an offer.
    #[serde(default)]
    pub allow_downgrade: bool,
    /// v2: Unix time after which the offer is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Detached signature of the release ([`crate::update::verify_release`]): made at build time by the offline
    /// release key over `(target, version, sha256)`, never by the control plane, which only relays it. Agents that
    /// pinned a release key refuse offers without a valid one; others ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_signature: Option<String>,
}
kind!(AgentUpdate, "agent_update");

/// The keys an agent pinned (base64 Ed25519 public keys), in its hello and, as a message of its own (agent →
/// control), after any change. `message` says what changed or why an announcement was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedKeys {
    /// The control key it verifies frames with.
    pub control: String,
    /// The next control key, announced by [`ControlKeyRotate`]: also accepted; the first frame signed with it makes
    /// it the control key.
    #[serde(default)]
    pub control_next: Option<String>,
    /// The update key offers must be signed with. None: the control key's offers are accepted.
    #[serde(default)]
    pub update: Option<String>,
    /// The offline release key every offered binary must carry a signature of. None: not required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
kind!(PinnedKeys, "pinned_keys");

/// Control → agent, only to agents announcing [`feature::UPDATE_KEY`]: the update key that signs offers from now on.
/// An agent without one pins it (the frame is signed by its control key); an agent with another one pins it only
/// when `signature` is the pinned key's handover ([`crate::update::announce`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateKey {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}
kind!(UpdateKey, "update_key");

/// Control → agent, only to agents announcing [`feature::CONTROL_KEY_ROTATION`], and accepted only in a frame signed
/// by the agent's control key: the key the control plane signs with next. The agent pins it next to its control key
/// and accepts both until a frame signed by the next key arrives, which makes it the control key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlKeyRotate {
    pub next_public_key: String,
}
kind!(ControlKeyRotate, "control_key_rotate");

/// Agent → control: where an update stands. `version` and `sha256` name the binary concerned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub version: String,
    pub sha256: String,
    pub state: UpdateState,
    #[serde(default)]
    pub message: Option<String>,
}
kind!(UpdateStatus, "update_status");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    /// The agent already runs this binary.
    Current,
    /// Downloading and checking it.
    Downloading,
    /// Downloaded and checked; installed once no deployment or command runs.
    Deferred,
    /// Installed; the agent restarts on it now.
    Restarting,
    /// The new binary connected: the update is done.
    Confirmed,
    /// The new binary did not connect in time: the previous one is back.
    RolledBack,
    /// Not installed (`message` says why).
    Failed,
}

/// A command for the agent. `id` correlates its result; commands are typed, never shell strings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    pub op: Op,
}
kind!(Command, "command");

// A command lives for one frame and one execution; boxing `AppDeploy` would only make every construction noisier.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Docker Engine facts.
    DockerInfo,
    /// Containers of the engine, optionally only those labelled by OpenWAF Deploy.
    ContainerList { managed_only: bool },
    /// Fetch or pull, build, start the new container next to the current one, wait until healthy, point the router
    /// at it, drain and remove the old one. Streams `CommandEvent`s (steps and log lines) and ends with a
    /// `CommandResult` whose output is a [`DeployOutput`]. Cancellable until the router switched.
    DeployApp(AppDeploy),
    /// Start, stop, restart or remove the containers of an application (a Compose application: all its services).
    /// Remove also drops its router routes; volumes stay (see `VolumeRemove`).
    AppAction { resource: String, action: AppActionKind },
    /// State of the containers of an application (output: [`AppState`]).
    AppStatus { resource: String },
    /// Runtime logs of an application's current container: the last `tail` lines, then new ones while `follow`
    /// (streamed as `CommandEvent::Log` until cancelled). `since` is a Unix time in seconds. `service` selects the
    /// service of a Compose application (default: its newest container).
    AppLogs {
        resource: String,
        tail: u32,
        follow: bool,
        since: Option<i64>,
        #[serde(default)]
        service: Option<String>,
    },
    /// Removes images of an application other than those tagged in `keep` (rollback targets).
    ImagePrune { resource: String, keep: Vec<String> },
    /// Replaces the agent's firewall rules: published ports reachable only from the given sources, and the
    /// destinations (`deny`) refused to containers on top of the private ranges the agent always refuses.
    FirewallSync(FirewallRules),
    /// Replaces the configuration of the per-server router (output: [`RouterState`]).
    RouterSync(RouterConfig),
    /// A Docker Compose application: fetch (Git) or take the inline file, resolve it in a helper container, build its
    /// images on the rootless builder, apply it through the Engine API, then route its domains. Streams like
    /// `DeployApp`; output: [`ComposeOutput`]. Cancellable.
    DeployCompose(ComposeDeploy),
    /// Runs a command in an application's current container, or a service of a Compose application (scheduled
    /// tasks). Output lines are streamed as `CommandEvent::Log`; result: [`ExecOutput`]. Cancellable (the command is
    /// killed).
    Exec(ExecSpec),
    /// Removes the named volumes of an application (all of them when `names` is None) and, with them all, its file
    /// mounts. Output: `{"removed": [volume names]}`. Refused while a container of the application exists.
    VolumeRemove {
        resource: String,
        #[serde(default)]
        names: Option<Vec<String>>,
    },
}

/// One deployment of one application on this server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppDeploy {
    /// Application id: the value of [`LABEL_RESOURCE`] on its containers and images.
    pub resource: String,
    /// Deployment id: the value of [`LABEL_DEPLOYMENT`].
    pub deployment: String,
    /// Docker network of the environment (created if missing); the container joins it with its app name as alias.
    pub network: String,
    /// DNS alias of the container on `network`. The container is also reachable by its own name (its
    /// per-deployment alias), which is what the router points at.
    pub alias: String,
    pub source: Source,
    /// How to build a Git source (ignored for images).
    pub build: Option<BuildSpec>,
    pub run: RunSpec,
    /// Routes of the application on the router, applied when the new container takes over. None (a phase-2
    /// control plane): one route on the listener `run.publish`, if any, for every Host, to `run.port`.
    #[serde(default)]
    pub routes: Option<Vec<Route>>,
    /// Seconds the previous container keeps serving requests already in flight after the router switched to the
    /// new one, before it is stopped. None: [`DEFAULT_DRAIN_SECS`].
    #[serde(default)]
    pub drain_secs: Option<u32>,
}

pub const DEFAULT_DRAIN_SECS: u32 = 10;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    /// Clone `reference` (branch, tag or commit) of a repository in a throwaway helper container: an HTTPS URL
    /// (optionally with `auth`), or with `ssh` an SSH URL (`ssh://git@host[:port]/path` or `git@host:path`).
    Git {
        url: String,
        reference: String,
        auth: Option<GitAuth>,
        #[serde(default)]
        ssh: Option<SshAuth>,
        /// The commit the checkout must be at (agents with [`feature::ISOLATED_BUILDS`]): the deployment fails
        /// before building anything else, e.g. a pull request ref that moved past the commit approved for it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commit: Option<String>,
    },
    /// Pull an image from a registry.
    Image { image: String, auth: Option<RegistryAuth> },
    /// An image already on the server (redeploy without building, rollback).
    Local { image: String },
}

/// HTTPS credentials for a clone (a GitHub App installation token: short-lived). Never logged, never in argv.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct GitAuth {
    pub username: String,
    pub token: String,
}

impl std::fmt::Debug for GitAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitAuth").field("username", &self.username).field("token", &"…").finish()
    }
}

/// A deploy key for an SSH clone. Never logged, never in argv; it only exists on a tmpfs of the helper container.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SshAuth {
    /// OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`), unencrypted.
    pub private_key: String,
    /// Accepted host keys, `known_hosts` lines (`host[,host…] type base64`; `[host]:port` for another port). Empty:
    /// the agent's pinned keys for github.com, gitlab.com and bitbucket.org, else trust on first use: the key seen
    /// is accepted and returned in [`DeployOutput::known_hosts`] so the control plane pins it for the next clones.
    #[serde(default)]
    pub known_hosts: Vec<String>,
}

impl std::fmt::Debug for SshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshAuth").field("private_key", &"…").field("known_hosts", &self.known_hosts).finish()
    }
}

/// Credentials for one registry. Never logged, never in argv.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryAuth {
    /// The Docker config key of the registry (`deploy_proto::registry::config_key`).
    pub server: String,
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for RegistryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryAuth").field("server", &self.server).field("username", &self.username).finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuildSpec {
    /// Build context, relative to the repository root ("" or "." for the root).
    pub context: String,
    /// Dockerfile path relative to the context (pack `dockerfile` only).
    pub dockerfile: String,
    /// Build arguments (`dockerfile`), or build-time environment of a Railpack build.
    pub args: BTreeMap<String, String>,
    pub target: Option<String>,
    /// Build without the layer cache. Defaults to false so older control planes stay compatible.
    #[serde(default)]
    pub no_cache: bool,
    /// How the image is made. Default `dockerfile` (phase 2).
    #[serde(default)]
    pub pack: BuildPack,
    /// Railpack overrides (`railpack`, and `static` with a build): install, build and start commands, run by a shell.
    #[serde(default)]
    pub install_command: Option<String>,
    #[serde(default)]
    pub build_command: Option<String>,
    #[serde(default)]
    pub start_command: Option<String>,
    /// `static`: the directory served, relative to the context; after the build when `build_command` is set.
    /// None: the context itself.
    #[serde(default)]
    pub publish_dir: Option<String>,
    /// `static`: unknown paths answer `/index.html` (single-page applications) instead of 404.
    #[serde(default)]
    pub spa: bool,
    /// Untrusted code (a pull request from a fork): built on its own BuildKit builder (no cache shared with the
    /// other builds), cloned without submodules. Agents with [`feature::ISOLATED_BUILDS`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub untrusted: bool,
    /// What the build steps may reach on the Internet ([`feature::BUILD_EGRESS`]). None (older control planes):
    /// `open`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<BuildEgress>,
    /// Credentials for the base images the build pulls, matched by registry host. Sent only to agents with
    /// [`feature::REGISTRY_AUTH`]; never on an untrusted build.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry_auth: Vec<RegistryAuth>,
}

/// The egress policy of a deployment's build steps ([`feature::BUILD_EGRESS`]). Whatever the mode, build steps
/// reach the Internet only through the agent's build egress proxy, never private, loopback, link-local or reserved
/// addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildEgress {
    pub mode: EgressMode,
    /// `allowlist`: the destinations allowed ([`EgressRule`] syntax), at most [`MAX_EGRESS_ALLOW`]. Ignored in the
    /// other modes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

/// Most entries of [`BuildEgress::allow`].
pub const MAX_EGRESS_ALLOW: usize = 100;

impl BuildEgress {
    pub const OPEN: BuildEgress = BuildEgress { mode: EgressMode::Open, allow: Vec::new() };

    /// The allowlist's rules; Err names the first invalid entry (or an unknown mode, too many entries).
    pub fn rules(&self) -> Result<Vec<EgressRule>, String> {
        if self.mode == EgressMode::Unknown {
            return Err("unknown build egress mode".into());
        }
        if self.allow.len() > MAX_EGRESS_ALLOW {
            return Err(format!("more than {MAX_EGRESS_ALLOW} allowed destinations"));
        }
        self.allow.iter().map(|a| EgressRule::parse(a)).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    /// Every public destination; only denials are reported in the log (the behaviour before policies existed).
    Open,
    /// Every public destination, each recorded.
    Audit,
    /// Only the destinations of [`BuildEgress::allow`], each attempt recorded.
    Allowlist,
    /// A mode of a newer control plane: the agent refuses the build rather than guess.
    #[serde(other)]
    Unknown,
}

/// One allowed destination: `host` (exactly that name), or `*.domain` (any name below `domain`, not `domain`
/// itself), each with an optional `:port` (any port without). Names are ASCII (IDNs in their `xn--` form), compared
/// without case and without a trailing dot; IP addresses are not names and never match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    /// Lowercase, without `*.`.
    pub host: String,
    pub wildcard: bool,
    pub port: Option<u16>,
}

impl EgressRule {
    pub fn parse(s: &str) -> Result<EgressRule, String> {
        let bad = |why: &str| format!("invalid allowed destination {s:?}: {why}");
        let t = s.trim();
        let (name, port) = match t.rsplit_once(':') {
            Some((n, p)) => {
                let p: u16 = p.parse().ok().filter(|p| *p > 0).ok_or_else(|| bad("the port is not 1 to 65535"))?;
                (n, Some(p))
            }
            None => (t, None),
        };
        let (wildcard, name) = match name.strip_prefix("*.") {
            Some(n) => (true, n),
            None => (false, name),
        };
        let host = canonical_host(name).ok_or_else(|| bad("not a host name, `*.domain` or either with `:port`"))?;
        if ip_like(&host) {
            return Err(bad("IP addresses cannot be allowed, only names"));
        }
        if wildcard && !host.contains('.') {
            return Err(bad("a wildcard needs a domain of at least two labels"));
        }
        Ok(EgressRule { host, wildcard, port })
    }

    /// Whether `host` (as [`canonical_host`] makes it) on `port` is allowed.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|p| p != port) {
            return false;
        }
        match self.wildcard {
            false => host == self.host,
            true => {
                host.len() > self.host.len() + 1
                    && host.ends_with(self.host.as_str())
                    && host.as_bytes()[host.len() - self.host.len() - 1] == b'.'
            }
        }
    }
}

impl std::fmt::Display for EgressRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.wildcard {
            f.write_str("*.")?;
        }
        f.write_str(&self.host)?;
        match self.port {
            Some(p) => write!(f, ":{p}"),
            None => Ok(()),
        }
    }
}

/// A DNS host name as compared: ASCII letters, digits, hyphens and underscores in labels of 1 to 63 characters,
/// not starting or ending with a hyphen, at most 253 characters; lowercased, without the trailing dot. None for
/// anything else (IPv6 literals included).
pub fn canonical_host(s: &str) -> Option<String> {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    let ok = s.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then(|| s.to_ascii_lowercase())
}

/// Whether a canonical host reads as an IPv4 address in any of the forms resolvers accept (`1.2.3.4`, `127.1`,
/// `0x7f.1`, `2130706433`): its last label is numeric. No top-level domain is.
pub fn ip_like(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or_default();
    last.bytes().all(|b| b.is_ascii_digit())
        || (last.len() > 2 && last[..2].eq_ignore_ascii_case("0x") && last[2..].bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Build pack of a Git source. Compose applications use `DeployCompose` instead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildPack {
    /// The repository's Dockerfile (`BuildSpec::dockerfile`).
    #[default]
    Dockerfile,
    /// Railpack detects the language and builds the image (the Nixpacks equivalent).
    Railpack,
    /// Files served by a small static web server listening on `RunSpec::port`: the context as is, or what
    /// `build_command` produced (built with Railpack).
    Static,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunSpec {
    /// Tag given to the built, pulled or reused image: `owd/<resource>:<deployment>`.
    pub image_tag: String,
    pub env: BTreeMap<String, String>,
    /// Port the app listens on inside the container.
    pub port: u16,
    /// Host port of the application: a listener of the router (all addresses; the firewall opens it only to the
    /// OpenWAF edge). The container itself publishes nothing. None: only reachable on the environment network.
    pub publish: Option<u16>,
    pub health: Option<HealthCheck>,
    pub command: Option<Vec<String>>,
    pub memory_bytes: Option<u64>,
    pub cpus: Option<f64>,
    /// Extra labels; the agent always adds [`LABEL_RESOURCE`], [`LABEL_DEPLOYMENT`] and [`LABEL_ENVIRONMENT`].
    pub labels: BTreeMap<String, String>,
    /// Named volumes, kept across deployments.
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
    /// Files written by the agent under its state directory and mounted read-only.
    #[serde(default)]
    pub files: Vec<FileMount>,
}

/// A named volume `owd-<resource lowercased>-<name>` mounted at `path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeMount {
    /// `[a-z0-9_-]`, at most 48 characters.
    pub name: String,
    /// Absolute path in the container.
    pub path: String,
    /// Compose applications: the service it is mounted in (required there; ignored otherwise).
    #[serde(default)]
    pub service: Option<String>,
}

/// A file with the given content mounted read-only at `path`. The content may be secret: never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMount {
    /// Absolute path in the container.
    pub path: String,
    pub content: String,
    /// Compose applications: the service it is mounted in (required there; ignored otherwise).
    #[serde(default)]
    pub service: Option<String>,
}

impl std::fmt::Debug for FileMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileMount")
            .field("path", &self.path)
            .field("content", &format_args!("<{} bytes>", self.content.len()))
            .field("service", &self.service)
            .finish()
    }
}

/// HTTP check the agent runs against the new container before switching to it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthCheck {
    pub path: String,
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub retries: u32,
}

/// Output of a successful `DeployApp`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeployOutput {
    pub image: String,
    pub image_id: String,
    pub container_id: String,
    /// Commit that was built (Git sources).
    pub commit: Option<String>,
    /// Host keys accepted on first use during an SSH clone (`known_hosts` lines), to pin for the next clones.
    #[serde(default)]
    pub known_hosts: Vec<String>,
}

/// Where the router sends a request. The upstream is the application's current container (by its per-deployment
/// alias, switched by each deployment) or, for a Compose application, a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Host port of the listener: the application's published port. None: the per-server preview listener
    /// ([`RouterConfig::preview_port`]).
    pub listen: Option<u16>,
    /// Host names matched exactly (case-insensitive, without port). Empty: every request of the listener that no
    /// route with hosts matches (not allowed on the preview listener).
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Compose applications: the service. None: the application's current container.
    #[serde(default)]
    pub service: Option<String>,
    /// Port inside the upstream container.
    pub port: u16,
    /// The listener serves HTTPS and requires the OpenWAF edge's client certificate ([`RouterConfig::tls`]); plain
    /// HTTP is refused on it. With `listen: None`, the preview TLS listener ([`RouterConfig::preview_tls_port`]). All
    /// the routes of one listener agree. Sent only to agents with [`feature::EDGE_TLS`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls: bool,
}

/// Whole configuration of the per-server router.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Host port of the preview listener (routes with `listen: None`, by Host). None: no preview listener.
    pub preview_port: Option<u16>,
    /// Routes of every application and preview on the server; one not listed loses its routes and listeners.
    pub resources: Vec<ResourceRoutes>,
    /// Host port of the preview TLS listener (routes with `listen: None` and `tls`). Feature [`feature::EDGE_TLS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_tls_port: Option<u16>,
    /// What the TLS listeners serve and trust. None: no TLS listener. Feature [`feature::EDGE_TLS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<RouterTls>,
}

/// The certificates of the server's TLS listeners and the CA of the client certificates they require.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouterTls {
    /// The OpenWAF Edge Client CA bundle (PEM, every CA of a rotation): a TLS listener accepts only connections
    /// presenting a client certificate it signed.
    pub client_ca_pem: String,
    pub certificates: Vec<TlsCertificate>,
}

/// A certificate (OpenWAF Origin CA) a TLS listener serves for `hosts`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsCertificate {
    /// Stable across renewals (letters, digits, `-`, `_`): a renewal replaces the certificate of the same name
    /// without reloading the router.
    pub name: String,
    /// This version of the certificate; [`RouterState::certificates`] lists the installed ones.
    pub id: String,
    /// The TLS listener it is served on (an application's TLS port); None: the preview TLS listener.
    pub listen: Option<u16>,
    /// Exact names or one-level wildcards (`*.example.com`), lowercase.
    pub hosts: Vec<String>,
    /// The certificate chain, PEM.
    pub cert_pem: String,
    /// Its private key, PEM. Secret: never logged.
    pub key_pem: String,
}

impl std::fmt::Debug for TlsCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsCertificate")
            .field("name", &self.name)
            .field("id", &self.id)
            .field("listen", &self.listen)
            .field("hosts", &self.hosts)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceRoutes {
    pub resource: String,
    pub routes: Vec<Route>,
}

/// Output of `RouterSync`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RouterState {
    /// Host ports the router listens on.
    pub listeners: Vec<u16>,
    /// Resources whose routes are live.
    pub active: Vec<String>,
    /// Resources whose routes wait for their next deployment: not deployed yet, or deployed by a phase-2 agent (their
    /// container still publishes the port itself and moves behind the router on its next deployment).
    pub pending: Vec<String>,
    /// Listeners serving HTTPS with a certificate and requiring the edge's client certificate (feature
    /// [`feature::EDGE_TLS`]); a TLS listener without either is not opened.
    #[serde(default)]
    pub tls_listeners: Vec<u16>,
    /// Ids of the certificates the router serves ([`TlsCertificate::id`]).
    #[serde(default)]
    pub certificates: Vec<String>,
}

/// A Docker Compose application. Containers, images, networks and volumes belong to the Compose project
/// `owd-<resource lowercased>`; every service also joins `network` as `owd-<resource lowercased>-<service>`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComposeDeploy {
    pub resource: String,
    pub deployment: String,
    /// Docker network of the environment (created if missing).
    pub network: String,
    pub source: ComposeSource,
    /// Environment of every service (added to what the file sets) and of the file's `${VAR}` interpolation.
    pub env: BTreeMap<String, String>,
    /// Named volumes `owd-<resource>-<name>` and files, each mounted in its `service`.
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
    #[serde(default)]
    pub files: Vec<FileMount>,
    /// Extra labels on every container; the agent adds [`LABEL_RESOURCE`] and [`LABEL_DEPLOYMENT`].
    pub labels: BTreeMap<String, String>,
    /// Routes of the application; each names its `service`.
    pub routes: Vec<Route>,
    #[serde(default)]
    pub no_cache: bool,
    /// What the build steps of the services may reach on the Internet ([`feature::BUILD_EGRESS`]). None (older
    /// control planes): `open`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<BuildEgress>,
    /// Credentials for the service images the agent pulls and the base images it builds from, matched by registry
    /// host. Sent only to agents with [`feature::REGISTRY_AUTH`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry_auth: Vec<RegistryAuth>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ComposeSource {
    /// The repository (as `Source::Git`) and the Compose file's path in it.
    Git {
        url: String,
        reference: String,
        auth: Option<GitAuth>,
        #[serde(default)]
        ssh: Option<SshAuth>,
        /// Relative to the repository root; its directory is the project directory (build contexts, `env_file`).
        file: String,
    },
    /// A Compose file given inline (images only: there is nothing to build from).
    Inline { content: String },
}

/// Output of a successful `DeployCompose`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComposeOutput {
    /// Compose project name.
    pub project: String,
    pub services: Vec<ComposeService>,
    pub commit: Option<String>,
    #[serde(default)]
    pub known_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComposeService {
    pub service: String,
    pub container_id: String,
    pub image: String,
    pub state: String,
}

/// A command run in a running container, as `docker exec` does (no shell unless the command names one).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecSpec {
    pub resource: String,
    /// Compose applications: the service. None: the application's current container.
    #[serde(default)]
    pub service: Option<String>,
    pub command: Vec<String>,
    /// The command is killed after this long (and reported `timed_out`).
    pub timeout_secs: u32,
}

/// Output of `Exec`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecOutput {
    pub container_id: String,
    /// None when the command was killed before it reported one.
    pub exit_code: Option<i64>,
    pub timed_out: bool,
    /// Standard output and error interleaved, the last [`MAX_EXEC_OUTPUT`] bytes.
    pub output: String,
    /// Earlier output was dropped from `output` (it was still streamed).
    pub truncated: bool,
}

pub const MAX_EXEC_OUTPUT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppActionKind {
    Start,
    Stop,
    Restart,
    /// Remove the containers and the images of the application.
    Remove,
}

/// Output of `AppStatus`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppState {
    pub containers: Vec<ContainerState>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerState {
    pub id: String,
    pub deployment: Option<String>,
    pub image: String,
    /// Docker's state: created, running, restarting, exited, …
    pub state: String,
    /// Docker's health: healthy, unhealthy, starting, or None without a health check.
    pub health: Option<String>,
    pub started_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirewallRules {
    /// Sources allowed to reach the published ports (the OpenWAF edge), as CIDRs.
    pub allow: Vec<String>,
    /// Published ports of the applications on this server.
    pub ports: Vec<u16>,
    /// Destinations the server's containers must never reach (control-plane-only services), as CIDRs, on top of
    /// the private, link-local (cloud metadata) and special ranges the agent always refuses. Older agents ignore it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

/// Progress of a running command (agent → control), sent before its `CommandResult`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandEvent {
    pub id: String,
    pub event: Event,
}
kind!(CommandEvent, "command_event");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Lines of output, at most [`MAX_EVENT_LINES`] lines and [`MAX_LINE_BYTES`] each (longer lines are cut).
    Log {
        stream: LogStream,
        lines: Vec<String>,
        /// The step the command was in when it wrote these lines (none before the first step; older agents never
        /// send it).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        step: Option<Step>,
    },
    Step {
        step: Step,
        /// The commit just fetched, on the step that follows the fetch (older agents never send it).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commit: Option<CommitInfo>,
    },
    /// Software bill of materials of an image the deployment runs ([`feature::SBOM`]): an SPDX 2.3 JSON document,
    /// gzip-compressed then base64-encoded, sent in parts of at most [`MAX_SBOM_PART_BYTES`] characters of base64.
    /// `part` counts from 0; the last part has `last: true`; at most [`MAX_SBOM_PARTS`] parts per image.
    Sbom {
        /// The image's content digest (`sha256:…`, the image ID the Engine reports).
        image_digest: String,
        /// The Compose service that runs the image; None for a single-container application.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
        part: u32,
        last: bool,
        data: String,
    },
    /// The destinations the build steps asked the build egress proxy for ([`feature::BUILD_EGRESS`]), sent once
    /// at the end of the build (failed or not): every one in `audit` and `allowlist` mode, the denied ones in `open`
    /// mode. At most [`MAX_EGRESS_ENTRIES`] entries, most attempted first; `truncated` when there were more.
    Egress {
        mode: EgressMode,
        /// Whether direct connections from the builders were refused by the server's firewall, so the proxy was
        /// the only way out (false: Docker without its iptables integration).
        enforced: bool,
        entries: Vec<EgressEntry>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        truncated: bool,
    },
}

/// Largest `Event::Sbom::data`, in characters of base64.
pub const MAX_SBOM_PART_BYTES: usize = 512 * 1024;
/// Most parts of one image's SBOM (16 MiB of base64).
pub const MAX_SBOM_PARTS: u32 = 32;
/// Most entries of one `Event::Egress`.
pub const MAX_EGRESS_ENTRIES: usize = 500;

/// Connections to one destination through the build egress proxy, with one decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressEntry {
    /// The host name asked for (canonical, see [`canonical_host`]), or the IP address when one was asked for; at
    /// most 253 characters.
    pub host: String,
    pub port: u16,
    pub decision: EgressDecision,
    /// Why it was denied (denied entries only): `not_allowed` (not in the allowlist), `ip_literal` (an address
    /// instead of a name, in allowlist mode), `private_address` (the name resolves to a private, loopback,
    /// link-local or reserved address), `unresolved` (the name does not resolve), `invalid` (not a host name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Connections (CONNECT tunnels and plain HTTP requests).
    pub count: u64,
    /// Bytes sent to the destination and received from it (allowed entries).
    pub bytes_out: u64,
    pub bytes_in: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressDecision {
    Allowed,
    Denied,
    /// A decision of a newer agent.
    #[serde(other)]
    Unknown,
}

/// What the agent read from a fetched commit: its author and the subject of its message.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CommitInfo {
    pub sha: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_email: Option<String>,
    /// The subject (first line) of the commit message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
    /// The agent's own messages about the deployment.
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Fetching,
    Building,
    Pulling,
    Starting,
    HealthCheck,
    Switching,
    Cleaning,
}

/// Control → agent: stop a running command (a cancelled deployment, a closed log stream). The command still ends
/// with its `CommandResult` (an error "cancelled").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cancel {
    pub id: String,
}
kind!(Cancel, "cancel");

pub const MAX_EVENT_LINES: usize = 200;
pub const MAX_LINE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandResult {
    pub id: String,
    pub outcome: Outcome,
}
kind!(CommandResult, "command_result");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Ok {
        output: serde_json::Value,
    },
    Error {
        message: String,
    },
    /// The agent does not know the operation (older agent).
    Unsupported,
}

/// Label on every container and image OpenWAF Deploy creates, with the owning resource id.
pub const LABEL_RESOURCE: &str = "dev.openwaf.deploy.resource";
/// Label with the deployment that created a container or image.
pub const LABEL_DEPLOYMENT: &str = "dev.openwaf.deploy.deployment";
/// Label with the environment id of a container.
pub const LABEL_ENVIRONMENT: &str = "dev.openwaf.deploy.environment";

#[cfg(test)]
mod tests {
    use super::*;

    /// A line's step and a step's commit are optional both ways: events of older agents read as untagged, and an
    /// event without them is written exactly as before.
    #[test]
    fn event_step_and_commit_are_optional_on_the_wire() {
        let old: Event = serde_json::from_str(r#"{"type":"log","stream":"stdout","lines":["a"]}"#).unwrap();
        assert_eq!(old, Event::Log { stream: LogStream::Stdout, lines: vec!["a".into()], step: None });
        let old: Event = serde_json::from_str(r#"{"type":"step","step":"building"}"#).unwrap();
        assert_eq!(old, Event::Step { step: Step::Building, commit: None });
        let plain = Event::Step { step: Step::Building, commit: None };
        assert_eq!(serde_json::to_string(&plain).unwrap(), r#"{"type":"step","step":"building"}"#);
        let tagged = Event::Log { stream: LogStream::Stderr, lines: vec![], step: Some(Step::HealthCheck) };
        assert_eq!(serde_json::to_value(&tagged).unwrap()["step"], "health_check");
        let commit = CommitInfo { sha: "ab".repeat(20), author_name: Some("Ana".into()), ..Default::default() };
        let v = serde_json::to_value(Event::Step { step: Step::Building, commit: Some(commit.clone()) }).unwrap();
        assert_eq!(v["commit"], serde_json::json!({"sha": "ab".repeat(20), "author_name": "Ana"}));
        assert_eq!(
            serde_json::from_value::<Event>(v).unwrap(),
            Event::Step { step: Step::Building, commit: Some(commit) }
        );
    }

    /// The internally tagged `op` keeps a newtype variant's fields at the top level, the shape older agents and the
    /// control plane exchange.
    #[test]
    fn deploy_op_round_trips_flat() {
        let op = Op::DeployApp(AppDeploy {
            resource: "app_01".into(),
            deployment: "dep_01".into(),
            network: "owd-env".into(),
            alias: "web".into(),
            source: Source::Git {
                url: "git@github.com:o/r.git".into(),
                reference: "main".into(),
                auth: Some(GitAuth { username: "x-access-token".into(), token: "secret".into() }),
                ssh: Some(SshAuth { private_key: "secret-key".into(), known_hosts: vec![] }),
                commit: Some("0123456789abcdef0123456789abcdef01234567".into()),
            },
            build: Some(BuildSpec {
                context: ".".into(),
                dockerfile: "Dockerfile".into(),
                args: BTreeMap::new(),
                target: None,
                no_cache: false,
                pack: BuildPack::Railpack,
                install_command: None,
                build_command: Some("npm run build".into()),
                start_command: None,
                publish_dir: None,
                spa: false,
                untrusted: true,
                egress: Some(BuildEgress { mode: EgressMode::Allowlist, allow: vec!["*.npmjs.org:443".into()] }),
                registry_auth: vec![RegistryAuth {
                    server: "ghcr.io".into(),
                    username: "bot".into(),
                    password: "secret-registry".into(),
                }],
            }),
            run: RunSpec {
                image_tag: "owd/app_01:dep_01".into(),
                env: BTreeMap::new(),
                port: 3000,
                publish: Some(20001),
                health: None,
                command: None,
                memory_bytes: None,
                cpus: None,
                labels: BTreeMap::new(),
                volumes: vec![VolumeMount { name: "data".into(), path: "/data".into(), service: None }],
                files: vec![FileMount { path: "/etc/app.conf".into(), content: "secret-file".into(), service: None }],
            },
            routes: Some(vec![Route {
                listen: None,
                hosts: vec!["pr-1.example.com".into()],
                service: None,
                port: 3000,
                tls: false,
            }]),
            drain_secs: Some(5),
        });
        let v = serde_json::to_value(&op).unwrap();
        assert_eq!(v["op"], "deploy_app");
        assert_eq!(v["resource"], "app_01");
        assert_eq!(v["source"]["kind"], "git");
        assert_eq!(v["build"]["pack"], "railpack");
        assert_eq!(v["build"]["untrusted"], true);
        assert_eq!(v["source"]["commit"], "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(serde_json::from_value::<Op>(v).unwrap(), op);
        let debug = format!("{op:?}");
        assert!(!debug.contains("secret"), "credentials must not reach logs through Debug: {debug}");
    }

    /// `registry_auth` is new in agent 0.3.0: an older control plane's `ComposeDeploy` without it reads as an empty
    /// list, and an empty list is not written (older agents never see the field).
    #[test]
    fn registry_auth_is_optional_on_the_wire() {
        let old = serde_json::json!({
            "resource": "app_01", "deployment": "dep_01", "network": "owd-env",
            "source": {"kind": "inline", "content": "services: {}"}, "env": {}, "labels": {}, "routes": []
        });
        let c: ComposeDeploy = serde_json::from_value(old).unwrap();
        assert!(c.registry_auth.is_empty());
        assert!(serde_json::to_value(&c).unwrap().get("registry_auth").is_none());
        let with = ComposeDeploy {
            registry_auth: vec![RegistryAuth { server: "ghcr.io".into(), username: "u".into(), password: "p".into() }],
            ..c
        };
        let v = serde_json::to_value(&with).unwrap();
        assert_eq!(v["registry_auth"][0]["server"], "ghcr.io");
        assert_eq!(serde_json::from_value::<ComposeDeploy>(v).unwrap(), with);
    }

    /// A phase-2 control plane sends none of the phase-3 fields; a phase-3 agent reads its commands with the phase-2
    /// behaviour (Dockerfile build, a listener on the published port, no volumes).
    #[test]
    fn phase2_deploy_json_still_decodes() {
        let v = serde_json::json!({
            "op": "deploy_app", "resource": "app_01", "deployment": "dep_01", "network": "owd-env", "alias": "web",
            "source": {"kind": "git", "url": "https://github.com/o/r", "reference": "main", "auth": null},
            "build": {"context": ".", "dockerfile": "Dockerfile", "args": {}, "target": null},
            "run": {"image_tag": "owd/app_01:dep_01", "env": {}, "port": 3000, "publish": 20001, "health": null,
                    "command": null, "memory_bytes": null, "cpus": null, "labels": {}}
        });
        let Op::DeployApp(d) = serde_json::from_value::<Op>(v).unwrap() else { panic!("not a deployment") };
        assert_eq!(d.build.unwrap().pack, BuildPack::Dockerfile);
        assert!(matches!(d.source, Source::Git { ssh: None, .. }));
        assert_eq!((d.routes, d.drain_secs), (None, None));
        assert!(d.run.volumes.is_empty() && d.run.files.is_empty());
        let logs: Op = serde_json::from_value(serde_json::json!({
            "op": "app_logs", "resource": "app_01", "tail": 10, "follow": false, "since": null
        }))
        .unwrap();
        assert!(matches!(logs, Op::AppLogs { service: None, .. }));
        let hello: Hello = serde_json::from_value(serde_json::json!({
            "agent_version": "0.2.0", "hostname": "h", "os": "linux", "arch": "x86_64", "kernel": "6", "docker": null
        }))
        .unwrap();
        assert!(hello.features.is_empty());
        assert_eq!(hello.privileges, None, "an agent from before privilege separation");
        let with = |p: &str| {
            serde_json::from_value::<Hello>(serde_json::json!({
                "agent_version": "0.3.0", "hostname": "h", "os": "linux", "arch": "x86_64", "kernel": "6",
                "docker": null, "privileges": p
            }))
            .unwrap()
            .privileges
        };
        assert_eq!(with("split"), Some(Privileges::Split));
        assert_eq!(with("legacy"), Some(Privileges::Legacy));
        assert_eq!(with("sandboxed"), Some(Privileges::Unknown), "a newer agent's value still reads");
        // And a phase-2 agent reads what a phase-3 agent reports.
        let out = DeployOutput {
            image: "i".into(),
            image_id: "sha256:1".into(),
            container_id: "c".into(),
            commit: None,
            known_hosts: vec![],
        };
        assert_eq!(serde_json::to_value(&out).unwrap()["container_id"], "c");
    }

    /// A route without TLS and a configuration without TLS serialize exactly as before (an older agent reads them),
    /// an older agent's `RouterState` still decodes, and a certificate's key never reaches logs through Debug.
    #[test]
    fn edge_tls_fields_are_additive() {
        let plain = Route { listen: Some(20001), hosts: vec![], service: None, port: 80, tls: false };
        let cfg = RouterConfig {
            preview_port: None,
            resources: vec![ResourceRoutes { resource: "app_01".into(), routes: vec![plain] }],
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&cfg).unwrap(),
            serde_json::json!({"preview_port": null, "resources": [{"resource": "app_01",
                "routes": [{"listen": 20001, "hosts": [], "service": null, "port": 80}]}]})
        );
        let old: RouterState =
            serde_json::from_value(serde_json::json!({"listeners": [20001], "active": ["app_01"], "pending": []}))
                .unwrap();
        assert!(old.tls_listeners.is_empty() && old.certificates.is_empty());
        let cert = TlsCertificate {
            name: "app_01-zone".into(),
            id: "c1".into(),
            listen: Some(20002),
            hosts: vec!["www.example.com".into()],
            cert_pem: "-----BEGIN CERTIFICATE-----".into(),
            key_pem: "secret-key".into(),
        };
        let tls = RouterConfig {
            tls: Some(RouterTls { client_ca_pem: "ca".into(), certificates: vec![cert] }),
            preview_tls_port: Some(20003),
            ..cfg
        };
        let v = serde_json::to_value(&tls).unwrap();
        assert_eq!(serde_json::from_value::<RouterConfig>(v).unwrap(), tls);
        assert!(!format!("{tls:?}").contains("secret-key"));
    }

    /// Allowlist entries: exact names, wildcards below a domain (not the domain itself), optional ports; IP
    /// addresses and malformed names refused.
    #[test]
    fn egress_rules_parse_and_match() {
        let r = |s: &str| EgressRule::parse(s).unwrap();
        let exact = r("Registry.NPMjs.org.");
        assert_eq!(exact.to_string(), "registry.npmjs.org");
        assert!(exact.matches("registry.npmjs.org", 443) && exact.matches("registry.npmjs.org", 80));
        assert!(!exact.matches("x.registry.npmjs.org", 443) && !exact.matches("npmjs.org", 443));
        let wild = r("*.github.com:443");
        assert_eq!(wild.to_string(), "*.github.com:443");
        assert!(wild.matches("api.github.com", 443) && wild.matches("a.b.github.com", 443));
        assert!(!wild.matches("github.com", 443), "a wildcard does not cover the domain itself");
        assert!(!wild.matches("api.github.com", 80), "only its port");
        assert!(!wild.matches("evilgithub.com", 443) && !wild.matches("github.com.evil.io", 443));
        for bad in [
            "",
            "*",
            "*.com",
            "1.2.3.4",
            "127.1",
            "0x7f.1",
            "2130706433",
            "[::1]",
            "::1",
            "a..b",
            "-a.com",
            "a-.com",
            "a.com:0",
            "a.com:65536",
            "a.com:x",
            "a b.com",
            "*.*.a.com",
            "a.*.com",
            "http://a.com",
            "a.com/path",
            &"a".repeat(64),
            &format!("{}com", "a.".repeat(126)),
        ] {
            assert!(EgressRule::parse(bad).is_err(), "{bad:?} must be refused");
        }
        let policy = |allow: Vec<&str>| BuildEgress {
            mode: EgressMode::Allowlist,
            allow: allow.into_iter().map(str::to_string).collect(),
        };
        assert_eq!(policy(vec!["a.com", "*.b.com:8443"]).rules().unwrap().len(), 2);
        assert!(policy(vec!["a.com"; MAX_EGRESS_ALLOW + 1]).rules().is_err());
        assert!(policy(vec!["a.com", "192.0.2.1"]).rules().unwrap_err().contains("192.0.2.1"));
        let unknown: BuildEgress = serde_json::from_value(serde_json::json!({"mode": "strict"})).unwrap();
        assert_eq!(unknown.mode, EgressMode::Unknown);
        assert!(unknown.rules().is_err(), "an unknown mode is refused, not read as open");
    }

    /// Without a policy a build spec and a Compose deployment are written exactly as before; an older agent's
    /// events still decode and an `egress` event round-trips.
    #[test]
    fn egress_fields_are_additive() {
        let v = serde_json::json!({"context": ".", "dockerfile": "Dockerfile", "args": {}, "target": null});
        let spec: BuildSpec = serde_json::from_value(v).unwrap();
        assert_eq!(spec.egress, None);
        assert!(serde_json::to_value(&spec).unwrap().get("egress").is_none());
        let e = Event::Egress {
            mode: EgressMode::Audit,
            enforced: true,
            entries: vec![EgressEntry {
                host: "registry.npmjs.org".into(),
                port: 443,
                decision: EgressDecision::Allowed,
                reason: None,
                count: 3,
                bytes_out: 10,
                bytes_in: 2000,
            }],
            truncated: false,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "egress");
        assert!(v.get("truncated").is_none() && v["entries"][0].get("reason").is_none());
        assert_eq!(serde_json::from_value::<Event>(v).unwrap(), e);
    }
}
