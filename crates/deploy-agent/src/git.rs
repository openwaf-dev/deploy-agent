//! Git sources: the clone runs in a throwaway helper container (never on the host, never with the host's
//! credentials). For Dockerfile builds the build context is then copied out of it, filtered by `.dockerignore`, the
//! build arguments declared in every stage of the Dockerfile, and packed for the Engine's build API; other builds clone
//! with the same script in the builder's source helper. Neither has the Engine's socket.
//!
//! Credentials (a short-lived GitHub App installation token, or a deploy key) reach the helper only through its
//! stdin, land in a 0600 file on a tmpfs that dies with the helper and are handed to git by a credential helper
//! scoped to the repository's origin, or to ssh with `-i`: never in argv, the environment, the image or a log.
//! SSH host keys are checked against the given `known_hosts` lines, the agent's pinned keys of the big hosts, or
//! accepted on first use and reported back so the control plane pins them.

use std::io::Read;
use std::path::{Path, PathBuf};

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::models::ContainerCreateBody;
use bollard::query_parameters::{
    AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, DownloadFromContainerOptionsBuilder,
};
use deploy_proto::msg::{CommitInfo, GitAuth, LogStream, SshAuth};
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::CANCELLED;
use crate::docker::{LABEL_HELPER, ensure_image, message, remove_container};
use crate::dockerfile::declare_args;
use crate::dockerignore::{Ignore, clean};
use crate::events::{Events, Lines};

/// Small maintained image with git, ssh and a POSIX shell, pinned so a clone behaves the same on every server.
pub const HELPER_IMAGE: &str = "alpine/git:v2.52.0";

/// Host keys of the big Git hosts (published by GitHub, GitLab and Bitbucket), used when the control plane sends
/// none for them: a first clone from these hosts is never trust-on-first-use.
const PINNED_HOSTS: &[&str] = &[
    "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
    "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
    "gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf",
    "gitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=",
    "gitlab.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9",
    "bitbucket.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO",
    "bitbucket.org ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBuKdWeF4+a2sjSSpBK0iqitSQ+5BM9KhpexuGt20JpTVM7u5BDZngncgrqDMbWdxMWWOGtZ9UgbqgZE=",
    "bitbucket.org ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQeJzhupRu0u0cdegZIa8e86EG2qOCsIsD1Xw0xSeiPDlCr7kq97NLmMbpKTX6Esc30NuoqEEHCuc7yWtwp8dI76EEEB1VqY9QJq6vk+aySyboD5QF61I/1WeTwu+deCbgKMGbUijeXhtfbxSxm6JwGrXrhBdofTsbKRUsrN1WoNgUa8uqN1Vx6WAJw1JHPhglEGGHea6QICwJOAr/6mrui/oB7pkaWKHj3z7d1IC4KWLtY47elvjbaTlkN04Kc/5LFEirorGYVbt15kAUlqGM65pk6ZBxtaO3+30LVlORZkxOh+LKL/BvbZ/iRNhItLqNyieoQj/uh/7Iv4uyH/cV/0b4WDSd3DptigWq84lJubb9t/DnZlrJazxyDCulTmKdOR7vs9gMTo+uoIrPSb8ScTtvw65+odKAlBj59dhnVp9zd7QUojOpXlL62Aw56U4oO+FALuevvMjiWeavKhJqlR7i5n9srYcrNV7ttmDw7kf/97P5zauIhxcjX+xHv4M=",
];

/// The clone script. It reads the secret from stdin (two lines of HTTPS credentials, or a private key) and takes
/// the URL, reference, credential scope and host keys from the environment, so no value of the deployment is ever
/// parsed as shell. A shallow fetch of the reference works for branches, tags and (on GitHub and most hosts)
/// commits; the full fetch is the fallback for hosts that refuse to serve an unadvertised commit. It checks out into
/// /src and ends by printing the commit and, on first use, the host keys accepted.
pub const SCRIPT: &str = r#"set -eu
umask 077
case "$OWD_AUTH" in
https)
  cat > /run/owd/cred
  git config --global "credential.$OWD_CRED_SCOPE.helper" '!f() { test "$1" = get || exit 0; printf "username=%s\npassword=%s\n" "$(sed -n 1p /run/owd/cred)" "$(sed -n 2p /run/owd/cred)"; }; f'
  ;;
ssh)
  cat > /run/owd/key
  printf '%s\n' "$OWD_KNOWN_HOSTS" > /run/owd/known_hosts
  export GIT_SSH_COMMAND="ssh -i /run/owd/key -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile=/run/owd/known_hosts -o GlobalKnownHostsFile=/dev/null -o HashKnownHosts=no -o StrictHostKeyChecking=$OWD_STRICT"
  ;;
esac
git config --global advice.detachedHead false
rm -rf /src
mkdir /src
cd /src
git init -q
git remote add origin "$OWD_URL"
if git fetch --depth 1 --no-tags origin "$OWD_REF"; then
  git checkout -q --detach FETCH_HEAD
else
  echo "shallow fetch of $OWD_REF failed; fetching the whole repository" >&2
  git fetch --tags origin '+refs/heads/*:refs/remotes/origin/*'
  git checkout -q --detach "origin/$OWD_REF" 2>/dev/null || git checkout -q --detach "$OWD_REF"
fi
if [ -n "${OWD_EXPECT:-}" ]; then
  case "$(git rev-parse HEAD)" in
  "$OWD_EXPECT"*) ;;
  *) echo "$OWD_REF is at $(git rev-parse HEAD), not at the commit to deploy ($OWD_EXPECT)" >&2; exit 3 ;;
  esac
fi
if [ -f .gitmodules ] && [ "${OWD_SUBMODULES:-1}" = 1 ]; then
  git submodule update --init --recursive --depth 1
fi
rm -f /run/owd/cred /run/owd/key
echo "OWD_COMMIT=$(git rev-parse HEAD)"
git log -1 --format='OWD_AUTHOR_NAME=%an%nOWD_AUTHOR_EMAIL=%ae%nOWD_SUBJECT=%s' || true
if [ "$OWD_AUTH" = ssh ] && [ "$OWD_STRICT" = accept-new ]; then
  grep -v '^$' /run/owd/known_hosts | sed 's/^/OWD_KNOWN_HOST=/' || true
fi
"#;

/// Mount of the clone script's secrets: memory only, gone with the helper.
pub const SECRETS_TMPFS: (&str, &str) = ("/run/owd", "rw,noexec,nosuid,nodev,size=64k,mode=0700");

/// A directory only the agent can read, removed with everything in it when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Result<TempDir, String> {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).expect("OS randomness");
        let p = std::env::temp_dir().join(format!("owdeploy-{}", hex::encode(r)));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(TempDir(p))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// How the helper authenticates to the repository.
#[derive(Clone, Copy)]
pub enum Credentials<'a> {
    Public,
    Https(&'a GitAuth),
    Ssh(&'a SshAuth),
}

impl<'a> Credentials<'a> {
    /// The credentials of a source: a deploy key wins over HTTPS credentials.
    pub fn of(auth: Option<&'a GitAuth>, ssh: Option<&'a SshAuth>) -> Credentials<'a> {
        match (ssh, auth) {
            (Some(k), _) => Credentials::Ssh(k),
            (None, Some(a)) => Credentials::Https(a),
            (None, None) => Credentials::Public,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Repo<'a> {
    pub url: &'a str,
    pub reference: &'a str,
    pub creds: Credentials<'a>,
    /// The commit the checkout must be at (a prefix of 7 to 64 hexadecimal digits).
    pub commit: Option<&'a str>,
    /// Untrusted code: its submodules (URLs it chose) are not fetched.
    pub untrusted: bool,
}

/// What the clone script needs: its environment (no secret in it) and its stdin (the secret, if any).
pub struct Clone {
    pub env: Vec<String>,
    pub stdin: Vec<u8>,
}

impl Drop for Clone {
    fn drop(&mut self) {
        self.stdin.iter_mut().for_each(|b| *b = 0);
    }
}

/// Checks the source and prepares the clone script's input.
pub fn prepare(r: &Repo<'_>) -> Result<Clone, String> {
    check_reference(r.reference)?;
    let mut env =
        vec![format!("OWD_URL={}", r.url), format!("OWD_REF={}", r.reference), "GIT_TERMINAL_PROMPT=0".to_string()];
    if let Some(c) = r.commit {
        if !(7..=64).contains(&c.len()) || !c.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("invalid commit {c:?}"));
        }
        env.push(format!("OWD_EXPECT={}", c.to_ascii_lowercase()));
    }
    if r.untrusted {
        env.push("OWD_SUBMODULES=0".into());
    }
    let stdin = match r.creds {
        Credentials::Public => {
            if !r.url.starts_with("https://") {
                ssh_target(r.url).map_err(|_| "the repository URL must be https:// (or SSH with a deploy key)")?;
                return Err("an SSH repository URL needs a deploy key".into());
            }
            origin(r.url)?;
            env.push("OWD_AUTH=none".into());
            Vec::new()
        }
        Credentials::Https(a) => {
            let scope = origin(r.url)?;
            if a.username.contains(['\n', '\r', '\0']) || a.token.contains(['\n', '\r', '\0']) {
                return Err("the Git credentials contain line breaks".into());
            }
            env.push("OWD_AUTH=https".into());
            env.push(format!("OWD_CRED_SCOPE={scope}"));
            format!("{}\n{}\n", a.username, a.token).into_bytes()
        }
        Credentials::Ssh(k) => {
            let target = ssh_target(r.url)?;
            let key = k.private_key.trim();
            if !key.starts_with("-----BEGIN ") || key.contains('\0') {
                return Err("the deploy key is not an OpenSSH private key".into());
            }
            let mut lines = Vec::new();
            for l in &k.known_hosts {
                lines.push(known_host_line(l)?);
            }
            if lines.is_empty() {
                lines = PINNED_HOSTS
                    .iter()
                    .filter(|l| l.split(' ').next() == Some(target.as_str()))
                    .map(|l| l.to_string())
                    .collect();
            }
            // No key for the host: trust on first use, reported back by the script.
            let strict = if lines.is_empty() { "accept-new" } else { "yes" };
            env.push("OWD_AUTH=ssh".into());
            env.push(format!("OWD_STRICT={strict}"));
            env.push(format!("OWD_KNOWN_HOSTS={}", lines.join("\n")));
            // OpenSSH refuses a key file without its final newline.
            format!("{key}\n").into_bytes()
        }
    };
    Ok(Clone { env, stdin })
}

/// What the clone script reported: the commit checked out, its author and subject, and the host keys accepted on
/// first use.
#[derive(Default)]
pub struct Cloned {
    pub commit: Option<String>,
    pub author_name: Option<String>,
    pub author_email: Option<String>,
    pub subject: Option<String>,
    pub known_hosts: Vec<String>,
}

/// A commit's author or subject as stored: control characters dropped, at most `max` characters, None when empty.
fn meta(value: &str, max: usize) -> Option<String> {
    let v: String = value.chars().filter(|c| !c.is_control()).take(max).collect();
    let v = v.trim();
    (!v.is_empty()).then(|| v.to_string())
}

impl Cloned {
    /// Takes a marker line of the script; false for an ordinary line, which belongs in the log.
    pub fn marker(&mut self, line: &str) -> bool {
        if let Some(c) = line.strip_prefix("OWD_COMMIT=") {
            self.commit = Some(c.trim().to_string());
        } else if let Some(k) = line.strip_prefix("OWD_KNOWN_HOST=") {
            self.known_hosts.push(k.trim().to_string());
        } else if let Some(v) = line.strip_prefix("OWD_AUTHOR_NAME=") {
            self.author_name = meta(v, 200);
        } else if let Some(v) = line.strip_prefix("OWD_AUTHOR_EMAIL=") {
            self.author_email = meta(v, 320);
        } else if let Some(v) = line.strip_prefix("OWD_SUBJECT=") {
            self.subject = meta(v, 300);
        } else {
            return false;
        }
        true
    }

    /// The commit, once the script ended with `code`.
    pub fn commit(&self, code: i64) -> Result<String, String> {
        match (code, &self.commit) {
            (0, Some(c)) if c.len() >= 40 && c.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(c.clone()),
            _ => Err(format!("git fetch failed (exit code {code})")),
        }
    }

    /// What the deployment reports about the commit checked out.
    pub fn info(&self) -> CommitInfo {
        CommitInfo {
            sha: self.commit.clone().unwrap_or_default(),
            author_name: self.author_name.clone(),
            author_email: self.author_email.clone(),
            subject: self.subject.clone(),
        }
    }
}

/// A build context ready for the Engine: `tar`, removed with its temporary directory when the context is dropped.
pub struct Context {
    _dir: TempDir,
    pub tar: PathBuf,
    pub commit: String,
    pub info: CommitInfo,
    pub known_hosts: Vec<String>,
    /// Dockerfile path inside the context.
    pub dockerfile: String,
}

pub struct Fetch<'a> {
    pub repo: Repo<'a>,
    pub context: &'a str,
    pub dockerfile: &'a str,
    pub resource: &'a str,
    /// Names of the build arguments, declared after every `FROM` of the Dockerfile that lacks them.
    pub args: Vec<&'a str>,
}

/// `https://host[:port]`, the credential helper's scope: the token is offered to that origin only (submodules on
/// other hosts never see it).
fn origin(url: &str) -> Result<String, String> {
    let rest = url.strip_prefix("https://").ok_or("the repository URL must be https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err("the repository URL must name a host and carry no credentials".into());
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("the repository URL contains spaces or control characters".into());
    }
    Ok(format!("https://{authority}"))
}

/// The `known_hosts` name of an SSH repository URL (`host`, or `[host]:port` off port 22), for
/// `ssh://[user@]host[:port]/path` and scp-like `user@host:path`.
fn ssh_target(url: &str) -> Result<String, String> {
    let bad = || format!("invalid SSH repository URL {url:?}");
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad());
    }
    let (authority, path) = match url.strip_prefix("ssh://") {
        Some(rest) => rest.split_once('/').ok_or_else(bad)?,
        None => {
            let (a, p) = url.split_once(':').ok_or_else(bad)?;
            if a.contains('/') || !a.contains('@') {
                return Err(bad());
            }
            (a, p)
        }
    };
    let host_port = match authority.rsplit_once('@') {
        Some((user, hp)) => {
            if user.is_empty() || !user.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
                return Err(bad());
            }
            hp
        }
        None => authority,
    };
    let (host, port) = match (url.starts_with("ssh://"), host_port.split_once(':')) {
        (true, Some((h, p))) => (h, Some(p.parse::<u16>().map_err(|_| bad())?)),
        _ => (host_port, None),
    };
    let host_ok = !host.is_empty()
        && !host.starts_with(['-', '.'])
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b));
    if !host_ok || path.is_empty() || path.starts_with('-') {
        return Err(bad());
    }
    let host = host.to_ascii_lowercase();
    Ok(match port {
        Some(p) if p != 22 => format!("[{host}]:{p}"),
        _ => host,
    })
}

/// A `known_hosts` line as given: one line of `names keytype base64`, nothing else.
fn known_host_line(l: &str) -> Result<String, String> {
    let l = l.trim();
    let fields: Vec<&str> = l.split(' ').filter(|f| !f.is_empty()).collect();
    let ok = fields.len() >= 3
        && !l.chars().any(|c| c.is_control())
        && !fields[0].starts_with('@')
        && (fields[1].starts_with("ssh-") || fields[1].starts_with("ecdsa-") || fields[1].starts_with("sk-"));
    if !ok {
        return Err(format!("invalid known_hosts line {l:?}"));
    }
    Ok(fields.join(" "))
}

fn check_reference(r: &str) -> Result<(), String> {
    if r.is_empty() || r.starts_with('-') || r.len() > 255 || r.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!("invalid Git reference {r:?}"));
    }
    Ok(())
}

/// A path inside the repository: cleaned, relative, not escaping it. "" for the root.
pub fn inside(p: &str, what: &str) -> Result<String, String> {
    let c = clean(p.trim_start_matches('/'));
    if c == ".." || c.starts_with("../") || p.contains('\0') {
        return Err(format!("{what} {p:?} leaves the repository"));
    }
    Ok(if c == "." { String::new() } else { c })
}

pub async fn fetch(d: &Docker, f: Fetch<'_>, ev: &Events, cancel: &CancellationToken) -> Result<Context, String> {
    let clone = prepare(&f.repo)?;
    let context = inside(f.context, "build context")?;
    let dockerfile = inside(f.dockerfile, "Dockerfile path")?;
    if dockerfile.is_empty() {
        return Err("the Dockerfile path is empty".into());
    }
    ensure_image(d, HELPER_IMAGE, Some(ev)).await?;
    let dir = TempDir::new()?;
    let mut labels = std::collections::HashMap::new();
    labels.insert(LABEL_HELPER.to_string(), f.resource.to_string());
    let body = ContainerCreateBody {
        image: Some(HELPER_IMAGE.into()),
        entrypoint: Some(vec!["/bin/sh".into(), "-c".into()]),
        cmd: Some(vec![SCRIPT.into()]),
        env: Some(clone.env.clone()),
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        open_stdin: Some(true),
        stdin_once: Some(true),
        labels: Some(labels),
        // No capability, `no-new-privileges`, the build limits, the secrets tmpfs.
        host_config: Some(crate::builder::source_host_config()),
        ..Default::default()
    };
    let created = d
        .create_container(Some(CreateContainerOptionsBuilder::default().build()), body)
        .await
        .map_err(|e| format!("create the Git helper: {}", message(&e)))?;
    let helper = created.id;
    let r = clone_and_pack(d, &helper, clone, &context, &dockerfile, &f.args, &dir, ev, cancel).await;
    // The helper goes on success, failure and cancel alike; the temporary directory goes with `dir` on error.
    remove_container(d, &helper).await.ok();
    let cloned = r?;
    Ok(Context {
        tar: dir.path().join("context.tar"),
        _dir: dir,
        info: cloned.info(),
        commit: cloned.commit.unwrap_or_default(),
        known_hosts: cloned.known_hosts,
        dockerfile,
    })
}

/// Removes helpers an earlier agent process left behind (it stopped in the middle of a clone or a build): clone,
/// source and build helpers alike, which all carry [`LABEL_HELPER`].
pub async fn remove_leftover_helpers() -> Result<usize, String> {
    let d = crate::docker::client()?;
    let filters = std::collections::HashMap::from([("label".to_string(), vec![LABEL_HELPER.to_string()])]);
    let opts = bollard::query_parameters::ListContainersOptionsBuilder::default().all(true).filters(&filters).build();
    let list = d.list_containers(Some(opts)).await.map_err(|e| format!("docker ps: {}", message(&e)))?;
    for c in &list {
        remove_container(&d, c.id.as_deref().unwrap_or_default()).await?;
    }
    Ok(list.len())
}

#[allow(clippy::too_many_arguments)]
async fn clone_and_pack(
    d: &Docker,
    helper: &str,
    clone: Clone,
    context: &str,
    dockerfile: &str,
    args: &[&str],
    dir: &TempDir,
    ev: &Events,
    cancel: &CancellationToken,
) -> Result<Cloned, String> {
    let opts = AttachContainerOptionsBuilder::default().stdin(true).stdout(true).stderr(true).stream(true).build();
    let mut io = d.attach_container(helper, Some(opts)).await.map_err(|e| format!("attach: {}", message(&e)))?;
    d.start_container(helper, None).await.map_err(|e| format!("start the Git helper: {}", message(&e)))?;
    let w = io.input.write_all(&clone.stdin).await.and(io.input.shutdown().await);
    drop(clone);
    w.map_err(|e| format!("Git helper stdin: {e}"))?;
    let mut cloned = Cloned::default();
    let (mut out, mut err) = (Lines::default(), Lines::default());
    loop {
        let item = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(CANCELLED.into()),
            i = io.output.next() => i,
        };
        let Some(item) = item else { break };
        match item.map_err(|e| format!("Git helper output: {e}"))? {
            LogOutput::StdOut { message } | LogOutput::Console { message } => {
                for l in out.push(&message) {
                    if !cloned.marker(&l) {
                        ev.line(LogStream::Stdout, l).await;
                    }
                }
            }
            LogOutput::StdErr { message } => {
                for l in err.push(&message) {
                    ev.line(LogStream::Stderr, l).await;
                }
            }
            LogOutput::StdIn { .. } => {}
        }
    }
    if let Some(l) = err.finish() {
        ev.line(LogStream::Stderr, l).await;
    }
    if let Some(l) = out.finish()
        && !cloned.marker(&l)
    {
        ev.line(LogStream::Stdout, l).await;
    }
    let state = d.inspect_container(helper, None).await.map_err(|e| format!("inspect: {}", message(&e)))?.state;
    let commit = cloned.commit(state.and_then(|s| s.exit_code).unwrap_or(-1))?;
    ev.system(format!("Checked out commit {commit}")).await;
    for k in &cloned.known_hosts {
        ev.system(format!("Accepted the host key on first use: {k}")).await;
    }

    let raw = dir.path().join("raw.tar");
    let src = if context.is_empty() { "/src".to_string() } else { format!("/src/{context}") };
    let mut file = tokio::fs::File::create(&raw).await.map_err(|e| format!("{}: {e}", raw.display()))?;
    let mut s =
        d.download_from_container(helper, Some(DownloadFromContainerOptionsBuilder::default().path(&src).build()));
    loop {
        let chunk = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(CANCELLED.into()),
            c = s.next() => c,
        };
        let Some(chunk) = chunk else { break };
        let chunk = chunk.map_err(|e| match &e {
            e if crate::docker::is_not_found(e) => format!("build context {context:?} not found in the repository"),
            e => format!("copy the build context: {}", message(e)),
        })?;
        file.write_all(&chunk).await.map_err(|e| format!("{}: {e}", raw.display()))?;
    }
    file.flush().await.map_err(|e| e.to_string())?;
    drop(file);
    let out = dir.path().join("context.tar");
    let dockerfile = dockerfile.to_string();
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let stats = tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        pack(&raw, &out, &dockerfile, &args)
    })
    .await
    .map_err(|e| e.to_string())??;
    ev.system(format!(
        "Build context: {} files, {} KiB ({} left out by .dockerignore)",
        stats.files,
        stats.bytes / 1024,
        stats.ignored
    ))
    .await;
    if stats.arg_lines > 0 {
        let s = if stats.arg_stages == 1 { "" } else { "s" };
        let names = stats.args.join(", ");
        ev.system(format!("Dockerfile: declared build arguments {names} after {} FROM line{s}", stats.arg_stages))
            .await;
    }
    Ok(cloned)
}

#[derive(Debug, Default, PartialEq)]
pub struct PackStats {
    pub files: u64,
    pub bytes: u64,
    pub ignored: u64,
    /// Build arguments declared in the Dockerfile, the `ARG` lines inserted and the `FROM`s they follow.
    pub args: Vec<String>,
    pub arg_lines: u64,
    pub arg_stages: u64,
}

/// Path of an entry relative to the copied directory: the Engine's archive puts everything under that directory's
/// own name.
fn relative(p: &Path) -> Option<String> {
    let s = p.to_string_lossy().replace('\\', "/");
    let s = s.trim_start_matches("./");
    let rest = s.split_once('/').map(|(_, r)| r).unwrap_or("");
    let rest = rest.trim_end_matches('/');
    (!rest.is_empty()).then(|| rest.to_string())
}

/// Re-roots the archive of the context directory at the context and drops what `.dockerignore` leaves out (never the
/// Dockerfile or `.dockerignore` itself, as the Docker CLI does). A regular-file Dockerfile gets an `ARG` line for each
/// of `args` in every stage that does not declare it; a non-UTF-8 one is kept as is.
pub fn pack(raw: &Path, out: &Path, dockerfile: &str, args: &[&str]) -> Result<PackStats, String> {
    let open = || std::fs::File::open(raw).map(std::io::BufReader::new).map_err(|e| format!("{}: {e}", raw.display()));
    let mut ignore_text = String::new();
    let mut found_dockerfile = false;
    let mut a = tar::Archive::new(open()?);
    for e in a.entries().map_err(|e| e.to_string())? {
        let mut e = e.map_err(|e| format!("build context archive: {e}"))?;
        let rel = relative(&e.path().map_err(|e| e.to_string())?);
        match rel.as_deref() {
            Some(".dockerignore") => {
                e.read_to_string(&mut ignore_text).map_err(|e| format!(".dockerignore: {e}"))?;
            }
            Some(p) if p == dockerfile => found_dockerfile = true,
            _ => {}
        }
    }
    if !found_dockerfile {
        return Err(format!("{dockerfile} not found in the build context"));
    }
    let ignore = Ignore::parse(&ignore_text);
    let mut stats = PackStats::default();
    let file = std::fs::File::create(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut b = tar::Builder::new(std::io::BufWriter::new(file));
    b.follow_symlinks(false);
    let mut a = tar::Archive::new(open()?);
    for e in a.entries().map_err(|e| e.to_string())? {
        let mut e = e.map_err(|e| format!("build context archive: {e}"))?;
        let Some(rel) = relative(&e.path().map_err(|e| e.to_string())?) else { continue };
        if rel != dockerfile && rel != ".dockerignore" && ignore.excludes(&rel) {
            stats.ignored += 1;
            continue;
        }
        let mut h = e.header().clone();
        let kind = h.entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            let target = e.link_name().map_err(|e| e.to_string())?.ok_or("link without a target")?.into_owned();
            // Hard links name a path in the archive, which lost its first component like every entry.
            let target = if kind.is_hard_link() {
                PathBuf::from(relative(&target).ok_or("hard link to the context root")?)
            } else {
                target
            };
            b.append_link(&mut h, &rel, &target).map_err(|e| e.to_string())?;
        } else if kind.is_file() && rel == dockerfile && !args.is_empty() {
            let mut data = Vec::new();
            e.read_to_end(&mut data).map_err(|e| format!("{dockerfile}: {e}"))?;
            if let Some(d) = std::str::from_utf8(&data).ok().and_then(|t| declare_args(t, args)) {
                data = d.text.into_bytes();
                h.set_size(data.len() as u64);
                stats.args = d.args;
                stats.arg_lines = d.lines as u64;
                stats.arg_stages = d.stages as u64;
            }
            stats.files += 1;
            stats.bytes += data.len() as u64;
            b.append_data(&mut h, &rel, data.as_slice()).map_err(|e| e.to_string())?;
        } else {
            if kind.is_file() {
                stats.files += 1;
                stats.bytes += h.size().unwrap_or(0);
            }
            b.append_data(&mut h, &rel, e).map_err(|e| e.to_string())?;
        }
    }
    b.into_inner().and_then(|mut w| std::io::Write::flush(&mut w)).map_err(|e| e.to_string())?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(b: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, path, data).unwrap();
    }

    #[test]
    fn pack_reroots_and_filters_but_keeps_dockerfile_and_ignore_file() {
        let dir = TempDir::new().unwrap();
        let raw = dir.path().join("raw.tar");
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o755);
        h.set_size(0);
        b.append_data(&mut h, "app/", std::io::empty()).unwrap();
        entry(&mut b, "app/.dockerignore", b"*.md\nDockerfile\n.dockerignore\nnode_modules\n");
        entry(&mut b, "app/Dockerfile", b"FROM scratch\n");
        entry(&mut b, "app/README.md", b"x");
        entry(&mut b, "app/node_modules/a/index.js", b"x");
        entry(&mut b, "app/src/main.js", b"console.log(1)");
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "app/link", "src/main.js").unwrap();
        std::fs::write(&raw, b.into_inner().unwrap()).unwrap();

        let out = dir.path().join("ctx.tar");
        let stats = pack(&raw, &out, "Dockerfile", &[]).unwrap();
        assert_eq!(stats, PackStats { files: 3, bytes: 43 + 13 + 14, ignored: 2, ..Default::default() });
        let mut names: Vec<String> = tar::Archive::new(std::fs::File::open(&out).unwrap())
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, [".dockerignore", "Dockerfile", "link", "src/main.js"]);
        assert!(pack(&raw, &out, "docker/Dockerfile", &[]).unwrap_err().contains("not found"));
    }

    /// The packed entries of `out` with their kind and content.
    fn unpacked(out: &Path) -> Vec<(String, bool, Vec<u8>)> {
        let mut a = tar::Archive::new(std::fs::File::open(out).unwrap());
        a.entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                (e.path().unwrap().to_string_lossy().into_owned(), e.header().entry_type().is_symlink(), data)
            })
            .collect()
    }

    #[test]
    fn pack_declares_build_arguments_in_a_regular_utf8_dockerfile() {
        let dir = TempDir::new().unwrap();
        let raw = dir.path().join("raw.tar");
        let mut b = tar::Builder::new(Vec::new());
        entry(&mut b, "app/Dockerfile", b"FROM a\nRUN x\nFROM b AS c\nARG B\n");
        entry(&mut b, "app/latin1.Dockerfile", b"FROM a\n# \xe9\n");
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "app/link.Dockerfile", "Dockerfile").unwrap();
        entry(&mut b, "app/after", b"z");
        std::fs::write(&raw, b.into_inner().unwrap()).unwrap();
        let out = dir.path().join("ctx.tar");

        let stats = pack(&raw, &out, "Dockerfile", &["A", "B"]).unwrap();
        let rewritten = b"FROM a\nARG A\nARG B\nRUN x\nFROM b AS c\nARG A\nARG B\n";
        assert_eq!((stats.args, stats.arg_lines, stats.arg_stages), (vec!["A".into(), "B".into()], 3, 2));
        assert_eq!(stats.bytes, (rewritten.len() + 11 + 1) as u64);
        let entries = unpacked(&out);
        assert_eq!(entries[0], ("Dockerfile".into(), false, rewritten.to_vec()));
        assert_eq!(entries[3], ("after".into(), false, b"z".to_vec()));

        for dockerfile in ["latin1.Dockerfile", "link.Dockerfile"] {
            let stats = pack(&raw, &out, dockerfile, &["A"]).unwrap();
            assert_eq!((stats.arg_lines, stats.bytes), (0, 31 + 11 + 1), "{dockerfile}");
            let entries = unpacked(&out);
            assert_eq!(entries[1], ("latin1.Dockerfile".into(), false, b"FROM a\n# \xe9\n".to_vec()));
            assert!(entries[2].1, "the symlink stays a symlink");
        }
    }

    #[test]
    fn urls_references_and_paths() {
        assert_eq!(origin("https://github.com/o/r.git").unwrap(), "https://github.com");
        assert_eq!(origin("https://git.example:8443/o/r").unwrap(), "https://git.example:8443");
        assert!(origin("http://github.com/o/r").is_err());
        assert!(origin("https://user:pw@github.com/o/r").is_err());
        assert!(origin("https://github.com/o/r\n").is_err());
        assert!(check_reference("--upload-pack=x").is_err());
        assert!(check_reference("main").is_ok());
        assert!(check_reference("v1.2.3").is_ok());
        assert_eq!(inside(".", "c").unwrap(), "");
        assert_eq!(inside("./apps/web/", "c").unwrap(), "apps/web");
        assert!(inside("../etc", "c").is_err());
        assert!(inside("a/../../etc", "c").is_err());
    }

    #[test]
    fn ssh_urls_name_their_known_hosts_entry() {
        assert_eq!(ssh_target("git@github.com:o/r.git").unwrap(), "github.com");
        assert_eq!(ssh_target("ssh://git@GitLab.com/o/r.git").unwrap(), "gitlab.com");
        assert_eq!(ssh_target("ssh://git@git.example:22/o/r").unwrap(), "git.example");
        assert_eq!(ssh_target("ssh://git@git.example:2222/srv/r.git").unwrap(), "[git.example]:2222");
        for bad in [
            "ssh://-oProxyCommand=x/r",
            "ssh://git@-oProxyCommand=x/r",
            "git@host:-r",
            "host:o/r",
            "ssh://git@host",
            "ssh://git@host:x/r",
            "git@host:o/r x",
            "ssh://us er@host/r",
        ] {
            assert!(ssh_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn deploy_keys_use_given_then_pinned_host_keys_then_trust_on_first_use() {
        let env = |url: &str, known: Vec<String>| {
            let key = SshAuth { private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n".into(), known_hosts: known };
            let c = prepare(&Repo {
                url,
                reference: "main",
                creds: Credentials::Ssh(&key),
                commit: None,
                untrusted: false,
            })
            .unwrap();
            assert!(c.stdin.ends_with(b"-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"));
            assert!(!c.env.iter().any(|e| e.contains("PRIVATE KEY")), "the key never reaches the environment");
            c.env.clone()
        };
        let pinned = env("git@github.com:o/r.git", vec![]);
        assert!(pinned.contains(&"OWD_STRICT=yes".to_string()));
        assert!(
            pinned.iter().any(|e| e.starts_with("OWD_KNOWN_HOSTS=github.com ssh-ed25519 ") && !e.contains("gitlab"))
        );
        let tofu = env("ssh://git@git.example:2222/r.git", vec![]);
        assert!(tofu.contains(&"OWD_STRICT=accept-new".to_string()));
        assert!(tofu.contains(&"OWD_KNOWN_HOSTS=".to_string()));
        let given = env("ssh://git@git.example:2222/r.git", vec!["[git.example]:2222  ssh-ed25519 AAAA".into()]);
        assert!(given.contains(&"OWD_KNOWN_HOSTS=[git.example]:2222 ssh-ed25519 AAAA".to_string()));
        let key = SshAuth { private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".into(), known_hosts: vec![] };
        for bad in ["h ssh-ed25519 AAAA\nh2 ssh-rsa BBBB", "@cert-authority * ssh-ed25519 AAAA", "h AAAA"] {
            let key = SshAuth { known_hosts: vec![bad.into()], ..key.clone() };
            let r = Repo {
                url: "git@h:r",
                reference: "main",
                creds: Credentials::Ssh(&key),
                commit: None,
                untrusted: false,
            };
            assert!(prepare(&r).is_err(), "{bad}");
        }
        // An SSH URL without a key, or a key with an HTTPS URL, is refused.
        let public = Repo {
            url: "git@github.com:o/r",
            reference: "main",
            creds: Credentials::Public,
            commit: None,
            untrusted: false,
        };
        assert!(prepare(&public).is_err());
        let r = Repo { url: "https://github.com/o/r", creds: Credentials::Ssh(&key), ..public };
        assert!(prepare(&r).is_err());
    }

    #[test]
    fn untrusted_clones_pin_their_commit_and_skip_submodules() {
        let r = Repo {
            url: "https://github.com/o/r",
            reference: "refs/pull/7/head",
            creds: Credentials::Public,
            commit: Some("0123456789ABCDEF0123456789abcdef01234567"),
            untrusted: true,
        };
        let env = prepare(&r).unwrap().env.clone();
        assert!(env.contains(&"OWD_EXPECT=0123456789abcdef0123456789abcdef01234567".to_string()), "{env:?}");
        assert!(env.contains(&"OWD_SUBMODULES=0".to_string()));
        let trusted = prepare(&Repo { commit: None, untrusted: false, ..r }).unwrap().env.clone();
        assert!(!trusted.iter().any(|e| e.starts_with("OWD_EXPECT=") || e.starts_with("OWD_SUBMODULES=")));
        for bad in ["abc", "0123456789abcdeg", "$(id)"] {
            assert!(prepare(&Repo { commit: Some(bad), ..r }).is_err(), "{bad}");
        }
    }

    #[test]
    fn clone_markers_are_taken_out_of_the_log() {
        let mut c = Cloned::default();
        assert!(!c.marker("Cloning into /src"));
        assert!(c.marker("OWD_KNOWN_HOST=[h]:2222 ssh-ed25519 AAAA"));
        assert!(c.marker(&format!("OWD_COMMIT={}", "a".repeat(40))));
        assert!(c.marker("OWD_AUTHOR_NAME=Ana \u{1b}[31mGarcía"));
        assert!(c.marker("OWD_AUTHOR_EMAIL="));
        assert!(c.marker(&format!("OWD_SUBJECT=Fix the {}", "x".repeat(400))));
        assert_eq!(c.commit(0).unwrap(), "a".repeat(40));
        assert!(c.commit(1).is_err());
        assert_eq!(c.known_hosts, ["[h]:2222 ssh-ed25519 AAAA"]);
        let info = c.info();
        assert_eq!(info.sha, "a".repeat(40));
        assert_eq!(info.author_name.as_deref(), Some("Ana [31mGarcía"));
        assert_eq!(info.author_email, None);
        assert_eq!(info.subject.as_ref().map(|s| s.chars().count()), Some(300));
    }
}
