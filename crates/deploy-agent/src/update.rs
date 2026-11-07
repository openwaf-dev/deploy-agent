//! Self-update (PROTOCOL.md). The control plane offers the agent binary it serves with `AgentUpdate`, signed
//! over `(target, version, sha256)` by the pinned update key, or the control key while none is pinned ([`Trust`]);
//! an agent that pinned the offline release key also requires the release's own signature of that binary.
//! Only a strictly newer version is installed ([`deploy_proto::version`]) unless an administrator's signed offer
//! allows a downgrade. The agent downloads it from the control plane's own base URL into `<binary>.new` next to
//! itself (same filesystem), checks its SHA-256 and that it runs (`version`), and
//! installs it only while no command other than a log stream runs: the running binary is hard-linked to
//! `<binary>.prev`, the new one renamed over it, and the agent exits with [`RESTART_EXIT`] for systemd
//! (`Restart=always`) to start the new binary.
//!
//! Before the swap a marker (`update.json` in the state directory) records both binaries. A new binary that finds it
//! is on probation: once its first control frame verifies it clears the marker; if [`CONFIRM_WITHIN`] passes first it
//! renames `.prev` back over itself and exits. The previous binary, started again, finds the marker naming it as the
//! old one, records the new binary as failed (automatic offers of it are declined; an administrator's is not) and
//! reports the rollback once connected.

use std::path::{Path, PathBuf};
use std::time::Duration;

use deploy_proto::msg::{AgentUpdate, UpdateState, UpdateStatus};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

/// Exit code of an agent that installed a new binary or rolled back: systemd starts the binary again.
pub const RESTART_EXIT: u8 = 75;
/// How long a newly installed binary has to connect before the previous one is put back.
pub const CONFIRM_WITHIN: Duration = Duration::from_secs(120);
const RECORD: &str = "update.json";
const MAX_BINARY_BYTES: u64 = 256 << 20;
/// Failed binaries remembered (most recent last).
const MAX_FAILED: usize = 8;

/// The binary this process runs, as found at start (before any swap).
#[derive(Debug, Clone)]
pub struct Binary {
    pub path: PathBuf,
    pub sha256: String,
}

impl Binary {
    pub fn current() -> Result<Binary, String> {
        let path = std::env::current_exe().map_err(|e| format!("own binary: {e}"))?;
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Binary { path, sha256: hex::encode(Sha256::digest(&bytes)) })
    }

    fn sibling(&self, suffix: &str) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(suffix);
        self.path.with_file_name(name)
    }

    /// Where a downloaded binary waits for its installation.
    pub fn staged(&self) -> PathBuf {
        self.sibling(".new")
    }

    pub fn previous(&self) -> PathBuf {
        self.sibling(".prev")
    }
}

/// An installation in progress: the swap happened (or is about to), the new binary has not connected yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub from_version: String,
    pub from_sha256: String,
    pub to_version: String,
    pub to_sha256: String,
    pub installed_at: i64,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    #[serde(default)]
    installing: Option<Marker>,
    /// Binaries that did not connect after their installation.
    #[serde(default)]
    failed: Vec<String>,
}

impl Record {
    fn load(dir: &Path) -> Result<Record, String> {
        let p = dir.join(RECORD);
        match std::fs::read_to_string(&p) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Record::default()),
            Err(e) => Err(format!("{}: {e}", p.display())),
        }
    }

    fn save(&self, dir: &Path) -> Result<(), String> {
        crate::write_private(&dir.join(RECORD), serde_json::to_string_pretty(self).expect("record").as_bytes())
    }
}

/// What an agent does at start about an earlier installation.
#[derive(Debug, PartialEq, Eq)]
pub enum Start {
    Normal,
    /// This is the new binary: it must connect before `deadline` (Unix time) or roll back.
    Probation {
        deadline: i64,
        marker: Marker,
    },
    /// This is the new binary and its time is up: put the previous one back now.
    RollBack(Marker),
    /// This is the previous binary again: the new one failed. Reported once connected.
    Failed(UpdateStatus),
}

pub fn on_start(dir: &Path, own_sha256: &str, now: i64) -> Result<Start, String> {
    let mut r = Record::load(dir)?;
    let Some(m) = r.installing.clone() else { return Ok(Start::Normal) };
    if m.to_sha256 == own_sha256 {
        let deadline = m.installed_at + CONFIRM_WITHIN.as_secs() as i64;
        return Ok(match now >= deadline {
            true => Start::RollBack(m),
            false => Start::Probation { deadline, marker: m },
        });
    }
    r.installing = None;
    if m.from_sha256 != own_sha256 {
        // Neither binary of the marker (reinstalled by hand): nothing to judge.
        r.save(dir)?;
        return Ok(Start::Normal);
    }
    r.failed.retain(|s| *s != m.to_sha256);
    r.failed.push(m.to_sha256.clone());
    let excess = r.failed.len().saturating_sub(MAX_FAILED);
    r.failed.drain(..excess);
    r.save(dir)?;
    Ok(Start::Failed(UpdateStatus {
        version: m.to_version,
        sha256: m.to_sha256,
        state: UpdateState::RolledBack,
        message: Some(format!(
            "the new agent did not connect within {} s; {} runs again",
            CONFIRM_WITHIN.as_secs(),
            m.from_version
        )),
    }))
}

/// The new binary connected: the installation is done.
pub fn confirm(dir: &Path, marker: &Marker) -> Result<UpdateStatus, String> {
    let mut r = Record::load(dir)?;
    if r.installing.as_ref() == Some(marker) {
        r.installing = None;
    }
    r.failed.retain(|s| *s != marker.to_sha256);
    r.save(dir)?;
    Ok(UpdateStatus {
        version: marker.to_version.clone(),
        sha256: marker.to_sha256.clone(),
        state: UpdateState::Confirmed,
        message: None,
    })
}

/// Hard-links `from` to a temporary name next to `to`, then renames it over `to`: `to` always names a complete
/// binary. Copies when the filesystem refuses hard links.
fn replace_with_copy_of(from: &Path, to: &Path) -> Result<(), String> {
    let tmp = to.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    if std::fs::hard_link(from, &tmp).is_err() {
        std::fs::copy(from, &tmp).map_err(|e| format!("copy {} to {}: {e}", from.display(), tmp.display()))?;
    }
    std::fs::rename(&tmp, to).map_err(|e| format!("rename {} to {}: {e}", tmp.display(), to.display()))
}

fn sync_dir(p: &Path) {
    if let Some(dir) = p.parent()
        && let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
}

/// Puts the staged binary in place of the running one, keeping the running one as `.prev`. The marker is written
/// first: a binary started after a crash halfway still knows what to judge.
pub fn install(dir: &Path, bin: &Binary, u: &AgentUpdate, now: i64) -> Result<Marker, String> {
    let marker = Marker {
        from_version: deploy_proto::build_version(),
        from_sha256: bin.sha256.clone(),
        to_version: u.version.clone(),
        to_sha256: u.sha256.clone(),
        installed_at: now,
    };
    let mut r = Record::load(dir)?;
    r.installing = Some(marker.clone());
    r.save(dir)?;
    let swap = replace_with_copy_of(&bin.path, &bin.previous())
        .and_then(|()| std::fs::rename(bin.staged(), &bin.path).map_err(|e| format!("install: {e}")));
    if let Err(e) = swap {
        r.installing = None;
        let _ = r.save(dir);
        return Err(e);
    }
    sync_dir(&bin.path);
    Ok(marker)
}

/// Puts `.prev` back in place of the binary (whose process then exits).
pub fn roll_back(bin: &Path) -> Result<(), String> {
    let b = Binary { path: bin.to_path_buf(), sha256: String::new() };
    let prev = b.previous();
    if !prev.exists() {
        return Err(format!("{} is missing", prev.display()));
    }
    replace_with_copy_of(&prev, bin)?;
    sync_dir(bin);
    Ok(())
}

/// What the agent does with an offer.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Fetch,
    Current,
    Refuse(String),
}

/// The keys offers are checked with: the pinned update key once there is one, else the control key; and the offline
/// release key, when pinned, whose signature every offered binary must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    pub control: VerifyingKey,
    pub update: Option<VerifyingKey>,
    pub release: Option<VerifyingKey>,
}

/// What to do with an offer to an agent running `running` (its build version) at Unix time `now`.
pub fn consider(dir: &Path, trust: &Trust, bin: &Binary, running: &str, u: &AgentUpdate, now: i64) -> Decision {
    let signed = match (&trust.update, u.expires_at) {
        (Some(k), Some(_)) => deploy_proto::update::verify(k, u),
        (Some(_), None) => {
            return Decision::Refuse("an update key is pinned: offers signed with the control key are refused".into());
        }
        (None, _) => deploy_proto::update::verify(&trust.control, u),
    };
    if let Err(e) = signed {
        return Decision::Refuse(e.to_string());
    }
    // The release key signed this exact binary and version when it was built; the control plane only relays it.
    if let Some(release) = &trust.release
        && let Err(e) = deploy_proto::update::verify_release(release, u)
    {
        return Decision::Refuse(format!("the binary is not signed by the pinned release key ({e})"));
    }
    if u.expires_at.is_some_and(|exp| now > exp + deploy_proto::MAX_SKEW_SECS) {
        return Decision::Refuse("the offer expired".into());
    }
    if Some(u.target.as_str()) != deploy_proto::update::target_of(std::env::consts::ARCH) {
        return Decision::Refuse(format!("this agent runs on {}, not {}", std::env::consts::ARCH, u.target));
    }
    if u.sha256 == bin.sha256 {
        return Decision::Current;
    }
    match deploy_proto::version::is_newer(&u.version, running) {
        Some(true) => {}
        Some(false) if deploy_proto::update::allows_downgrade(u) => {
            tracing::warn!("installing {} over the newer or equal {running}: allowed by an administrator", u.version);
        }
        Some(false) => {
            return Decision::Refuse(format!(
                "{} is not newer than the running {running} (a downgrade needs an administrator's allow_downgrade)",
                u.version
            ));
        }
        None => return Decision::Refuse(format!("cannot order the versions {} and {running}", u.version)),
    }
    match Record::load(dir) {
        Ok(r) if !u.force && r.failed.contains(&u.sha256) => {
            Decision::Refuse("this binary failed to connect after an earlier installation".into())
        }
        Ok(_) => Decision::Fetch,
        Err(e) => Decision::Refuse(e),
    }
}

/// The control plane's HTTP base URL, from the agent's connect URL (`wss://host[/prefix]/v1/agent/connect`).
pub fn base_url(connect_url: &str) -> Result<String, String> {
    let mut u = reqwest::Url::parse(connect_url).map_err(|e| format!("connect URL: {e}"))?;
    let scheme = match u.scheme() {
        "wss" | "https" => "https",
        "ws" | "http" => "http",
        s => return Err(format!("connect URL: unexpected scheme {s}")),
    };
    u.set_scheme(scheme).map_err(|()| "connect URL: scheme".to_string())?;
    let path = u.path().strip_suffix("/v1/agent/connect").unwrap_or("").to_string();
    u.set_path(&path);
    u.set_query(None);
    u.set_fragment(None);
    Ok(u.as_str().trim_end_matches('/').to_string())
}

/// Downloads the offered binary to `bin.staged()`, checks its SHA-256 and that it runs.
pub async fn fetch(base: &str, bin: &Binary, u: &AgentUpdate) -> Result<(), String> {
    let staged = bin.staged();
    let r = download(base, &staged, u).await;
    let r = match r {
        Ok(()) => preflight(&staged, &u.version).await,
        e => e,
    };
    if r.is_err() {
        let _ = tokio::fs::remove_file(&staged).await;
    }
    r
}

async fn download(base: &str, staged: &Path, u: &AgentUpdate) -> Result<(), String> {
    let url = format!("{base}/v1/agent/binary/{}", u.target);
    let mut resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|e| e.to_string())?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("download: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("download: HTTP {}", resp.status()));
    }
    let mut o = tokio::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true).mode(0o700);
    let mut f = o.open(staged).await.map_err(|e| format!("{}: {e}", staged.display()))?;
    let mut h = Sha256::new();
    let mut len = 0u64;
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("download: {e}"))? {
        len += chunk.len() as u64;
        if len > MAX_BINARY_BYTES {
            return Err("download: the binary is too large".into());
        }
        h.update(&chunk);
        f.write_all(&chunk).await.map_err(|e| format!("{}: {e}", staged.display()))?;
    }
    f.sync_all().await.map_err(|e| format!("{}: {e}", staged.display()))?;
    drop(f);
    let got = hex::encode(h.finalize());
    if got != u.sha256 {
        return Err(format!("SHA-256 mismatch: got {got}, signed {}", u.sha256));
    }
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o755))
        .await
        .map_err(|e| format!("{}: {e}", staged.display()))
}

/// The end of a download started by [`Updater::offer`].
pub struct Fetched {
    update: AgentUpdate,
    result: Result<(), String>,
}

/// What [`Updater::poll`] asks of the session.
#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    Idle,
    /// Report this.
    Status(UpdateStatus),
    /// Installed: report this and restart.
    Restart(UpdateStatus),
}

fn status(u: &AgentUpdate, state: UpdateState, message: Option<String>) -> UpdateStatus {
    UpdateStatus { version: u.version.clone(), sha256: u.sha256.clone(), state, message }
}

/// Update state of the agent across its sessions: a download outlives a reconnection, a downloaded binary waits for
/// a moment without deployments.
pub struct Updater {
    dir: PathBuf,
    bin: Option<Binary>,
    trust: Trust,
    base: Result<String, String>,
    tx: tokio::sync::mpsc::Sender<Fetched>,
    fetching: Option<String>,
    staged: Option<AgentUpdate>,
    deferred_told: bool,
    probation: Option<(Marker, tokio_util::sync::CancellationToken)>,
    reports: Vec<UpdateStatus>,
}

impl Updater {
    pub fn new(
        dir: PathBuf,
        bin: Option<Binary>,
        trust: Trust,
        connect_url: &str,
        tx: tokio::sync::mpsc::Sender<Fetched>,
    ) -> Updater {
        Updater {
            dir,
            bin,
            trust,
            base: base_url(connect_url),
            tx,
            fetching: None,
            staged: None,
            deferred_told: false,
            probation: None,
            reports: Vec::new(),
        }
    }

    pub fn own_sha256(&self) -> Option<String> {
        self.bin.as_ref().map(|b| b.sha256.clone())
    }

    /// The pinned keys changed (an update key announced, a control key rotated).
    pub fn set_trust(&mut self, trust: Trust) {
        self.trust = trust;
    }

    /// This binary was just installed: `confirmed` is cancelled once it connects (see [`Updater::connected`]).
    pub fn on_probation(&mut self, marker: Marker, confirmed: tokio_util::sync::CancellationToken) {
        self.probation = Some((marker, confirmed));
    }

    /// A status to send once connected.
    pub fn report(&mut self, st: UpdateStatus) {
        self.reports.push(st);
    }

    /// The first control frame of a session verified: confirms a binary on probation; returns what to report.
    pub fn connected(&mut self) -> Vec<UpdateStatus> {
        if let Some((m, confirmed)) = self.probation.take() {
            confirmed.cancel();
            match confirm(&self.dir, &m) {
                Ok(st) => {
                    tracing::info!("update to {} confirmed", m.to_version);
                    self.reports.push(st);
                }
                Err(e) => tracing::error!("update confirmation: {e}"),
            }
        }
        std::mem::take(&mut self.reports)
    }

    /// An offer from the control plane: checked, then downloaded in the background.
    pub fn offer(&mut self, u: AgentUpdate, now: i64) -> Option<UpdateStatus> {
        let Some(bin) = self.bin.clone() else {
            return Some(status(&u, UpdateState::Failed, Some("the agent cannot read its own binary".into())));
        };
        match consider(&self.dir, &self.trust, &bin, &deploy_proto::build_version(), &u, now) {
            Decision::Current => return Some(status(&u, UpdateState::Current, None)),
            Decision::Refuse(why) => {
                tracing::warn!("update to {} refused: {why}", u.version);
                return Some(status(&u, UpdateState::Failed, Some(why)));
            }
            Decision::Fetch => {}
        }
        if self.staged.as_ref().is_some_and(|s| s.sha256 == u.sha256) || self.fetching.as_ref() == Some(&u.sha256) {
            return None;
        }
        if self.fetching.is_some() {
            return Some(status(&u, UpdateState::Failed, Some("another download is in progress".into())));
        }
        let base = match &self.base {
            Ok(b) => b.clone(),
            Err(e) => return Some(status(&u, UpdateState::Failed, Some(e.clone()))),
        };
        tracing::info!("downloading agent {} ({})", u.version, u.sha256);
        self.staged = None;
        self.deferred_told = false;
        self.fetching = Some(u.sha256.clone());
        let st = status(&u, UpdateState::Downloading, None);
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let result = fetch(&base, &bin, &u).await;
            let _ = tx.send(Fetched { update: u, result }).await;
        });
        Some(st)
    }

    pub fn fetched(&mut self, f: Fetched) -> Option<UpdateStatus> {
        if self.fetching.as_ref() == Some(&f.update.sha256) {
            self.fetching = None;
        }
        match f.result {
            Ok(()) => {
                self.staged = Some(f.update);
                None
            }
            Err(e) => {
                tracing::warn!("update to {} failed: {e}", f.update.version);
                Some(status(&f.update, UpdateState::Failed, Some(e)))
            }
        }
    }

    /// Installs a downloaded binary unless a command holds it back (`busy`).
    pub fn poll(&mut self, busy: bool, now: i64) -> Poll {
        let (Some(u), Some(bin)) = (&self.staged, &self.bin) else { return Poll::Idle };
        if busy {
            if std::mem::replace(&mut self.deferred_told, true) {
                return Poll::Idle;
            }
            tracing::info!("agent {} downloaded; installed once the running commands end", u.version);
            return Poll::Status(status(u, UpdateState::Deferred, Some("waiting for running commands".into())));
        }
        let u = self.staged.take().expect("staged");
        match install(&self.dir, bin, &u, now) {
            Ok(_) => Poll::Restart(status(&u, UpdateState::Restarting, None)),
            Err(e) => {
                let _ = std::fs::remove_file(bin.staged());
                tracing::error!("installing agent {}: {e}", u.version);
                Poll::Status(status(&u, UpdateState::Failed, Some(e)))
            }
        }
    }
}

/// The new binary must at least start and name itself (wrong architecture, truncated file).
async fn preflight(staged: &Path, version: &str) -> Result<(), String> {
    let mut c = tokio::process::Command::new(staged);
    c.arg("version").kill_on_drop(true).stdin(std::process::Stdio::null());
    let out = tokio::time::timeout(Duration::from_secs(10), c.output())
        .await
        .map_err(|_| "the new binary did not answer `version`".to_string())?
        .map_err(|e| format!("the new binary does not run: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !text.starts_with("owdeploy-agent ") {
        return Err(format!("the new binary does not run: `version` answered {:?}", text.trim()));
    }
    if !text.starts_with(&format!("owdeploy-agent {version} ")) {
        tracing::warn!("the new binary names itself {:?}, offered as {version}", text.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("owd-update-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bin")).unwrap();
        std::fs::create_dir_all(d.join("state")).unwrap();
        d
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    /// What the production agent ran before build ordinals.
    const RUNNING: &str = "0.1.0+67536ac";

    fn offer(content: &[u8], force: bool) -> (ed25519_dalek::SigningKey, AgentUpdate) {
        let k = deploy_proto::generate_key();
        let target = deploy_proto::update::target_of(std::env::consts::ARCH).unwrap_or("linux-amd64");
        let u = deploy_proto::update::offer(&k, target, "0.2.0+new", &sha(content), force);
        (k, u)
    }

    fn trust(control: &ed25519_dalek::SigningKey) -> Trust {
        Trust { control: control.verifying_key(), update: None, release: None }
    }

    /// The whole cycle on files: install keeps the previous binary, a new binary that never connects is rolled
    /// back once its time is up, and the previous binary then records the failure and declines the same offer
    /// unless an administrator forces it.
    #[test]
    fn install_then_roll_back_after_no_connection() {
        let d = temp("rollback");
        let state = d.join("state");
        let path = d.join("bin/owdeploy-agent");
        std::fs::write(&path, b"old binary").unwrap();
        let old = Binary { path: path.clone(), sha256: sha(b"old binary") };
        let (k, u) = offer(b"new binary", false);
        std::fs::write(old.staged(), b"new binary").unwrap();
        assert_eq!(consider(&state, &trust(&k), &old, RUNNING, &u, 1000), Decision::Fetch);

        let m = install(&state, &old, &u, 1000).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new binary");
        assert_eq!(std::fs::read(old.previous()).unwrap(), b"old binary");
        assert!(!old.staged().exists());

        // The new binary starts within its time: probation. Started again after it: roll back.
        let new_sha = sha(b"new binary");
        let deadline = 1000 + CONFIRM_WITHIN.as_secs() as i64;
        assert_eq!(on_start(&state, &new_sha, 1010).unwrap(), Start::Probation { deadline, marker: m.clone() });
        assert_eq!(on_start(&state, &new_sha, deadline).unwrap(), Start::RollBack(m.clone()));
        roll_back(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"old binary");

        // The previous binary runs again: failure recorded once, marker cleared.
        let Start::Failed(st) = on_start(&state, &old.sha256, deadline + 5).unwrap() else { panic!("not failed") };
        assert_eq!((st.state, st.sha256.as_str()), (UpdateState::RolledBack, new_sha.as_str()));
        assert_eq!(on_start(&state, &old.sha256, deadline + 10).unwrap(), Start::Normal);
        assert!(matches!(consider(&state, &trust(&k), &old, RUNNING, &u, 1000), Decision::Refuse(_)));
        let forced = deploy_proto::update::offer(&k, &u.target, &u.version, &u.sha256, true);
        assert_eq!(consider(&state, &trust(&k), &old, RUNNING, &forced, 1000), Decision::Fetch);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_confirmed_binary_stays_and_offers_are_checked() {
        let d = temp("confirm");
        let state = d.join("state");
        let path = d.join("bin/owdeploy-agent");
        std::fs::write(&path, b"old").unwrap();
        let old = Binary { path: path.clone(), sha256: sha(b"old") };
        let (k, u) = offer(b"new", false);
        std::fs::write(old.staged(), b"new").unwrap();
        let m = install(&state, &old, &u, 1000).unwrap();
        let Start::Probation { marker, .. } = on_start(&state, &sha(b"new"), 1001).unwrap() else { panic!() };
        assert_eq!(confirm(&state, &marker).unwrap().state, UpdateState::Confirmed);
        assert_eq!(on_start(&state, &sha(b"new"), 5000).unwrap(), Start::Normal, "no rollback once confirmed");
        assert_eq!(m, marker);

        let new = Binary { path, sha256: sha(b"new") };
        assert_eq!(consider(&state, &trust(&k), &new, RUNNING, &u, 1000), Decision::Current);
        // Signed by another key, or for a binary other than the signed one: refused.
        let other = deploy_proto::generate_key();
        assert!(matches!(consider(&state, &trust(&other), &old, RUNNING, &u, 1000), Decision::Refuse(_)));
        let tampered = AgentUpdate { sha256: sha(b"evil"), ..u.clone() };
        assert!(matches!(consider(&state, &trust(&k), &old, RUNNING, &tampered, 1000), Decision::Refuse(_)));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Once an update key is pinned, offers signed by the control key are refused (v1 or v2) and v2 offers by the
    /// update key are accepted until they expire.
    #[test]
    fn a_pinned_update_key_is_required() {
        let state = temp("pinned").join("state");
        let bin = Binary { path: state.join("agent"), sha256: sha(b"old") };
        let (control, v1) = offer(b"new", false);
        let update = deploy_proto::generate_key();
        let pinned = Trust { control: control.verifying_key(), update: Some(update.verifying_key()), release: None };
        let refused = |d: Decision| matches!(d, Decision::Refuse(_));

        assert!(refused(consider(&state, &pinned, &bin, RUNNING, &v1, 1000)), "a v1 offer by the control key");
        let by_control = deploy_proto::update::offer_v2(&control, &v1, false, 2000);
        assert!(refused(consider(&state, &pinned, &bin, RUNNING, &by_control, 1000)), "a v2 offer by the control key");
        let by_update = deploy_proto::update::offer_v2(&update, &v1, false, 2000);
        assert_eq!(consider(&state, &pinned, &bin, RUNNING, &by_update, 1000), Decision::Fetch);
        let late = 2000 + deploy_proto::MAX_SKEW_SECS + 1;
        assert_eq!(
            consider(&state, &pinned, &bin, RUNNING, &by_update, late),
            Decision::Refuse("the offer expired".into())
        );
        // Without a pinned update key (an older control plane, or one without an update key) the control key's
        // offers, v1 and v2, are accepted as before.
        assert_eq!(consider(&state, &trust(&control), &bin, RUNNING, &v1, 1000), Decision::Fetch);
        assert_eq!(consider(&state, &trust(&control), &bin, RUNNING, &by_control, 1000), Decision::Fetch);
        assert!(refused(consider(&state, &trust(&control), &bin, RUNNING, &by_update, 1000)));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// With a pinned release key, only offers carrying its signature of the offered binary and version are fetched,
    /// whatever key signed the offer itself; without one, offers are judged as before.
    #[test]
    fn a_pinned_release_key_is_required() {
        let state = temp("release").join("state");
        let bin = Binary { path: state.join("agent"), sha256: sha(b"old") };
        let (update, base) = offer(b"new", false);
        let release = deploy_proto::generate_key();
        let t = Trust {
            control: deploy_proto::generate_key().verifying_key(),
            update: Some(update.verifying_key()),
            release: Some(release.verifying_key()),
        };
        let signed = |by: &ed25519_dalek::SigningKey, version: &str| {
            let mut u = deploy_proto::update::offer_v2(
                &update,
                &AgentUpdate { version: version.into(), ..base.clone() },
                false,
                2000,
            );
            u.release_signature =
                Some(deploy_proto::update::sign_release(by, &u.target, &u.version, &u.sha256).unwrap());
            u
        };
        let refused = |d: Decision| matches!(d, Decision::Refuse(m) if m.contains("release key"));
        assert_eq!(consider(&state, &t, &bin, RUNNING, &signed(&release, "0.2.0+new"), 1000), Decision::Fetch);
        let unsigned = deploy_proto::update::offer_v2(&update, &base, false, 2000);
        assert!(refused(consider(&state, &t, &bin, RUNNING, &unsigned, 1000)), "no release signature");
        // The control plane's update key cannot stand in for the release key.
        assert!(refused(consider(&state, &t, &bin, RUNNING, &signed(&update, "0.2.0+new"), 1000)));
        // A release signature of another version does not carry over.
        let mut moved = signed(&release, "0.2.0+new");
        moved = deploy_proto::update::offer_v2(&update, &AgentUpdate { version: "0.3.0".into(), ..moved }, false, 2000);
        assert!(refused(consider(&state, &t, &bin, RUNNING, &moved, 1000)));
        // No release key pinned (agents enrolled before it): the release signature is not looked at.
        let before = Trust { release: None, ..t.clone() };
        assert_eq!(consider(&state, &before, &bin, RUNNING, &unsigned, 1000), Decision::Fetch);
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// Only a strictly newer version is installed, unless an administrator's (forced) v2 offer signs
    /// `allow_downgrade`.
    #[test]
    fn downgrades_need_an_administrators_signed_permission() {
        let state = temp("downgrade").join("state");
        let bin = Binary { path: state.join("agent"), sha256: sha(b"running") };
        let (k, base) = offer(b"other", false);
        let t = Trust {
            control: deploy_proto::generate_key().verifying_key(),
            update: Some(k.verifying_key()),
            release: None,
        };
        let running = "0.1.0+70.abc1234";
        let at = |version: &str, force: bool, allow: bool| {
            let u = AgentUpdate { version: version.into(), force, ..base.clone() };
            consider(&state, &t, &bin, running, &deploy_proto::update::offer_v2(&k, &u, allow, 2000), 1000)
        };
        assert_eq!(at("0.1.0+71.def5678", false, false), Decision::Fetch, "newer build");
        assert_eq!(at("0.2.0", false, false), Decision::Fetch, "newer version");
        for older in ["0.1.0+69.def5678", "0.1.0+70.def5678", "0.1.0+67536ac", "0.0.9+500.a", "0.1.0-rc.1+99.a"] {
            assert!(matches!(at(older, false, false), Decision::Refuse(m) if m.contains("not newer")), "{older}");
            assert!(matches!(at(older, true, false), Decision::Refuse(_)), "force alone: {older}");
            assert!(matches!(at(older, false, true), Decision::Refuse(_)), "allow_downgrade without force: {older}");
            assert_eq!(at(older, true, true), Decision::Fetch, "force with allow_downgrade: {older}");
        }
        assert!(matches!(at("latest", true, true), Decision::Refuse(m) if m.contains("cannot order")));
        // A v1 offer's allow_downgrade is not signed: never honoured.
        let legacy = Trust { control: k.verifying_key(), update: None, release: None };
        let mut v1 = deploy_proto::update::offer(&k, &base.target, "0.1.0+69.def5678", &base.sha256, true);
        v1.allow_downgrade = true;
        assert!(matches!(consider(&state, &legacy, &bin, running, &v1, 1000), Decision::Refuse(_)));
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    /// A downloaded binary is not installed while a deployment runs: reported deferred once, installed when idle.
    #[test]
    fn update_waits_for_running_deployments() {
        let d = temp("defer");
        let state = d.join("state");
        let path = d.join("bin/owdeploy-agent");
        std::fs::write(&path, b"old").unwrap();
        let bin = Binary { path: path.clone(), sha256: sha(b"old") };
        let (k, u) = offer(b"new", false);
        std::fs::write(bin.staged(), b"new").unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut up = Updater::new(state.clone(), Some(bin), trust(&k), "wss://d.example/v1/agent/connect", tx);
        assert_eq!(up.poll(false, 1000), Poll::Idle, "nothing downloaded");
        assert_eq!(up.fetched(Fetched { update: u.clone(), result: Ok(()) }), None);

        let Poll::Status(st) = up.poll(true, 1000) else { panic!("not deferred") };
        assert_eq!(st.state, UpdateState::Deferred);
        assert_eq!(up.poll(true, 1001), Poll::Idle, "deferral reported once");
        assert_eq!(std::fs::read(&path).unwrap(), b"old", "not installed during a deployment");
        assert!(Record::load(&state).unwrap().installing.is_none());

        let Poll::Restart(st) = up.poll(false, 1002) else { panic!("not installed") };
        assert_eq!((st.state, st.sha256), (UpdateState::Restarting, u.sha256));
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn base_url_comes_from_the_connect_url() {
        assert_eq!(base_url("wss://deploy.openwaf.dev/v1/agent/connect").unwrap(), "https://deploy.openwaf.dev");
        assert_eq!(base_url("ws://127.0.0.1:8080/d/v1/agent/connect").unwrap(), "http://127.0.0.1:8080/d");
        assert!(base_url("ftp://x/v1/agent/connect").is_err());
    }
}
