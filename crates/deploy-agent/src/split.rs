//! Privilege separation on a server: which half `owdeploy-agent run` is, the two systemd units, and
//! `owdeploy-agent migrate-split`, which installs them (README.md, SECURITY.md «Agent privileges»).
//!
//! - `owdeploy-agent-broker.service` runs `owdeploy-agent broker` as root ([`crate::broker`]): the keys, the checks,
//!   Docker, the firewall, the self-update installation, under the same sandbox as the single-process unit.
//! - `owdeploy-agent.service` runs `owdeploy-agent run` as the `owdeploy` user ([`crate::relay`]): only the control
//!   plane's connection, without capabilities, in a strict sandbox, outside the docker group.
//!
//! Servers installed before keep their single root process (`owdeploy-agent.service` running `run` as root, no broker
//! unit) after self-updating: [`run_mode`] keeps that legacy mode, which says so in its hello, until an operator runs
//! `owdeploy-agent migrate-split`. The migration writes and verifies both units, switches to them, and puts the
//! previous unit back if the relay's session has not verified within [`MIGRATION_WITHIN`].

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::UnixStream;

use crate::ipc::{self, Status, ToBroker, ToRelay};

/// What `owdeploy-agent capabilities` lists when the binary runs privilege-separated; the broker installs only
/// binaries that list it.
pub const CAPABILITY: &str = "split-privileges";
pub const BROKER_UNIT: &str = "owdeploy-agent-broker.service";
/// The relay's unit keeps the name of the single-process one (`journalctl -u owdeploy-agent` keeps working).
pub const RELAY_UNIT: &str = "owdeploy-agent.service";
/// Where systemd unit files are looked for (the broker's, to tell the two modes apart).
const UNIT_DIRS: [&str; 3] = ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"];
/// Where `migrate-split` writes the units.
const UNIT_DIR: &str = "/etc/systemd/system";
/// How long the relay has to connect and verify a frame after the switch before the previous unit is put back.
pub const MIGRATION_WITHIN: Duration = Duration::from_secs(120);
/// The single-process unit, kept in the state directory by `migrate-split` (to revert by hand).
pub const LEGACY_BACKUP: &str = "legacy-unit.service";

/// What `owdeploy-agent run` is.
#[derive(Debug, PartialEq, Eq)]
pub enum RunMode {
    /// The single root process of servers installed before privilege separation.
    Legacy,
    /// The unprivileged relay of a broker.
    Relay,
}

/// `run` as any user but root is the relay; as root it is the relay only when the broker's unit is installed (a relay
/// started by hand), else the single-process agent of a server that has not migrated.
pub fn run_mode(uid: u32, broker_installed: bool) -> RunMode {
    match uid != 0 || broker_installed {
        true => RunMode::Relay,
        false => RunMode::Legacy,
    }
}

/// Whether the broker's unit is installed.
pub fn broker_installed() -> bool {
    UNIT_DIRS.iter().any(|d| Path::new(d).join(BROKER_UNIT).exists())
}

pub fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// The uid and gid of the local user `name` (`/etc/passwd`).
pub fn lookup_user(name: &str) -> Option<(u32, u32)> {
    parse_passwd(&std::fs::read_to_string("/etc/passwd").ok()?, name)
}

fn parse_passwd(text: &str, name: &str) -> Option<(u32, u32)> {
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 4 && f[0] == name).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))?
    })
}

/// Whether the group named `group` (`/etc/group`) has gid `gid` or lists `user`.
fn in_group(text: &str, group: &str, user: &str, gid: u32) -> bool {
    text.lines().any(|l| {
        let f: Vec<&str> = l.split(':').collect();
        f.len() >= 4
            && f[0] == group
            && (f[2].parse::<u32>().ok() == Some(gid) || f[3].split(',').any(|m| m.trim() == user))
    })
}

/// The broker's unit for the binary `bin`: what the single-process unit was, root under the same sandbox.
pub fn broker_unit(bin: &Path) -> String {
    let dir = bin.parent().unwrap_or(Path::new("/usr/local/bin")).display();
    format!(
        "# Installed by owdeploy-agent migrate-split.
[Unit]
Description=OpenWAF Deploy agent broker (root: keys, frame checks, Docker, firewall)
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart={bin} broker
Restart=always
RestartSec=5
Environment=OWDEPLOY_AGENT_STATE=/var/lib/owdeploy-agent
# The relay's socket: /run/owdeploy-agent/broker.sock, directory 0750 and socket 0660 of group owdeploy.
RuntimeDirectory=owdeploy-agent
RuntimeDirectoryMode=0750
# Root, as the single-process agent was (it drives the Docker Engine, which is root-equivalent, and iptables), but
# with no network connection of its own: the relay carries the control plane's. The same sandbox: the Docker socket
# and /run/xtables.lock under /run, securityfs to load its builders' AppArmor profile, its state under /var/lib, its
# own binary's directory for self-updates, and CSF's post hook. /usr (but that directory), /boot, /etc (but CSF's)
# are read-only to it, /home and /root hidden, /tmp private. NoNewPrivileges is not set: for a root process it adds
# nothing, and on SELinux hosts it would forbid the domain transitions of the iptables and apparmor_parser it runs.
ProtectSystem=full
ReadWritePaths={dir} -/etc/csf -/usr/local/csf/bin
ProtectHome=yes
PrivateTmp=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
",
        bin = bin.display()
    )
}

/// The relay's unit for the binary `bin`: the `owdeploy` user, no capabilities, nothing writable but its staging
/// directory.
pub fn relay_unit(bin: &Path) -> String {
    format!(
        "# Installed by owdeploy-agent migrate-split.
[Unit]
Description=OpenWAF Deploy agent relay (unprivileged: the control plane's connection)
After=network-online.target {BROKER_UNIT}
Wants=network-online.target {BROKER_UNIT}

[Service]
ExecStart={bin} run
Restart=always
RestartSec=5
# Not root, not in the docker group, no capabilities, no secret: DNS, TCP, TLS and WebSocket for the broker, and
# update downloads into its own staging directory, which the broker copies and checks before installing.
User={user}
Group={user}
StateDirectory=owdeploy-agent-relay
StateDirectoryMode=0700
Environment=OWDEPLOY_RELAY_STATE=/var/lib/owdeploy-agent-relay
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
",
        bin = bin.display(),
        user = ipc::RELAY_USER,
    )
}

/// Progress on the terminal; never fails (the operator's session may be gone: the migration still completes or
/// rolls back).
fn say(line: &str) {
    let _ = writeln!(std::io::stdout(), "owdeploy-agent: {line}");
}

async fn systemctl(args: &[&str]) -> Result<(), String> {
    let out = tokio::process::Command::new("systemctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| format!("systemctl: {e}"))?;
    match out.status.success() {
        true => Ok(()),
        false => Err(format!("systemctl {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim())),
    }
}

/// Asks the broker on `socket` for its status.
pub async fn query(socket: &Path) -> Result<Status, String> {
    let mut s = UnixStream::connect(socket).await.map_err(|e| format!("broker socket {}: {e}", socket.display()))?;
    ipc::write(&mut s, &ToBroker::Status {}).await?;
    match tokio::time::timeout(Duration::from_secs(10), ipc::read::<ToRelay, _>(&mut s)).await {
        Ok(Ok(Some(ToRelay::Status { status }))) => Ok(status),
        Ok(Ok(other)) => Err(format!("broker: unexpected answer {other:?}")),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("the broker did not answer".into()),
    }
}

/// Waits until the broker's session verified a control frame, at most `within`.
async fn wait_connected(socket: &Path, within: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + within;
    let mut last = "the broker has not started".to_string();
    while tokio::time::Instant::now() < deadline {
        match query(socket).await {
            Ok(Status { session: Some(s), .. }) if s.verified => return Ok(()),
            Ok(Status { relay: false, .. }) => last = "no relay attached to the broker".into(),
            Ok(_) => last = "the relay has not established a session".into(),
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(last)
}

/// Creates the relay's system user when missing (no home, no shell, a group of its own), and refuses one that is in
/// the docker group (or has its gid): the relay must not reach the Docker Engine.
async fn ensure_user() -> Result<(), String> {
    let user = ipc::RELAY_USER;
    if lookup_user(user).is_none() {
        let shell =
            ["/usr/sbin/nologin", "/sbin/nologin"].into_iter().find(|p| Path::new(p).exists()).unwrap_or("/bin/false");
        let out = tokio::process::Command::new("useradd")
            .args([
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                shell,
                user,
            ])
            .output()
            .await
            .map_err(|e| format!("useradd: {e}"))?;
        if !out.status.success() {
            return Err(format!("useradd {user}: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        say(&format!("created the system user {user}"));
    }
    let (_, gid) = lookup_user(user).ok_or(format!("the user {user} was not created"))?;
    let groups = std::fs::read_to_string("/etc/group").map_err(|e| format!("/etc/group: {e}"))?;
    if in_group(&groups, "docker", user, gid) {
        return Err(format!("the user {user} is in the docker group: remove it (gpasswd -d {user} docker) first"));
    }
    Ok(())
}

/// Writes a unit file, mode 0644 whatever the umask (install.sh runs with 077).
fn write_unit(path: &Path, text: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut f = std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.set_permissions(std::fs::Permissions::from_mode(0o644)))
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Checks the units with `systemd-analyze verify` when it is installed.
async fn verify(units: &[PathBuf]) -> Result<(), String> {
    let out = match tokio::process::Command::new("systemd-analyze").arg("verify").args(units).output().await {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            say("systemd-analyze is not installed: the units are not verified before the switch");
            return Ok(());
        }
        Err(e) => return Err(format!("systemd-analyze: {e}")),
    };
    match out.status.success() {
        true => Ok(()),
        false => Err(format!("the new units do not verify: {}", String::from_utf8_lossy(&out.stderr).trim())),
    }
}

/// `owdeploy-agent migrate-split` (root): installs the broker's and the relay's units for the binary `bin` and switches
/// to them. A server running the single-process unit is put back on it if the relay's session has not verified
/// within [`MIGRATION_WITHIN`]; a fresh install (no unit yet, install.sh) keeps the new units and reports the error.
pub async fn migrate(bin: &Path, state: &Path) -> Result<(), String> {
    if uid() != 0 {
        return Err("migrate-split must run as root".into());
    }
    // An operator's session that drops halfway must not stop the migration before its rollback.
    // SAFETY: setting SIGHUP to ignored has no preconditions.
    unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
    if !crate::keys::Identity::path(state).exists() {
        return Err(format!("{} is missing: enroll first", crate::keys::Identity::path(state).display()));
    }
    let bin_text = bin.to_str().ok_or("the binary's path is not UTF-8")?;
    if !bin.is_absolute() || bin_text.chars().any(|c| c.is_whitespace() || c == '%') {
        return Err(format!("{bin_text}: the binary needs an absolute path without spaces or %"));
    }
    systemctl(&["--version"]).await.map_err(|e| format!("systemd is required: {e}"))?;
    let dir = Path::new(UNIT_DIR);
    let (relay_path, broker_path) = (dir.join(RELAY_UNIT), dir.join(BROKER_UNIT));
    let (relay_text, broker_text) = (relay_unit(bin), broker_unit(bin));
    let previous = match std::fs::read_to_string(&relay_path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", relay_path.display())),
    };
    if previous.as_deref() == Some(relay_text.as_str())
        && std::fs::read_to_string(&broker_path).ok().as_deref() == Some(broker_text.as_str())
    {
        say("already privilege-separated; checking the connection");
        return wait_connected(&ipc::socket_path(), MIGRATION_WITHIN).await.map(|()| say("connected"));
    }
    ensure_user().await?;

    // The new units, verified next to each other before anything changes.
    let staging = Path::new("/run/owdeploy-agent-migrate");
    let _ = std::fs::remove_dir_all(staging);
    std::fs::create_dir_all(staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    let (relay_new, broker_new) = (staging.join(RELAY_UNIT), staging.join(BROKER_UNIT));
    write_unit(&relay_new, &relay_text)?;
    write_unit(&broker_new, &broker_text)?;
    let verified = verify(&[broker_new.clone(), relay_new.clone()]).await;
    if let Err(e) = verified {
        let _ = std::fs::remove_dir_all(staging);
        return Err(e);
    }
    let backup = state.join(LEGACY_BACKUP);
    if let Some(p) = &previous {
        crate::write_private(&backup, p.as_bytes())?;
        say(&format!("previous unit kept in {}", backup.display()));
    }

    // The switch: the single process stops first, so that never two processes speak for this server.
    say("switching to the broker and the relay");
    let switched = async {
        if previous.is_some() {
            systemctl(&["stop", RELAY_UNIT]).await?;
        }
        let copy = |from: &Path, to: &Path| {
            let tmp = to.with_extension("tmp");
            std::fs::copy(from, &tmp)
                .and_then(|_| std::fs::rename(&tmp, to))
                .map_err(|e| format!("{}: {e}", to.display()))
        };
        copy(&broker_new, &broker_path)?;
        copy(&relay_new, &relay_path)?;
        systemctl(&["daemon-reload"]).await?;
        systemctl(&["enable", BROKER_UNIT, RELAY_UNIT]).await?;
        systemctl(&["restart", BROKER_UNIT]).await?;
        systemctl(&["restart", RELAY_UNIT]).await?;
        say(&format!("waiting up to {} s for the relay's session", MIGRATION_WITHIN.as_secs()));
        wait_connected(&ipc::socket_path(), MIGRATION_WITHIN).await
    }
    .await;
    let _ = std::fs::remove_dir_all(staging);
    let e = match switched {
        Ok(()) => {
            say("privilege-separated and connected: the relay runs as owdeploy, the broker as root");
            return Ok(());
        }
        Err(e) => e,
    };
    let Some(previous) = previous else {
        return Err(format!(
            "the units are installed but the agent has not connected: {e} (journalctl -u {BROKER_UNIT} -u {RELAY_UNIT})"
        ));
    };
    say(&format!("not connected ({e}): putting the single-process unit back"));
    let _ = systemctl(&["disable", "--now", BROKER_UNIT]).await;
    let _ = systemctl(&["stop", RELAY_UNIT]).await;
    let restored = write_unit(&relay_path, &previous)
        .and_then(|()| std::fs::remove_file(&broker_path).map_err(|e| format!("{}: {e}", broker_path.display())));
    let reloaded = match restored {
        Ok(()) => systemctl(&["daemon-reload"]).await.and(systemctl(&["restart", RELAY_UNIT]).await),
        Err(e) => Err(e),
    };
    match reloaded {
        Ok(()) => Err(format!("migration rolled back: {e} (journalctl -u {BROKER_UNIT} -u {RELAY_UNIT})")),
        Err(r) => {
            Err(format!("migration failed ({e}) and so did its rollback ({r}): restore {} by hand", backup.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_is_the_relay_unless_root_without_a_broker() {
        assert_eq!(run_mode(0, false), RunMode::Legacy, "a server installed before, after its self-update");
        assert_eq!(run_mode(0, true), RunMode::Relay, "root with the broker installed: never a second agent");
        assert_eq!(run_mode(998, true), RunMode::Relay);
        assert_eq!(run_mode(998, false), RunMode::Relay, "not root: never the legacy agent (it would hold no keys)");
    }

    #[test]
    fn users_and_groups_from_their_files() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nowdeploy:x:998:997::/nonexistent:/usr/sbin/nologin\nbad:x:a:b\n";
        assert_eq!(parse_passwd(passwd, "owdeploy"), Some((998, 997)));
        assert_eq!(parse_passwd(passwd, "owdeplo"), None);
        assert_eq!(parse_passwd(passwd, "bad"), None);
        let group = "docker:x:999:alice,owdeploy\nowdeploy:x:997:\n";
        assert!(in_group(group, "docker", "owdeploy", 997), "a member");
        assert!(!in_group(group, "docker", "owdeploy2", 997));
        assert!(in_group("docker:x:997:\n", "docker", "owdeploy", 997), "the docker gid as its own");
        assert!(!in_group("docker:x:999:\n", "docker", "owdeploy", 997));
    }

    /// The relay's unit drops everything the relay does not need; the broker's keeps what the single-process unit
    /// had (root, the binary's directory writable for self-updates).
    #[test]
    fn units_run_the_halves_with_their_privileges() {
        let bin = Path::new("/usr/local/bin/owdeploy-agent");
        let relay = relay_unit(bin);
        for line in [
            "ExecStart=/usr/local/bin/owdeploy-agent run",
            "User=owdeploy",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=\n",
            "AmbientCapabilities=\n",
            "ProtectSystem=strict",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "MemoryDenyWriteExecute=yes",
            "SystemCallFilter=@system-service",
            "UMask=0077",
        ] {
            assert!(relay.contains(line), "relay unit lacks {line:?}");
        }
        assert!(!relay.contains("SupplementaryGroups"), "never in another group (docker)");
        let broker = broker_unit(bin);
        assert!(broker.contains("ExecStart=/usr/local/bin/owdeploy-agent broker"));
        assert!(broker.contains("ReadWritePaths=/usr/local/bin -/etc/csf"));
        assert!(broker.contains("RuntimeDirectory=owdeploy-agent"));
        assert!(!broker.contains("User="), "root");
    }
}
