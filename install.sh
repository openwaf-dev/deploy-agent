#!/bin/sh
# OpenWAF Deploy agent installer, served by the control plane at /install.sh.
#   curl -fsSL @PUBLIC_URL@/install.sh | sudo OWDEPLOY_TOKEN=owde_… sh
# Optional: OWDEPLOY_NAME (server name shown in the dashboard; default: hostname).
# Needs Linux with systemd and Docker Engine. Installs /usr/local/bin/owdeploy-agent and the owdeploy-agent service.
set -eu

URL="@PUBLIC_URL@"
STATE=/var/lib/owdeploy-agent
BIN=/usr/local/bin/owdeploy-agent

fail() { echo "owdeploy: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run as root (sudo)"
[ "$(uname -s)" = Linux ] || fail "Linux only"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"
command -v docker >/dev/null 2>&1 || fail "Docker Engine is required: https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || fail "Docker Engine is installed but not running"
[ -n "${OWDEPLOY_TOKEN:-}" ] || fail "OWDEPLOY_TOKEN is missing (create one in the dashboard: Deploy > Servers > Add)"
[ -f "$STATE/identity.json" ] && fail "already enrolled ($STATE/identity.json); revoke it in the dashboard and remove $STATE to enroll again"

case "$(uname -m)" in
  x86_64|amd64) TARGET=linux-amd64 ;;
  aarch64|arm64) TARGET=linux-arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$URL/v1/agent/binary/$TARGET" -o "$TMP/owdeploy-agent"
curl -fsSL "$URL/v1/agent/binary/$TARGET.sha256" -o "$TMP/sum"
WANT=$(cut -d' ' -f1 "$TMP/sum")
GOT=$(sha256sum "$TMP/owdeploy-agent" | cut -d' ' -f1)
[ "$WANT" = "$GOT" ] || fail "checksum mismatch for the agent binary"
install -m 0755 "$TMP/owdeploy-agent" "$BIN"

# The token goes through a 0600 file, never through argv; the agent deletes it after enrolling.
umask 077
printf '%s' "$OWDEPLOY_TOKEN" > "$TMP/token"
if [ -n "${OWDEPLOY_NAME:-}" ]; then
  "$BIN" enroll --url "$URL" --token-file "$TMP/token" --name "$OWDEPLOY_NAME"
else
  "$BIN" enroll --url "$URL" --token-file "$TMP/token"
fi

# CSF flushes iptables on `csf -r`; its post hook puts the agent's firewall rules back at once (the agent also
# checks them every 30 s). Only when CSF is installed.
if [ -d /etc/csf ]; then
  "$BIN" csf-hook || echo "owdeploy: could not add the CSF post hook; the agent still repairs its rules every 30 s" >&2
fi

cat > /etc/systemd/system/owdeploy-agent.service <<'UNIT'
[Unit]
Description=OpenWAF Deploy agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/owdeploy-agent run
Restart=always
RestartSec=5
Environment=OWDEPLOY_AGENT_STATE=/var/lib/owdeploy-agent
# Sandboxing that leaves the agent what it needs: root (it drives the Docker Engine, which is root-equivalent, and
# iptables), the Docker socket and /run/xtables.lock under /run, securityfs to load its builders' AppArmor profile,
# its state under /var/lib, its own binary's directory for self-updates, and CSF's post hook. /usr (but that
# directory), /boot, /etc (but CSF's) are read-only to it, /home and /root hidden, /tmp private.
# NoNewPrivileges is not set: for a root process it adds nothing, and on SELinux hosts it would forbid the domain
# transitions of the iptables and apparmor_parser it runs.
ProtectSystem=full
ReadWritePaths=/usr/local/bin -/etc/csf -/usr/local/csf/bin
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
UNIT
systemctl daemon-reload
systemctl enable --now owdeploy-agent.service
echo "owdeploy: agent installed and running (journalctl -u owdeploy-agent)"
