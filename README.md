# OpenWAF Deploy agent

**Managed deployment for agencies, integrated with managed edge security.**

`owdeploy-agent` is the open-source agent of [OpenWAF Deploy](https://openwaf.dev). It runs on your own servers and
deploys applications from Git or container images there, behind the OpenWAF edge. This repository holds the agent, its
wire protocol (`deploy-proto`), the installer and the release pipeline, so you can read, build and verify exactly what
runs as root on your servers.

Documentation: <https://developers.openwaf.dev/deploy/>

## How it fits together

```text
 your team ── dashboard / API ──▶  OpenWAF Deploy control plane (managed by OpenWAF)
                                          ▲
                                          │ one outbound WebSocket over TLS, every frame signed (Ed25519)
                                          │
 visitors ──▶ OpenWAF edge (WAF, TLS) ──▶ your server: owdeploy-agent + Docker + router
                                          (application ports open to the edge only)
```

- **Managed control plane.** OpenWAF runs the control plane. It keeps your projects, environments, variables and
  secrets, builds the deployment plan, handles webhooks and previews, and attaches every domain to the OpenWAF edge.
- **Agent on your servers.** The agent runs on each of your servers and executes typed operations (deploy, start,
  stop, logs, exec, router and firewall changes) against the local Docker Engine. Builds run on the server itself,
  inside rootless BuildKit.
- **Outbound only.** The agent dials the control plane and never listens on a port of its own. The control plane holds
  no SSH key or password for your server. Every frame either side sends is signed. The agent pins the control plane's
  keys at enrollment and refuses anything else ([PROTOCOL.md](PROTOCOL.md)).
- **Edge-only ports.** Applications are published through a per-server router (Caddy). The agent's firewall rules
  accept traffic to those ports only from the OpenWAF edge, which terminates TLS and runs the WAF in front of every
  domain. Containers are kept off private ranges, cloud metadata and the host.

## Requirements

- Linux on x86_64 or arm64, with systemd;
- Docker Engine;
- iptables (and ip6tables for IPv6);
- root.

CSF is supported: when it is present, the agent adds a post hook so that its rules come back after `csf -r`.

## Install

In the dashboard, open **Deploy → Servers → Add** and run the command it shows on the server:

```sh
curl -fsSL https://deploy.openwaf.dev/install.sh | sudo OWDEPLOY_TOKEN=owde_… sh
```

The control plane serves [install.sh](install.sh) with its own URL in place of `@PUBLIC_URL@`. The installer:

1. checks the system;
2. downloads the agent binary for your architecture and checks its SHA-256;
3. installs the binary as `/usr/local/bin/owdeploy-agent`;
4. enrolls the server (the token goes through a 0600 file, never through argv);
5. adds the CSF hook when CSF is present;
6. starts the `owdeploy-agent` systemd service.

The state of the agent (its identity and the keys it pinned) lives in `/var/lib/owdeploy-agent`, with mode 0700/0600.

```text
owdeploy-agent enroll --url URL --token-file PATH [--name NAME]   # what the installer runs
owdeploy-agent run                                                  # the service
owdeploy-agent firewall-repair                                      # re-applies missing firewall rules
owdeploy-agent csf-hook                                             # installs the CSF post hook
owdeploy-agent pin-keys [--control-key KEY] [--update-key KEY] [--release-key KEY]   # key recovery, see below
owdeploy-agent version
```

To remove a server, revoke it in the dashboard, then on the server run:

```sh
systemctl disable --now owdeploy-agent
rm -rf /var/lib/owdeploy-agent /usr/local/bin/owdeploy-agent /etc/systemd/system/owdeploy-agent.service
```

This removes the agent only. The containers, images, volumes and networks it created (labelled
`dev.openwaf.deploy.*` or named `owd-…`, including the `owd-router` container) and its iptables chains (`OWDEPLOY*`)
stay until you remove them. The chains also go away at the next reboot, unless your system saves its iptables rules.

## Updates

The agent updates itself when the control plane offers a newer binary. Each offer is signed by an update key, a key
of its own that the agent pins, over the exact target, version and SHA-256. The agent applies these rules:

- it installs only a strictly newer version, unless an administrator signs a downgrade;
- it installs only between deployments;
- it rolls back by itself when the new binary does not reconnect within 120 s;
- once it has pinned the offline release key, it installs only binaries that key signed when they were built.

The binaries OpenWAF offers to agents are the ones the release workflow of this repository builds and publishes; OpenWAF adds the release key's signature before serving them. New versions reach a few servers first and the rest only after that stage passes.

[PROTOCOL.md §10](PROTOCOL.md#10-self-update) covers the details.

## Verify a release

Every release on GitHub publishes these files:

| File | Contents |
|---|---|
| `owdeploy-agent-linux-amd64`, `owdeploy-agent-linux-arm64` | static musl binaries, named as the control plane serves them |
| `SHA256SUMS` | SHA-256 of both binaries |
| `owdeploy-agent-linux-*.cdx.json` | CycloneDX SBOM of each binary |
| `*.sigstore.json` | keyless cosign signature bundle of each file above |

Each release also has GitHub artifact attestations (SLSA build provenance) for the binaries and SBOMs.

```sh
tag=v0.1.0   # the release to check
repo=openwaf-dev/deploy-agent
gh release download "$tag" -R "$repo"

# 1. The files are what the release workflow of this repository built and signed for that tag.
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS
gh attestation verify owdeploy-agent-linux-amd64 -R "$repo"

# 2. The binary on your server is one of them (compare with SHA256SUMS).
sha256sum /usr/local/bin/owdeploy-agent
owdeploy-agent version
```

### Rebuild it yourself

[verify.sh](verify.sh) rebuilds a release from this repository and compares the result with the published binaries
byte for byte:

```sh
git clone https://github.com/openwaf-dev/deploy-agent && cd deploy-agent
./verify.sh v0.1.0
```

It checks the signature of `SHA256SUMS` when cosign is installed, builds the tag in a clean worktree with
[scripts/build-release.sh](scripts/build-release.sh) and prints `reproduced` for each binary. It needs the same tools
as a build from source (below).

## Build from source

Requirements:

- [rustup](https://rustup.rs). [rust-toolchain.toml](rust-toolchain.toml) pins the toolchain (Rust 1.98.1) and its
  musl targets.
- [zig](https://ziglang.org/download/) 0.17.0 and
  [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) 0.23.4
  (`cargo install --locked cargo-zigbuild --version 0.23.4`). These are needed only for release builds.

Development:

```sh
cargo test --workspace --locked                  # unit tests, any OS
cargo build --release -p deploy-agent            # a local build
```

The end-to-end tests in `crates/deploy-agent/src/e2e.rs` drive a real Docker Engine (and, for the firewall tests,
iptables as root). They skip themselves unless `OWDEPLOY_TEST_DOCKER=1` is set; the module documentation explains how
to run them in a throwaway Linux container.

Release build (what the release workflow and `verify.sh` run):

```sh
scripts/build-release.sh dist     # dist/owdeploy-agent-linux-{amd64,arm64} and dist/SHA256SUMS
```

The output depends only on the commit. To get this property, the release build:

- uses the pinned toolchain, linker and `Cargo.lock`;
- sets the release profile explicitly;
- maps the checkout and Cargo home to fixed paths in Rust and C code;
- disables incremental builds;
- sets `SOURCE_DATE_EPOCH` from the commit.

The version embedded in the binary is `<crate version>+<ordinal>.<commit>`. The ordinal comes from
[BUILD_ORDINAL](BUILD_ORDINAL), which grows with every release, so agents can order releases and refuse downgrades
([PROTOCOL.md §11](PROTOCOL.md#11-versions)).

## Recovering the pinned keys

The agent trusts only the control key, the update key and the release key it pinned. Changes to them arrive signed by the keys already
pinned ([PROTOCOL.md §8](PROTOCOL.md#8-keys)). If the control plane ever loses or must revoke a key, OpenWAF will
announce the new public keys through its usual channels. A root user then pins them on each server by hand:

```sh
systemctl stop owdeploy-agent
owdeploy-agent pin-keys --control-key <base64> --update-key <base64> [--release-key <base64>]
systemctl start owdeploy-agent
```

## Security

[SECURITY.md](SECURITY.md) explains what the agent can do on a server and why, the threat model, and how to report a
vulnerability: write to security@openwaf.dev or use GitHub's private vulnerability reporting. Please do not open
public issues for vulnerabilities.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). The agent is licensed under the [Apache License 2.0](LICENSE).
