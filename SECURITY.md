# Security policy

## Reporting a vulnerability

You can report a vulnerability in either of two ways:

- Email **security@openwaf.dev**.
- Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** in this repository.

Please include a description, the affected version or commit (`owdeploy-agent version`) and steps to reproduce. Do not
open a public issue or pull request for a vulnerability.

What happens next:

- We confirm receipt within 24 hours and keep you informed until a fix ships.
- Fixes are released as a new version. The control plane offers it to every agent, and agents install it themselves
  (README.md, «Updates»).
- We credit reporters in the release notes unless you ask us not to.

## Scope

Everything in this repository is in scope: the agent (`crates/deploy-agent`), the protocol (`crates/deploy-proto`,
[PROTOCOL.md](PROTOCOL.md)), the installer (`install.sh`) and the release pipeline (`.github/workflows`,
`scripts/build-release.sh`, `verify.sh`).

Examples of what we want to hear about:

- a frame, offer or key announcement the agent accepts without a valid signature from a pinned key;
- a replay or downgrade that gets through;
- a way for an application or its repository to reach the host, another application, private networks or cloud
  metadata;
- a Compose file that gets around the agent's validation;
- a secret that reaches logs, argv or the environment of the wrong process;
- firewall rules that open an application port to anyone other than the OpenWAF edge;
- a release that does not reproduce from its tag.

Issues in the OpenWAF service itself (the control plane, the edge, the dashboard) are welcome at the same address.
Their code is not in this repository.

Out of scope:

- denial of service by volume;
- findings that need root on the server or a compromised OpenWAF account;
- vulnerabilities in the applications you deploy.

## What the agent can do on a server, and why

The agent runs as root under systemd. It needs root for these tasks:

| Capability | Why |
|---|---|
| Docker Engine API (the Engine's socket) | deploy, start, stop and remove application containers, images, networks and volumes; run `exec` commands inside application containers |
| Per-deployment helper containers | Repository content is handled in a source helper without the Engine's socket, without capabilities and with `no-new-privileges`: Git clone, Railpack's plan, Compose's resolution. Only then a build helper, which holds the Engine's socket, runs `docker buildx` and `docker compose` on the copied result. Both exist only for one deployment and run pinned images and tools. |
| Rootless BuildKit builders (pinned by digest) | build Dockerfile, Railpack and Compose images. Build steps are root only inside a user namespace mapped to unprivileged host ids, and builders have no host mounts. Code from forks builds on a separate builder, without secrets and without a shared cache. |
| The router container `owd-router` (Caddy) | listens on the application ports on the host and switches traffic between containers during rolling deployments |
| iptables and ip6tables, in its own chains (`OWDEPLOY*`) plus jumps in `DOCKER-USER`, `INPUT`, `FORWARD` and nat `PREROUTING`/`OUTPUT` | open application ports to the OpenWAF edge only; keep containers off private ranges, cloud metadata and the host. Your own rules are left untouched. |
| The CSF post hook (`csfpost.sh`), only when CSF is installed | put its rules back after `csf -r` |
| Its own binary, `/usr/local/bin/owdeploy-agent` | self-update, signed by the pinned update key, with automatic rollback |
| `/var/lib/owdeploy-agent` (mode 0700) | its identity, its pinned keys, the last firewall and router configuration, and file mounts of applications |

What the agent never does:

- open a listening port of its own;
- accept unsigned or shell-string commands. Every operation is a typed message ([PROTOCOL.md §7](PROTOCOL.md#7-operations)),
  and `exec` runs an argv in an application's container, not on the host;
- edit firewall rules or containers it did not create;
- run Compose services that are privileged or that use host namespaces, devices, extra capabilities or bind mounts of
  the server's files. These are refused before `docker compose up`.

## Threat model

| Threat | What protects you |
|---|---|
| **A network attacker** between the server and the control plane | TLS, plus Ed25519 signatures on every frame in both directions. The control plane's keys are pinned at enrollment. Each frame carries its direction, a strictly increasing sequence number and a timestamp checked within 300 s. The handshake nonce is single-use. |
| **Someone with an enrollment token** | They can enroll one server into your organization until the token expires or is used up. Tokens are short-lived; revoke unused ones. |
| **A malicious repository or image** | The repository is cloned and analysed without access to the Docker Engine. Builds run in rootless BuildKit, on a network that cannot reach private ranges, cloud metadata or the host, with CPU, memory, process and cache limits. The public internet stays reachable for package registries. Applications run as containers on their environment's network behind the same egress guard, and their ports are reachable only through the router and from the edge. |
| **A compromised control plane** | It can do what the control plane is for: deploy and run containers on your servers, which is root-equivalent through Docker. It cannot replace the agent binary on its own: offers must be signed by the update key, a separate key that the agent requires once pinned, and an agent that pinned the release key also requires that key's signature, made offline when the binary is built and never held by the control plane. Binaries are checked against the signed SHA-256, and anti-downgrade refuses older versions without an administrator's signed downgrade. If you lose trust in the control plane, revoke the server and stop the agent. |
| **A malicious release** | Releases are built on GitHub from a tag by [release.yml](.github/workflows/release.yml), signed with keyless cosign, and attested (SLSA provenance). They are reproducible: [verify.sh](verify.sh) rebuilds a tag and compares the binaries byte for byte. |

### Known limitations

- The build helper has the Docker Engine's socket. Anything that escapes `docker buildx` or `docker compose` in it has
  root on the host. Repository content reaches it only after the source helper, which has no socket, has handled it.
- Builders are long-lived (one per server for trusted code, one for untrusted code), and build egress to the public
  internet is not restricted to an allowlist.
- The agent runs as root. The systemd unit installed by `install.sh` narrows it (read-only system directories, hidden
  home directories, a private /tmp, protected kernel logs, cgroups and hostname), but anything that takes over the
  agent still controls the Docker Engine.
- Frames are not bound to one connection. Within the 300 s skew window, TLS is what keeps a frame recorded on one
  connection out of a later one ([PROTOCOL.md §4](PROTOCOL.md#4-frames)).

## Supported versions

Only the latest release is supported. Agents connected to OpenWAF Deploy are offered new releases automatically.
Fixes are not backported.
