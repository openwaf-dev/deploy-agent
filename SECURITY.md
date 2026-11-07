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

## Agent privileges

`install.sh` runs the agent as two processes of the same binary, so that the code that handles network input runs
without privileges:

| Process | systemd unit | Runs as | Holds | Does |
|---|---|---|---|---|
| Relay (`owdeploy-agent run`) | `owdeploy-agent` | the system user `owdeploy`: no shell, no home, not in the `docker` group, no capabilities (`CapabilityBoundingSet=` empty, `NoNewPrivileges`), read-only system (`ProtectSystem=strict`), private `/tmp` and `/dev`, only UNIX and IP sockets, `@system-service` system calls, no writable and executable memory | no key and no state; it writes only its staging directory `/var/lib/owdeploy-agent-relay` | DNS, TCP, TLS, the HTTP upgrade and WebSocket framing to the control plane; downloads the update binaries the broker asks for |
| Broker (`owdeploy-agent broker`) | `owdeploy-agent-broker` | root, in the sandbox described below | the identity key, the pinned keys, each session's keys and all the state in `/var/lib/owdeploy-agent` (0700) | signs the connect request; checks the control plane's handshake against the pinned keys and derives the session's keys; opens every incoming frame (signature, session, direction, sequence, time, decryption) and seals every outgoing one; executes operations; checks and installs updates |

The relay talks to the broker over a UNIX socket, `/run/owdeploy-agent/broker.sock`. The socket's directory has mode
0750 and the socket 0660, both with group `owdeploy`. The broker also checks the peer's user (`SO_PEERCRED`: only
`owdeploy` or root) and serves one relay at a time. Their protocol has a fixed set of length-prefixed JSON messages
(at most 8 MiB): the signed headers of a connect request, the headers of the control plane's answer, frames in and
out as opaque strings, the end of a session, the staging of an update, and the broker's status. No message asks the
broker to execute something. The broker acts only on frames that verify for its current session, and drops a relay
that sends anything else.

In a protocol 2 session (the only kind an agent accepts once it used protocol 2 or enrolled with a control plane that
speaks it, [PROTOCOL.md §3](PROTOCOL.md#3-connect-handshake)), frame bodies are encrypted end to end between the
broker and the control plane, with keys of that connection only that the broker derives and holds
([PROTOCOL.md §4](PROTOCOL.md#4-frames)). The relay carries them without being able to read them.

A relay that an attacker controls **can**:

- drop, delay or reorder traffic, which ends the session (a reordered frame fails the sequence check);
- see what is not encrypted: each frame's kind, sequence number, timestamp, size and signature, and their timing (so,
  for instance, that a command was sent and how large it was, or how much log a deployment produced), the handshake
  headers (server id, nonces, public keys), and the URL and SHA-256 of the update binaries the broker asks it to
  download;
- make the broker sign connect requests for this server, which lets it open connections to the control plane as this
  server, but not complete a session without the broker;
- give the broker any file as a downloaded update. The broker copies the file without following links, then checks
  the copy's size, SHA-256 and signatures (section «Updates» in README.md) before it installs it.

It **cannot** read the messages (operations, environment variables, Git tokens, registry credentials, deploy keys,
file mounts, logs and output), make the broker execute anything, forge, replay or move a frame, put its own key in the
handshake to decrypt the session (both sides sign both exchange keys), change the pinned keys, install a binary that is
not signed, read the identity key, the session keys or the state, or reach the Docker Engine.

Servers installed before privilege separation keep one root process (the unit `owdeploy-agent` running `run` as root)
after they update themselves. The agent then reports `legacy` privileges to the control plane.
`owdeploy-agent migrate-split` moves them to the two processes (README.md, «Upgrade to separated privileges»).

## What the agent can do on a server, and why

The broker (or, on servers that have not migrated, the single agent process) runs as root under systemd. It needs
root for these tasks:

| Capability | Why |
|---|---|
| Docker Engine API (the Engine's socket) | deploy, start, stop and remove application containers, images, networks and volumes; load the images builds produce; run `exec` commands inside application containers. Only the agent process talks to the Engine. |
| Per-deployment helper containers | None has the Engine's socket. Repository content is handled in a source helper without capabilities and with `no-new-privileges`: Git clone, Railpack's plan, Compose's resolution. A build helper (same restrictions) then runs `docker buildx` on the copied result against one rootless builder only, through that builder's socket, and exports each image as an OCI image layout. The agent checks every layout before loading it into the Engine itself: blob digests, exactly one image, its resource and deployment labels, and no tag or reference name from the build; it tags the loaded image after checking its ID and labels again. An SBOM generator (syft, pinned and checksummed) scans images without an SBOM attestation in a helper without network. Helpers exist only for one deployment and run pinned images and tools. |
| Rootless BuildKit builders (pinned by digest) | build Dockerfile, Railpack, static-site and Compose images, with an SPDX SBOM attestation from a generator pinned by digest. Build steps are root only inside a user namespace mapped to unprivileged host ids, and builders have no host mounts. Each listens only on a unix socket in a memory-backed volume mounted into the builder and its build helpers, owned by the builder's unprivileged user. Code from forks builds on a separate builder, without secrets and without a shared cache. |
| The build egress proxy `owd-build-proxy` | the only way out of the build network ([PROTOCOL.md «Build egress»](PROTOCOL.md#build-egress)): the agent's own static binary (`owdeploy-agent build-proxy`) in a container of its own, as user 65534, without capabilities, with `no-new-privileges`, a read-only root file system and no mount but a small memory file system for its control socket, which the agent reaches with `docker exec`. It parses the build steps' requests, so it never runs in the agent's process. It applies each deployment's egress policy, never connects to private, link-local or reserved addresses, and reports where builds went. |
| Compose applications | applied by the agent through the Engine API from a typed plan of the resolved project: networks, volumes and containers with Compose's labels, dependencies (`service_started`, `service_healthy`, `service_completed_successfully`), recreation of changed services, removal of orphans, waiting for health. Fields the agent does not model are refused. |
| The router container `owd-router` (Caddy) | listens on the application ports on the host and switches traffic between containers during rolling deployments |
| iptables and ip6tables, in its own chains (`OWDEPLOY*`) plus jumps in `DOCKER-USER`, `INPUT`, `FORWARD` and nat `PREROUTING`/`OUTPUT` | open application ports to the OpenWAF edge only; keep containers off private ranges, cloud metadata and the host. Your own rules are left untouched. |
| The CSF post hook (`csfpost.sh`), only when CSF is installed | put its rules back after `csf -r` |
| Its own binary, `/usr/local/bin/owdeploy-agent` | self-update, signed by the pinned update key, with automatic rollback. The relay downloads the binary; the broker checks and installs it |
| `/var/lib/owdeploy-agent` (mode 0700) | its identity, its pinned keys, the last firewall and router configuration, file mounts of applications, image archives while it checks and loads them, and the SBOMs it generated |

What the agent never does:

- open a listening port of its own (the broker's UNIX socket is local to the server, for the relay only);
- accept unsigned or shell-string commands. Every operation is a typed message ([PROTOCOL.md §7](PROTOCOL.md#7-operations)),
  and `exec` runs an argv in an application's container, not on the host;
- edit firewall rules or containers it did not create;
- run Compose services that are privileged or that use host namespaces, devices, extra capabilities, bind mounts of
  the server's files, security options other than `no-new-privileges`, or logging drivers that send logs from the
  server. These, and any field the agent does not model, are refused before anything is created;
- give a container it runs for a deployment (helper, builder or application) the Docker Engine's socket.

## Threat model

| Threat | What protects you |
|---|---|
| **A flaw in the agent's network code** (TLS, HTTP, WebSocket) | That code runs only in the relay, as an unprivileged user with no capabilities and no access to Docker or to the agent's keys. The broker acts only on frames that verify for its session (section «Agent privileges»). |
| **A network attacker** between the server and the control plane | TLS, plus Ed25519 signatures on every frame in both directions. The control plane's keys are pinned at enrollment. Each frame carries its direction, a strictly increasing sequence number and a timestamp checked within 300 s. The handshake nonce is single-use. In protocol 2 the control plane adds a nonce of its own, both sides contribute an ephemeral X25519 key and sign the handshake transcript, every frame's signature covers the session id derived from both nonces, so a frame recorded on one connection is refused on any other, and every frame's body is encrypted with keys derived from that exchange, so even whoever terminates TLS (a proxy, or the agent's relay) reads no message. The keys are per connection and wiped when it ends: a later theft of any long-term key does not decrypt a recorded session. An agent that used protocol 2 refuses protocol 1 sessions from then on ([PROTOCOL.md §3](PROTOCOL.md#3-connect-handshake)). |
| **Someone with an enrollment token** | They can enroll one server into your organization until the token expires or is used up. Tokens are short-lived; revoke unused ones. |
| **A malicious repository or image** | The repository is cloned, analysed and built without access to the Docker Engine, and what a build exports is checked by the agent before it reaches the Engine. Builds run in rootless BuildKit, with CPU, memory, process and cache limits, on an internal network with no way out but the build egress proxy, which never reaches private ranges, cloud metadata or the host, records every destination under an `audit` policy and lets only listed destinations through under an `allowlist` policy (public package registries stay reachable under the default `open` policy). Applications run as containers on their environment's network behind the egress guard, and their ports are reachable only through the router and from the edge. |
| **A compromised control plane** | It can do what the control plane is for: deploy and run containers on your servers, which is root-equivalent through Docker. It cannot replace the agent binary on its own: offers must be signed by the update key, a separate key that the agent requires once pinned, and an agent that pinned the release key also requires that key's signature, made offline when the binary is built and never held by the control plane. Binaries are checked against the signed SHA-256, and anti-downgrade refuses older versions without an administrator's signed downgrade. If you lose trust in the control plane, revoke the server and stop the agent. |
| **A malicious release** | Releases are built on GitHub from a tag by [release.yml](.github/workflows/release.yml), signed with keyless cosign, and attested (SLSA provenance). They are reproducible: [verify.sh](verify.sh) rebuilds a tag and compares the binaries byte for byte. |

### Known limitations

- The agent process itself holds the Docker Engine, which is root-equivalent. No container it runs for a deployment
  has the Engine's socket, but a flaw in the agent's own checks (of the image layouts builds export, of the Compose
  plan) would reach the Engine. Repository-derived input is still parsed by buildx in the build helper (build
  contexts and their `.dockerignore`, Railpack's plan) and by BuildKit and its frontends in the builders: an escape
  there reaches that helper or builder (no capability, no Engine, no host path) and the build network, not the host;
  through the build egress proxy it gets that builder's own `open` token, not an allowlist.
- Builders are long-lived (one per server for trusted code, one for untrusted code).
- Build egress (enforced since `build_egress`): build steps have no route out of the build network, Docker resolves
  no outside name for them, and the firewall rejects whatever that network would forward or send to the server, DNS
  included. They reach the Internet only through the build egress proxy, as HTTP (`CONNECT` tunnels and plain
  requests). What remains:
  - Tools that ignore `HTTP_PROXY`/`HTTPS_PROXY` (raw TCP or UDP, Git over SSH, some language runtimes' own HTTP
    clients) cannot reach anything and fail the build, whatever the policy; they need their own proxy setting.
  - DNS: the proxy resolves the names the steps ask for with the server's resolvers. Under `open` and `audit` a step
    can therefore make the server resolve names it chooses (a channel for data, as the connections themselves are);
    under `allowlist` only allowed names are resolved. Docker versions before 26 may forward a build container's
    queries to a loopback name server of the server (Docker's `dns` setting) from the host's namespace, out of the
    firewall's sight.
  - The allowlist decides on the name a client asks the proxy for (`CONNECT` or the URL), not on what it sends inside
    a tunnel: allowing a shared CDN or cloud domain also allows what is reachable through it (domain fronting).
  - BuildKit's own fetches (base images, `ADD`/`COPY` from URLs or Git, remote contexts) and buildx's registry
    tokens use each builder's own token: always `open` (private ranges still refused), not recorded per
    deployment. A Dockerfile can put build arguments in such a URL; the policy covers what build steps run.
  - A build step can read its own build's proxy token, which only grants its own policy, for that build.
- The broker runs as root and drives the Docker Engine. Its systemd unit narrows it (read-only system directories,
  hidden home directories, a private /tmp, protected kernel logs, cgroups and hostname), but anything that takes over
  the broker still controls the Docker Engine. This includes a control plane that is compromised (it signs frames)
  and a flaw in how the broker handles frames that verify. The broker parses input from the relay before it can
  verify it: the socket messages and the JSON of each frame, both size-limited.
- An attacker controlling the relay, or anyone terminating TLS, sees the size, kind and timing of every frame, which
  says what kind of activity runs (a deployment, a log stream) and roughly how much data it moves, though not what it
  contains (section «Agent privileges»).
- Servers installed before privilege separation keep one root process until an operator runs `owdeploy-agent
  migrate-split`. On those servers a flaw in the network code is root on the host.
- Protocol 1 sessions are neither bound to one connection nor encrypted beyond TLS: within the 300 s skew window, TLS
  is what keeps a frame recorded on one connection out of a later one ([PROTOCOL.md §4](PROTOCOL.md#4-frames)), and
  whoever terminates TLS, including a relay taken over, reads their messages. An agent accepts protocol 1 sessions
  until its first protocol 2 session (or an enrollment with a control plane that speaks protocol 2); until then, a
  relay taken over could strip the protocol 2 headers and make its session a protocol 1 one.

## Controls by version

| Control | 0.1.0 | 0.2.0 |
|---|---|---|
| Every frame signed (Ed25519), keys pinned at enrollment | yes | yes |
| Frames bound to their connection, no protocol downgrade once protocol 2 was used | no | yes (protocol 2) |
| Frame bodies encrypted end to end (X25519, ChaCha20-Poly1305) | no | yes (protocol 2) |
| Network code without privileges (relay and broker) | no | new installs; `migrate-split` for earlier ones |
| Updates signed by the update key and the offline release key, anti-downgrade | yes | yes |
| Repository content handled without the Docker Engine | clone and analysis only | everything: no deployment container gets the Engine |
| Images built on rootless BuildKit, checked by the agent before loading | rootless builds, loaded by a helper with the Engine | yes |
| Compose applied from a typed plan, unmodelled fields refused | partly (`docker compose up` after checks) | yes |
| Build egress only through the agent's proxy, with `open`, `audit` and `allowlist` policies | no (private ranges blocked, Internet open) | yes |
| SBOM of every deployed image | no | yes |

The control plane adds signed-image policies (cosign, SLSA provenance), digest pinning and a hash-chained audit log;
they do not depend on the agent's version.

## Supported versions

Only the latest release is supported. Agents connected to OpenWAF Deploy are offered new releases automatically.
Fixes are not backported.
