# OpenWAF Deploy agent protocol

This document describes the protocol between the OpenWAF Deploy control plane and `owdeploy-agent`. The reference
implementation is the `deploy-proto` crate in this repository (`crates/deploy-proto/src/lib.rs` for framing, keys,
updates and versions; `crates/deploy-proto/src/msg.rs` for messages). Where this document and the code disagree, the
code is right and this document has a bug.

## 1. Overview

- The agent dials out. It never listens on a port of its own. It opens one WebSocket over TLS to the control plane and
  keeps it open, reconnecting when it drops.
- Each side has an Ed25519 key and signs every frame it sends. The agent creates its key at enrollment, and the
  control plane stores only the public half. The control plane's public keys are pinned by the agent: the control key
  (frames) and the update key (binary updates).
- A signed frame carries its direction, a sequence number that strictly increases, a timestamp and the SHA-256 of its
  body. A frame therefore cannot be replayed, reordered or reflected back to its sender, and it cannot be moved to
  another kind.
- Commands are typed operations (section 7), never shell strings. A message kind or an operation that a side does not
  know never breaks the session, so either side can be upgraded first (section 9).

### Encodings

| Value | Encoding |
|---|---|
| Ed25519 public key | standard base64 with padding of the 32 bytes |
| Ed25519 signature | standard base64 with padding of the 64 bytes |
| SHA-256 digest | lowercase hex |
| Timestamps | Unix time in seconds (`i64`) |
| Messages | JSON (UTF-8) |

The control plane verifies the connect handshake with `verify_strict` (RFC 8032 with the stricter checks of
`ed25519-dalek`), and the agent uses it for update offers and key handovers. Frames are verified with `verify`.

## 2. Enrollment

An administrator creates a one-use enrollment token (`owde_…`) in the dashboard. The installer (`install.sh`) writes it
to a 0600 file and runs `owdeploy-agent enroll --url <control plane> --token-file <file> [--name <name>]`. The agent
then:

1. Generates its Ed25519 key from 32 bytes of OS randomness.
2. Sends `POST <url>/v1/agent/enroll` with this JSON body:

   ```json
   {"token": "owde_…", "public_key": "<agent public key>", "name": "web-1",
    "hostname": "…", "os": "…", "arch": "…", "kernel": "…", "agent_version": "0.1.0+…"}
   ```

3. Receives:

   ```json
   {"server_id": "…", "org_id": "…", "control_public_key": "<base64>",
    "connect_url": "wss://…/v1/agent/connect", "update_public_key": "<base64, optional>"}
   ```

4. Rejects the answer if `update_public_key` is present and is not a valid key.
5. Writes `identity.json` to its state directory (`$OWDEPLOY_AGENT_STATE`, default `/var/lib/owdeploy-agent`; the
   directory has mode 0700 and the file 0600). The file holds the server id, the agent's private key, the connect URL
   and the pinned keys.
6. Deletes the token file.

The token is the only credential in this exchange, so enrollment must use HTTPS. From this point the agent trusts only
the keys it pinned here and the changes those keys sign (section 8).

## 3. Connect handshake

The agent opens the WebSocket with `GET <connect_url>` (the control plane's `/v1/agent/connect`) and adds four headers.
They prove that it holds its key before the upgrade:

| Header | Value |
|---|---|
| `OWDeploy-Server` | the server id |
| `OWDeploy-Timestamp` | the agent's current Unix time |
| `OWDeploy-Nonce` | 16 random bytes, lowercase hex (32 characters) |
| `OWDeploy-Signature` | the agent key's signature of the signing message below |

The signed message is the frame signing message (section 4) with direction `agent-to-control`, sequence `0`, kind
`connect` and body `<server id>\n<nonce>`.

The control plane answers 401 and does not upgrade if any of these checks fails:

- every header is present and well formed, and the nonce is exactly 32 hex characters;
- the server exists and has not been revoked;
- the signature verifies with the agent's stored public key;
- the timestamp is within `MAX_SKEW_SECS` (300 s) of the control plane's clock;
- the nonce has not been used before by this server (nonces are stored and are single-use).

After the upgrade, the largest WebSocket message either side accepts is `MAX_FRAME_BYTES`, which is 1 MiB.

When a connection fails, the agent waits before dialling again: `min(2 << min(failures, 6), 120)` seconds plus 0–2 s
of random jitter. A session that ends without an error resets the failure count.

## 4. Frames

Every WebSocket text message is one frame:

```json
{"seq": 1, "ts": 1767225600, "kind": "hello", "body": "{\"agent_version\":…}", "sig": "<base64>"}
```

`body` is the message's JSON **as a string**, so the signature covers its exact bytes. The agent ignores WebSocket
binary messages and control frames.

### Signing message

```text
owdeploy-agent-v1\n<direction>\n<seq>\n<ts>\n<kind>\n<hex sha256(body)>
```

- `owdeploy-agent-v1` is `CONTEXT`.
- `<direction>` is `agent-to-control` or `control-to-agent`.
- `<seq>` and `<ts>` are decimal.
- There is no trailing newline.

### Sealing

Each side keeps one sealer per connection for the direction it sends. Its sequence starts at 1 and goes up by 1 with
each frame. To seal a message, the sealer serializes it, signs the signing message with its key and emits the frame.

A control key rotation (section 8) changes the key of the control plane's sealer. The sequence carries on.

### Opening

Each side keeps one opener per connection for the direction it receives. An opener accepts one or more peer keys (the
agent accepts two during a control key rotation) and records the last sequence it accepted, starting at 0. A frame is
refused, in this order, when:

1. it is larger than 1 MiB (`TooLarge`);
2. it is not a JSON frame (`Malformed`);
3. its signature does not decode or does not verify with any accepted key over the signing message rebuilt with the
   opener's direction (`BadSignature`);
4. `|now − ts|` is greater than 300 s (`Skew`);
5. `seq` is not greater than the last accepted sequence (`Replay`). Gaps are allowed.

A frame that passes these checks updates the last sequence. Its body is decoded only when its `kind` is the expected
one (`Body` error otherwise).

When the agent cannot open a control frame, the session ends with an error and the agent reconnects.

The signing message does not name the connection, and sequences start again at 1 on every connection. Within the
300 s skew window, a frame recorded on one connection would also pass the checks on a later connection of the same
agent, as long as that connection's last accepted sequence is lower. Only TLS keeps such a frame out of the stream:
an attacker would have to inject it into the TLS session of the new connection.

## 5. Session

1. The agent sends `hello` first.
2. The control plane sends whatever the agent needs in signed frames: `update_key`, `control_key_rotate`, commands,
   `agent_update`, `ping`.
3. The agent sends `heartbeat` every 30 s. It answers each `ping` with a `pong` that carries the same nonce.
4. For each `command`, the agent sends zero or more `command_event` frames and then exactly one `command_result` with
   the same `id`. Commands run concurrently. `cancel` asks a running command to stop, and the command still ends with
   its `command_result`.
5. When a session ends, the agent cancels every command still running, because their results can no longer be
   delivered. A deployment that has not yet switched the router rolls back to the previous container.

### Message kinds

| `kind` | Direction | Body |
|---|---|---|
| `hello` | agent → control | `agent_version`, `hostname`, `os`, `arch`, `kernel`, `docker` (`DockerInfo` or null), `features` (section 9), `binary_sha256` (SHA-256 of the running binary, or null), `keys` (`PinnedKeys`, or null) |
| `heartbeat` | agent → control | `uptime_secs`, `load1`, `mem_total_bytes`, `mem_available_bytes`, `disk_total_bytes`, `disk_avail_bytes`, `containers_running` |
| `ping` / `pong` | control → agent / agent → control | `nonce` (u64) |
| `command` | control → agent | `id`, `op` (section 7) |
| `command_event` | agent → control | `id`, `event`: `{"type": "log", "stream": "stdout"\|"stderr"\|"system", "lines": […], "step": <step>}` (at most 200 lines of at most 16 KiB each; longer lines are cut; `step` is the step the command was in, omitted before the first one) or `{"type": "step", "step": "fetching"\|"building"\|"pulling"\|"starting"\|"health_check"\|"switching"\|"cleaning", "commit": CommitInfo}` (`commit` only on the step that follows a Git fetch) |
| `command_result` | agent → control | `id`, `outcome`: `{"status": "ok", "output": <JSON>}`, `{"status": "error", "message": "…"}` or `{"status": "unsupported"}` |
| `cancel` | control → agent | `id` |
| `agent_update` | control → agent | an update offer (section 10) |
| `update_status` | agent → control | `version`, `sha256`, `state` (section 10), `message` |
| `update_key` | control → agent | `public_key`, `signature` (optional; section 8) |
| `control_key_rotate` | control → agent | `next_public_key` (section 8) |
| `pinned_keys` | agent → control | `control`, `control_next`, `update`, `message`: the keys the agent pinned, sent after any change or refused announcement |

`DockerInfo` has the fields `version`, `api_version`, `containers_running`, `containers_total` and `images`.

`CommitInfo` describes the commit just fetched: `sha`, and when the agent could read them `author_name`, `author_email` and `subject` (the first line of the message). Control characters are removed and the values are cut
at 200, 320 and 300 bytes. Peers that do not know `step` on log lines or `commit` on steps ignore them.

## 6. Labels and names

Every container and image the agent creates carries these labels:

- `dev.openwaf.deploy.resource`: the application id;
- `dev.openwaf.deploy.deployment`: the deployment id;
- `dev.openwaf.deploy.environment`: the environment id (application containers).

The agent's own objects carry these labels or the `owd-` name prefix: its Docker networks, the `owd-router` container,
its builders and helpers, and its iptables chains (`OWDEPLOY*`).

Images are tagged `owd/<resource>:<deployment>`. Named volumes are `owd-<resource lowercased>-<name>`. Compose projects
are `owd-<resource lowercased>`.

## 7. Operations

A `command` carries one operation, tagged by `op`. The fields of the operation sit next to `op` at the top level:

```json
{"id": "cmd_01", "op": {"op": "app_status", "resource": "app_01"}}
```

| `op` | Fields | Output (`ok`) | Feature |
|---|---|---|---|
| `docker_info` | — | `DockerInfo` | — |
| `container_list` | `managed_only` | array of containers | — |
| `deploy_app` | `AppDeploy` (below) | `DeployOutput`: `image`, `image_id`, `container_id`, `commit`, `known_hosts` | — |
| `app_action` | `resource`, `action`: `start`\|`stop`\|`restart`\|`remove` | `AppState` | — |
| `app_status` | `resource` | `AppState`: `containers[]` of `id`, `deployment`, `image`, `state`, `health`, `started_at` | — |
| `app_logs` | `resource`, `tail`, `follow`, `since` (Unix s or null), `service` | lines streamed as `log` events (while `follow`, until cancelled), then `{"lines": n}` | — |
| `image_prune` | `resource`, `keep` (image tags to keep: rollback targets) | `{"removed": [images]}` | — |
| `firewall_sync` | `allow` (CIDRs), `ports`, `deny` (CIDRs) | `{"applied": true, "backend", "ipv6", "ports", "router_ports", "denied", "egress_interfaces"}` | — |
| `router_sync` | `RouterConfig` (below) | `RouterState`: `listeners`, `active`, `pending`, `tls_listeners`, `certificates` | `router` |
| `deploy_compose` | `ComposeDeploy` (below) | `ComposeOutput`: `project`, `services[]` (`service`, `container_id`, `image`, `state`), `commit`, `known_hosts` | `compose` |
| `exec` | `resource`, `service`, `command` (argv), `timeout_secs` | `ExecOutput`: `container_id`, `exit_code`, `timed_out`, `output` (last 64 KiB), `truncated` | `exec` |
| `volume_remove` | `resource`, `names` (null: all) | `{"removed": [names]}` | `volumes` |

Notes on specific operations:

- **`deploy_app`** fetches the source (Git) or pulls the image, builds it, and starts the new container next to the
  current one. It then waits until the container is healthy, points the router at it, drains the old container and
  removes it. Progress is streamed as `step` and `log` events. The deployment can be cancelled until the router
  switches, and a cancelled deployment restores the previous container.
- **`app_action`** with `remove` deletes the application's containers, images and router routes. Volumes stay
  (`volume_remove`).
- **`volume_remove`** is refused while any container of the application exists. It also removes the application's
  file mounts.
- **`firewall_sync`** replaces the agent's rules. Published ports become reachable only from `allow`, which is the
  OpenWAF edge. Containers are refused `deny`, on top of the ranges the agent always refuses (`firewall.rs`: "this
  network", RFC 1918, CGNAT, loopback, link-local including cloud metadata, IETF assignments, benchmarking, multicast,
  reserved, and their NAT64 forms).
- **`router_sync`** replaces the whole configuration of the per-server router (Caddy). A resource that is not listed
  loses its routes and listeners. This operation is never abandoned halfway.

### `AppDeploy`

| Field | Meaning |
|---|---|
| `resource`, `deployment` | application and deployment ids (labels) |
| `network`, `alias` | the environment's Docker network (created if missing) and the container's alias on it |
| `source` | `{"kind": "git", "url", "reference", "auth", "ssh", "commit"}`, `{"kind": "image", "image", "auth"}` or `{"kind": "local", "image"}` |
| `build` | `BuildSpec` (Git sources): `context`, `dockerfile`, `args`, `target`, `no_cache`, `pack` (`dockerfile`\|`railpack`\|`static`), `install_command`, `build_command`, `start_command`, `publish_dir`, `spa`, `untrusted` |
| `run` | `RunSpec`: `image_tag`, `env`, `port`, `publish`, `health` (`path`, `interval_secs`, `timeout_secs`, `retries`), `command`, `memory_bytes`, `cpus`, `labels`, `volumes` (`name`, `path`, `service`), `files` (`path`, `content`, `service`) |
| `routes` | router routes applied when the new container takes over (null: one route on `run.publish`) |
| `drain_secs` | seconds the previous container keeps serving requests in flight (default 10) |

Notes on `AppDeploy` fields:

- **Credentials.** `auth` for Git is a `username` and `token` pair (HTTPS). For registries it is `server`, `username`
  and `password`. `ssh` is a deploy key: `private_key` (OpenSSH format, unencrypted) and `known_hosts` lines.
  Credentials are never logged and never passed in argv. A deploy key exists only on a tmpfs of the helper container.
- **Host keys.** When `known_hosts` is empty, the agent uses the host keys it pins for github.com, gitlab.com and
  bitbucket.org. For any other host it trusts the key on first use and returns it in `known_hosts` so that the control
  plane can pin it.
- **`commit`.** When set, the checkout must be at exactly this commit or the deployment fails.
- **`untrusted`.** Code from a fork is built on its own BuildKit builder, without a shared cache and without
  submodules.

### `ComposeDeploy`

| Field | Meaning |
|---|---|
| `resource`, `deployment`, `network` | as in `AppDeploy` |
| `source` | `{"kind": "git", "url", "reference", "auth", "ssh", "file"}` or `{"kind": "inline", "content"}` (inline Compose files reference images only) |
| `env` | environment for every service and for `${VAR}` interpolation |
| `volumes`, `files` | each mounted in its `service` |
| `labels`, `routes`, `no_cache` | as in `AppDeploy`; each route names its `service` |

### `RouterConfig`

| Field | Meaning |
|---|---|
| `preview_port` | host port of the preview listener (routes with `listen: null`), or null |
| `resources` | `[{"resource", "routes": [Route]}]` for every application and preview on the server |
| `preview_tls_port` | host port of the preview TLS listener (`edge_tls`) |
| `tls` | `{"client_ca_pem", "certificates": [{"name", "id", "listen", "hosts", "cert_pem", "key_pem"}]}` (`edge_tls`) |

A `Route` has these fields:

- `listen`: a host port, or null for the preview listener;
- `hosts`: exact host names. An empty list catches every request on that listener (not allowed on the preview
  listener);
- `service`: the Compose service;
- `port`: the port inside the container;
- `tls`: when true, the listener serves HTTPS with an OpenWAF Origin CA certificate and requires the OpenWAF edge's
  client certificate.

## 8. Keys

### Control key

The control key signs every control frame.

**Rotation.** A `control_key_rotate` frame announces the next control key. The frame must be signed by the current
control key, like every frame the agent accepts. The agent pins the new key as `control_next` and then accepts frames
signed by either key. The first frame signed by `control_next` makes it the control key and drops the previous one.
The agent reports every change with `pinned_keys`.

### Update key

The update key signs update offers.

- **Pinning.** The agent pins the update key at enrollment, or from the first `update_key` announcement if it has
  none. In that case the announcement frame's control-key signature is enough.
- **After pinning.** Offers signed by the control key are refused.
- **Replacement.** A different update key is accepted only with a handover signature from the pinned update key over:

  ```text
  owdeploy-update-key-v1\n<new public key base64>
  ```

### Release key

The release key is an offline key that signs each agent binary when it is built, on the operator's machine and never on the control plane. The control plane only relays the signature in its offers (`release_signature`) and serves it at `/v1/agent/binary/{target}.sig`.

- **Pinning.** New agents pin it at enrollment when the control plane has one. An agent that has none behaves as before; a root user can pin it by hand (`pin-keys --release-key`).
- **After pinning.** Every offer must carry the release key's signature of the exact binary and version, so even someone holding the control and update keys cannot make the agent install a binary the release key did not sign.
- The signed message:

  ```text
  owdeploy-agent-release-v1\n<target>\n<version>\n<sha256>\n
  ```

`hello.keys` and `pinned_keys` report it as `release`.

### Persistence and recovery

Every key change is written to `identity.json` before it takes effect.

If a key is lost or leaked, a root user on the server can replace the pinned keys by hand with
`owdeploy-agent pin-keys [--control-key KEY] [--update-key KEY] [--release-key KEY]`, with the agent stopped
(README.md).

## 9. Compatibility and features

- Each side ignores a message `kind` it does not know.
- **Unknown operations.** If the agent cannot decode a `command` because its `op` is unknown, it answers
  `{"status": "unsupported"}`. Any other decoding error gets `{"status": "error", "message": "invalid command: …"}`.
  A command without an `id` ends the session.
- **Optional fields.** New fields are optional and have defaults (`#[serde(default)]`). Fields that are off are
  omitted when serialized, so an older peer reads newer messages unchanged.
- **Features.** The agent lists the operations and fields it understands beyond the base set in `hello.features`. The
  control plane sends an operation or field only to agents that list its feature:

| Feature | Enables |
|---|---|
| `router` | `router_sync`, `AppDeploy.routes`, rolling updates through the per-server router |
| `build_packs` | `BuildSpec.pack` `railpack` and `static` |
| `compose` | `deploy_compose` |
| `ssh_git` | `Source.git.ssh` (deploy keys) |
| `volumes` | `RunSpec.volumes`, `RunSpec.files`, `volume_remove` |
| `exec` | `exec` |
| `self_update` | `agent_update`, `update_status` |
| `update_key` | `update_key`, v2 offers, anti-downgrade, `hello.keys`, `pinned_keys` |
| `control_key_rotation` | `control_key_rotate` |
| `edge_tls` | `Route.tls`, `RouterConfig.tls`, `RouterConfig.preview_tls_port` |
| `isolated_builds` | rootless BuildKit builders, `BuildSpec.untrusted`, `Source.git.commit` |

## 10. Self-update

The control plane serves agent binaries at `GET /v1/agent/binary/{target}`, where the target is `linux-amd64` or
`linux-arm64`. The SHA-256 of each binary is at `/v1/agent/binary/{target}.sha256`.

An `agent_update` offer names one binary. Besides the frame's own signature, the offer carries a signature over the
binary itself, under a context of its own:

```json
{"target": "linux-amd64", "version": "0.1.0+33.0123456789ab", "sha256": "<hex>", "signature": "<base64>",
 "force": false, "allow_downgrade": false, "expires_at": 1767229200, "release_signature": "<base64>"}
```

### Signed message

The offer comes in two versions:

- **v1** (no `expires_at`) is signed by the control key:

  ```text
  owdeploy-agent-update-v1\n<target>\n<version>\n<sha256>
  ```

- **v2** (with `expires_at`) is signed by the pinned update key, or by the control key while the agent has pinned no
  update key. It also covers `allow_downgrade` (`0` or `1`) and the expiry:

  ```text
  owdeploy-agent-update-v2\n<target>\n<version>\n<sha256>\n<allow_downgrade>\n<expires_at>
  ```

The control plane issues v2 offers valid for `OFFER_TTL_SECS` (3600 s), and v1 offers only to agents that do not
list `update_key`. Field rules: `target` is one of the two targets, `version` is 1–64 characters from `[A-Za-z0-9.+_-]`,
and `sha256` is 64 lowercase hex characters.

### Agent checks, in order

1. **Signature.** If an update key is pinned, the offer must be v2 and verify with that key. A v1 offer is refused.
   Otherwise the offer must verify with the control key.
2. **Release signature.** If a release key is pinned, `release_signature` must verify with it over the exact
   target, version and SHA-256 (section 8).
3. **Expiry.** A v2 offer is refused when `now > expires_at + 300`.
4. **Target.** The target must be the agent's own architecture.
5. **Current binary.** An offer for the binary the agent already runs is answered `current`.
6. **Version.** The offered version must be strictly newer than the running one (section 11). The only exception is a
   v2 offer with both `allow_downgrade` and `force`, which records an administrator's audited downgrade.
7. **Earlier failure.** A binary that failed after an earlier installation is refused unless the offer has `force`.

### Rollout

The control plane offers a new version to its `canary` servers first and to the others only after a waiting period without a canary failure; an operator can pause every offer at once. The agent sees none of this: it only judges the offers it gets.

### Installation

1. **Download.** The agent downloads the binary from the control plane's base URL, which it derives from its connect
   URL, into `<binary>.new` (at most 256 MiB). It checks that the SHA-256 is the signed one, then runs
   `<binary>.new version` (10 s limit). The output must start with `owdeploy-agent `.
2. **Wait for idle.** The agent installs only when no command other than a log stream is running.
3. **Swap.** It records both binaries in a marker (`update.json`), keeps a copy of the running binary as
   `<binary>.prev`, renames the new binary over the running one and exits with code 75 so that systemd
   (`Restart=always`) starts the new binary.
4. **Probation.** The new binary must verify its first control frame within 120 s. If it does not, it moves `.prev`
   back into place and exits. The previous binary, started again, records the new one as failed and reports the
   rollback.

### `update_status` states

| State | Meaning |
|---|---|
| `current` | the agent already runs this binary |
| `downloading` | the agent is downloading and checking it |
| `deferred` | checked; it will be installed when no command is running |
| `restarting` | installed; the agent is restarting on it |
| `confirmed` | the new binary connected |
| `rolled_back` | the new binary did not connect in time; the previous one is back |
| `failed` | not installed; `message` says why |

## 11. Versions

The agent reports `<crate version>[+<build>]`, where `<build>` is `OWDEPLOY_BUILD` at compile time. Release builds set
it to `<ordinal>.<commit>` (`scripts/build-release.sh`). `owdeploy-agent version` prints
`owdeploy-agent <version> (protocol owdeploy-agent-v1)`.

Versions are compared for anti-downgrade (`deploy_proto::version`) in this order:

1. `major.minor.patch`, numerically.
2. Pre-release by SemVer precedence. A version with a pre-release (`-…`) comes before the same version without one.
   Identifiers are compared one by one: numeric identifiers are compared numerically and come before alphanumeric
   ones.
3. The build ordinal: the leading number of the build metadata `+<ordinal>.<tag>`. Build metadata that is not a
   number, a `.` and something more comes before any ordinal.

Two versions that are equal on all three are equal, so neither is newer. A version that does not parse cannot be
ordered, and the agent refuses its offer.

The release ordinal comes from `BUILD_ORDINAL` and grows with every release. Each release therefore orders after the
one before it, even when the crate version stays the same.
