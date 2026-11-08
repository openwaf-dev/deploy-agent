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
  another kind. In protocol 2 both sides contribute a nonce and an ephemeral X25519 key to the connect handshake,
  which both sign. Every frame's signature also covers the resulting session id, so a frame of one connection never
  verifies on another, and every frame's body is encrypted with keys of that connection only, so whoever carries the
  frames without being one of the two ends (a TLS terminator, the agent's relay) sees only each frame's kind,
  sequence, timestamp and size (sections 3 and 4).
- Commands are typed operations (section 7), never shell strings. A message kind or an operation that a side does not
  know never breaks the session, so either side can be upgraded first (section 9).
- On the server, the agent may run as two processes ([SECURITY.md](SECURITY.md#agent-privileges)): an unprivileged
  relay holds the WebSocket and passes frames unchanged, and a root broker builds and signs the connect request, checks
  the answer, holds the session's keys, and opens and seals every frame. The wire protocol is the same either way.

### Encodings

| Value | Encoding |
|---|---|
| Ed25519 public key | standard base64 with padding of the 32 bytes |
| Ed25519 signature | standard base64 with padding of the 64 bytes |
| X25519 public key (exchange key) | standard base64 with padding of the 32 bytes |
| Ciphertext (protocol 2 frame body) | standard base64 with padding |
| SHA-256 digest | lowercase hex |
| Timestamps | Unix time in seconds (`i64`) |
| Messages | JSON (UTF-8) |

The control plane verifies the connect handshake with `verify_strict` (RFC 8032 with the stricter checks of
`ed25519-dalek`). Both sides use it for the protocol 2 handshake transcript, and the agent uses it for update offers
and key handovers. Frames are verified with `verify`.

## 2. Enrollment

An administrator creates a one-use enrollment token (`owde_…`) in the dashboard. The installer (`install.sh`) writes it
to a 0600 file and runs `owdeploy-agent enroll --url <control plane> --token-file <file> [--name <name>]`. The agent
then:

1. Generates its Ed25519 key from 32 bytes of OS randomness.
2. Sends `POST <url>/v1/agent/enroll` with this JSON body:

   ```json
   {"token": "owde_…", "public_key": "<agent public key>", "name": "web-1",
    "hostname": "…", "os": "…", "arch": "…", "kernel": "…", "agent_version": "0.3.0+…", "protocol": 2}
   ```

   `protocol` is the highest protocol version the agent speaks (absent: 1). The control plane holds a server enrolled
   with 2 or more to protocol 2 from its first connection (section 3).

3. Receives:

   ```json
   {"server_id": "…", "org_id": "…", "control_public_key": "<base64>",
    "connect_url": "wss://…/v1/agent/connect", "update_public_key": "<base64, optional>",
    "release_public_key": "<base64, optional>", "protocol": 2}
   ```

   `protocol` is the highest protocol version the control plane speaks (absent from control planes before protocol 2).

4. Rejects the answer if `update_public_key` or `release_public_key` is present and is not a valid key.
5. Writes `identity.json` to its state directory (`$OWDEPLOY_AGENT_STATE`, default `/var/lib/owdeploy-agent`; the
   directory has mode 0700 and the file 0600). The file holds the server id, the agent's private key, the connect URL,
   the pinned keys and, when both sides speak protocol 2, `"protocol": 2` (section 3, «Negotiation»).
6. Deletes the token file.

The token is the only credential in this exchange, so enrollment must use HTTPS. From this point the agent trusts only
the keys it pinned here and the changes those keys sign (section 8).

## 3. Connect handshake

The agent opens the WebSocket with `GET <connect_url>` (the control plane's `/v1/agent/connect`) and adds four headers
(the `HDR_*` constants of the `connect` module in `crates/deploy-proto/src/lib.rs`).
They prove that it holds its key before the upgrade:

| Header | Value |
|---|---|
| `OWDeploy-Server` | the server id |
| `OWDeploy-Timestamp` | the agent's current Unix time |
| `OWDeploy-Nonce` | 16 random bytes, lowercase hex (32 characters) |
| `OWDeploy-Signature` | the agent key's signature of the signing message below |

The signed message is the v1 frame signing message (section 4) with direction `agent-to-control`, sequence `0`, kind
`connect` and body `<server id>\n<nonce>`. It is the same in both protocol versions, so an agent that speaks protocol 2
still connects to a control plane that only speaks protocol 1.

An agent that speaks protocol 2 adds three headers, which ask for a v2 session:

| Header | Value |
|---|---|
| `OWDeploy-Protocol` | the highest protocol version the agent speaks (`2`); absent: 1 |
| `OWDeploy-Control-Keys` | the control keys the agent accepts, comma-separated: its pinned control key, then its next one during a rotation (section 8) |
| `OWDeploy-Exchange-Key` | the agent's exchange key: the public half of an X25519 key made from OS randomness for this connection only |

The request's signature does not cover these headers. Both sides sign them, with everything else the session depends
on, in the handshake transcript below.

The control plane answers 401 and does not upgrade if any of these checks fails:

- every header is present and well formed, and the nonce is exactly 32 hex characters (with `OWDeploy-Protocol` 2 or
  more, `OWDeploy-Control-Keys` holds one or two valid keys and `OWDeploy-Exchange-Key` is 32 bytes);
- the server exists and has not been revoked;
- the signature verifies with the agent's stored public key;
- the timestamp is within `MAX_SKEW_SECS` (300 s) of the control plane's clock;
- the nonce has not been used before by this server (nonces are stored and are single-use);
- in protocol 2, the agent's exchange key gives a shared secret (a key of low order gives the all-zero secret, known
  to anyone, and is refused).

It then answers 426 and does not upgrade when the session would use protocol 1 (no `OWDeploy-Protocol`, or `1`) and
the server is held to protocol 2 (see «Negotiation» below).

After the upgrade, the largest WebSocket message either side accepts is `MAX_FRAME_BYTES`, which is 1 MiB, measured
on the wire (in protocol 2, after encryption and base64, which make a body about a third larger).

When a connection fails, the agent waits before dialling again: `min(2 << min(failures, 6), 120)` seconds plus 0–2 s
of random jitter. A session that ends without an error resets the failure count.

### Protocol 2: the control plane's answer

The session uses the highest version both sides speak. For a v2 session, the control plane's answer to the upgrade
(`101 Switching Protocols`) carries five headers:

| Header | Value |
|---|---|
| `OWDeploy-Protocol` | `2` |
| `OWDeploy-Control-Nonce` | 16 fresh random bytes, lowercase hex (32 characters) |
| `OWDeploy-Control-Key` | the control key that signs the answer and the session's first frames: the first of the agent's `OWDeploy-Control-Keys` it holds (its control key, else the previous one during a rotation) |
| `OWDeploy-Control-Signature` | that key's signature of the transcript below, as `control-to-agent` |
| `OWDeploy-Control-Exchange-Key` | the control plane's exchange key: the public half of an X25519 key made for this connection only |

The transcript `signer` signs (`session::Transcript`), one field per line, without a trailing newline:

```text
owdeploy-agent-v2-handshake\n<signer>\n<protocol>\n<server id>\n<agent nonce>\n<control nonce>\n<control key>\n<agent exchange key>\n<control exchange key>
```

- `<signer>` is `control-to-agent` for the control plane's signature and `agent-to-control` for the agent's, so one
  side's signature never stands for the other's.
- `<protocol>` is `2`; `<agent nonce>` is `OWDeploy-Nonce` exactly as the agent sent it; `<control nonce>` is
  `OWDeploy-Control-Nonce`; `<control key>` is `OWDeploy-Control-Key` (base64); `<agent exchange key>` and `<control
  exchange key>` are `OWDeploy-Exchange-Key` and `OWDeploy-Control-Exchange-Key` (base64).

The agent refuses the answer, closes the connection and dials again later, when:

- `OWDeploy-Protocol` is not a version it offered;
- `OWDeploy-Control-Nonce` is not 32 hex characters;
- `OWDeploy-Control-Key` is not one of the control keys it pinned (`control`, `control_next`);
- `OWDeploy-Control-Exchange-Key` is missing or is not 32 bytes;
- the signature does not verify (`verify_strict`) with that key over the transcript rebuilt with its own server id,
  nonce and exchange key;
- the control plane's exchange key gives no shared secret (a key of low order).

Otherwise its first frame is `session_proof` (section 5): its own key's signature of the same transcript as
`agent-to-control`. The control plane closes a v2 session whose first frame is anything else or whose signature does
not verify, and reads nothing before it.

Each side signs both exchange keys, so nobody between them can put an exchange key of its own in their place: a key
swapped in the request makes the control plane sign a transcript the agent does not rebuild, and a key swapped in
the answer makes the agent rebuild a transcript the control plane did not sign. Neither side's signature, nor the
agent's proof, verifies for the other side's view of the handshake.

The session id, which every frame of the session signs (section 4), is

```text
SHA-256("owdeploy-agent-v2-session\n<server id>\n<agent nonce>\n<control nonce>")
```

in lowercase hex. None of the fields can contain a newline (the server id travels as an HTTP header value, nonces are
hex). Both nonces are fresh on every connection, so every connection has its own session id.

### Protocol 2: session keys

Each side computes the X25519 shared secret of its exchange key and the other side's, then derives one 32-byte key per
direction with HKDF-SHA256 (RFC 5869):

- salt: the 32 bytes of the session id;
- input key material: the 32-byte shared secret;
- info: `owdeploy-agent-v2-keys\n<direction>\n` followed by the 32 bytes of the transcript hash, where
  `<direction>` is `agent-to-control` or `control-to-agent` and the transcript hash is

  ```text
  SHA-256("owdeploy-agent-v2-transcript\n<protocol>\n<server id>\n<agent nonce>\n<control nonce>\n<control key>\n<agent exchange key>\n<control exchange key>")
  ```

  (the fields of the signed transcript, without the signer).

The agent's frames are encrypted with the `agent-to-control` key, the control plane's with the `control-to-agent` key.

**Forward secrecy.** Both exchange keys are made for one connection and kept in memory only. Each side drops its
exchange secret as soon as the session keys are derived (or when the connection fails before), and the session keys
when the session ends; the implementation wipes them (`zeroize`). Neither side's long-term keys (the agent's key, the
control, update and release keys) take part in the encryption: someone who records a session and later steals any of
them still cannot decrypt it. They can only sign, which is what lets each side check the other's exchange key.

### Negotiation

Neither side lets a session fall back to protocol 1 once protocol 2 was used, so removing the v2 headers in transit
does not downgrade a session:

- **Agent.** It records `"protocol": 2` in `identity.json` (written before the session goes on) when a control plane
  answers with a valid v2 handshake, or at enrollment when the control plane says it speaks protocol 2. From then on it
  refuses an answer without the v2 headers. Until then, an answer without them is a v1 session (a control plane that
  only speaks protocol 1). The record can only be removed by hand (root, agent stopped), for instance to return to a
  control plane that only speaks protocol 1.
- **Control plane.** It records protocol 2 for the server once the agent's `session_proof` verified, or at enrollment
  when the agent announced protocol 2, and from then on answers that server's v1 handshakes 426. Its operator can also
  refuse protocol 1 for every server, or set one server back to protocol 1 (for an agent rolled back to a build that
  only speaks it).

Agents that do not speak protocol 2 keep connecting with protocol 1 to servers that never used protocol 2, unless the
operator requires protocol 2.

## 4. Frames

Every WebSocket text message is one frame:

```json
{"seq": 1, "ts": 1767225600, "kind": "hello", "body": "{\"agent_version\":…}", "sig": "<base64>"}
```

In protocol 1, `body` is the message's JSON **as a string**, so the signature covers its exact bytes. In protocol 2,
`body` is that JSON encrypted for the session, in base64 (see «Encryption» below):

```json
{"seq": 2, "ts": 1767225600, "kind": "hello", "body": "zn9T4LYX…", "sig": "<base64>"}
```

The agent ignores WebSocket binary messages and control frames.

### Signing message

Protocol 1:

```text
owdeploy-agent-v1\n<direction>\n<seq>\n<ts>\n<kind>\n<hex sha256(body)>
```

Protocol 2:

```text
owdeploy-agent-v2\n<session id>\n<direction>\n<seq>\n<ts>\n<kind>\n<hex sha256(body)>
```

- `owdeploy-agent-v1` is `CONTEXT`, `owdeploy-agent-v2` is `CONTEXT_V2`.
- `<session id>` is the session's id in lowercase hex (section 3).
- `<direction>` is `agent-to-control` or `control-to-agent`.
- `<seq>` and `<ts>` are decimal.
- `body` is the frame's `body` as on the wire: in protocol 2, the base64 ciphertext.
- There is no trailing newline.

### Encryption (protocol 2)

The body of a protocol 2 frame is encrypted with ChaCha20-Poly1305 (RFC 8439) under the session key of the sender's
direction (section 3, «Protocol 2: session keys»):

- **Nonce** (12 bytes): the direction as a 4-byte big-endian number (`1` agent-to-control, `2` control-to-agent),
  then `seq` as an 8-byte big-endian number. A sealer's sequence starts at 1 and only goes up, and each direction has
  its own key, so no nonce is ever used twice with a key.
- **Associated data**: the first six lines of the frame's signing message, without the body digest:
  `owdeploy-agent-v2\n<session id>\n<direction>\n<seq>\n<ts>\n<kind>`. A ciphertext therefore opens only in its
  session and direction, under its own sequence, timestamp and kind.
- **Body**: base64 of the ciphertext followed by its 16-byte tag.

Every frame stays signed as well, over the ciphertext (encrypt, then sign):

- The signature does not depend on the session keys. Someone who obtained one session's keys (from the memory of
  either end, say) can read that session, but still cannot forge a frame in it without the sender's long-term key.
  Someone who holds a long-term key but not the session's keys cannot inject a frame either: it does not decrypt.
- It tells which key signed each frame, which the control key rotation relies on (section 8).
- Each frame remains attributable to its sender's long-term key (non-repudiation): a stored frame and its signature
  prove who sent that ciphertext in that session.
- It covers the ciphertext, not the message, so it gives an observer no way to confirm a guess of the message.

What stays visible to whoever carries the frames (a TLS terminator, the agent's relay): each frame's `kind`, `seq`,
`ts`, size (the ciphertext is the message's length plus 16 bytes) and signature, their timing, and the handshake
headers (server id, nonces, public keys, signatures). Messages, and so operations, variables, credentials, deploy
keys, file mounts and output, are not.

### Sealing

Each side keeps one sealer per connection for the direction it sends, bound to the session in protocol 2. Its sequence
starts at 1 and goes up by 1 with each frame. To seal a message, the sealer serializes it, in protocol 2 encrypts it,
signs the signing message of the session's protocol with its key and emits the frame.

A control key rotation (section 8) changes the key of the control plane's sealer. The sequence carries on.

### Opening

Each side keeps one opener per connection for the direction it receives, bound to the session in protocol 2. An opener
accepts one or more peer keys (the agent accepts two during a control key rotation) and records the last sequence it
accepted, starting at 0. A frame is refused, in this order, when:

1. it is larger than 1 MiB (`TooLarge`);
2. it is not a JSON frame (`Malformed`);
3. its signature does not decode or does not verify with any accepted key over the signing message rebuilt with the
   opener's direction (and, in protocol 2, its session id) (`BadSignature`);
4. `|now − ts|` is greater than 300 s (`Skew`);
5. `seq` is not greater than the last accepted sequence (`Replay`). Gaps are allowed;
6. in protocol 2, its body does not decrypt with the session key of the sender's direction, under its own header
   (`Undecryptable`).

A frame that passes these checks updates the last sequence. Its body (in protocol 2, the decrypted message) is decoded
only when its `kind` is the expected one (`Body` error otherwise).

When the agent cannot open a control frame, the session ends with an error and the agent reconnects. When the control
plane cannot open an agent frame, it closes the session.

Sequences start again at 1 on every connection. In protocol 2 that does not let a frame move between connections:
a frame recorded on one connection, however recent and whatever its sequence, does not verify on any other, because
its signature covers its own session id. In protocol 1 the signing message does not name the connection: within the
300 s skew window, a frame recorded on one connection would also pass the checks on a later connection of the same
agent, as long as that connection's last accepted sequence is lower, and only TLS keeps such a frame out of the
stream.

## 5. Session

The message structs are in `crates/deploy-proto/src/msg.rs`; the agent's session loop is in
`crates/deploy-agent/src/session.rs`.

1. In protocol 2 the agent sends `session_proof` first (section 3). Then, in both versions, it sends `hello`.
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
| `session_proof` | agent → control | `signature`: the agent key's signature (base64) of the handshake transcript as `agent-to-control` (section 3). Protocol 2 only, always the first frame |
| `hello` | agent → control | `agent_version`, `hostname`, `os`, `arch`, `kernel`, `docker` (`DockerInfo` or null), `features` (section 9), `binary_sha256` (SHA-256 of the running binary, or null), `keys` (`PinnedKeys`, or null), `privileges` (`"split"`: an unprivileged relay carries the connection and a root broker signs, checks and executes; `"legacy"`: one root process; omitted by agents from before privilege separation, which run as one root process; a control plane reads an unknown value as unknown) |
| `heartbeat` | agent → control | `uptime_secs`, `load1`, `mem_total_bytes`, `mem_available_bytes`, `disk_total_bytes`, `disk_avail_bytes`, `containers_running` |
| `ping` / `pong` | control → agent / agent → control | `nonce` (u64) |
| `command` | control → agent | `id`, `op` (section 7) |
| `command_event` | agent → control | `id`, `event`: `{"type": "log", "stream": "stdout"\|"stderr"\|"system", "lines": […], "step": <step>}` (at most 200 lines of at most 16 KiB each; longer lines are cut; `step` is the step the command was in, omitted before the first one), `{"type": "step", "step": "fetching"\|"building"\|"pulling"\|"starting"\|"health_check"\|"switching"\|"cleaning", "commit": CommitInfo}` (`commit` only on the step that follows a Git fetch), `{"type": "sbom", "image_digest", "service", "part", "last", "data"}` (`sbom`, see below) or `{"type": "egress", "mode", "enforced", "entries", "truncated"}` (`build_egress`, see below) |
| `command_result` | agent → control | `id`, `outcome`: `{"status": "ok", "output": <JSON>}`, `{"status": "error", "message": "…"}` or `{"status": "unsupported"}` |
| `cancel` | control → agent | `id` |
| `agent_update` | control → agent | an update offer (section 10) |
| `update_status` | agent → control | `version`, `sha256`, `state` (section 10), `message` |
| `update_key` | control → agent | `public_key`, `signature` (optional; section 8) |
| `control_key_rotate` | control → agent | `next_public_key` (section 8) |
| `pinned_keys` | agent → control | `control`, `control_next`, `update`, `release` (omitted when none is pinned), `message`: the keys the agent pinned, sent after any change or refused announcement |

`DockerInfo` has the fields `version`, `api_version`, `containers_running`, `containers_total` and `images`.

`CommitInfo` describes the commit just fetched: `sha`, and when the agent could read them `author_name`, `author_email` and `subject` (the first line of the message). Control characters are removed and the values are cut
at 200, 320 and 300 characters (Unicode scalar values). Peers that do not know `step` on log lines or `commit` on steps ignore them.

An `sbom` event carries part of the software bill of materials of an image a deployment runs (`deploy_app`,
`deploy_compose`): an SPDX 2.3 JSON document, gzip-compressed, then base64-encoded (standard alphabet, padded), cut
into parts of at most 524288 characters. `part` counts from 0 and the last part has `last: true`; the receiver joins
the parts' `data` in order before decoding. An image has at most 32 parts: the agent sends nothing for a larger
document and says so in the log. `image_digest` is the image ID the Engine reports (`sha256:…`); `service` names the
Compose service and is omitted otherwise. The parts follow the image's existence and precede the `command_result`.
Built images get the SBOM of BuildKit's attestation; pulled images the registry's SPDX attestation for the server's
platform, or one syft generates. An SBOM that cannot be made never fails the deployment.

An `egress` event reports where a build's steps went through the build egress proxy (section 7, «Build egress»),
once per build, at its end, failed or not, before the `command_result`: `mode` (`open`, `audit`, `allowlist`: the
policy applied), `enforced` (true when the build network gave the steps no other way out), and `entries`, each
`{"host", "port", "decision": "allowed"|"denied", "reason", "count", "bytes_out", "bytes_in"}`: the name asked for
(or the IP address), the connections with that decision, and the bytes of the allowed ones. `reason` is set on
denied entries: `not_allowed`, `ip_literal`, `private_address`, `unresolved` or `invalid`. In `audit` and
`allowlist` mode every destination is listed; in `open` mode only the denied ones. At most 500 entries, most
connections first; `truncated` (omitted when false) says there were more. A control plane that does not know the
event ignores it.

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

A `command` carries one operation, tagged by `op` (the `Op` enum in `crates/deploy-proto/src/msg.rs`; the agent runs
them in `crates/deploy-agent/src/main.rs` and `crates/deploy-agent/src/app.rs`). The fields of the operation sit next to `op` at the top level:

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
| `build` | `BuildSpec` (Git sources): `context`, `dockerfile`, `args`, `target`, `no_cache`, `pack` (`dockerfile`\|`railpack`\|`static`), `install_command`, `build_command`, `start_command`, `publish_dir`, `spa`, `untrusted`, `egress` (`build_egress`), `registry_auth` (`registry_auth`) |
| `run` | `RunSpec`: `image_tag`, `env`, `port`, `publish`, `health` (`path`, `interval_secs`, `timeout_secs`, `retries`), `command`, `memory_bytes`, `cpus`, `labels`, `volumes` (`name`, `path`, `service`), `files` (`path`, `content`, `service`) |
| `routes` | router routes applied when the new container takes over (null: one route on `run.publish`) |
| `drain_secs` | seconds the previous container keeps serving requests in flight (default 10) |

Notes on `AppDeploy` fields:

- **Credentials.** `auth` for Git is a `username` and `token` pair (HTTPS). For registries it is a `RegistryAuth`:
  `server`, `username` and `password`, where `server` is the key of the registry in a Docker config's `auths`: the
  registry host (with its port, `:443` dropped, lowercase) or `https://index.docker.io/v1/` for Docker Hub (every
  alias: `docker.io`, `index.docker.io`, `registry-1.docker.io`, `registry.hub.docker.com`, `hub.docker.com`, and
  images without a host). `ssh` is a deploy key: `private_key` (OpenSSH format, unencrypted) and `known_hosts` lines.
  Credentials are never logged and never passed in argv. A deploy key exists only on a tmpfs of the helper container.
- **`registry_auth`.** A list of `RegistryAuth`, at most one per registry, matched by host to each base image the
  build pulls (`registry_auth`; omitted when empty). The agent refuses a build with `untrusted` that carries any.
- **Host keys.** When `known_hosts` is empty, the agent uses the host keys it pins for github.com, gitlab.com and
  bitbucket.org. For any other host it trusts the key on first use and returns it in `known_hosts` so that the control
  plane can pin it.
- **Image references.** An `image` source is a Docker reference: `name[:tag]` or `name@sha256:<digest>`. The control
  plane may resolve a tag to its manifest digest (after checking the image's signature, for instance) and send the
  digest form; the agent pulls that reference as it is, so the server runs exactly those bytes.
- **`commit`.** When set, the checkout must be at exactly this commit or the deployment fails.
- **`untrusted`.** Code from a fork is built on its own BuildKit builder, without a shared cache and without
  submodules.
- **`egress`.** The build egress policy, `{"mode": "open"|"audit"|"allowlist", "allow": [...]}` (below). Omitted:
  `open`. An agent refuses a build whose mode it does not know or whose allowlist is invalid.

### `ComposeDeploy`

| Field | Meaning |
|---|---|
| `resource`, `deployment`, `network` | as in `AppDeploy` |
| `source` | `{"kind": "git", "url", "reference", "auth", "ssh", "file"}` or `{"kind": "inline", "content"}` (inline Compose files reference images only) |
| `env` | environment for every service and for `${VAR}` interpolation |
| `volumes`, `files` | each mounted in its `service` |
| `labels`, `no_cache` | as in `AppDeploy` |
| `routes` | as in `AppDeploy`, but required: a list (possibly empty), never `null`; each route names its `service` |
| `egress` | the build egress policy of the services' builds, as in `AppDeploy.build.egress` (`build_egress`) |
| `registry_auth` | a list of `RegistryAuth` (as in `AppDeploy`), at most one per registry: each service image pull, SBOM lookup and build base image pull uses the one whose `server` matches the image's host (`registry_auth`; omitted when empty) |

Compose resolves the file (`docker compose config`, without access to the Docker Engine); the agent then applies the
resolved project itself through the Engine API, with Compose's names and labels (`com.docker.compose.project`,
`com.docker.compose.service`), so projects deployed by earlier agents are updated in place. Fields it does not model
(`crates/deploy-agent/src/project.rs` lists them) are refused with an error naming them.

### Build egress

Agents with `build_egress` build on an *internal* Docker network (`owd-build-internal`): its containers have no
route out and Docker resolves no outside name for them, and the agent's firewall also rejects anything its bridge
would forward or send to the server. The only way out is the build egress proxy (container `owd-build-proxy`, the
agent's own static binary running `owdeploy-agent build-proxy` as user 65534, without capabilities, on a read-only
root file system), which is on that network and on `owd-build-egress`, an ordinary Deploy network behind the egress
guard. It is an HTTP proxy: `CONNECT host:port` tunnels and plain `http://` requests (one per connection).

Each build gets a random token, registered with the build's policy; the build steps get the proxy's URL with the
token as credentials in `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` and `NO_PROXY`/`no_proxy`
(loopback): as BuildKit's predefined proxy build arguments for Dockerfile and Compose builds (kept out of the image's
history and the cache key; a value the user set for them is replaced, with a log line) and as BuildKit secrets for
Railpack builds (its steps see them as environment). Each builder has a token of its own, `open`, for BuildKit's own
traffic (image pulls, remote contexts) and buildx's (registry tokens).

The proxy refuses unknown credentials (407). It then decides on the host the client asked for:

| Mode | Names | IP addresses |
|---|---|---|
| `open` | allowed | allowed |
| `audit` | allowed, each recorded | allowed, each recorded |
| `allowlist` | allowed when an entry matches, else `not_allowed` | `ip_literal` |

An allowlist entry is `host` (that name exactly), `*.domain` (any name below `domain`, not `domain` itself), each
with an optional `:port` (any port without); names are ASCII (IDNs in `xn--` form), compared without case or
trailing dot; IP addresses cannot be entries; at most 100 entries. Then, in every mode, the proxy resolves the name
itself and connects only to public addresses: a name or address in a private, shared, loopback, link-local (cloud
metadata), multicast or reserved range (the firewall's) is refused (`private_address`), so DNS rebinding cannot reach
them. A refusal answers 403; the agent writes `Build egress denied: host:port (reason)` to the deployment's log as it
happens, and at the end a summary line and the `egress` event (section 5).

Compatibility: agents without `build_egress` build with direct Internet access and ignore `egress`, so the control
plane fails a deployment whose policy is `allowlist` on such a server rather than build it unrestricted (and warns
that an `audit` policy is not recorded there). Agents with it build through the proxy whatever the control plane
sends: without `egress` (older control planes), the policy is `open`.

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

- **Protocol version.** Negotiated at the connect handshake (section 3): an agent that speaks protocol 2 still
  connects to a control plane that only speaks protocol 1 (it sends the same signed request, and such a control plane
  ignores the v2 headers and answers without them), and a control plane that speaks protocol 2 still accepts protocol
  1 agents, except for servers held to protocol 2. Neither side falls back to protocol 1 once protocol 2 was used
  («Negotiation»).
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
| `sbom` | `sbom` events of `deploy_app` and `deploy_compose` |
| `build_egress` | builds only through the build egress proxy, `BuildSpec.egress`, `ComposeDeploy.egress`, `egress` events |
| `registry_auth` | `ComposeDeploy.registry_auth`, `BuildSpec.registry_auth`, redaction of credentials from the operation's logs and errors (agent 0.3.0) |

## 10. Self-update

The control plane serves agent binaries at `GET /v1/agent/binary/{target}`, where the target is `linux-amd64` or
`linux-arm64`. The SHA-256 of each binary is at `/v1/agent/binary/{target}.sha256`. The agent's checks are in
`crates/deploy-agent/src/update.rs` (`consider`, `install`, `preflight`).

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
   `<binary>.new version` (10 s limit). The output must start with `owdeploy-agent `. With separated privileges
   (`hello.privileges` `"split"`) the relay downloads the binary into its own directory, and the broker copies that
   file into `<binary>.new` (without following a link, regular files only) and checks the copy as above. It also
   requires `<binary>.new capabilities` to list `split-privileges`, so that a binary that cannot run as broker and
   relay is never installed under their units.
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
`owdeploy-agent <version> (protocol owdeploy-agent-v2)`, naming the highest protocol it speaks.

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
