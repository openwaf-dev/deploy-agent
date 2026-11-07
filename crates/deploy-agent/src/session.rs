//! A session with the control plane, whatever carries its frames: the WebSocket itself in the single-process agent,
//! or the relay over the broker's socket when privileges are separated ([`crate::broker`]). Either way the frames are
//! signed, encrypted, opened and acted upon here, with the keys only this process holds: [`Agent::connect_request`]
//! signs the upgrade request and makes the connection's ephemeral exchange key, [`Agent::accept`] checks the control
//! plane's answer against the pinned keys and derives the session's keys, and [`Agent::drive`] proves the session,
//! opens every incoming frame (signature, session, sequence, clock, decryption) and seals every outgoing one. What
//! carries the frames sees only their kind, sequence, timestamp and size in a v2 session.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use deploy_proto::msg::{
    AgentUpdate, Cancel, Command, CommandResult, ControlKeyRotate, Heartbeat, Hello, Op, Outcome, Ping, Pong,
    Privileges, SessionProof, UpdateKey,
};
use deploy_proto::session::{Exchange, Session};
use deploy_proto::{Direction, Frame, Sealer, connect};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::{HeaderMap, HeaderName, HeaderValue};
use tokio_util::sync::CancellationToken;

use crate::events::{Events, Outgoing};
use crate::ipc::SessionState;
use crate::keys::KeyRing;
use crate::update::{Fetched, Poll, Updater};
use crate::{docker, host, now};

const HEARTBEAT_EVERY: Duration = Duration::from_secs(30);

/// What carries a session's frames. Both directions are text frames as on the wire.
pub trait Link {
    /// The next frame from the control plane: None once the connection closed cleanly, an error when it broke. Must
    /// be cancel-safe (it is one branch of a `select!`).
    async fn recv(&mut self) -> Option<Result<String, String>>;
    /// Sends a frame to the control plane.
    async fn send(&mut self, text: String) -> Result<(), String>;
    /// The agent is about to restart: closes the connection, best effort.
    async fn close(&mut self);
}

/// The control plane's WebSocket, in the single-process agent.
pub struct WsLink<S>(pub S);

impl<S> Link for WsLink<S>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    async fn recv(&mut self) -> Option<Result<String, String>> {
        loop {
            return match self.0.next().await {
                Some(Ok(Message::Text(t))) => Some(Ok(t.as_str().to_string())),
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_) | Message::Binary(_))) => continue,
                Some(Ok(Message::Close(_))) | None => None,
                Some(Err(e)) => Some(Err(e.to_string())),
            };
        }
    }

    async fn send(&mut self, text: String) -> Result<(), String> {
        self.0.send(Message::Text(text.into())).await.map_err(|e| e.to_string())
    }

    async fn close(&mut self) {
        let _ = self.0.close().await;
    }
}

/// The upgrade request to `url` with `headers` (those of [`Agent::connect_request`]).
pub fn request(url: &str, headers: &[(String, String)]) -> Result<Request, String> {
    let mut req = url.into_client_request().map_err(|e| e.to_string())?;
    for (name, value) in headers {
        let n = HeaderName::from_bytes(name.as_bytes()).map_err(|_| format!("connect header name {name:?}"))?;
        let v = HeaderValue::from_str(value).map_err(|_| format!("connect header {name}"))?;
        req.headers_mut().insert(n, v);
    }
    Ok(req)
}

/// How a session ended without an error.
#[derive(Debug, PartialEq, Eq)]
pub enum Flow {
    /// The connection closed: dial again.
    Closed,
    /// A new binary is installed: exit for systemd to start it.
    Restart,
}

/// The current session, shared with whoever reports it (the broker's status).
pub type Live = Arc<Mutex<Option<SessionState>>>;

/// Clears the shared session when the session ends, however it ends.
struct LiveGuard(Live);

impl Drop for LiveGuard {
    fn drop(&mut self) {
        *self.0.lock() = None;
    }
}

/// A connect request in flight: its nonce and its exchange key, which the answer must name. Dropped (and the key
/// wiped) when the connection fails before its answer.
pub struct Handshake {
    nonce: String,
    exchange: Exchange,
}

/// The agent's side of the protocol: its identity and pinned keys, its update state and how it is privileged.
pub struct Agent {
    ring: KeyRing,
    key: SigningKey,
    up: Updater,
    fetched: tokio::sync::mpsc::Receiver<Fetched>,
    privileges: Privileges,
    pub live: Live,
}

impl Agent {
    pub fn new(
        ring: KeyRing,
        up: Updater,
        fetched: tokio::sync::mpsc::Receiver<Fetched>,
        privileges: Privileges,
    ) -> Result<Agent, String> {
        let key = ring.id.signing_key()?;
        Ok(Agent { ring, key, up, fetched, privileges, live: Live::default() })
    }

    /// The control plane's connect URL.
    pub fn connect_url(&self) -> String {
        self.ring.id.connect_url.clone()
    }

    /// The headers of a new connect request: the server id, a timestamp and a fresh nonce signed by the agent's key
    /// (the same in both protocol versions), then the v2 request with a fresh exchange key. Returns them with the
    /// handshake the answer must complete ([`Agent::accept`]).
    pub fn connect_request(&self) -> (Vec<(String, String)>, Handshake) {
        let id = &self.ring.id;
        let nonce = deploy_proto::session::nonce();
        let exchange = Exchange::generate();
        let ts = now();
        let body = format!("{}\n{nonce}", id.server_id);
        let sig = self.key.sign(&deploy_proto::signing_message(
            Direction::AgentToControl,
            0,
            ts,
            connect::KIND,
            body.as_bytes(),
        ));
        let mut h = vec![
            (connect::HDR_SERVER.to_string(), id.server_id.clone()),
            (connect::HDR_TIMESTAMP.to_string(), ts.to_string()),
            (connect::HDR_NONCE.to_string(), nonce.clone()),
            (connect::HDR_SIGNATURE.to_string(), deploy_proto::encode_signature(&sig)),
        ];
        h.extend(self.ring.session_request(&exchange.public_key()).map(|(n, v)| (n.to_string(), v)));
        (h, Handshake { nonce, exchange })
    }

    /// The control plane's answer to the connect request of `handshake`: a v2 session once a pinned control key
    /// signed its handshake, v1 only while this agent never used v2 (see [`KeyRing::accept_session`]).
    pub fn accept(&mut self, handshake: Handshake, answer: &HeaderMap) -> Result<Option<Session>, String> {
        self.ring.accept_session(&handshake.nonce, handshake.exchange, answer)
    }

    /// Runs the session `session` (None: v1) over `link` until it ends: every incoming frame must open with the
    /// pinned keys for this session, or the session ends with an error. The session's keys live in its sealer and
    /// opener only, and are wiped when the session ends.
    pub async fn drive<L: Link>(&mut self, session: Option<Session>, link: &mut L) -> Result<Flow, String> {
        let protocol = session.as_ref().map_or(1, |s| s.transcript.protocol);
        tracing::info!(server = %self.ring.id.server_id, protocol, "connected");
        *self.live.lock() = Some(SessionState { protocol, since: now(), verified: false });
        let _live = LiveGuard(self.live.clone());
        let mut sealer = Sealer::new(self.key.clone(), Direction::AgentToControl);
        let mut opener = self.ring.opener(session.as_ref().map(|s| &s.keys))?;
        if let Some(Session { transcript, keys }) = session {
            sealer = sealer.in_session(&keys);
            drop(keys);
            let proof = SessionProof {
                signature: deploy_proto::encode_signature(&transcript.sign(&self.key, Direction::AgentToControl)),
            };
            out(link, &sealer.seal(&proof, now())).await?;
        }
        let facts = host::facts();
        let hello = Hello {
            agent_version: deploy_proto::build_version(),
            hostname: facts.hostname,
            os: facts.os,
            arch: facts.arch,
            kernel: facts.kernel,
            docker: docker::info().await.ok(),
            features: deploy_proto::msg::feature::ALL.iter().map(|f| f.to_string()).collect(),
            binary_sha256: self.up.own_sha256(),
            keys: Some(self.ring.id.pinned(None)),
            privileges: Some(self.privileges),
        };
        out(link, &sealer.seal(&hello, now())).await?;
        let mut beat = tokio::time::interval(HEARTBEAT_EVERY);
        beat.tick().await;
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Outgoing>(256);
        let mut running = Running::default();
        let mut verified = false;
        // A binary downloaded during an earlier session installs now, before any command.
        if after_change(&mut self.up, &running, link, &mut sealer).await? {
            return Ok(Flow::Restart);
        }
        loop {
            tokio::select! {
                m = link.recv() => {
                    let text = match m {
                        Some(Ok(t)) => t,
                        None => return Ok(Flow::Closed),
                        Some(Err(e)) => return Err(e),
                    };
                    let (frame, rotated) = self.ring.open(&mut opener, &text, now())?;
                    if let Some(keys) = rotated {
                        self.up.set_trust(self.ring.id.trust()?);
                        out(link, &sealer.seal(&keys, now())).await?;
                    }
                    if !verified {
                        // Both ways work with the pinned key: a binary on probation after an update is confirmed.
                        verified = true;
                        if let Some(s) = self.live.lock().as_mut() {
                            s.verified = true;
                        }
                        for st in self.up.connected() {
                            out(link, &sealer.seal(&st, now())).await?;
                        }
                    }
                    match frame.kind.as_str() {
                        "command" => {
                            let cmd = match serde_json::from_str::<Command>(&frame.body) {
                                Ok(c) => c,
                                // An operation of a newer control plane: answered, not fatal to the session.
                                Err(e) => {
                                    let id = serde_json::from_str::<serde_json::Value>(&frame.body)
                                        .ok()
                                        .and_then(|v| v.get("id")?.as_str().map(str::to_string))
                                        .ok_or("command without an id")?;
                                    let outcome = match e.to_string().contains("unknown variant") {
                                        true => Outcome::Unsupported,
                                        false => Outcome::Error { message: format!("invalid command: {e}") },
                                    };
                                    out(link, &sealer.seal(&CommandResult { id, outcome }, now())).await?;
                                    continue;
                                }
                            };
                            let cancel = CancellationToken::new();
                            running.0.insert(cmd.id.clone(), (cancel.clone(), blocks_update(&cmd.op)));
                            let out = out_tx.clone();
                            tokio::spawn(async move {
                                let (ev, batcher) = Events::start(cmd.id.clone(), out.clone());
                                let outcome = crate::execute(cmd.op, &ev, &cancel).await;
                                // Every event of the command is out before its result.
                                drop(ev);
                                let _ = batcher.await;
                                let _ = out.send(Outgoing::Result(CommandResult { id: cmd.id, outcome })).await;
                            });
                        }
                        "cancel" => {
                            let c: Cancel = frame.decode().map_err(|e| e.to_string())?;
                            if let Some((t, _)) = running.0.get(&c.id) {
                                t.cancel();
                            }
                        }
                        "ping" => {
                            let p: Ping = frame.decode().map_err(|e| e.to_string())?;
                            out(link, &sealer.seal(&Pong { nonce: p.nonce }, now())).await?;
                        }
                        "agent_update" => match frame.decode::<AgentUpdate>() {
                            Ok(u) => {
                                if let Some(st) = self.up.offer(u, now()) {
                                    out(link, &sealer.seal(&st, now())).await?;
                                }
                                if after_change(&mut self.up, &running, link, &mut sealer).await? {
                                    return Ok(Flow::Restart);
                                }
                            }
                            Err(e) => tracing::warn!("update offer: {e}"),
                        },
                        // Key announcements: only in frames the pinned keys opened (see `keys`).
                        "control_key_rotate" => match frame.decode::<ControlKeyRotate>() {
                            Ok(m) => {
                                let keys = self.ring.rotate(&mut opener, &m);
                                out(link, &sealer.seal(&keys, now())).await?;
                            }
                            Err(e) => tracing::warn!("control key rotation: {e}"),
                        },
                        "update_key" => match frame.decode::<UpdateKey>() {
                            Ok(m) => {
                                let keys = self.ring.update_key(&m);
                                self.up.set_trust(self.ring.id.trust()?);
                                out(link, &sealer.seal(&keys, now())).await?;
                            }
                            Err(e) => tracing::warn!("update key: {e}"),
                        },
                        _ => {}
                    }
                }
                Some(o) = out_rx.recv() => match o {
                    Outgoing::Event(e) => out(link, &sealer.seal(&e, now())).await?,
                    Outgoing::Result(r) => {
                        running.0.remove(&r.id);
                        out(link, &sealer.seal(&r, now())).await?;
                        if after_change(&mut self.up, &running, link, &mut sealer).await? {
                            return Ok(Flow::Restart);
                        }
                    }
                },
                Some(f) = self.fetched.recv() => {
                    if let Some(st) = self.up.fetched(f) {
                        out(link, &sealer.seal(&st, now())).await?;
                    }
                    if after_change(&mut self.up, &running, link, &mut sealer).await? {
                        return Ok(Flow::Restart);
                    }
                }
                _ = beat.tick() => {
                    let hb: Heartbeat = host::heartbeat(docker::running().await.unwrap_or(0));
                    out(link, &sealer.seal(&hb, now())).await?;
                }
            }
        }
    }
}

async fn out<L: Link>(link: &mut L, f: &Frame) -> Result<(), String> {
    link.send(serde_json::to_string(f).expect("frame")).await
}

/// Installs a downloaded binary when nothing but log streams runs. True: installed, the agent restarts now.
async fn after_change<L: Link>(
    up: &mut Updater,
    running: &Running,
    link: &mut L,
    sealer: &mut Sealer,
) -> Result<bool, String> {
    match up.poll(running.busy(), now()) {
        Poll::Idle => Ok(false),
        Poll::Status(st) => out(link, &sealer.seal(&st, now())).await.map(|()| false),
        Poll::Restart(st) => {
            tracing::info!("installed {}: restarting", st.version);
            out(link, &sealer.seal(&st, now())).await?;
            link.close().await;
            Ok(true)
        }
    }
}

/// Whether a running command holds back an update: everything but a log stream, which only loses its follower.
fn blocks_update(op: &Op) -> bool {
    !matches!(op, Op::AppLogs { .. })
}

/// Commands of a session by id, with whether each holds back an update. When the session ends their results can no
/// longer be delivered, so they are cancelled: a following log stream stops, a deployment rolls back to the previous
/// container.
#[derive(Default)]
struct Running(HashMap<String, (CancellationToken, bool)>);

impl Running {
    fn busy(&self) -> bool {
        self.0.values().any(|(_, blocks)| *blocks)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.0.values().for_each(|(t, _)| t.cancel());
    }
}

#[cfg(test)]
pub mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use deploy_proto::encode_key;
    use deploy_proto::session::{Exchange, Session, Transcript};

    use super::*;
    use crate::keys::Identity;
    use crate::update::Fetcher;

    /// An enrolled agent in `dir` that pinned `control`, dialing `connect_url`, without a binary of its own (no
    /// self-update).
    pub fn agent(dir: &std::path::Path, control: &SigningKey, connect_url: &str, fetcher: Fetcher) -> Agent {
        let id = Identity {
            server_id: "srv_1".into(),
            org_id: "org".into(),
            key: B64.encode(deploy_proto::generate_key().to_bytes()),
            control_public_key: encode_key(&control.verifying_key()),
            connect_url: connect_url.into(),
            control_next_public_key: None,
            update_public_key: None,
            release_public_key: None,
            protocol: Some(2),
        };
        id.save(dir).unwrap();
        let ring = KeyRing::load(dir).unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let up = Updater::new(dir.to_path_buf(), None, ring.id.trust().unwrap(), connect_url, tx, fetcher);
        Agent::new(ring, up, rx, Privileges::Split).unwrap()
    }

    /// The control plane's side of a v2 handshake: the answer headers to a connect request with `headers`, signed by
    /// `control`, and the control plane's session (its transcript and keys).
    pub fn answer(control: &SigningKey, headers: &[(String, String)]) -> (Vec<(String, String)>, Session) {
        let get = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap_or_default();
        answer_to(control, &get)
    }

    /// [`answer`] to a request whose headers `get` reads.
    pub fn answer_to(control: &SigningKey, get: &dyn Fn(&str) -> String) -> (Vec<(String, String)>, Session) {
        let exchange = Exchange::generate();
        let t = Transcript {
            protocol: 2,
            server_id: get(connect::HDR_SERVER),
            agent_nonce: get(connect::HDR_NONCE),
            control_nonce: deploy_proto::session::nonce(),
            control_key: control.verifying_key(),
            agent_exchange: deploy_proto::session::decode_exchange_key(&get(connect::HDR_EXCHANGE_KEY))
                .expect("the agent's exchange key"),
            control_exchange: exchange.public_key(),
        };
        let sig = t.sign(control, Direction::ControlToAgent);
        let h = vec![
            (connect::HDR_PROTOCOL.to_string(), "2".to_string()),
            (connect::HDR_CONTROL_NONCE.to_string(), t.control_nonce.clone()),
            (connect::HDR_CONTROL_KEY.to_string(), encode_key(&control.verifying_key())),
            (connect::HDR_CONTROL_SIGNATURE.to_string(), deploy_proto::encode_signature(&sig)),
            (
                connect::HDR_CONTROL_EXCHANGE_KEY.to_string(),
                deploy_proto::session::encode_exchange_key(&t.control_exchange),
            ),
        ];
        let keys = exchange.finish(&t, Direction::ControlToAgent).unwrap();
        (h, Session { transcript: t, keys })
    }

    /// A running deployment (or any command but a log stream) holds an update back; a log stream does not.
    #[test]
    fn update_skipped_while_a_deployment_runs() {
        let mut r = Running::default();
        let logs = Op::AppLogs { resource: "app_1".into(), tail: 10, follow: true, since: None, service: None };
        r.0.insert("logs".into(), (CancellationToken::new(), blocks_update(&logs)));
        assert!(!r.busy(), "a following log stream does not hold an update");
        let deploy = Op::DeployCompose(deploy_proto::msg::ComposeDeploy {
            resource: "app_1".into(),
            deployment: "dep_1".into(),
            network: "owd-env".into(),
            source: deploy_proto::msg::ComposeSource::Inline { content: "services: {}".into() },
            env: Default::default(),
            volumes: vec![],
            files: vec![],
            labels: Default::default(),
            routes: vec![],
            no_cache: false,
            egress: None,
        });
        r.0.insert("dep".into(), (CancellationToken::new(), blocks_update(&deploy)));
        assert!(r.busy());
        r.0.remove("dep");
        assert!(!r.busy(), "installed once the deployment ended");
    }
}
