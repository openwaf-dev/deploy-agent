//! The relay (`owdeploy-agent run` as the unprivileged `owdeploy` user): the network-facing half of a
//! privilege-separated agent (README.md, SECURITY.md «Agent privileges»).
//!
//! It resolves, dials, speaks TLS, the HTTP upgrade and WebSocket framing, and nothing else: it holds no key and reads
//! no state. It asks the broker for each connect request's signed headers, hands it the `OWDeploy-*` headers of the
//! control plane's answer, then passes frames both ways as opaque strings (at most [`deploy_proto::MAX_FRAME_BYTES`]
//! from the control plane). It reconnects with the same backoff as the single-process agent, and downloads the
//! binaries the broker asks for into its own staging file, which the broker copies and checks before installing.
//! Taken over, it can drop, delay or reorder traffic, never make the broker execute: the broker acts only on frames
//! that verify for its current session. Nor can it read them in a protocol 2 session: their bodies are encrypted end
//! to end between the broker and the control plane, so it sees only each frame's kind, sequence, timestamp and size.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{BufReader, BufWriter};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::ipc::{self, ToBroker, ToRelay};

/// How long the relay waits for the broker's socket at start (the broker may be starting too).
const BROKER_WITHIN: Duration = Duration::from_secs(60);
/// How long a dial (DNS, TCP, TLS, upgrade) may take.
const DIAL_WITHIN: Duration = Duration::from_secs(30);

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Waits before the next dial: exponential up to 120 s after failures, plus up to 2 s of jitter.
fn backoff(failures: u32) -> Duration {
    Duration::from_secs((2u64 << failures.min(6)).min(120)) + Duration::from_millis(crate::jitter_ms())
}

async fn connect_broker(socket: &Path) -> Result<UnixStream, String> {
    let deadline = Instant::now() + BROKER_WITHIN;
    loop {
        match UnixStream::connect(socket).await {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() >= deadline => return Err(format!("broker socket {}: {e}", socket.display())),
            Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
}

/// Dials the control plane with the broker's headers; returns the WebSocket and its answer's `OWDeploy-*` headers.
async fn dial(url: &str, headers: &[(String, String)]) -> Result<(Ws, Vec<(String, String)>), String> {
    let req = crate::session::request(url, headers)?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(deploy_proto::MAX_FRAME_BYTES))
        .max_frame_size(Some(deploy_proto::MAX_FRAME_BYTES));
    let (ws, answer) =
        tokio::time::timeout(DIAL_WITHIN, tokio_tungstenite::connect_async_with_config(req, Some(config), false))
            .await
            .map_err(|_| format!("no answer within {} s", DIAL_WITHIN.as_secs()))?
            .map_err(|e| e.to_string())?;
    let headers = answer
        .headers()
        .iter()
        .filter(|(n, _)| n.as_str().starts_with("owdeploy-"))
        .filter_map(|(n, v)| Some((n.as_str().to_string(), v.to_str().ok()?.to_string())))
        .take(ipc::MAX_HEADERS)
        .collect();
    Ok((ws, headers))
}

enum State {
    /// Waiting to ask for the next connect request.
    Idle(Instant),
    /// The connect request is asked for.
    Requested,
    /// The session's WebSocket.
    Live(Box<Ws>),
}

struct Relay {
    wr: BufWriter<OwnedWriteHalf>,
    rx: mpsc::Receiver<Result<ToRelay, String>>,
    /// Ends of downloads, for the broker.
    done_tx: mpsc::Sender<ToBroker>,
    done_rx: mpsc::Receiver<ToBroker>,
    staged: PathBuf,
    downloading: bool,
}

impl Relay {
    async fn tell(&mut self, m: &ToBroker) -> Result<(), String> {
        ipc::write(&mut self.wr, m).await
    }

    /// Starts downloading a binary the broker asked for into the staging file.
    fn stage(&mut self, url: String, sha256: String) {
        let refused = match url.split_once("://") {
            Some(("https" | "http", _)) if !self.downloading => None,
            Some(("https" | "http", _)) => Some("another download is in progress".to_string()),
            _ => Some(format!("not an HTTP URL: {url}")),
        };
        let done = self.done_tx.clone();
        if let Some(message) = refused {
            tokio::spawn(async move { done.send(ToBroker::StageFailed { sha256, message }).await });
            return;
        }
        self.downloading = true;
        let path = self.staged.clone();
        tokio::spawn(async move {
            let m = match crate::update::download(&url, &path, &sha256, 0o600).await {
                Ok(()) => ToBroker::Staged { sha256 },
                Err(message) => {
                    let _ = tokio::fs::remove_file(&path).await;
                    ToBroker::StageFailed { sha256, message }
                }
            };
            let _ = done.send(m).await;
        });
    }

    /// A download ended: told to the broker.
    async fn done(&mut self, m: ToBroker) -> Result<(), String> {
        self.downloading = false;
        if let ToBroker::StageFailed { message, .. } = &m {
            tracing::warn!("update download: {message}");
        }
        self.tell(&m).await
    }

    /// A message of the broker other than what the current state waits for. Ok(true): exit for a restart.
    fn other(&mut self, m: Option<Result<ToRelay, String>>) -> Result<bool, String> {
        match m {
            None => Err("the broker closed the connection".into()),
            Some(Err(e)) => Err(format!("broker: {e}")),
            Some(Ok(ToRelay::Stage { url, sha256 })) => {
                self.stage(url, sha256);
                Ok(false)
            }
            Some(Ok(ToRelay::End { restart: true, .. })) => Ok(true),
            // Late frames of a session that ended, the end of one already closed.
            Some(Ok(ToRelay::FrameOut { .. } | ToRelay::End { .. })) => Ok(false),
            Some(Ok(m)) => Err(format!("broker: unexpected {m:?}")),
        }
    }
}

async fn read_loop(rd: tokio::net::unix::OwnedReadHalf, tx: mpsc::Sender<Result<ToRelay, String>>) {
    let mut rd = BufReader::new(rd);
    loop {
        let item = match ipc::read::<ToRelay, _>(&mut rd).await {
            Ok(Some(m)) => Ok(m),
            Ok(None) => break,
            Err(e) => Err(e),
        };
        let stop = item.is_err();
        if tx.send(item).await.is_err() || stop {
            break;
        }
    }
}

/// `owdeploy-agent run` without privileges: relays for the broker on `socket` until the broker restarts (Ok: exit for
/// systemd to start the installed binary) or goes away (an error; systemd starts the relay again).
pub async fn run(socket: &Path, staging_dir: &Path) -> Result<(), String> {
    let stream = connect_broker(socket).await?;
    let (rd, wr) = stream.into_split();
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(read_loop(rd, tx));
    let (done_tx, done_rx) = mpsc::channel(2);
    let mut r = Relay {
        wr: BufWriter::new(wr),
        rx,
        done_tx,
        done_rx,
        staged: staging_dir.join(ipc::STAGED_FILE),
        downloading: false,
    };
    r.tell(&ToBroker::Attach { version: ipc::VERSION }).await?;
    match r.rx.recv().await {
        Some(Ok(ToRelay::Attached { version: ipc::VERSION, agent_version })) => {
            tracing::info!("relay attached to the broker ({agent_version}); no privileges, no keys here");
        }
        Some(Ok(ToRelay::End { error, .. })) => {
            tracing::warn!("the broker refused this relay: {}", error.unwrap_or_default());
            return Ok(());
        }
        other => return Err(format!("broker: unexpected answer {other:?}")),
    }
    let mut failures = 0u32;
    let mut state = State::Idle(Instant::now());
    loop {
        state = match state {
            State::Idle(at) => tokio::select! {
                _ = tokio::time::sleep_until(at) => {
                    r.tell(&ToBroker::Connect {}).await?;
                    State::Requested
                }
                m = r.rx.recv() => match r.other(m)? {
                    true => return Ok(()),
                    false => State::Idle(at),
                },
                Some(d) = r.done_rx.recv() => {
                    r.done(d).await?;
                    State::Idle(at)
                }
            },
            State::Requested => tokio::select! {
                m = r.rx.recv() => match m {
                    Some(Ok(ToRelay::ConnectHeaders { url, headers })) => match dial(&url, &headers).await {
                        Ok((ws, headers)) => {
                            r.tell(&ToBroker::Answer { headers }).await?;
                            State::Live(Box::new(ws))
                        }
                        Err(e) => {
                            failures += 1;
                            tracing::warn!("connection: {e}");
                            if e.contains("401") {
                                tracing::error!("the control plane refused this agent (revoked or unknown); retrying slowly");
                            }
                            r.tell(&ToBroker::Ended { error: Some(e) }).await?;
                            State::Idle(Instant::now() + backoff(failures))
                        }
                    },
                    m => match r.other(m)? {
                        true => return Ok(()),
                        false => State::Requested,
                    },
                },
                Some(d) = r.done_rx.recv() => {
                    r.done(d).await?;
                    State::Requested
                }
            },
            State::Live(mut ws) => tokio::select! {
                m = ws.next() => {
                    let ended = match m {
                        Some(Ok(Message::Text(t))) => {
                            r.tell(&ToBroker::FrameIn { text: t.as_str().to_string() }).await?;
                            None
                        }
                        Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_) | Message::Binary(_))) => None,
                        Some(Ok(Message::Close(_))) | None => Some(None),
                        Some(Err(e)) => Some(Some(e.to_string())),
                    };
                    match ended {
                        None => State::Live(ws),
                        Some(error) => {
                            match &error {
                                Some(e) => {
                                    failures += 1;
                                    tracing::warn!("connection: {e}");
                                }
                                None => failures = 0,
                            }
                            r.tell(&ToBroker::Ended { error }).await?;
                            State::Idle(Instant::now() + backoff(failures))
                        }
                    }
                }
                m = r.rx.recv() => match m {
                    Some(Ok(ToRelay::FrameOut { text })) => match ws.send(Message::Text(text.into())).await {
                        Ok(()) => State::Live(ws),
                        Err(e) => {
                            failures += 1;
                            tracing::warn!("connection: {e}");
                            r.tell(&ToBroker::Ended { error: Some(e.to_string()) }).await?;
                            State::Idle(Instant::now() + backoff(failures))
                        }
                    },
                    Some(Ok(ToRelay::End { error, restart })) => {
                        let _ = ws.close().await;
                        if restart {
                            return Ok(());
                        }
                        match error {
                            Some(e) => {
                                failures += 1;
                                tracing::warn!("the broker ended the session: {e}");
                            }
                            None => failures = 0,
                        }
                        State::Idle(Instant::now() + backoff(failures))
                    }
                    m => match r.other(m)? {
                        true => return Ok(()),
                        false => State::Live(ws),
                    },
                },
                Some(d) = r.done_rx.recv() => {
                    r.done(d).await?;
                    State::Live(ws)
                }
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use deploy_proto::msg::{CommandResult, Hello, Outcome, Ping, Pong};
    use deploy_proto::session::{Exchange, Session, Transcript};
    use deploy_proto::{Direction, Frame, Sealer};
    use ed25519_dalek::SigningKey;
    use serde::Serialize;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};

    use super::*;
    use crate::broker::{Staging, bind, serve};
    use crate::git::TempDir;
    use crate::update::Fetcher;

    /// A secret a deployment would carry. `-` and `_` are not base64 characters: no ciphertext contains it by chance.
    const SECRET: &str = "postgres://u:hunter2-x_7@db/app";

    /// A command whose operation this agent does not know (answered `unsupported`, never executed), carrying
    /// [`SECRET`] the way a deployment carries its variables.
    #[derive(Serialize)]
    struct FutureCommand {
        id: String,
        op: serde_json::Value,
    }

    impl deploy_proto::msg::Kind for FutureCommand {
        const KIND: &'static str = "command";
    }

    /// A control plane signing with `control` that answers one v2 handshake per connection: it checks the agent's
    /// session proof, then sends `ping` frames and a command carrying [`SECRET`] in the session (and, at the end, one
    /// of another session) and returns the pongs it got. It fails when any frame it sent or received, as the relay
    /// carried it, shows a message: the secret, or the field names of the agent's hello.
    async fn control_plane(control: SigningKey) -> (String, mpsc::Receiver<Result<Vec<u64>, String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/agent/connect", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let control = control.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(one_connection(tcp, control).await).await;
                });
            }
        });
        (url, rx)
    }

    async fn one_connection(tcp: tokio::net::TcpStream, control: SigningKey) -> Result<Vec<u64>, String> {
        let seen = std::sync::Arc::new(parking_lot::Mutex::new(None::<Session>));
        let s = seen.clone();
        let c = control.clone();
        // The signature tungstenite requires of the callback.
        #[allow(clippy::result_large_err)]
        let callback = move |req: &Request, mut resp: Response| {
            let get = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
            let (headers, session) = crate::session::tests::answer_to(&c, &get);
            for (n, v) in headers {
                resp.headers_mut()
                    .insert(HeaderName::from_bytes(n.as_bytes()).unwrap(), HeaderValue::from_str(&v).unwrap());
            }
            *s.lock() = Some(session);
            Ok(resp)
        };
        let mut ws = tokio_tungstenite::accept_hdr_async(tcp, callback).await.map_err(|e| e.to_string())?;
        let session = seen.lock().take().expect("handshake");
        // Every frame as the relay carried it, both ways.
        let mut wire: Vec<String> = Vec::new();
        let next = async |ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
                          wire: &mut Vec<String>| loop {
            match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
                Ok(Some(Ok(Message::Text(t)))) => {
                    wire.push(t.as_str().to_string());
                    return Ok(serde_json::from_str::<Frame>(t.as_str()).unwrap());
                }
                Ok(Some(Ok(_))) => continue,
                Ok(_) => return Err("closed".to_string()),
                Err(_) => return Err("no frame in time".to_string()),
            }
        };
        let read = |f: &Frame| {
            let c = session.keys.cipher(Direction::AgentToControl);
            c.open(f.seq, f.ts, &f.kind, &f.body).ok_or_else(|| format!("{} not sealed for this session", f.kind))
        };
        // The session starts with the agent's proof of the transcript, then its hello.
        let proof = next(&mut ws, &mut wire).await?;
        if proof.kind != "session_proof" || !read(&proof)?.contains("signature") {
            return Err(format!("no session proof first: {}", proof.kind));
        }
        let hello = next(&mut ws, &mut wire).await?;
        serde_json::from_str::<Hello>(&read(&hello)?).map_err(|e| e.to_string())?;
        let mut sealer = Sealer::new(control.clone(), Direction::ControlToAgent).in_session(&session.keys);
        type Ws = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;
        let send = async |ws: &mut Ws, wire: &mut Vec<String>, f: &Frame| {
            let text = serde_json::to_string(f).unwrap();
            wire.push(text.clone());
            ws.send(Message::Text(text.into())).await.unwrap();
        };
        let mut pongs = Vec::new();
        for nonce in [1, 2] {
            send(&mut ws, &mut wire, &sealer.seal(&Ping { nonce }, crate::now())).await;
            let pong = loop {
                let f = next(&mut ws, &mut wire).await?;
                if f.kind == "pong" {
                    break f;
                }
            };
            pongs.push(serde_json::from_str::<Pong>(&read(&pong)?).unwrap().nonce);
        }
        let op = serde_json::json!({"op": "deploy_app_v9", "env": {"DATABASE_URL": SECRET}});
        send(&mut ws, &mut wire, &sealer.seal(&FutureCommand { id: "cmd_1".into(), op }, crate::now())).await;
        let result = loop {
            let f = next(&mut ws, &mut wire).await?;
            if f.kind == "command_result" {
                break serde_json::from_str::<CommandResult>(&read(&f)?).unwrap();
            }
        };
        if result.outcome != Outcome::Unsupported {
            return Err(format!("the broker did not read the command: {result:?}"));
        }
        // A frame recorded on another connection: the broker refuses it and the relay closes this one.
        let x = Exchange::generate();
        let t = Transcript {
            control_nonce: deploy_proto::session::nonce(),
            control_exchange: x.public_key(),
            ..session.transcript.clone()
        };
        let other = x.finish(&t, Direction::ControlToAgent).unwrap();
        let mut foreign = Sealer::new(control, Direction::ControlToAgent).in_session(&other);
        for _ in 0..3 {
            foreign.seal(&Ping { nonce: 0 }, crate::now());
        }
        send(&mut ws, &mut wire, &foreign.seal(&Ping { nonce: 9 }, crate::now())).await;
        loop {
            match next(&mut ws, &mut wire).await {
                Ok(f) if f.kind == "pong" => return Err("the foreign frame was answered".into()),
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        for text in &wire {
            if text.contains("hunter2-x_7") || text.contains("\"hostname\"") || text.contains("deploy_app_v9") {
                return Err(format!("a message in clear on the wire: {text}"));
            }
        }
        if wire.len() < 9 {
            return Err(format!("only {} frames carried", wire.len()));
        }
        Ok(pongs)
    }

    /// A relay and a broker in this process, over a UNIX socket, against a fake control plane: the relay carries
    /// the session the broker signs and checks; a frame of another session closes the connection, and the relay dials
    /// again.
    #[tokio::test]
    async fn relay_carries_the_brokers_session() {
        let dir = TempDir::new().unwrap();
        let control = deploy_proto::generate_key();
        let (url, mut sessions) = control_plane(control.clone()).await;
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let staging = Staging::new(dir.path().join(ipc::STAGED_FILE));
        let agent = crate::session::tests::agent(&state, &control, &url, Fetcher::Relay(staging.clone()));
        let sock = dir.path().join("run/broker.sock");
        let listener = bind(&sock, None).unwrap();
        // SAFETY: getuid has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        tokio::spawn(serve(listener, Some(uid), agent, staging));
        let relay_dir = dir.path().to_path_buf();
        let relay = tokio::spawn(async move { run(&sock, &relay_dir).await });

        let first = tokio::time::timeout(Duration::from_secs(20), sessions.recv()).await.unwrap().unwrap();
        assert_eq!(first, Ok(vec![1, 2]), "pings answered through relay and broker");
        // The relay dials again after the refused frame (2 s of backoff and up to 2 s of jitter).
        let second = tokio::time::timeout(Duration::from_secs(20), sessions.recv()).await.unwrap().unwrap();
        assert_eq!(second, Ok(vec![1, 2]));
        assert!(!relay.is_finished());
        relay.abort();
    }
}
