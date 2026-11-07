//! The protocol between the two processes of a privilege-separated agent, over the broker's UNIX socket (README.md,
//! SECURITY.md «Agent privileges»).
//!
//! The relay (`owdeploy-agent run` as the unprivileged `owdeploy` user) carries the control plane's connection: DNS,
//! TCP, TLS, the HTTP upgrade and WebSocket framing. The broker (`owdeploy-agent broker`, root) holds the identity and
//! the pinned keys, signs the connect request, checks the control plane's answer, opens every incoming frame, seals
//! every outgoing one and executes. Between them travel only the messages below: connect headers one way and the
//! answer's headers back, frames as opaque strings both ways, the end of a session, the staging of an update and the
//! broker's status. There is no message that asks the broker to execute anything: it executes only what a frame that
//! verifies for its current session says, so a relay taken over can drop, delay or reorder traffic, never command.
//!
//! Each message is a 4-byte big-endian length, then that many bytes of JSON (at most [`MAX_MESSAGE_BYTES`]): an object
//! whose `type` names the message. An unknown type or field, or a longer message, ends the connection.
//!
//! A connection starts with [`ToBroker::Attach`] (a relay, answered [`ToRelay::Attached`]; the broker serves one at a
//! time) or [`ToBroker::Status`] (a query, answered [`ToRelay::Status`], then closed). The broker accepts peers whose
//! `SO_PEERCRED` user is root or the relay's user ([`peer_allowed`]); its socket's directory and file modes
//! (0750/0660, group of the relay's user) keep everyone else out before that.

use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::http::{HeaderMap, HeaderName, HeaderValue};

/// Version of this protocol, exchanged in [`ToBroker::Attach`] and [`ToRelay::Attached`]: both processes run the same
/// binary, so a difference means one of them still runs the previous one (it restarts).
pub const VERSION: u32 = 1;
/// Largest message: a frame of [`deploy_proto::MAX_FRAME_BYTES`] whose every byte JSON escapes to six (`\u0000`) still
/// fits.
pub const MAX_MESSAGE_BYTES: usize = 8 * deploy_proto::MAX_FRAME_BYTES;
/// At most this many headers of the control plane's answer, each name and value at most [`MAX_HEADER_BYTES`].
pub const MAX_HEADERS: usize = 32;
pub const MAX_HEADER_BYTES: usize = 4096;
/// The relay's user: the broker accepts its uid and gives its group the socket.
pub const RELAY_USER: &str = "owdeploy";
/// The relay's staging file for a downloaded binary, in its state directory.
pub const STAGED_FILE: &str = "agent.new";

/// The broker's socket: `$OWDEPLOY_BROKER_SOCKET`, default `/run/owdeploy-agent/broker.sock`.
pub fn socket_path() -> PathBuf {
    std::env::var_os("OWDEPLOY_BROKER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/owdeploy-agent/broker.sock"))
}

/// The relay's state directory, where it stages downloaded binaries: `$OWDEPLOY_RELAY_STATE`, default
/// `/var/lib/owdeploy-agent-relay` (systemd's `StateDirectory=` of the relay's unit, owned by the relay's user).
pub fn relay_state_dir() -> PathBuf {
    std::env::var_os("OWDEPLOY_RELAY_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/owdeploy-agent-relay"))
}

/// Relay → broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToBroker {
    /// First message of a relay: the protocol version it speaks.
    Attach { version: u32 },
    /// First and only message of a status query.
    Status {},
    /// Asks for the signed headers of a new connect request (and forgets any earlier one).
    Connect {},
    /// The headers of the control plane's answer to the last connect request (those named `OWDeploy-*`).
    Answer { headers: Vec<(String, String)> },
    /// A text frame from the control plane, as received.
    FrameIn { text: String },
    /// The WebSocket closed: cleanly when `error` is None.
    Ended { error: Option<String> },
    /// The binary of the last [`ToRelay::Stage`] is in the relay's staging file ([`STAGED_FILE`]).
    Staged { sha256: String },
    /// Its download failed.
    StageFailed { sha256: String, message: String },
}

impl ToBroker {
    /// The message's type, for logs.
    pub fn name(&self) -> &'static str {
        match self {
            ToBroker::Attach { .. } => "attach",
            ToBroker::Status {} => "status",
            ToBroker::Connect {} => "connect",
            ToBroker::Answer { .. } => "answer",
            ToBroker::FrameIn { .. } => "frame_in",
            ToBroker::Ended { .. } => "ended",
            ToBroker::Staged { .. } => "staged",
            ToBroker::StageFailed { .. } => "stage_failed",
        }
    }
}

/// Broker → relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToRelay {
    /// The relay is attached.
    Attached { version: u32, agent_version: String },
    /// The answer to a status query.
    Status { status: Status },
    /// The connect request to send: the control plane's URL and the signed headers.
    ConnectHeaders { url: String, headers: Vec<(String, String)> },
    /// A sealed frame to send to the control plane.
    FrameOut { text: String },
    /// Close the WebSocket: the broker ended the session (`error`: why, None when it ends normally). With `restart`,
    /// the broker is about to exit (a new binary installed or the previous one put back): the relay exits too, and
    /// systemd starts both on the installed binary. Also the refusal of an [`ToBroker::Attach`].
    End { error: Option<String>, restart: bool },
    /// Download the binary at `url` (the control plane's) into the staging file; its SHA-256 must be `sha256`. The
    /// broker checks it again, with every signature, on its own copy.
    Stage { url: String, sha256: String },
}

/// What a status query returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub agent_version: String,
    /// Whether a relay is attached.
    pub relay: bool,
    /// The current session with the control plane, if any.
    pub session: Option<SessionState>,
}

/// A session of the broker with the control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub protocol: u32,
    /// Unix time of its start.
    pub since: i64,
    /// Whether a frame of the control plane verified in it (what confirms an update, and a migration).
    pub verified: bool,
}

/// Reads one message: None at the end of the stream (before a message starts).
pub async fn read<T: DeserializeOwned, R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<T>, String> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("socket: {e}")),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_MESSAGE_BYTES {
        return Err(format!("message of {n} bytes refused (at most {MAX_MESSAGE_BYTES})"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await.map_err(|e| format!("socket: {e}"))?;
    serde_json::from_slice(&buf).map(Some).map_err(|e| format!("message refused: {e}"))
}

/// Writes one message.
pub async fn write<T: Serialize, W: AsyncWrite + Unpin>(w: &mut W, msg: &T) -> Result<(), String> {
    let body = serde_json::to_vec(msg).expect("messages serialize");
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(format!("message of {} bytes not sent (at most {MAX_MESSAGE_BYTES})", body.len()));
    }
    let len = u32::try_from(body.len()).expect("bounded").to_be_bytes();
    w.write_all(&len).await.map_err(|e| format!("socket: {e}"))?;
    w.write_all(&body).await.map_err(|e| format!("socket: {e}"))?;
    w.flush().await.map_err(|e| format!("socket: {e}"))
}

/// Whether the broker serves a peer whose `SO_PEERCRED` user is `uid`: root (an operator's status query, a relay run
/// by hand) or the relay's user (`relay`, None when that user does not exist).
pub fn peer_allowed(uid: u32, relay: Option<u32>) -> bool {
    uid == 0 || Some(uid) == relay
}

/// The control plane's answer headers as the relay passed them, checked: few, short and valid.
pub fn answer_headers(pairs: &[(String, String)]) -> Result<HeaderMap, String> {
    if pairs.len() > MAX_HEADERS {
        return Err(format!("{} answer headers (at most {MAX_HEADERS})", pairs.len()));
    }
    let mut h = HeaderMap::new();
    for (name, value) in pairs {
        if name.len() > MAX_HEADER_BYTES || value.len() > MAX_HEADER_BYTES {
            return Err("answer header too long".into());
        }
        let n = HeaderName::from_bytes(name.as_bytes()).map_err(|_| format!("invalid answer header name {name:?}"))?;
        let v = HeaderValue::from_str(value).map_err(|_| format!("invalid value of answer header {name}"))?;
        h.append(n, v);
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<Option<T>, String> {
        read(&mut &bytes[..]).await
    }

    fn framed(json: &str) -> Vec<u8> {
        let mut b = (json.len() as u32).to_be_bytes().to_vec();
        b.extend_from_slice(json.as_bytes());
        b
    }

    #[tokio::test]
    async fn messages_round_trip_and_the_stream_ends_cleanly() {
        let msgs = [
            ToBroker::Attach { version: VERSION },
            ToBroker::Status {},
            ToBroker::Answer { headers: vec![("OWDeploy-Protocol".into(), "2".into())] },
            ToBroker::FrameIn { text: "{\"seq\":1}".into() },
            ToBroker::Ended { error: None },
        ];
        let mut buf = Vec::new();
        for m in &msgs {
            write(&mut buf, m).await.unwrap();
        }
        let mut r = &buf[..];
        for m in &msgs {
            assert_eq!(read::<ToBroker, _>(&mut r).await.unwrap().as_ref(), Some(m));
        }
        assert_eq!(read::<ToBroker, _>(&mut r).await.unwrap(), None, "end of stream");
        assert_eq!(decode::<ToBroker>(&framed(r#"{"type":"status"}"#)).await.unwrap(), Some(ToBroker::Status {}));
    }

    /// Nothing outside the protocol gets through: no unknown type (there is no generic «execute»), no unknown field,
    /// no message over the limit (refused from its length, before it is read), no invalid JSON.
    #[tokio::test]
    async fn out_of_protocol_messages_are_refused() {
        for json in [
            r#"{"type":"execute","op":"docker_info"}"#,
            r#"{"type":"command","body":"{}"}"#,
            r#"{"type":"connect","url":"wss://elsewhere"}"#,
            r#"{"type":"frame_in"}"#,
            r#"{"text":"x"}"#,
            "not json",
        ] {
            let e = decode::<ToBroker>(&framed(json)).await.unwrap_err();
            assert!(e.starts_with("message refused"), "{json}: {e}");
        }
        let mut huge = ((MAX_MESSAGE_BYTES + 1) as u32).to_be_bytes().to_vec();
        huge.extend_from_slice(b"{}");
        assert!(decode::<ToBroker>(&huge).await.unwrap_err().contains("refused (at most"));
        // A frame of the largest size the control plane may send, escaped at worst, still fits.
        let text = "\u{1}".repeat(deploy_proto::MAX_FRAME_BYTES);
        let mut buf = Vec::new();
        write(&mut buf, &ToBroker::FrameIn { text: text.clone() }).await.unwrap();
        assert_eq!(decode::<ToBroker>(&buf).await.unwrap(), Some(ToBroker::FrameIn { text }));
    }

    #[test]
    fn only_root_and_the_relay_user_are_served() {
        assert!(peer_allowed(0, Some(998)));
        assert!(peer_allowed(998, Some(998)));
        assert!(peer_allowed(0, None));
        assert!(!peer_allowed(1000, Some(998)), "another user");
        assert!(!peer_allowed(998, None), "no relay user: root only");
        assert!(!peer_allowed(65534, Some(998)), "nobody");
    }

    #[test]
    fn answer_headers_are_bounded_and_valid() {
        let ok = answer_headers(&[("OWDeploy-Protocol".into(), "2".into())]).unwrap();
        assert_eq!(ok.get("owdeploy-protocol").unwrap(), "2");
        let many: Vec<_> = (0..=MAX_HEADERS).map(|i| (format!("x-{i}"), "v".into())).collect();
        assert!(answer_headers(&many).is_err());
        assert!(answer_headers(&[("bad name".into(), "v".into())]).is_err());
        assert!(answer_headers(&[("x".into(), "a\nb".into())]).is_err());
        assert!(answer_headers(&[("x".into(), "v".repeat(MAX_HEADER_BYTES + 1))]).is_err());
    }
}
