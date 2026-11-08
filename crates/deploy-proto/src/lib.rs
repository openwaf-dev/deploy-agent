//! Wire protocol between the OpenWAF Deploy control plane and the agents on servers (PROTOCOL.md).
//!
//! The agent dials the control plane and keeps one WebSocket. Every frame is signed by its sender: the agent with its
//! own Ed25519 key (the control plane stores only the public key), the control plane with its key, whose public half
//! the agent pinned at enrollment. A frame carries a direction, a strictly increasing sequence number and a timestamp,
//! so a frame cannot be replayed, reordered or reflected back to its sender. In protocol v2 ([`session`]) both sides
//! contribute a nonce and an ephemeral X25519 key to the connect handshake, which both sign: every frame's signature
//! also names the session it belongs to, so a frame recorded on one connection never verifies on another, and every
//! frame's body is encrypted with the session's keys, so whoever carries the frames (TLS terminators, the agent's
//! unprivileged relay) reads only their kind, sequence, timestamp and size.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod msg;
pub mod registry;

/// First line of every signed message of protocol v1: its frames and the agent's connect request (in both versions).
pub const CONTEXT: &str = "owdeploy-agent-v1";
/// First line of the signed message of every protocol v2 frame, which names the frame's session ([`session`]).
pub const CONTEXT_V2: &str = "owdeploy-agent-v2";
/// The highest protocol version this build speaks: 1 (frames not bound to a connection) or 2 ([`session`]).
pub const PROTOCOL_VERSION: u32 = 2;
/// Accepted distance between a frame's timestamp and the receiver's clock.
pub const MAX_SKEW_SECS: i64 = 300;
/// Largest frame accepted on the wire (build logs are chunked below this).
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// Version of this build: the crate version, plus `+<build>` when compiled with `OWDEPLOY_BUILD` set (by
/// scripts/build-release.sh, `<ordinal>.<commit>`: see [`version`] for how versions are ordered). The control plane and its
/// agents are built together, so this names what they run.
pub fn build_version() -> String {
    match option_env!("OWDEPLOY_BUILD") {
        Some(b) if !b.is_empty() => format!("{}+{b}", env!("CARGO_PKG_VERSION")),
        _ => env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Who sent a frame. Part of the signed message, so a frame of one direction never verifies in the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    AgentToControl,
    ControlToAgent,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::AgentToControl => "agent-to-control",
            Direction::ControlToAgent => "control-to-agent",
        }
    }
}

/// A frame on the wire. `body` is the JSON of a message kept as a string, so the signature covers its exact bytes; in
/// protocol v2 it is that JSON encrypted for the session, in base64 ([`session::Cipher`]). An opened frame carries
/// the message's JSON in both versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub seq: u64,
    pub ts: i64,
    pub kind: String,
    pub body: String,
    pub sig: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame is not valid JSON")]
    Malformed,
    #[error("frame too large")]
    TooLarge,
    #[error("bad signature")]
    BadSignature,
    #[error("timestamp {0} s away from the local clock")]
    Skew(i64),
    #[error("sequence {got} not after {last}")]
    Replay { got: u64, last: u64 },
    #[error("body does not match kind {0}")]
    Body(String),
    #[error("body does not decrypt with the session's keys")]
    Undecryptable,
}

/// The signed message of a v1 frame (or of the connect request, with `kind` "connect" and `<server id>\n<nonce>` as
/// body).
pub fn signing_message(dir: Direction, seq: u64, ts: i64, kind: &str, body: &[u8]) -> Vec<u8> {
    let digest = hex::encode(Sha256::digest(body));
    format!("{CONTEXT}\n{}\n{seq}\n{ts}\n{kind}\n{digest}", dir.as_str()).into_bytes()
}

/// The first lines of a v2 frame's signing message: [`CONTEXT_V2`], the session id, the direction, the sequence, the
/// timestamp and the kind. They are also the associated data of the frame's encryption ([`session::Cipher`]), so a
/// ciphertext opens only under the header it was sealed with.
pub fn frame_header_v2(session: &session::SessionId, dir: Direction, seq: u64, ts: i64, kind: &str) -> String {
    format!("{CONTEXT_V2}\n{}\n{}\n{seq}\n{ts}\n{kind}", session.to_hex(), dir.as_str())
}

/// The signed message of a v2 frame: its header ([`frame_header_v2`]) and the SHA-256 of its body as on the wire
/// (the ciphertext's base64), so a frame verifies only in its own session and its signature reveals nothing of the
/// message.
pub fn signing_message_v2(
    session: &session::SessionId,
    dir: Direction,
    seq: u64,
    ts: i64,
    kind: &str,
    body: &[u8],
) -> Vec<u8> {
    let digest = hex::encode(Sha256::digest(body));
    format!("{}\n{digest}", frame_header_v2(session, dir, seq, ts, kind)).into_bytes()
}

/// The signed message of a frame: v2 when the frame belongs to a session, else v1.
fn frame_message(
    session: Option<&session::SessionId>,
    dir: Direction,
    seq: u64,
    ts: i64,
    kind: &str,
    body: &[u8],
) -> Vec<u8> {
    match session {
        Some(s) => signing_message_v2(s, dir, seq, ts, kind, body),
        None => signing_message(dir, seq, ts, kind, body),
    }
}

/// Signs outgoing frames with consecutive sequence numbers; in a v2 session, encrypts their bodies first.
pub struct Sealer {
    key: SigningKey,
    dir: Direction,
    next_seq: u64,
    session: Option<session::Cipher>,
}

impl Sealer {
    /// A sealer of v1 frames; [`Sealer::in_session`] makes it seal v2 frames.
    pub fn new(key: SigningKey, dir: Direction) -> Sealer {
        Sealer { key, dir, next_seq: 1, session: None }
    }

    /// Seals v2 frames of the session of `keys`: their bodies are encrypted with its key for this sealer's direction
    /// and their signatures name it.
    pub fn in_session(self, keys: &session::Keys) -> Sealer {
        Sealer { session: Some(keys.cipher(self.dir)), ..self }
    }

    /// Signs the following frames with another key (a control key rotation); the sequence carries on.
    pub fn rekey(&mut self, key: SigningKey) {
        self.key = key;
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn seal<M: Serialize + msg::Kind>(&mut self, msg: &M, now: i64) -> Frame {
        let json = serde_json::to_string(msg).expect("messages serialize");
        let seq = self.next_seq;
        // Never wraps: a sequence (and so an encryption nonce) is never used twice in a session.
        self.next_seq = seq.checked_add(1).expect("frame sequence exhausted");
        let body = match &self.session {
            // The clear message is wiped once encrypted.
            Some(c) => c.seal(seq, now, M::KIND, zeroize::Zeroizing::new(json).as_bytes()),
            None => json,
        };
        let session = self.session.as_ref().map(|c| c.id());
        let sig = self.key.sign(&frame_message(session.as_ref(), self.dir, seq, now, M::KIND, body.as_bytes()));
        Frame { seq, ts: now, kind: M::KIND.to_string(), body, sig: B64.encode(sig.to_bytes()) }
    }
}

/// Checks incoming frames: signature by the peer's key, direction (and session, in v2), clock skew and strictly
/// increasing sequence; in a v2 session, then decrypts their bodies.
pub struct Opener {
    peers: Vec<VerifyingKey>,
    dir: Direction,
    last_seq: u64,
    session: Option<session::Cipher>,
}

impl Opener {
    pub fn new(peer: VerifyingKey, dir: Direction) -> Opener {
        Opener::with_keys(vec![peer], dir)
    }

    /// Accepts frames signed by any of `peers`: during a control key rotation the agent accepts its pinned key and
    /// the announced next one.
    pub fn with_keys(peers: Vec<VerifyingKey>, dir: Direction) -> Opener {
        Opener { peers, dir, last_seq: 0, session: None }
    }

    /// Opens only v2 frames of the session of `keys`: a v1 frame, or a frame of any other session, has a bad
    /// signature, and a body not encrypted with the session's key for this direction does not decrypt.
    pub fn in_session(self, keys: &session::Keys) -> Opener {
        Opener { session: Some(keys.cipher(self.dir)), ..self }
    }

    /// Replaces the accepted keys; the sequence carries on.
    pub fn set_keys(&mut self, peers: Vec<VerifyingKey>) {
        self.peers = peers;
    }

    pub fn open(&mut self, raw: &str, now: i64) -> Result<Frame, FrameError> {
        self.open_keyed(raw, now).map(|(f, _)| f)
    }

    /// Opens a frame and says which of the keys (its index) signed it. In a v2 session the frame's body is the
    /// decrypted message.
    pub fn open_keyed(&mut self, raw: &str, now: i64) -> Result<(Frame, usize), FrameError> {
        if raw.len() > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge);
        }
        let mut f: Frame = serde_json::from_str(raw).map_err(|_| FrameError::Malformed)?;
        let sig =
            B64.decode(&f.sig).ok().and_then(|b| Signature::from_slice(&b).ok()).ok_or(FrameError::BadSignature)?;
        let session = self.session.as_ref().map(|c| c.id());
        let msg = frame_message(session.as_ref(), self.dir, f.seq, f.ts, &f.kind, f.body.as_bytes());
        let which = self.peers.iter().position(|k| k.verify(&msg, &sig).is_ok()).ok_or(FrameError::BadSignature)?;
        if (now - f.ts).abs() > MAX_SKEW_SECS {
            return Err(FrameError::Skew(f.ts - now));
        }
        if f.seq <= self.last_seq {
            return Err(FrameError::Replay { got: f.seq, last: self.last_seq });
        }
        if let Some(c) = &self.session {
            f.body = c.open(f.seq, f.ts, &f.kind, &f.body).ok_or(FrameError::Undecryptable)?;
        }
        self.last_seq = f.seq;
        Ok((f, which))
    }
}

impl Frame {
    /// The message of a frame whose kind is `M::KIND`.
    pub fn decode<M: for<'de> Deserialize<'de> + msg::Kind>(&self) -> Result<M, FrameError> {
        if self.kind != M::KIND {
            return Err(FrameError::Body(self.kind.clone()));
        }
        serde_json::from_str(&self.body).map_err(|_| FrameError::Body(self.kind.clone()))
    }
}

/// Headers of the agent's connect request: the agent proves it holds the host key before the upgrade. The request
/// is signed as in v1 in both versions (a control plane that only speaks v1 checks it); the v2 headers ask for a
/// session ([`crate::session`]) and the control plane's answer to the upgrade carries its half of the handshake. The
/// v2 headers are not covered by the request's signature: both sides sign them in the handshake transcript instead.
pub mod connect {
    pub const HDR_SERVER: &str = "OWDeploy-Server";
    pub const HDR_TIMESTAMP: &str = "OWDeploy-Timestamp";
    pub const HDR_NONCE: &str = "OWDeploy-Nonce";
    pub const HDR_SIGNATURE: &str = "OWDeploy-Signature";
    pub const KIND: &str = "connect";
    /// Request: the highest protocol version the agent speaks (absent: 1). Answer: the version of the session (absent:
    /// 1, a control plane that only speaks v1).
    pub const HDR_PROTOCOL: &str = "OWDeploy-Protocol";
    /// Request (v2): the control keys the agent accepts, comma-separated base64: its pinned control key, then the next
    /// one during a rotation.
    pub const HDR_CONTROL_KEYS: &str = "OWDeploy-Control-Keys";
    /// Request (v2): the agent's ephemeral X25519 public key for this connection (base64 of 32 bytes).
    pub const HDR_EXCHANGE_KEY: &str = "OWDeploy-Exchange-Key";
    /// Answer (v2): the control plane's nonce, 16 random bytes in lowercase hex.
    pub const HDR_CONTROL_NONCE: &str = "OWDeploy-Control-Nonce";
    /// Answer (v2): the control key (base64) that signed the answer and signs the session's first frames.
    pub const HDR_CONTROL_KEY: &str = "OWDeploy-Control-Key";
    /// Answer (v2): that key's signature of the handshake transcript ([`crate::session::Transcript`]).
    pub const HDR_CONTROL_SIGNATURE: &str = "OWDeploy-Control-Signature";
    /// Answer (v2): the control plane's ephemeral X25519 public key for this connection (base64 of 32 bytes).
    pub const HDR_CONTROL_EXCHANGE_KEY: &str = "OWDeploy-Control-Exchange-Key";

    /// A connect nonce as both sides send it: 32 hex characters (16 bytes).
    pub fn valid_nonce(n: &str) -> bool {
        n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit())
    }
}

/// Protocol v2 sessions. The agent's connect request carries its nonce and an ephemeral X25519 key; the control plane
/// answers the upgrade with a nonce and an ephemeral X25519 key of its own and its control key's signature over the
/// handshake [`Transcript`] (protocol version, server id, both nonces, the control key, both exchange keys); the
/// agent checks that signature with a key it pinned, then signs the same transcript in its first frame
/// ([`crate::msg::SessionProof`]). Both nonces are fresh, so the transcript and the [`SessionId`] derived from it are
/// new on every connection, and every frame's signature covers that id ([`signing_message_v2`]): a frame recorded in
/// one session never verifies in another, whatever its sequence number and however recent.
///
/// The exchange keys give the session its [`Keys`]: X25519, then HKDF-SHA256 salted with the session id and bound to
/// the transcript's hash, one ChaCha20-Poly1305 key per direction ([`Cipher`]). Each side signed both exchange keys, so
/// nobody between them (a TLS terminator, the agent's relay) can substitute its own; both secrets are ephemeral and
/// wiped when dropped, so a later theft of either side's long-term keys does not decrypt a recorded session.
pub mod session {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use hkdf::Hkdf;
    use x25519_dalek::EphemeralSecret;
    pub use x25519_dalek::PublicKey as ExchangeKey;
    use zeroize::Zeroizing;

    use super::*;

    /// First line of the hashed input of a [`SessionId`].
    pub const SESSION_CONTEXT: &str = "owdeploy-agent-v2-session";
    /// First line of the handshake transcript each side signs.
    pub const HANDSHAKE_CONTEXT: &str = "owdeploy-agent-v2-handshake";
    /// First line of the hashed transcript the session's keys are bound to ([`Transcript::hash`]).
    pub const TRANSCRIPT_CONTEXT: &str = "owdeploy-agent-v2-transcript";
    /// First line of the HKDF info of each direction's key ([`Keys`]).
    pub const KEYS_CONTEXT: &str = "owdeploy-agent-v2-keys";

    /// The id of a v2 session: SHA-256 of [`SESSION_CONTEXT`], the server id, the agent's nonce and the control plane's
    /// nonce, separated by newlines (none of them can contain one: the server id travels as an HTTP header value, and
    /// nonces are hex).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SessionId([u8; 32]);

    impl SessionId {
        pub fn derive(server_id: &str, agent_nonce: &str, control_nonce: &str) -> SessionId {
            SessionId(Sha256::digest(format!("{SESSION_CONTEXT}\n{server_id}\n{agent_nonce}\n{control_nonce}")).into())
        }

        /// Lowercase hex, as it appears in the signed message of a frame.
        pub fn to_hex(&self) -> String {
            hex::encode(self.0)
        }
    }

    /// What both sides of a v2 handshake sign.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Transcript {
        /// The session's protocol version (2).
        pub protocol: u32,
        pub server_id: String,
        /// The nonce of the agent's connect request.
        pub agent_nonce: String,
        /// The control plane's nonce, from its answer.
        pub control_nonce: String,
        /// The control key that signs the answer, one the agent pinned.
        pub control_key: VerifyingKey,
        /// The agent's ephemeral X25519 key, from its connect request.
        pub agent_exchange: ExchangeKey,
        /// The control plane's ephemeral X25519 key, from its answer.
        pub control_exchange: ExchangeKey,
    }

    impl Transcript {
        /// The session these nonces open.
        pub fn session_id(&self) -> SessionId {
            SessionId::derive(&self.server_id, &self.agent_nonce, &self.control_nonce)
        }

        /// The protocol version, the server id, both nonces, the control key and both exchange keys (base64), one per
        /// line.
        fn fields(&self) -> String {
            format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}",
                self.protocol,
                self.server_id,
                self.agent_nonce,
                self.control_nonce,
                encode_key(&self.control_key),
                encode_exchange_key(&self.agent_exchange),
                encode_exchange_key(&self.control_exchange)
            )
        }

        /// The message `signer` signs: [`HANDSHAKE_CONTEXT`], the signer's direction, then the protocol version, the
        /// server id, both nonces, the control key and the agent's and the control plane's exchange keys (base64), one
        /// per line, without a trailing newline. The direction keeps one side's signature from standing for the
        /// other's.
        pub fn message(&self, signer: Direction) -> Vec<u8> {
            format!("{HANDSHAKE_CONTEXT}\n{}\n{}", signer.as_str(), self.fields()).into_bytes()
        }

        /// SHA-256 of [`TRANSCRIPT_CONTEXT`] and the same fields as [`Transcript::message`] (without a signer).
        pub fn hash(&self) -> [u8; 32] {
            Sha256::digest(format!("{TRANSCRIPT_CONTEXT}\n{}", self.fields())).into()
        }

        pub fn sign(&self, key: &SigningKey, signer: Direction) -> Signature {
            key.sign(&self.message(signer))
        }

        /// Whether `sig` is `key`'s signature of this transcript as `signer` (RFC 8032 with the strict checks).
        pub fn verify(&self, key: &VerifyingKey, signer: Direction, sig: &Signature) -> bool {
            key.verify_strict(&self.message(signer), sig).is_ok()
        }
    }

    /// A fresh handshake nonce: 16 bytes of OS randomness in lowercase hex.
    pub fn nonce() -> String {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("OS randomness");
        hex::encode(b)
    }

    /// Base64 of an exchange key, as in the handshake headers and the transcript.
    pub fn encode_exchange_key(k: &ExchangeKey) -> String {
        B64.encode(k.as_bytes())
    }

    pub fn decode_exchange_key(s: &str) -> Option<ExchangeKey> {
        let b: [u8; 32] = B64.decode(s).ok()?.try_into().ok()?;
        Some(ExchangeKey::from(b))
    }

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum ExchangeError {
        #[error("the transcript does not carry this side's exchange key")]
        NotOurs,
        #[error("the peer's exchange key gives no shared secret (a low-order point)")]
        NonContributory,
    }

    /// One side's ephemeral X25519 key for one handshake: made for a connection, consumed by [`Exchange::finish`]
    /// (or dropped with the connection), wiped either way.
    pub struct Exchange {
        secret: EphemeralSecret,
        public: ExchangeKey,
    }

    impl Exchange {
        /// A new key from OS randomness.
        pub fn generate() -> Exchange {
            let secret = EphemeralSecret::random();
            let public = ExchangeKey::from(&secret);
            Exchange { secret, public }
        }

        pub fn public_key(&self) -> ExchangeKey {
            self.public
        }

        /// The session's keys, once `t` is the transcript both sides sign: `side` is the direction this side sends,
        /// its own exchange key must be the transcript's for that side, and the peer's is the other one. Fails on a
        /// peer key of low order, which would make the shared secret known to anyone.
        pub fn finish(self, t: &Transcript, side: Direction) -> Result<Keys, ExchangeError> {
            let (own, peer) = match side {
                Direction::AgentToControl => (t.agent_exchange, t.control_exchange),
                Direction::ControlToAgent => (t.control_exchange, t.agent_exchange),
            };
            if own != self.public {
                return Err(ExchangeError::NotOurs);
            }
            let shared = self.secret.diffie_hellman(&peer);
            if !shared.was_contributory() {
                return Err(ExchangeError::NonContributory);
            }
            Ok(Keys::derive(t, shared.as_bytes()))
        }
    }

    /// The keys of a v2 session: for each direction, HKDF-SHA256 with the session id as salt and the X25519 shared
    /// secret as input, expanded with the info `owdeploy-agent-v2-keys\n<direction>\n` followed by the 32 bytes of
    /// [`Transcript::hash`]. Held only while the session's [`Sealer`] and [`Opener`] are made from them, wiped when
    /// dropped.
    pub struct Keys {
        id: SessionId,
        agent_to_control: Zeroizing<[u8; 32]>,
        control_to_agent: Zeroizing<[u8; 32]>,
    }

    impl std::fmt::Debug for Keys {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Keys({}, …)", self.id.to_hex())
        }
    }

    impl Keys {
        pub(crate) fn derive(t: &Transcript, shared: &[u8; 32]) -> Keys {
            let id = t.session_id();
            let hash = t.hash();
            let hk = Hkdf::<Sha256>::new(Some(&id.0), shared);
            let key = |dir: Direction| {
                let mut k = Zeroizing::new([0u8; 32]);
                let info: [&[u8]; 5] = [KEYS_CONTEXT.as_bytes(), b"\n", dir.as_str().as_bytes(), b"\n", &hash];
                hk.expand_multi_info(&info, k.as_mut_slice()).expect("32 bytes is a valid HKDF-SHA256 output");
                k
            };
            Keys {
                id,
                agent_to_control: key(Direction::AgentToControl),
                control_to_agent: key(Direction::ControlToAgent),
            }
        }

        pub fn id(&self) -> SessionId {
            self.id
        }

        /// The cipher of the frames sent in direction `dir`.
        pub fn cipher(&self, dir: Direction) -> Cipher {
            let key = match dir {
                Direction::AgentToControl => &self.agent_to_control,
                Direction::ControlToAgent => &self.control_to_agent,
            };
            let aead = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("a 32-byte key");
            Cipher { id: self.id, dir, aead }
        }
    }

    /// The two ends of a v2 handshake once it verified: its transcript (which the agent proves in its first frame)
    /// and the session's keys.
    #[derive(Debug)]
    pub struct Session {
        pub transcript: Transcript,
        pub keys: Keys,
    }

    /// ChaCha20-Poly1305 for the frames of one direction of a session. The 96-bit nonce is the direction (4 bytes,
    /// big-endian: 1 agent-to-control, 2 control-to-agent) and the frame's sequence (8 bytes, big-endian): a sealer's
    /// sequence only goes up, so a nonce is never used twice with a key. The associated data is the frame's header
    /// ([`frame_header_v2`]): session id, direction, sequence, timestamp and kind.
    pub struct Cipher {
        id: SessionId,
        dir: Direction,
        aead: ChaCha20Poly1305,
    }

    impl Cipher {
        pub fn id(&self) -> SessionId {
            self.id
        }

        /// The nonce of the frame of sequence `seq` in direction `dir`.
        pub fn nonce(dir: Direction, seq: u64) -> [u8; 12] {
            let tag: u32 = match dir {
                Direction::AgentToControl => 1,
                Direction::ControlToAgent => 2,
            };
            let mut n = [0u8; 12];
            n[..4].copy_from_slice(&tag.to_be_bytes());
            n[4..].copy_from_slice(&seq.to_be_bytes());
            n
        }

        /// The base64 ciphertext (with its 16-byte tag) of `plaintext` as the body of the frame `seq`, `ts`, `kind`.
        pub fn seal(&self, seq: u64, ts: i64, kind: &str, plaintext: &[u8]) -> String {
            let aad = frame_header_v2(&self.id, self.dir, seq, ts, kind);
            let nonce = Nonce::from(Cipher::nonce(self.dir, seq));
            let ct = self.aead.encrypt(&nonce, Payload { msg: plaintext, aad: aad.as_bytes() }).expect("frame sizes");
            B64.encode(ct)
        }

        /// The plaintext of a frame's `body`: None when it is not base64, was sealed under another key or header, or
        /// was changed, or is not UTF-8.
        pub fn open(&self, seq: u64, ts: i64, kind: &str, body: &str) -> Option<String> {
            let ct = B64.decode(body).ok()?;
            let aad = frame_header_v2(&self.id, self.dir, seq, ts, kind);
            let nonce = Nonce::from(Cipher::nonce(self.dir, seq));
            let pt = self.aead.decrypt(&nonce, Payload { msg: &ct, aad: aad.as_bytes() }).ok()?;
            String::from_utf8(pt).ok()
        }
    }
}

/// Base64 of a public key, as stored and exchanged.
pub fn encode_key(k: &VerifyingKey) -> String {
    B64.encode(k.to_bytes())
}

pub fn decode_key(s: &str) -> Option<VerifyingKey> {
    let b: [u8; 32] = B64.decode(s).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&b).ok()
}

pub fn encode_signature(s: &Signature) -> String {
    B64.encode(s.to_bytes())
}

pub fn decode_signature(s: &str) -> Option<Signature> {
    Signature::from_slice(&B64.decode(s).ok()?).ok()
}

/// A new random signing key.
pub fn generate_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS randomness");
    SigningKey::from_bytes(&seed)
}

/// Agent self-update (PROTOCOL.md). Besides the frame's own signature, the control plane signs the exact
/// binary it offers under a context of its own, so a signature over one binary can never stand for another, and the
/// agent installs only bytes whose SHA-256 is the signed one.
///
/// Two signed forms exist. v1 — `(target, version, sha256)` signed by the control key — is what agents before
/// [`crate::msg::feature::UPDATE_KEY`] understand. v2 adds whether the offer allows a downgrade and until when it is
/// valid (`expires_at`), and is signed by the update key: a key of its own, which agents pin (at enrollment, or once
/// from an [`UpdateKey`] announcement) and from then on require, so the control key alone can no longer replace
/// their binary. A control plane without an update key signs v2 with its control key, which agents that pinned no
/// update key accept.
///
/// Independently of both, a release can carry a detached signature by the offline release key
/// ([`release_message`]): made on the operator's machine (OpenSSL) when the binary is released,
/// never on the control plane, which only serves it. An agent that pinned the release key installs only binaries
/// signed by it, so even a control plane holding every online key cannot hand it a binary that was not released.
pub mod update {
    use super::*;
    use crate::msg::{AgentUpdate, UpdateKey};

    /// First line of the signed v1 update message.
    pub const CONTEXT: &str = "owdeploy-agent-update-v1";
    /// First line of the signed v2 update message.
    pub const CONTEXT_V2: &str = "owdeploy-agent-update-v2";
    /// First line of the message by which a pinned update key hands over to its successor.
    pub const KEY_CONTEXT: &str = "owdeploy-update-key-v1";
    /// First line of the message a release signature covers.
    pub const RELEASE_CONTEXT: &str = "owdeploy-agent-release-v1";
    /// How long a v2 offer stays valid: a recorded offer (notably one allowing a downgrade) cannot be replayed later.
    pub const OFFER_TTL_SECS: i64 = 3600;
    /// Targets the control plane serves at `/v1/agent/binary/{target}`.
    pub const TARGETS: [&str; 2] = ["linux-amd64", "linux-arm64"];

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum UpdateError {
        #[error("invalid {0}")]
        Invalid(&'static str),
        #[error("bad update signature")]
        BadSignature,
    }

    /// The binary target of a machine architecture (`uname -m` or Rust's `std::env::consts::ARCH`).
    pub fn target_of(arch: &str) -> Option<&'static str> {
        match arch {
            "x86_64" | "amd64" => Some(TARGETS[0]),
            "aarch64" | "arm64" => Some(TARGETS[1]),
            _ => None,
        }
    }

    /// Checks the fields that go into the signed message: none can contain its separator.
    fn check(target: &str, version: &str, sha256: &str) -> Result<(), UpdateError> {
        if !TARGETS.contains(&target) {
            return Err(UpdateError::Invalid("target"));
        }
        let version_ok = !version.is_empty()
            && version.len() <= 64
            && version.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'));
        if !version_ok {
            return Err(UpdateError::Invalid("version"));
        }
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(UpdateError::Invalid("sha256"));
        }
        Ok(())
    }

    /// The signed message of an offer: v2 when it has an expiry, else v1 (where `allow_downgrade` is not signed).
    pub fn message(u: &AgentUpdate) -> Vec<u8> {
        let (t, v, s) = (&u.target, &u.version, &u.sha256);
        match u.expires_at {
            None => format!("{CONTEXT}\n{t}\n{v}\n{s}").into_bytes(),
            Some(exp) => format!("{CONTEXT_V2}\n{t}\n{v}\n{s}\n{}\n{exp}", u8::from(u.allow_downgrade)).into_bytes(),
        }
    }

    /// A v1 offer of a binary, signed by the control key (agents before `update_key`).
    pub fn offer(key: &SigningKey, target: &str, version: &str, sha256: &str, force: bool) -> AgentUpdate {
        let mut u = AgentUpdate {
            target: target.into(),
            version: version.into(),
            sha256: sha256.into(),
            signature: String::new(),
            force,
            allow_downgrade: false,
            expires_at: None,
            release_signature: None,
        };
        u.signature = encode_signature(&key.sign(&message(&u)));
        u
    }

    /// A v2 offer, valid until `expires_at` (Unix time). `allow_downgrade` lets the agent install a version that is
    /// not newer than its own, together with `force` (an administrator's request).
    pub fn offer_v2(key: &SigningKey, base: &AgentUpdate, allow_downgrade: bool, expires_at: i64) -> AgentUpdate {
        let mut u =
            AgentUpdate { allow_downgrade, expires_at: Some(expires_at), signature: String::new(), ..base.clone() };
        u.signature = encode_signature(&key.sign(&message(&u)));
        u
    }

    /// Checks an offer: well-formed fields and a signature by `key` over exactly them (v1 or v2).
    pub fn verify(key: &VerifyingKey, u: &AgentUpdate) -> Result<(), UpdateError> {
        check(&u.target, &u.version, &u.sha256)?;
        let sig = decode_signature(&u.signature).ok_or(UpdateError::BadSignature)?;
        key.verify_strict(&message(u), &sig).map_err(|_| UpdateError::BadSignature)
    }

    /// Whether a verified offer lets the agent install a version that is not newer than its own: only a signed v2
    /// `allow_downgrade` with an administrator's `force`.
    pub fn allows_downgrade(u: &AgentUpdate) -> bool {
        u.expires_at.is_some() && u.allow_downgrade && u.force
    }

    /// The message the offline release key signs for a binary: its target, version and SHA-256 (hex). The version is
    /// signed so that an old, signed binary cannot be offered as a newer one (agents refuse downgrades by version).
    pub fn release_message(target: &str, version: &str, sha256: &str) -> Result<Vec<u8>, UpdateError> {
        check(target, version, sha256)?;
        Ok(format!("{RELEASE_CONTEXT}\n{target}\n{version}\n{sha256}\n").into_bytes())
    }

    /// Signs a release (tests; production signatures are made on the operator's machine with OpenSSL, over the same
    /// bytes).
    pub fn sign_release(key: &SigningKey, target: &str, version: &str, sha256: &str) -> Result<String, UpdateError> {
        Ok(encode_signature(&key.sign(&release_message(target, version, sha256)?)))
    }

    /// Checks that `signature` is the release key's over `(target, version, sha256)`.
    pub fn verify_release_signature(
        key: &VerifyingKey,
        target: &str,
        version: &str,
        sha256: &str,
        signature: &str,
    ) -> Result<(), UpdateError> {
        let msg = release_message(target, version, sha256)?;
        let sig = decode_signature(signature).ok_or(UpdateError::BadSignature)?;
        key.verify_strict(&msg, &sig).map_err(|_| UpdateError::BadSignature)
    }

    /// Checks an offer's release signature against the pinned release key: required, and over exactly the offered
    /// target, version and SHA-256.
    pub fn verify_release(key: &VerifyingKey, u: &AgentUpdate) -> Result<(), UpdateError> {
        let sig = u.release_signature.as_deref().ok_or(UpdateError::Invalid("release signature (missing)"))?;
        verify_release_signature(key, &u.target, &u.version, &u.sha256, sig)
    }

    fn key_message(public_key: &str) -> Vec<u8> {
        format!("{KEY_CONTEXT}\n{public_key}").into_bytes()
    }

    /// The announcement of the update key `new`. `previous`: the update key agents may have pinned, which signs the
    /// handover (agents that pinned none accept the announcement on the strength of its control-key frame alone).
    pub fn announce(new: &VerifyingKey, previous: Option<&SigningKey>) -> UpdateKey {
        let public_key = encode_key(new);
        let signature = previous.map(|p| encode_signature(&p.sign(&key_message(&public_key))));
        UpdateKey { public_key, signature }
    }

    /// The update key an announcement hands over to, when signed by the `pinned` one.
    pub fn verify_handover(pinned: &VerifyingKey, m: &UpdateKey) -> Result<VerifyingKey, UpdateError> {
        let new = decode_key(&m.public_key).ok_or(UpdateError::Invalid("public_key"))?;
        let sig = m.signature.as_deref().and_then(decode_signature).ok_or(UpdateError::BadSignature)?;
        pinned.verify_strict(&key_message(&m.public_key), &sig).map_err(|_| UpdateError::BadSignature)?;
        Ok(new)
    }
}

/// Order of agent versions, for anti-downgrade. A version is `<major>.<minor>.<patch>[-<pre>][+<build>]`; versions
/// compare by SemVer precedence (a pre-release before its release), then by the build ordinal: the leading number of
/// build metadata `+<ordinal>.<tag>`, which scripts/build-release.sh sets from BUILD_ORDINAL, a number that
/// grows with every release (README.md). Build metadata without an
/// ordinal (`+<commit>` of earlier builds) comes before any ordinal; two versions equal in all of this are equal, so
/// neither is newer.
pub mod version {
    use std::cmp::Ordering;

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    enum Ident {
        Num(u64),
        Alpha(String),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Version {
        core: [u64; 3],
        pre: Vec<Ident>,
        build: Option<u64>,
    }

    impl Version {
        /// The build ordinal, when the version has one.
        pub fn build(&self) -> Option<u64> {
            self.build
        }
    }

    pub fn parse(s: &str) -> Option<Version> {
        let (main, build) = match s.split_once('+') {
            Some((m, b)) => (m, Some(b)),
            None => (s, None),
        };
        let (core, pre) = match main.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (main, None),
        };
        let num = |p: &str| p.bytes().all(|b| b.is_ascii_digit()).then(|| p.parse::<u64>().ok()).flatten();
        let mut parts = core.split('.');
        let core = [num(parts.next()?)?, num(parts.next()?)?, num(parts.next()?)?];
        if parts.next().is_some() {
            return None;
        }
        let ident = |p: &str| match num(p) {
            Some(n) => Some(Ident::Num(n)),
            None if !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') => {
                Some(Ident::Alpha(p.into()))
            }
            None => None,
        };
        let pre = match pre {
            Some(p) => p.split('.').map(ident).collect::<Option<Vec<_>>>()?,
            None => Vec::new(),
        };
        let build = match build.map(|b| b.split_once('.')) {
            Some(Some((first, rest))) if !rest.is_empty() && first.bytes().all(|b| b.is_ascii_digit()) => {
                Some(num(first)?)
            }
            _ => None,
        };
        Some(Version { core, pre, build })
    }

    impl Ord for Version {
        fn cmp(&self, o: &Version) -> Ordering {
            let pre = match (self.pre.is_empty(), o.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&o.pre),
            };
            self.core.cmp(&o.core).then(pre).then(self.build.cmp(&o.build))
        }
    }

    impl PartialOrd for Version {
        fn partial_cmp(&self, o: &Version) -> Option<Ordering> {
            Some(self.cmp(o))
        }
    }

    /// Whether `offered` is strictly newer than `running`; None when either is not a version.
    pub fn is_newer(offered: &str, running: &str) -> Option<bool> {
        Some(parse(offered)? > parse(running)?)
    }
}

#[cfg(test)]
mod tests {
    use super::msg::{AgentUpdate, Ping, Pong};
    use super::*;

    fn pair() -> (Sealer, Opener, SigningKey) {
        let k = generate_key();
        (
            Sealer::new(k.clone(), Direction::AgentToControl),
            Opener::new(k.verifying_key(), Direction::AgentToControl),
            k,
        )
    }

    #[test]
    fn sealed_frames_open_in_order_once() {
        let (mut s, mut o, _) = pair();
        let f1 = serde_json::to_string(&s.seal(&Ping { nonce: 1 }, 1000)).unwrap();
        let f2 = serde_json::to_string(&s.seal(&Ping { nonce: 2 }, 1001)).unwrap();
        assert_eq!(o.open(&f1, 1000).unwrap().decode::<Ping>().unwrap().nonce, 1);
        assert_eq!(o.open(&f2, 1001).unwrap().seq, 2);
        assert_eq!(o.open(&f1, 1001), Err(FrameError::Replay { got: 1, last: 2 }), "a replayed frame is refused");
    }

    #[test]
    fn tampering_direction_and_clock() {
        let (mut s, mut o, k) = pair();
        let mut f = s.seal(&Ping { nonce: 7 }, 1000);
        f.body = r#"{"nonce":8}"#.into();
        assert_eq!(o.open(&serde_json::to_string(&f).unwrap(), 1000), Err(FrameError::BadSignature));
        // A frame signed for the other direction (reflected back) does not verify.
        let mut back = Sealer::new(k, Direction::ControlToAgent);
        let r = serde_json::to_string(&back.seal(&Ping { nonce: 1 }, 1000)).unwrap();
        assert_eq!(o.open(&r, 1000), Err(FrameError::BadSignature));
        let late = serde_json::to_string(&s.seal(&Ping { nonce: 9 }, 1000)).unwrap();
        assert_eq!(o.open(&late, 1000 + MAX_SKEW_SECS + 1), Err(FrameError::Skew(-MAX_SKEW_SECS - 1)));
    }

    #[test]
    fn decode_checks_the_kind_and_keys_roundtrip() {
        let (mut s, mut o, k) = pair();
        let f = o.open(&serde_json::to_string(&s.seal(&Ping { nonce: 3 }, 5)).unwrap(), 5).unwrap();
        assert!(f.decode::<Pong>().is_err());
        assert_eq!(decode_key(&encode_key(&k.verifying_key())), Some(k.verifying_key()));
        assert!(decode_key("AAAA").is_none());
    }

    #[test]
    fn update_offers_verify_only_with_the_control_key_and_their_exact_binary() {
        let control = generate_key();
        let sha = "ab".repeat(32);
        let u = update::offer(&control, "linux-amd64", "0.2.0+abc1234", &sha, false);
        assert_eq!(update::verify(&control.verifying_key(), &u), Ok(()));
        // Another key (an attacker's, or the agent's own) does not verify.
        assert_eq!(update::verify(&generate_key().verifying_key(), &u), Err(update::UpdateError::BadSignature));
        // The signature binds the SHA-256, the target and the version.
        let other_sha = AgentUpdate { sha256: "cd".repeat(32), ..u.clone() };
        assert_eq!(update::verify(&control.verifying_key(), &other_sha), Err(update::UpdateError::BadSignature));
        let other_target = AgentUpdate { target: "linux-arm64".into(), ..u.clone() };
        assert_eq!(update::verify(&control.verifying_key(), &other_target), Err(update::UpdateError::BadSignature));
        let other_version = AgentUpdate { version: "0.2.1".into(), ..u.clone() };
        assert_eq!(update::verify(&control.verifying_key(), &other_version), Err(update::UpdateError::BadSignature));
        // A frame signature does not stand for an update signature: different contexts.
        let frame_sig = control.sign(&signing_message(Direction::ControlToAgent, 1, 0, "agent_update", sha.as_bytes()));
        let reused = AgentUpdate { signature: encode_signature(&frame_sig), ..u.clone() };
        assert_eq!(update::verify(&control.verifying_key(), &reused), Err(update::UpdateError::BadSignature));
        // Malformed fields are refused before the signature is looked at, even when signed.
        for (t, v, s, what) in [
            ("linux-mips", "1", sha.as_str(), "target"),
            ("linux-amd64", "1\nx", sha.as_str(), "version"),
            ("linux-amd64", "", sha.as_str(), "version"),
            ("linux-amd64", "1", "AB", "sha256"),
            ("linux-amd64", "1", &"AB".repeat(32), "sha256"),
        ] {
            let bad = update::offer(&control, t, v, s, false);
            assert_eq!(update::verify(&control.verifying_key(), &bad), Err(update::UpdateError::Invalid(what)));
        }
        assert_eq!(update::target_of("aarch64"), Some("linux-arm64"));
        assert_eq!(update::target_of("riscv64"), None);
    }

    /// A release signature made with OpenSSL (as the operator's signing script does) verifies here: both sign the
    /// same bytes as `release_message`.
    #[test]
    fn release_signatures_of_the_signing_script_verify() {
        let key = decode_key("1pfB405Rj3qZOB0AgpT249ayzxxh06n3Jc/MWCCE5mU=").unwrap();
        let (target, version) = ("linux-amd64", "0.1.0+700.abc1234");
        let sha = "f56251ef925773aac9611d763a3a5e95425032a7d8c0f2c2df3d530c679f9c3a";
        let sig = "/dB0+TEoSbo623LyutvXqk6yG5fnYOZzZX4rYL0Q6aDEoHbvA362QZ+MJmYGFZX38vE0qKpzHvAPdw86aUkkDQ==";
        assert_eq!(update::verify_release_signature(&key, target, version, sha, sig), Ok(()));
        let bad = Err(update::UpdateError::BadSignature);
        assert_eq!(update::verify_release_signature(&key, "linux-arm64", version, sha, sig), bad);
        assert_eq!(update::verify_release_signature(&key, target, "0.1.0+701.abc1234", sha, sig), bad);
        assert_eq!(update::verify_release_signature(&key, target, version, &"ab".repeat(32), sig), bad);
    }

    /// An offer's release signature must be the release key's over the offered binary: missing, by another key (the
    /// update or control key the control plane holds) or for another binary or version, it is refused.
    #[test]
    fn offers_carry_the_release_keys_signature_of_their_exact_binary() {
        let (release, update_key) = (generate_key(), generate_key());
        let sha = "ab".repeat(32);
        let base = update::offer(&update_key, "linux-amd64", "0.2.0+90.abc1234", &sha, false);
        let mut u = update::offer_v2(&update_key, &base, false, 5000);
        assert_eq!(
            update::verify_release(&release.verifying_key(), &u),
            Err(update::UpdateError::Invalid("release signature (missing)"))
        );
        u.release_signature = Some(update::sign_release(&release, &u.target, &u.version, &u.sha256).unwrap());
        assert_eq!(update::verify_release(&release.verifying_key(), &u), Ok(()));
        let by_update_key = update::sign_release(&update_key, &u.target, &u.version, &u.sha256).unwrap();
        let forged = AgentUpdate { release_signature: Some(by_update_key), ..u.clone() };
        assert_eq!(update::verify_release(&release.verifying_key(), &forged), Err(update::UpdateError::BadSignature));
        // The release signature of an old binary does not stand for a newer version (a downgrade in disguise).
        let relabelled = AgentUpdate { version: "0.3.0+99.abc1234".into(), ..u.clone() };
        assert_eq!(
            update::verify_release(&release.verifying_key(), &relabelled),
            Err(update::UpdateError::BadSignature)
        );
        // An offer signature does not stand for a release signature: different contexts.
        let reused = AgentUpdate { release_signature: Some(u.signature.clone()), ..u.clone() };
        assert_eq!(update::verify_release(&release.verifying_key(), &reused), Err(update::UpdateError::BadSignature));
        // Old agents ignore the field: the offer's own signature does not cover it.
        assert_eq!(update::verify(&update_key.verifying_key(), &u), Ok(()));
    }

    /// v2 also binds the downgrade permission and the expiry: neither can be changed or stripped (stripping the
    /// expiry makes it a v1 message, which the v2 signature does not cover).
    #[test]
    fn v2_offers_bind_downgrade_and_expiry() {
        let key = generate_key();
        let base = update::offer(&key, "linux-amd64", "0.1.0+5.abc", &"ab".repeat(32), true);
        let u = update::offer_v2(&key, &base, false, 2000);
        assert_eq!(update::verify(&key.verifying_key(), &u), Ok(()));
        assert!(!update::allows_downgrade(&u));
        for tampered in [
            AgentUpdate { allow_downgrade: true, ..u.clone() },
            AgentUpdate { expires_at: Some(9999), ..u.clone() },
            AgentUpdate { expires_at: None, ..u.clone() },
        ] {
            assert_eq!(update::verify(&key.verifying_key(), &tampered), Err(update::UpdateError::BadSignature));
        }
        let down = update::offer_v2(&key, &base, true, 2000);
        assert!(update::allows_downgrade(&down));
        assert!(!update::allows_downgrade(&AgentUpdate { force: false, ..down.clone() }), "needs an admin's force");
        // A v1 offer never allows a downgrade: its flag is not signed.
        assert!(!update::allows_downgrade(&AgentUpdate { allow_downgrade: true, ..base }));
    }

    #[test]
    fn versions_order_by_semver_then_build_ordinal() {
        use version::is_newer;
        assert_eq!(is_newer("0.1.0+68.abc1234", "0.1.0+67536ac"), Some(true), "an ordinal beats a bare commit");
        assert_eq!(is_newer("0.1.0+67536ac", "0.1.0+68.abc1234"), Some(false));
        assert_eq!(is_newer("0.1.0+69.aaa", "0.1.0+68.bbb"), Some(true));
        assert_eq!(is_newer("0.1.0+100.aaa", "0.1.0+99.bbb"), Some(true), "ordinals compare as numbers");
        assert_eq!(is_newer("0.1.0+68.aaa", "0.1.0+68.bbb"), Some(false), "same ordinal: not newer");
        assert_eq!(is_newer("0.1.0+68.aaa", "0.1.0+68.aaa"), Some(false));
        assert_eq!(is_newer("0.2.0+1.aaa", "0.1.9+500.bbb"), Some(true), "the semantic version first");
        assert_eq!(is_newer("0.10.0", "0.9.0"), Some(true));
        assert_eq!(is_newer("1.0.0-rc.1+9.a", "1.0.0+1.b"), Some(false), "a pre-release precedes its release");
        assert_eq!(is_newer("1.0.0-rc.10", "1.0.0-rc.9"), Some(true));
        assert_eq!(is_newer("1.0.0-rc", "1.0.0-1"), Some(true), "alphanumeric identifiers after numeric ones");
        assert_eq!(is_newer("0.1.0+1234567", "0.1.0+67536ac"), Some(false), "a numeric commit is not an ordinal");
        assert_eq!(is_newer("0.2.0+new", "0.1.0"), Some(true));
        for bad in ["1", "1.2", "1.2.3.4", "a.b.c", "1.2.3-", "1.2.3-a..b", "1.2.3+99999999999999999999.a"] {
            assert_eq!(is_newer(bad, "0.1.0"), None, "{bad}");
        }
    }

    /// During a rotation the agent opens frames signed by its control key or the announced next one and learns which;
    /// a control plane switching keys keeps its sequence.
    #[test]
    fn openers_with_two_keys_say_which_signed() {
        let (old, new, stranger) = (generate_key(), generate_key(), generate_key());
        let mut s = Sealer::new(old.clone(), Direction::ControlToAgent);
        let mut o = Opener::with_keys(vec![old.verifying_key(), new.verifying_key()], Direction::ControlToAgent);
        let f = serde_json::to_string(&s.seal(&Ping { nonce: 1 }, 10)).unwrap();
        assert_eq!(o.open_keyed(&f, 10).unwrap().1, 0);
        s.rekey(new.clone());
        assert_eq!(s.verifying_key(), new.verifying_key());
        let f = serde_json::to_string(&s.seal(&Ping { nonce: 2 }, 10)).unwrap();
        let (f, which) = o.open_keyed(&f, 10).unwrap();
        assert_eq!((f.seq, which), (2, 1));
        o.set_keys(vec![new.verifying_key()]);
        let mut s_old = Sealer::new(old, Direction::ControlToAgent);
        let mut s_stranger = Sealer::new(stranger, Direction::ControlToAgent);
        for _ in 0..3 {
            let _ = (s_old.seal(&Ping { nonce: 0 }, 10), s_stranger.seal(&Ping { nonce: 0 }, 10));
        }
        let by_old = serde_json::to_string(&s_old.seal(&Ping { nonce: 3 }, 10)).unwrap();
        assert_eq!(o.open_keyed(&by_old, 10).err(), Some(FrameError::BadSignature), "the old key is dropped");
        let by_stranger = serde_json::to_string(&s_stranger.seal(&Ping { nonce: 3 }, 10)).unwrap();
        assert_eq!(o.open_keyed(&by_stranger, 10).err(), Some(FrameError::BadSignature));
    }

    #[test]
    fn update_key_handover_needs_the_pinned_key() {
        let (pinned, next, other) = (generate_key(), generate_key(), generate_key());
        let m = update::announce(&next.verifying_key(), Some(&pinned));
        assert_eq!(update::verify_handover(&pinned.verifying_key(), &m), Ok(next.verifying_key()));
        let by_other = update::announce(&next.verifying_key(), Some(&other));
        assert_eq!(update::verify_handover(&pinned.verifying_key(), &by_other), Err(update::UpdateError::BadSignature));
        let unsigned = update::announce(&next.verifying_key(), None);
        assert_eq!(update::verify_handover(&pinned.verifying_key(), &unsigned), Err(update::UpdateError::BadSignature));
        let swapped = msg::UpdateKey { public_key: encode_key(&other.verifying_key()), ..m };
        assert_eq!(update::verify_handover(&pinned.verifying_key(), &swapped), Err(update::UpdateError::BadSignature));
    }

    const AGENT_NONCE: &str = "00112233445566778899aabbccddeeff";
    const CONTROL_NONCE: &str = "ffeeddccbbaa99887766554433221100";

    /// A transcript with fixed nonces and exchange keys (32 bytes of 0x11 for the agent, 0x22 for the control plane).
    fn transcript(control: &SigningKey) -> session::Transcript {
        session::Transcript {
            protocol: 2,
            server_id: "srv_1".into(),
            agent_nonce: AGENT_NONCE.into(),
            control_nonce: CONTROL_NONCE.into(),
            control_key: control.verifying_key(),
            agent_exchange: session::ExchangeKey::from([0x11; 32]),
            control_exchange: session::ExchangeKey::from([0x22; 32]),
        }
    }

    /// A complete key exchange with fresh keys and `control_nonce`: the transcript, then the agent's and the control
    /// plane's session keys.
    fn handshake(control: &SigningKey, control_nonce: &str) -> (session::Transcript, session::Keys, session::Keys) {
        let (a, c) = (session::Exchange::generate(), session::Exchange::generate());
        let t = session::Transcript {
            control_nonce: control_nonce.into(),
            agent_exchange: a.public_key(),
            control_exchange: c.public_key(),
            ..transcript(control)
        };
        let agent = a.finish(&t, Direction::AgentToControl).unwrap();
        let ctl = c.finish(&t, Direction::ControlToAgent).unwrap();
        (t, agent, ctl)
    }

    /// A deployment carrying every kind of secret the control plane sends: variables, a Git token, a deploy key and a
    /// file mount, each holding `secret`.
    fn deployment(secret: &str) -> msg::Command {
        use msg::*;
        let op = Op::DeployApp(AppDeploy {
            resource: "app_01".into(),
            deployment: "dep_01".into(),
            network: "owd-env".into(),
            alias: "web".into(),
            source: Source::Git {
                url: "https://github.com/o/r".into(),
                reference: "main".into(),
                auth: Some(GitAuth { username: "x-access-token".into(), token: format!("ghs_{secret}") }),
                ssh: Some(SshAuth { private_key: format!("-----{secret}-----"), known_hosts: vec![] }),
                commit: None,
            },
            build: None,
            run: RunSpec {
                image_tag: "owd/app_01:dep_01".into(),
                env: [("DATABASE_URL".to_string(), format!("postgres://u:{secret}@db/app"))].into(),
                port: 3000,
                publish: Some(20001),
                health: None,
                command: None,
                memory_bytes: None,
                cpus: None,
                labels: Default::default(),
                volumes: vec![],
                files: vec![FileMount { path: "/etc/app.conf".into(), content: secret.into(), service: None }],
            },
            routes: None,
            drain_secs: None,
        });
        Command { id: "cmd_1".into(), op }
    }

    /// The signed messages are the wire format other implementations (and agents already deployed) sign: v1 must not
    /// change, and v2 is the one PROTOCOL.md documents.
    #[test]
    fn signing_messages_keep_their_documented_bytes() {
        let body = br#"{"nonce":1}"#;
        let digest = "015c56323a283d5727a00db50dd2d1f310efa12c5a804e945880d910664f177b";
        assert_eq!(
            String::from_utf8(signing_message(Direction::AgentToControl, 1, 1000, "ping", body)).unwrap(),
            format!("owdeploy-agent-v1\nagent-to-control\n1\n1000\nping\n{digest}")
        );
        let sid = session::SessionId::derive("srv_1", AGENT_NONCE, CONTROL_NONCE);
        let sid_hex = "81de2a0266cff84319aea21955ccd26a25a68ab176a873f3088f7b03a3b106da";
        assert_eq!(sid.to_hex(), sid_hex, "SHA-256 of the session context, server id and nonces, one per line");
        assert_eq!(
            String::from_utf8(signing_message_v2(&sid, Direction::ControlToAgent, 1, 1000, "ping", body)).unwrap(),
            format!("owdeploy-agent-v2\n{sid_hex}\ncontrol-to-agent\n1\n1000\nping\n{digest}")
        );
        assert_eq!(
            frame_header_v2(&sid, Direction::AgentToControl, 7, 1000, "hello"),
            format!("owdeploy-agent-v2\n{sid_hex}\nagent-to-control\n7\n1000\nhello"),
            "the associated data of a frame's encryption"
        );
    }

    /// The key schedule and the frame encryption PROTOCOL.md documents, checked against values computed independently
    /// from that description (Python's `cryptography`: HKDF-SHA256, ChaCha20-Poly1305) with a fixed shared secret.
    #[test]
    fn session_keys_and_ciphertexts_keep_their_documented_bytes() {
        let control = SigningKey::from_bytes(&[0x44; 32]);
        let t = transcript(&control);
        assert_eq!(session::encode_exchange_key(&t.agent_exchange), "ERERERERERERERERERERERERERERERERERERERERERE=");
        assert_eq!(
            String::from_utf8(t.message(Direction::ControlToAgent)).unwrap(),
            format!(
                "owdeploy-agent-v2-handshake\ncontrol-to-agent\n2\nsrv_1\n{AGENT_NONCE}\n{CONTROL_NONCE}\n{}\n{}\n{}",
                encode_key(&control.verifying_key()),
                session::encode_exchange_key(&t.agent_exchange),
                session::encode_exchange_key(&t.control_exchange)
            )
        );
        assert_eq!(hex::encode(t.hash()), "f0c87fe1915cc068142e50f6eb023f9e90bc4e89db59e1fe6428c28a8cef8fa8");
        let keys = session::Keys::derive(&t, &[0x33; 32]);
        let a2c = keys.cipher(Direction::AgentToControl);
        let c2a = keys.cipher(Direction::ControlToAgent);
        assert_eq!(session::Cipher::nonce(Direction::ControlToAgent, 258), [0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(a2c.seal(1, 1000, "ping", br#"{"nonce":1}"#), "zn9T4LYXPlv96EW1TjUm9OjkXF0J6Qh8WpQ7");
        assert_eq!(c2a.seal(1, 1000, "ping", br#"{"nonce":1}"#), "Jefdlp2rwCJXq74B5n8yUk8j5ehn2rgIscIo");
        assert_eq!(
            c2a.open(1, 1000, "ping", "Jefdlp2rwCJXq74B5n8yUk8j5ehn2rgIscIo").as_deref(),
            Some(r#"{"nonce":1}"#)
        );
    }

    /// What anyone carrying a v2 frame sees: its kind, sequence, timestamp and size, never its message. A deployment's
    /// secrets appear nowhere in the frame; only an opener of the session reads them.
    #[test]
    fn v2_bodies_are_unreadable_without_the_session_keys() {
        let control = generate_key();
        let (_, agent, ctl) = handshake(&control, CONTROL_NONCE);
        let secret = "env-value-only-the-broker-reads";
        let cmd = deployment(secret);
        let mut sealer = Sealer::new(control.clone(), Direction::ControlToAgent).in_session(&ctl);
        let wire = serde_json::to_string(&sealer.seal(&cmd, 1000)).unwrap();
        assert!(!wire.contains(secret) && !wire.contains("DATABASE_URL") && !wire.contains("deploy_app"), "{wire}");
        let f: Frame = serde_json::from_str(&wire).unwrap();
        assert_eq!((f.seq, f.ts, f.kind.as_str()), (1, 1000, "command"), "the header stays readable");
        let plain = serde_json::to_string(&cmd).unwrap();
        assert_eq!(B64.decode(&f.body).unwrap().len(), plain.len() + 16, "the size shows, plus the 16-byte tag");
        assert!(f.decode::<msg::Command>().is_err(), "the body is no message");

        let mut opener = Opener::new(control.verifying_key(), Direction::ControlToAgent).in_session(&agent);
        assert_eq!(opener.open(&wire, 1000).unwrap().decode::<msg::Command>().unwrap(), cmd);
        // v1 frames keep their clear bodies (and protocol 1 its bytes).
        let v1 = Sealer::new(control, Direction::ControlToAgent).seal(&cmd, 1000);
        assert_eq!(v1.body, plain);
    }

    /// A frame sealed in one session fails to open in any other, even with a sequence the other has not reached and
    /// a fresh timestamp; v1 and v2 frames never stand for each other; v1 frames still open under v1.
    #[test]
    fn v2_frames_open_only_in_their_session() {
        let (k, control) = (generate_key(), generate_key());
        let (_, a, a_ctl) = handshake(&control, CONTROL_NONCE);
        let (_, b, _) = handshake(&control, &session::nonce());
        // Same nonces (so the same session id and signatures), another key exchange.
        let (_, c, _) = handshake(&control, CONTROL_NONCE);
        assert_eq!(a.id(), c.id());
        let opener = |s: Option<&session::Keys>| {
            let o = Opener::new(k.verifying_key(), Direction::AgentToControl);
            match s {
                Some(s) => o.in_session(s),
                None => o,
            }
        };
        let mut in_a = Sealer::new(k.clone(), Direction::AgentToControl).in_session(&a);
        for _ in 0..4 {
            in_a.seal(&Ping { nonce: 0 }, 1000);
        }
        let recorded = serde_json::to_string(&in_a.seal(&Ping { nonce: 5 }, 1000)).unwrap();
        assert_eq!(opener(Some(&b)).open(&recorded, 1000), Err(FrameError::BadSignature), "another session");
        assert_eq!(opener(Some(&c)).open(&recorded, 1000), Err(FrameError::Undecryptable), "another key exchange");
        assert_eq!(opener(None).open(&recorded, 1000), Err(FrameError::BadSignature), "a v1 session");
        assert_eq!(opener(Some(&a_ctl)).open(&recorded, 1000).unwrap().seq, 5, "its own session");

        let v1 =
            serde_json::to_string(&Sealer::new(k.clone(), Direction::AgentToControl).seal(&Ping { nonce: 1 }, 1000))
                .unwrap();
        assert_eq!(opener(Some(&a)).open(&v1, 1000), Err(FrameError::BadSignature), "a v1 frame in a session");
        assert_eq!(opener(None).open(&v1, 1000).unwrap().decode::<Ping>().unwrap().nonce, 1, "v1 still opens");
        // The other direction of the same session does not verify either (no reflection).
        let mut back = Sealer::new(k.clone(), Direction::ControlToAgent).in_session(&a);
        let reflected = serde_json::to_string(&back.seal(&Ping { nonce: 2 }, 1000)).unwrap();
        assert_eq!(opener(Some(&a)).open(&reflected, 1000), Err(FrameError::BadSignature));
    }

    /// The ciphertext is bound to its key, its direction and every header field: changing any of them, or a single
    /// bit of it, fails. A frame re-signed after such a change (by someone holding the signing key but not the
    /// session keys) is refused without moving the opener's sequence.
    #[test]
    fn tampered_ciphertexts_headers_and_sequences_fail() {
        let control = generate_key();
        let (_, keys, _) = handshake(&control, CONTROL_NONCE);
        let (_, other, _) = handshake(&control, CONTROL_NONCE);
        let c = keys.cipher(Direction::AgentToControl);
        let body = c.seal(3, 1000, "ping", br#"{"nonce":1}"#);
        assert_eq!(c.open(3, 1000, "ping", &body).as_deref(), Some(r#"{"nonce":1}"#));
        let mut flipped = B64.decode(&body).unwrap();
        flipped[0] ^= 1;
        assert_eq!(c.open(3, 1000, "ping", &B64.encode(&flipped)), None, "a changed ciphertext");
        let mut tag = B64.decode(&body).unwrap();
        *tag.last_mut().unwrap() ^= 0x80;
        assert_eq!(c.open(3, 1000, "ping", &B64.encode(&tag)), None, "a changed tag");
        assert_eq!(c.open(3, 1000, "ping", &body[..body.len() - 4]), None, "a cut ciphertext");
        assert_eq!(c.open(4, 1000, "ping", &body), None, "another sequence");
        assert_eq!(c.open(3, 1001, "ping", &body), None, "another timestamp");
        assert_eq!(c.open(3, 1000, "pong", &body), None, "another kind");
        assert_eq!(keys.cipher(Direction::ControlToAgent).open(3, 1000, "ping", &body), None, "the other direction");
        assert_eq!(other.cipher(Direction::AgentToControl).open(3, 1000, "ping", &body), None, "another session's key");

        // Through the opener: each header change re-signed with the right signing key.
        let k = generate_key();
        let mut s = Sealer::new(k.clone(), Direction::AgentToControl).in_session(&keys);
        let mut o = Opener::new(k.verifying_key(), Direction::AgentToControl).in_session(&keys);
        let f = s.seal(&Ping { nonce: 1 }, 1000);
        let resign = |f: &Frame| {
            let sig = k.sign(&signing_message_v2(
                &keys.id(),
                Direction::AgentToControl,
                f.seq,
                f.ts,
                &f.kind,
                f.body.as_bytes(),
            ));
            serde_json::to_string(&Frame { sig: encode_signature(&sig), ..f.clone() }).unwrap()
        };
        for forged in [
            Frame { seq: 2, ..f.clone() },
            Frame { ts: 1001, ..f.clone() },
            Frame { kind: "pong".into(), ..f.clone() },
            Frame { body: B64.encode(&flipped), ..f.clone() },
        ] {
            assert_eq!(o.open(&resign(&forged), 1000), Err(FrameError::Undecryptable), "{forged:?}");
        }
        let mut changed = f.clone();
        changed.body = B64.encode(&flipped);
        assert_eq!(o.open(&serde_json::to_string(&changed).unwrap(), 1000), Err(FrameError::BadSignature));
        assert_eq!(o.open(&serde_json::to_string(&f).unwrap(), 1000).unwrap().seq, 1, "the sequence did not move");
    }

    /// Every frame of a session gets its own nonce, in both directions: the direction and a sequence that only goes
    /// up. The same message sealed twice gives two different ciphertexts.
    #[test]
    fn nonces_never_repeat_in_a_session() {
        let k = generate_key();
        let (_, keys, _) = handshake(&k, CONTROL_NONCE);
        let mut seen = std::collections::HashSet::new();
        let mut bodies = std::collections::HashSet::new();
        for dir in [Direction::AgentToControl, Direction::ControlToAgent] {
            let mut s = Sealer::new(k.clone(), dir).in_session(&keys);
            let mut last = 0;
            for _ in 0..5000 {
                let f = s.seal(&Ping { nonce: 1 }, 1000);
                assert!(f.seq > last);
                last = f.seq;
                assert!(seen.insert(session::Cipher::nonce(dir, f.seq)), "nonce reused at {dir:?} {}", f.seq);
                assert!(bodies.insert(f.body));
            }
        }
        assert_eq!(seen.len(), 10_000);
    }

    /// Each side's handshake signature covers every field of the transcript: another protocol version, server, nonce,
    /// control key or exchange key, or the other side's direction, does not verify; the session id changes with each
    /// of its fields.
    #[test]
    fn handshake_transcripts_bind_every_field() {
        let (control, agent, other) = (generate_key(), generate_key(), generate_key());
        let t = transcript(&control);
        let by_control = t.sign(&control, Direction::ControlToAgent);
        assert!(t.verify(&control.verifying_key(), Direction::ControlToAgent, &by_control));
        assert!(!t.verify(&control.verifying_key(), Direction::AgentToControl, &by_control), "as the agent");
        assert!(!t.verify(&other.verifying_key(), Direction::ControlToAgent, &by_control), "another key");
        let mallory = session::Exchange::generate().public_key();
        let tampered = [
            session::Transcript { protocol: 1, ..t.clone() },
            session::Transcript { server_id: "srv_2".into(), ..t.clone() },
            session::Transcript { agent_nonce: session::nonce(), ..t.clone() },
            session::Transcript { control_nonce: session::nonce(), ..t.clone() },
            session::Transcript { control_key: other.verifying_key(), ..t.clone() },
            session::Transcript { agent_exchange: mallory, ..t.clone() },
            session::Transcript { control_exchange: mallory, ..t.clone() },
        ];
        for changed in &tampered {
            assert!(!changed.verify(&control.verifying_key(), Direction::ControlToAgent, &by_control), "{changed:?}");
            assert_ne!(changed.hash(), t.hash());
        }
        // Signed by the key it names, a transcript with another key is still another transcript.
        let by_other = tampered[4].sign(&other, Direction::ControlToAgent);
        assert!(!t.verify(&other.verifying_key(), Direction::ControlToAgent, &by_other));
        let by_agent = t.sign(&agent, Direction::AgentToControl);
        assert!(t.verify(&agent.verifying_key(), Direction::AgentToControl, &by_agent));
        assert!(!tampered[3].verify(&agent.verifying_key(), Direction::AgentToControl, &by_agent));

        let sid = t.session_id();
        for changed in &tampered[1..4] {
            assert_ne!(changed.session_id(), sid, "{changed:?}");
        }
        assert!(connect::valid_nonce(&session::nonce()));
        assert!(!connect::valid_nonce("00112233445566778899aabbccddeef") && !connect::valid_nonce(&"g".repeat(32)));
    }

    /// A man in the middle of the handshake (a TLS terminator, the agent's relay) that puts its own exchange key in
    /// the agent's request gets an answer signed over its key: the agent, which rebuilds the transcript with its own
    /// key, refuses the signature. Substituting the control plane's key in the answer fails the same way, and the
    /// agent's proof, signed over its view, does not verify for the control plane's. Neither side derives keys from a
    /// transcript that does not carry its own exchange key, or from a low-order peer key.
    #[test]
    fn swapped_exchange_keys_fail_the_handshake() {
        let (control, agent_key) = (generate_key(), generate_key());
        let (agent, ctl, mitm) =
            (session::Exchange::generate(), session::Exchange::generate(), session::Exchange::generate());
        let base = session::Transcript {
            agent_exchange: agent.public_key(),
            control_exchange: ctl.public_key(),
            ..transcript(&control)
        };
        // The control plane saw the attacker's key as the agent's.
        let seen_by_control = session::Transcript { agent_exchange: mitm.public_key(), ..base.clone() };
        let sig = seen_by_control.sign(&control, Direction::ControlToAgent);
        assert!(!base.verify(&control.verifying_key(), Direction::ControlToAgent, &sig), "the agent refuses");
        // The agent saw the attacker's key as the control plane's.
        let seen_by_agent = session::Transcript { control_exchange: mitm.public_key(), ..base.clone() };
        let sig = base.sign(&control, Direction::ControlToAgent);
        assert!(!seen_by_agent.verify(&control.verifying_key(), Direction::ControlToAgent, &sig), "the agent refuses");
        let proof = seen_by_agent.sign(&agent_key, Direction::AgentToControl);
        assert!(
            !base.verify(&agent_key.verifying_key(), Direction::AgentToControl, &proof),
            "the control plane refuses"
        );

        assert_eq!(mitm.finish(&base, Direction::AgentToControl).err(), Some(session::ExchangeError::NotOurs));
        assert_eq!(agent.finish(&base, Direction::ControlToAgent).err(), Some(session::ExchangeError::NotOurs));
        let low_order = session::Transcript { control_exchange: session::ExchangeKey::from([0; 32]), ..base };
        let a = session::Exchange::generate();
        let low_order = session::Transcript { agent_exchange: a.public_key(), ..low_order };
        assert_eq!(
            a.finish(&low_order, Direction::AgentToControl).err(),
            Some(session::ExchangeError::NonContributory)
        );
    }
}
