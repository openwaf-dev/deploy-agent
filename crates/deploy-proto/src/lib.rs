//! Wire protocol between the OpenWAF Deploy control plane and the agents on servers (PROTOCOL.md).
//!
//! The agent dials the control plane and keeps one WebSocket. Every frame is signed by its sender: the agent with its
//! own Ed25519 key (the control plane stores only the public key), the control plane with its key, whose public half
//! the agent pinned at enrollment. A frame carries a direction, a strictly increasing sequence number and a timestamp,
//! so a frame cannot be replayed, reordered or reflected back to its sender.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod msg;

/// First line of every signed message.
pub const CONTEXT: &str = "owdeploy-agent-v1";
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

/// A frame on the wire. `body` is the JSON of a message kept as a string, so the signature covers its exact bytes.
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
}

/// The signed message of a frame (or of the connect handshake, with `kind` "connect" and the host id as body).
pub fn signing_message(dir: Direction, seq: u64, ts: i64, kind: &str, body: &[u8]) -> Vec<u8> {
    let digest = hex::encode(Sha256::digest(body));
    format!("{CONTEXT}\n{}\n{seq}\n{ts}\n{kind}\n{digest}", dir.as_str()).into_bytes()
}

/// Signs outgoing frames with consecutive sequence numbers.
pub struct Sealer {
    key: SigningKey,
    dir: Direction,
    next_seq: u64,
}

impl Sealer {
    pub fn new(key: SigningKey, dir: Direction) -> Sealer {
        Sealer { key, dir, next_seq: 1 }
    }

    /// Signs the following frames with another key (a control key rotation); the sequence carries on.
    pub fn rekey(&mut self, key: SigningKey) {
        self.key = key;
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn seal<M: Serialize + msg::Kind>(&mut self, msg: &M, now: i64) -> Frame {
        let body = serde_json::to_string(msg).expect("messages serialize");
        let seq = self.next_seq;
        self.next_seq += 1;
        let sig = self.key.sign(&signing_message(self.dir, seq, now, M::KIND, body.as_bytes()));
        Frame { seq, ts: now, kind: M::KIND.to_string(), body, sig: B64.encode(sig.to_bytes()) }
    }
}

/// Checks incoming frames: signature by the peer's key, direction, clock skew and strictly increasing sequence.
pub struct Opener {
    peers: Vec<VerifyingKey>,
    dir: Direction,
    last_seq: u64,
}

impl Opener {
    pub fn new(peer: VerifyingKey, dir: Direction) -> Opener {
        Opener::with_keys(vec![peer], dir)
    }

    /// Accepts frames signed by any of `peers`: during a control key rotation the agent accepts its pinned key and
    /// the announced next one.
    pub fn with_keys(peers: Vec<VerifyingKey>, dir: Direction) -> Opener {
        Opener { peers, dir, last_seq: 0 }
    }

    /// Replaces the accepted keys; the sequence carries on.
    pub fn set_keys(&mut self, peers: Vec<VerifyingKey>) {
        self.peers = peers;
    }

    pub fn open(&mut self, raw: &str, now: i64) -> Result<Frame, FrameError> {
        self.open_keyed(raw, now).map(|(f, _)| f)
    }

    /// Opens a frame and says which of the keys (its index) signed it.
    pub fn open_keyed(&mut self, raw: &str, now: i64) -> Result<(Frame, usize), FrameError> {
        if raw.len() > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge);
        }
        let f: Frame = serde_json::from_str(raw).map_err(|_| FrameError::Malformed)?;
        let sig =
            B64.decode(&f.sig).ok().and_then(|b| Signature::from_slice(&b).ok()).ok_or(FrameError::BadSignature)?;
        let msg = signing_message(self.dir, f.seq, f.ts, &f.kind, f.body.as_bytes());
        let which = self.peers.iter().position(|k| k.verify(&msg, &sig).is_ok()).ok_or(FrameError::BadSignature)?;
        if (now - f.ts).abs() > MAX_SKEW_SECS {
            return Err(FrameError::Skew(f.ts - now));
        }
        if f.seq <= self.last_seq {
            return Err(FrameError::Replay { got: f.seq, last: self.last_seq });
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

/// Headers of the agent's connect request: the agent proves it holds the host key before the upgrade.
pub mod connect {
    pub const HDR_SERVER: &str = "OWDeploy-Server";
    pub const HDR_TIMESTAMP: &str = "OWDeploy-Timestamp";
    pub const HDR_NONCE: &str = "OWDeploy-Nonce";
    pub const HDR_SIGNATURE: &str = "OWDeploy-Signature";
    pub const KIND: &str = "connect";
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
}
