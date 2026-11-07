//! The agent's identity and the control plane's keys it pinned (PROTOCOL.md).
//!
//! - The control key signs every control frame. A `control_key_rotate` frame (signed by it, as every frame the agent
//!   accepts) announces the next one: the agent pins it as `control_next` and accepts frames signed by either until
//!   the first frame signed by the next key, which makes it the control key and drops the previous one.
//! - The update key signs update offers. Pinned at enrollment, or from the first `update_key` announcement when the
//!   agent has none (its frame is signed by the control key); then offers signed by the control key are refused and
//!   another update key is pinned only with the pinned one's handover signature.
//! - The release key is offline (the operator's machine): it signs each released binary when it is built. Pinned at
//!   enrollment (or by hand), never from the control plane's channel, so a control plane holding every online key
//!   still cannot make this agent install a binary that was not released. Without one, offers are not checked for it.
//! - The protocol: once a control plane answered with a protocol 2 handshake signed by a pinned control key (or said
//!   at enrollment that it speaks protocol 2), the agent records it and refuses protocol 1 sessions from then on, so
//!   stripping the v2 headers in transit cannot downgrade it.
//!
//! Every change is written to `identity.json` before it takes effect. `owdeploy-agent pin-keys` replaces the keys by
//! hand (root on the server), the recovery when a key is lost or leaked (README.md).

use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use deploy_proto::msg::{ControlKeyRotate, PinnedKeys, UpdateKey};
use deploy_proto::session::{Exchange, ExchangeKey, Keys, Session, Transcript};
use deploy_proto::{Direction, Frame, Opener, connect};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::http::HeaderMap;

use crate::update::Trust;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub server_id: String,
    pub org_id: String,
    /// Base64 Ed25519 seed of this agent.
    pub key: String,
    /// Base64 public key of the control plane, pinned at enrollment.
    pub control_public_key: String,
    pub connect_url: String,
    /// The next control key, announced by the control plane during a rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_next_public_key: Option<String>,
    /// The key update offers must be signed with. None: offers signed with the control key are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_public_key: Option<String>,
    /// The offline release key every installed binary must be signed by. None: release signatures are not required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_public_key: Option<String>,
    /// The highest protocol a session with the control plane used, or that it announced at enrollment: sessions of
    /// an older protocol are refused. None: 1 (an agent enrolled before protocol 2 that has not completed a v2
    /// session yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u32>,
}

impl Identity {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("identity.json")
    }

    pub fn load(dir: &Path) -> Result<Identity, String> {
        let p = Identity::path(dir);
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e} (enroll first)", p.display()))?;
        let id: Identity = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        id.control_key()?;
        id.next_key()?;
        id.update_key()?;
        id.release_key()?;
        Ok(id)
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        crate::write_private(&Identity::path(dir), serde_json::to_string_pretty(self).expect("identity").as_bytes())
    }

    pub fn signing_key(&self) -> Result<SigningKey, String> {
        let seed: [u8; 32] =
            B64.decode(&self.key).ok().and_then(|b| b.try_into().ok()).ok_or("identity key is invalid")?;
        Ok(SigningKey::from_bytes(&seed))
    }

    pub fn control_key(&self) -> Result<VerifyingKey, String> {
        deploy_proto::decode_key(&self.control_public_key).ok_or_else(|| "pinned control key is invalid".to_string())
    }

    fn next_key(&self) -> Result<Option<VerifyingKey>, String> {
        self.control_next_public_key
            .as_deref()
            .map(|k| deploy_proto::decode_key(k).ok_or_else(|| "pinned next control key is invalid".to_string()))
            .transpose()
    }

    pub fn update_key(&self) -> Result<Option<VerifyingKey>, String> {
        self.update_public_key
            .as_deref()
            .map(|k| deploy_proto::decode_key(k).ok_or_else(|| "pinned update key is invalid".to_string()))
            .transpose()
    }

    pub fn release_key(&self) -> Result<Option<VerifyingKey>, String> {
        self.release_public_key
            .as_deref()
            .map(|k| deploy_proto::decode_key(k).ok_or_else(|| "pinned release key is invalid".to_string()))
            .transpose()
    }

    /// Keys control frames are opened with: the control key, then the next one during a rotation.
    pub fn frame_keys(&self) -> Result<Vec<VerifyingKey>, String> {
        let mut keys = vec![self.control_key()?];
        keys.extend(self.next_key()?);
        Ok(keys)
    }

    pub fn trust(&self) -> Result<Trust, String> {
        Ok(Trust { control: self.control_key()?, update: self.update_key()?, release: self.release_key()? })
    }

    /// The oldest protocol this agent still accepts from the control plane.
    pub fn min_protocol(&self) -> u32 {
        self.protocol.unwrap_or(1)
    }

    pub fn pinned(&self, message: Option<String>) -> PinnedKeys {
        PinnedKeys {
            control: self.control_public_key.clone(),
            control_next: self.control_next_public_key.clone(),
            update: self.update_public_key.clone(),
            release: self.release_public_key.clone(),
            message,
        }
    }
}

/// The identity with the state directory it is saved in: opens control frames and applies key announcements.
pub struct KeyRing {
    pub id: Identity,
    dir: PathBuf,
}

impl KeyRing {
    pub fn load(dir: &Path) -> Result<KeyRing, String> {
        Ok(KeyRing { id: Identity::load(dir)?, dir: dir.to_path_buf() })
    }

    /// An opener for a new session's control frames: of the v2 session of `keys`, or v1 frames when None.
    pub fn opener(&self, keys: Option<&Keys>) -> Result<Opener, String> {
        let o = Opener::with_keys(self.id.frame_keys()?, Direction::ControlToAgent);
        Ok(match keys {
            Some(k) => o.in_session(k),
            None => o,
        })
    }

    /// The headers of the connect request that ask for a v2 session: the protocol, the control keys this agent
    /// accepts (the control plane signs the handshake with one of them) and the connection's exchange key.
    pub fn session_request(&self, exchange: &ExchangeKey) -> [(&'static str, String); 3] {
        let keys: Vec<&str> = std::iter::once(&self.id.control_public_key)
            .chain(&self.id.control_next_public_key)
            .map(|k| k.as_str())
            .collect();
        [
            (connect::HDR_PROTOCOL, deploy_proto::PROTOCOL_VERSION.to_string()),
            (connect::HDR_CONTROL_KEYS, keys.join(",")),
            (connect::HDR_EXCHANGE_KEY, deploy_proto::session::encode_exchange_key(exchange)),
        ]
    }

    /// The control plane's answer to the connect request whose nonce was `agent_nonce` and exchange key `exchange`'s.
    /// A v2 answer is accepted only when a pinned control key signed its transcript, which names both exchange keys;
    /// its session keys are derived, its protocol recorded (saved before it is used) and protocol 1 refused from then
    /// on. An answer without the v2 headers is a v1 session: refused once this agent used v2, since a control plane
    /// that did will not stop (a man in the middle removing the headers would).
    pub fn accept_session(
        &mut self,
        agent_nonce: &str,
        exchange: Exchange,
        answer: &HeaderMap,
    ) -> Result<Option<Session>, String> {
        let get = |name: &str| answer.get(name).and_then(|v| v.to_str().ok());
        let protocol = match get(connect::HDR_PROTOCOL) {
            None => 1,
            Some(p) => {
                p.parse::<u32>().ok().filter(|p| (1..=deploy_proto::PROTOCOL_VERSION).contains(p)).ok_or_else(|| {
                    format!("the control plane answered with protocol {p:?}, which this agent did not offer")
                })?
            }
        };
        if protocol < self.id.min_protocol() {
            return Err(format!(
                "the control plane answered with protocol {protocol}, but this agent already used protocol {} with \
                 it: refused (a downgrade)",
                self.id.min_protocol()
            ));
        }
        if protocol == 1 {
            return Ok(None);
        }
        let refused = |why: &str| format!("protocol {protocol} handshake refused: {why}");
        let control_nonce =
            get(connect::HDR_CONTROL_NONCE).filter(|n| connect::valid_nonce(n)).ok_or_else(|| refused("no nonce"))?;
        let control_key = get(connect::HDR_CONTROL_KEY)
            .and_then(deploy_proto::decode_key)
            .filter(|k| self.id.frame_keys().is_ok_and(|pinned| pinned.contains(k)))
            .ok_or_else(|| refused("not signed by a pinned control key"))?;
        let sig = get(connect::HDR_CONTROL_SIGNATURE)
            .and_then(deploy_proto::decode_signature)
            .ok_or_else(|| refused("no signature"))?;
        let control_exchange = get(connect::HDR_CONTROL_EXCHANGE_KEY)
            .and_then(deploy_proto::session::decode_exchange_key)
            .ok_or_else(|| refused("no exchange key"))?;
        let t = Transcript {
            protocol,
            server_id: self.id.server_id.clone(),
            agent_nonce: agent_nonce.to_string(),
            control_nonce: control_nonce.to_string(),
            control_key,
            agent_exchange: exchange.public_key(),
            control_exchange,
        };
        if !t.verify(&control_key, Direction::ControlToAgent, &sig) {
            return Err(refused("the signature does not verify"));
        }
        let keys = exchange.finish(&t, Direction::AgentToControl).map_err(|e| refused(&e.to_string()))?;
        if self.id.min_protocol() < protocol {
            let next = Identity { protocol: Some(protocol), ..self.id.clone() };
            self.commit(next).map_err(|e| format!("protocol {protocol} not recorded: {e}"))?;
            tracing::info!("protocol {protocol} recorded: older sessions are refused from now on");
        }
        Ok(Some(Session { transcript: t, keys }))
    }

    /// Saves `next` and makes it the identity; the in-memory identity is unchanged when saving fails.
    fn commit(&mut self, next: Identity) -> Result<(), String> {
        next.save(&self.dir)?;
        self.id = next;
        Ok(())
    }

    /// Opens a control frame. One signed by the next control key makes it the control key: the keys to report then
    /// come with it.
    pub fn open(&mut self, opener: &mut Opener, raw: &str, now: i64) -> Result<(Frame, Option<PinnedKeys>), String> {
        let (frame, which) = opener.open_keyed(raw, now).map_err(|e| format!("control frame refused: {e}"))?;
        if which == 0 {
            return Ok((frame, None));
        }
        let mut next = self.id.clone();
        next.control_public_key = next.control_next_public_key.take().expect("a second frame key is the next key");
        self.commit(next).map_err(|e| format!("the control plane switched to the next control key: {e}"))?;
        opener.set_keys(self.id.frame_keys()?);
        tracing::info!("control key rotated to {}", self.id.control_public_key);
        Ok((frame, Some(self.id.pinned(Some("control key rotated: the next key signs frames now".into())))))
    }

    /// A `control_key_rotate` frame (opened, so signed by the control key): pins its key as the next one.
    pub fn rotate(&mut self, opener: &mut Opener, m: &ControlKeyRotate) -> PinnedKeys {
        let message = match deploy_proto::decode_key(&m.next_public_key) {
            None => "control key rotation refused: invalid key".to_string(),
            Some(_) if m.next_public_key == self.id.control_public_key => {
                "control key rotation: already the control key".into()
            }
            Some(_) if self.id.control_next_public_key.as_ref() == Some(&m.next_public_key) => {
                "control key rotation: already pinned".into()
            }
            Some(_) => {
                let next = Identity { control_next_public_key: Some(m.next_public_key.clone()), ..self.id.clone() };
                match self.commit(next).and_then(|()| self.id.frame_keys()) {
                    Ok(keys) => {
                        opener.set_keys(keys);
                        tracing::info!("next control key pinned: {}", m.next_public_key);
                        "next control key pinned".into()
                    }
                    Err(e) => format!("control key rotation not saved: {e}"),
                }
            }
        };
        self.id.pinned(Some(message))
    }

    /// An `update_key` announcement: pinned when the agent has none, or with the pinned key's handover signature.
    pub fn update_key(&mut self, m: &UpdateKey) -> PinnedKeys {
        let pinned = match self.id.update_key() {
            Ok(p) => p,
            Err(e) => return self.id.pinned(Some(e)),
        };
        let accepted = match (pinned, deploy_proto::decode_key(&m.public_key)) {
            (_, None) => Err("update key refused: invalid key".to_string()),
            (Some(_), Some(_)) if self.id.update_public_key.as_ref() == Some(&m.public_key) => {
                return self.id.pinned(Some("update key: already pinned".into()));
            }
            (None, Some(_)) => Ok("update key pinned"),
            (Some(p), Some(_)) => deploy_proto::update::verify_handover(&p, m)
                .map(|_| "update key replaced by the pinned key's handover")
                .map_err(|e| {
                    format!("update key refused: another key is pinned and the handover does not verify ({e})")
                }),
        };
        let message = match accepted {
            Ok(what) => {
                let next = Identity { update_public_key: Some(m.public_key.clone()), ..self.id.clone() };
                match self.commit(next) {
                    Ok(()) => {
                        tracing::info!("{what}: {}", m.public_key);
                        what.to_string()
                    }
                    Err(e) => format!("update key not saved: {e}"),
                }
            }
            Err(e) => {
                tracing::warn!("{e}");
                e
            }
        };
        self.id.pinned(Some(message))
    }
}

/// `owdeploy-agent pin-keys`: replaces the pinned keys by hand (root on the server, agent stopped). A new control key
/// drops any pending next one.
pub fn pin_by_hand(
    dir: &Path,
    control: Option<&str>,
    update: Option<&str>,
    release: Option<&str>,
) -> Result<Identity, String> {
    if control.is_none() && update.is_none() && release.is_none() {
        return Err("nothing to pin: give --control-key, --update-key and/or --release-key".into());
    }
    let mut id = Identity::load(dir)?;
    if let Some(c) = control {
        deploy_proto::decode_key(c).ok_or("--control-key: not a base64 Ed25519 public key")?;
        id.control_public_key = c.to_string();
        id.control_next_public_key = None;
    }
    if let Some(u) = update {
        deploy_proto::decode_key(u).ok_or("--update-key: not a base64 Ed25519 public key")?;
        id.update_public_key = Some(u.to_string());
    }
    if let Some(r) = release {
        deploy_proto::decode_key(r).ok_or("--release-key: not a base64 Ed25519 public key")?;
        id.release_public_key = Some(r.to_string());
    }
    id.save(dir)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use deploy_proto::msg::Ping;
    use deploy_proto::{Sealer, encode_key, generate_key};

    use super::*;

    fn ring(name: &str, control: &SigningKey) -> KeyRing {
        let dir = std::env::temp_dir().join(format!("owd-keys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let id = Identity {
            server_id: "srv_1".into(),
            org_id: "org".into(),
            key: B64.encode(generate_key().to_bytes()),
            control_public_key: encode_key(&control.verifying_key()),
            connect_url: "wss://d.example/v1/agent/connect".into(),
            control_next_public_key: None,
            update_public_key: None,
            release_public_key: None,
            protocol: None,
        };
        id.save(&dir).unwrap();
        KeyRing::load(&dir).unwrap()
    }

    fn raw<M: Serialize + deploy_proto::msg::Kind>(s: &mut Sealer, m: &M) -> String {
        serde_json::to_string(&s.seal(m, 100)).unwrap()
    }

    /// A rotation frame is accepted only when signed by the control key; the next key is then accepted as well, and
    /// its first frame makes it the control key (saved), after which the previous key no longer opens frames.
    #[test]
    fn control_key_rotation_needs_the_current_key_and_completes_on_the_next_key() {
        let (old, new, stranger) = (generate_key(), generate_key(), generate_key());
        let mut r = ring("rotate", &old);
        let mut o = r.opener(None).unwrap();
        let rotate = ControlKeyRotate { next_public_key: encode_key(&new.verifying_key()) };

        // Signed by any other key (here the very key it announces): refused before it is read.
        let mut s_new = Sealer::new(new.clone(), Direction::ControlToAgent);
        let mut s_stranger = Sealer::new(stranger, Direction::ControlToAgent);
        assert!(r.open(&mut o, &raw(&mut s_stranger, &rotate), 100).is_err());
        assert!(r.open(&mut o, &raw(&mut s_new, &rotate), 100).is_err(), "the next key cannot announce itself");
        assert_eq!(r.id.control_next_public_key, None);

        let mut s = Sealer::new(old.clone(), Direction::ControlToAgent);
        for _ in 0..2 {
            s.seal(&Ping { nonce: 0 }, 100);
        }
        let (f, change) = r.open(&mut o, &raw(&mut s, &rotate), 100).unwrap();
        assert_eq!(change, None);
        let pinned = r.rotate(&mut o, &f.decode().unwrap());
        assert_eq!(pinned.control_next, Some(rotate.next_public_key.clone()));
        assert_eq!(Identity::load(&r.dir).unwrap().control_next_public_key, pinned.control_next, "saved");

        // Overlap: both keys open frames; the first by the next key completes the rotation.
        let (_, change) = r.open(&mut o, &raw(&mut s, &Ping { nonce: 1 }), 100).unwrap();
        assert_eq!(change, None);
        s.rekey(new.clone());
        let (_, change) = r.open(&mut o, &raw(&mut s, &Ping { nonce: 2 }), 100).unwrap();
        let change = change.expect("rotated");
        assert_eq!((change.control.as_str(), change.control_next), (rotate.next_public_key.as_str(), None));
        let saved = Identity::load(&r.dir).unwrap();
        assert_eq!((saved.control_public_key, saved.control_next_public_key), (rotate.next_public_key.clone(), None));
        let mut s_old = Sealer::new(old, Direction::ControlToAgent);
        for _ in 0..5 {
            s_old.seal(&Ping { nonce: 0 }, 100);
        }
        assert!(r.open(&mut o, &raw(&mut s_old, &Ping { nonce: 3 }), 100).is_err(), "the old key is dropped");
        assert_eq!(r.opener(None).unwrap().open_keyed(&raw(&mut s, &Ping { nonce: 4 }), 100).unwrap().1, 0);
        let _ = std::fs::remove_dir_all(&r.dir);
    }

    #[test]
    fn update_key_is_pinned_once_then_only_handed_over() {
        let control = generate_key();
        let mut r = ring("update", &control);
        let (k1, k2, k3) = (generate_key(), generate_key(), generate_key());
        let p = r.update_key(&deploy_proto::update::announce(&k1.verifying_key(), None));
        assert_eq!(p.update, Some(encode_key(&k1.verifying_key())));
        assert_eq!(r.id.trust().unwrap().update, Some(k1.verifying_key()));

        // Another key without the pinned key's handover (what a leaked control key could send): refused.
        let p = r.update_key(&deploy_proto::update::announce(&k2.verifying_key(), None));
        assert_eq!(p.update, Some(encode_key(&k1.verifying_key())));
        assert!(p.message.unwrap().contains("refused"));
        let p = r.update_key(&deploy_proto::update::announce(&k2.verifying_key(), Some(&k3)));
        assert_eq!(p.update, Some(encode_key(&k1.verifying_key())));

        let p = r.update_key(&deploy_proto::update::announce(&k2.verifying_key(), Some(&k1)));
        assert_eq!(p.update, Some(encode_key(&k2.verifying_key())));
        assert_eq!(Identity::load(&r.dir).unwrap().update_public_key, p.update, "saved");
        let _ = std::fs::remove_dir_all(&r.dir);
    }

    #[test]
    fn keys_pinned_by_hand() {
        let control = generate_key();
        let r = ring("hand", &control);
        let (c, u) = (encode_key(&generate_key().verifying_key()), encode_key(&generate_key().verifying_key()));
        assert!(pin_by_hand(&r.dir, None, None, None).is_err());
        assert!(pin_by_hand(&r.dir, Some("AAAA"), None, None).is_err());
        assert!(pin_by_hand(&r.dir, None, None, Some("AAAA")).is_err());
        let id = pin_by_hand(&r.dir, Some(&c), Some(&u), None).unwrap();
        assert_eq!((id.control_public_key, id.update_public_key), (c.clone(), Some(u.clone())));
        let rel = encode_key(&generate_key().verifying_key());
        let id = pin_by_hand(&r.dir, None, None, Some(&rel)).unwrap();
        assert_eq!((id.control_public_key, id.update_public_key, id.release_public_key), (c, Some(u), Some(rel)));
        assert!(Identity::load(&r.dir).unwrap().trust().unwrap().release.is_some(), "saved and trusted");
        let _ = std::fs::remove_dir_all(&r.dir);
    }

    /// The answer of a control plane signing the v2 handshake of `agent_nonce` and the agent's exchange key `agent`
    /// with `key`, naming `named` as its key, and the control plane's session keys.
    fn v2_answer(
        r: &KeyRing,
        key: &SigningKey,
        named: &VerifyingKey,
        agent_nonce: &str,
        agent: ExchangeKey,
    ) -> (HeaderMap, Keys) {
        let exchange = Exchange::generate();
        let t = Transcript {
            protocol: 2,
            server_id: r.id.server_id.clone(),
            agent_nonce: agent_nonce.into(),
            control_nonce: deploy_proto::session::nonce(),
            control_key: *named,
            agent_exchange: agent,
            control_exchange: exchange.public_key(),
        };
        let mut h = HeaderMap::new();
        h.insert(connect::HDR_PROTOCOL, "2".parse().unwrap());
        h.insert(connect::HDR_CONTROL_NONCE, t.control_nonce.parse().unwrap());
        h.insert(connect::HDR_CONTROL_KEY, encode_key(named).parse().unwrap());
        let sig = deploy_proto::encode_signature(&t.sign(key, Direction::ControlToAgent));
        h.insert(connect::HDR_CONTROL_SIGNATURE, sig.parse().unwrap());
        let x = deploy_proto::session::encode_exchange_key(&t.control_exchange);
        h.insert(connect::HDR_CONTROL_EXCHANGE_KEY, x.parse().unwrap());
        (h, exchange.finish(&t, Direction::ControlToAgent).unwrap())
    }

    /// A v1 answer is a v1 session until a pinned control key signed a v2 handshake: that records protocol 2 (saved),
    /// and from then on a v1 answer (what stripping the v2 headers in transit produces) is refused, after a restart
    /// too. v2 answers not signed by a pinned key, made for another connection's nonce or exchange key, or whose
    /// exchange key was swapped in transit, record nothing.
    #[test]
    fn v1_sessions_are_refused_once_v2_was_used() {
        let (control, stranger) = (generate_key(), generate_key());
        let mut r = ring("protocol", &control);
        let pinned = control.verifying_key();
        let x = Exchange::generate();
        assert_eq!(
            r.session_request(&x.public_key()),
            [
                (connect::HDR_PROTOCOL, "2".to_string()),
                (connect::HDR_CONTROL_KEYS, encode_key(&pinned)),
                (connect::HDR_EXCHANGE_KEY, deploy_proto::session::encode_exchange_key(&x.public_key()))
            ]
        );
        let nonce = deploy_proto::session::nonce();
        assert!(matches!(r.accept_session(&nonce, x, &HeaderMap::new()), Ok(None)), "a control plane that speaks v1");

        let mitm = Exchange::generate().public_key();
        type Answer<'a> = &'a dyn Fn(&KeyRing, ExchangeKey, &str) -> HeaderMap;
        let answers: [(&str, Answer); 6] = [
            ("a stranger's key", &|r, x, n| v2_answer(r, &stranger, &stranger.verifying_key(), n, x).0),
            ("signed by a stranger", &|r, x, n| v2_answer(r, &stranger, &pinned, n, x).0),
            ("another nonce", &|r, x, _| v2_answer(r, &control, &pinned, &deploy_proto::session::nonce(), x).0),
            ("the agent's key swapped in the request", &|r, _, n| v2_answer(r, &control, &pinned, n, mitm).0),
            ("the control plane's key swapped in the answer", &|r, x, n| {
                let mut h = v2_answer(r, &control, &pinned, n, x).0;
                let swapped = deploy_proto::session::encode_exchange_key(&mitm);
                h.insert(connect::HDR_CONTROL_EXCHANGE_KEY, swapped.parse().unwrap());
                h
            }),
            ("no exchange key", &|r, x, n| {
                let mut h = v2_answer(r, &control, &pinned, n, x).0;
                h.remove(connect::HDR_CONTROL_EXCHANGE_KEY);
                h
            }),
        ];
        for (what, answer) in answers {
            let x = Exchange::generate();
            let h = answer(&r, x.public_key(), &nonce);
            assert!(r.accept_session(&nonce, x, &h).is_err(), "{what}");
        }
        let x = Exchange::generate();
        let (mut unknown, _) = v2_answer(&r, &control, &pinned, &nonce, x.public_key());
        unknown.insert(connect::HDR_PROTOCOL, "3".parse().unwrap());
        assert!(r.accept_session(&nonce, x, &unknown).is_err(), "a version the agent did not offer");
        assert_eq!((r.id.protocol, Identity::load(&r.dir).unwrap().protocol), (None, None), "nothing recorded");

        let x = Exchange::generate();
        let (h, control_keys) = v2_answer(&r, &control, &pinned, &nonce, x.public_key());
        let s = r.accept_session(&nonce, x, &h).unwrap().expect("a v2 session");
        assert_eq!((s.transcript.protocol, s.transcript.control_key), (2, pinned));
        assert_eq!(s.keys.id(), control_keys.id());
        assert_eq!(Identity::load(&r.dir).unwrap().protocol, Some(2), "saved");
        let mut sealer = Sealer::new(control.clone(), Direction::ControlToAgent).in_session(&control_keys);
        let frame = raw(&mut sealer, &Ping { nonce: 1 });
        assert_eq!(r.opener(Some(&s.keys)).unwrap().open(&frame, 100).unwrap().decode::<Ping>().unwrap().nonce, 1);
        assert!(r.opener(None).unwrap().open(&frame, 100).is_err(), "v2 frames are no v1 frames");

        let e = r.accept_session(&nonce, Exchange::generate(), &HeaderMap::new()).unwrap_err();
        assert!(e.contains("downgrade"), "{e}");
        let mut restarted = KeyRing::load(&r.dir).unwrap();
        assert!(restarted.accept_session(&nonce, Exchange::generate(), &HeaderMap::new()).is_err(), "after a restart");
        let (n2, x) = (deploy_proto::session::nonce(), Exchange::generate());
        let (h, _) = v2_answer(&r, &control, &pinned, &n2, x.public_key());
        assert!(restarted.accept_session(&n2, x, &h).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&r.dir);
    }
}
