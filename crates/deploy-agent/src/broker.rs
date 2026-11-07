//! The broker (`owdeploy-agent broker`, root): the privileged half of a privilege-separated agent (README.md,
//! SECURITY.md «Agent privileges»).
//!
//! It holds the identity and the pinned keys (`/var/lib/owdeploy-agent`, 0700 root), opens no network connection of
//! its own and listens on a UNIX socket for the relay ([`crate::ipc`]). For each connection the relay makes to the
//! control plane it signs the connect request, checks the control plane's answer against the pinned keys, derives and
//! holds the session's keys, proves the session, opens (verifies and decrypts) every incoming frame with the
//! session-bound opener and seals every outgoing one ([`crate::session`]); it executes what those frames say exactly
//! as the single-process agent does, and the relay carries only ciphertext it cannot read. A frame that does not
//! verify for the current session ends the session, as on the wire; a message outside the protocol ends the
//! relay's connection. Updates are downloaded by the relay and copied, checked and installed here ([`Staging`]); the
//! probation of a new binary, and its rollback, stay here too.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use deploy_proto::msg::AgentUpdate;
use parking_lot::Mutex;
use tokio::io::{BufReader, BufWriter};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::ipc::{self, Status, ToBroker, ToRelay};
use crate::session::{Agent, Flow, Handshake, Link, Live};
use crate::update::{Binary, Fetched};

/// How long a new connection has to send its first message.
const FIRST_MESSAGE_WITHIN: Duration = Duration::from_secs(10);

/// Update downloads delegated to the relay: at most one at a time, matched by SHA-256 when the relay says it is done.
#[derive(Clone)]
pub struct Staging(Arc<Mutex<StagingState>>);

struct StagingState {
    /// The relay's staging file.
    file: PathBuf,
    /// The attached relay.
    relay: Option<mpsc::Sender<ToRelay>>,
    awaiting: Option<Awaiting>,
}

struct Awaiting {
    update: AgentUpdate,
    bin: Binary,
    done: mpsc::Sender<Fetched>,
}

impl Awaiting {
    fn finish(self, result: Result<(), String>) {
        tokio::spawn(async move {
            let _ = self.done.send(Fetched::new(self.update, result)).await;
        });
    }
}

impl Staging {
    pub fn new(file: PathBuf) -> Staging {
        Staging(Arc::new(Mutex::new(StagingState { file, relay: None, awaiting: None })))
    }

    fn state(&self) -> parking_lot::MutexGuard<'_, StagingState> {
        self.0.lock()
    }

    /// Asks the attached relay to download `update` from `url`; the result reaches `done` once the broker imported
    /// (or failed to import) the relay's file.
    pub fn request(
        &self,
        url: String,
        bin: Binary,
        update: AgentUpdate,
        done: mpsc::Sender<Fetched>,
    ) -> Result<(), String> {
        let mut s = self.state();
        let relay = s.relay.as_ref().ok_or("no relay is attached to download it")?;
        relay
            .try_send(ToRelay::Stage { url, sha256: update.sha256.clone() })
            .map_err(|_| "the relay is not taking messages".to_string())?;
        if let Some(earlier) = s.awaiting.replace(Awaiting { update, bin, done }) {
            earlier.finish(Err("replaced by another download".into()));
        }
        Ok(())
    }

    fn attach(&self, relay: mpsc::Sender<ToRelay>) {
        self.state().relay = Some(relay);
    }

    /// The relay is gone: a download it had not finished fails.
    fn detach(&self) {
        let mut s = self.state();
        s.relay = None;
        if let Some(a) = s.awaiting.take() {
            a.finish(Err("the relay disconnected during the download".into()));
        }
    }

    fn take(&self, sha256: &str) -> Result<(Awaiting, PathBuf), String> {
        let mut s = self.state();
        match s.awaiting.take_if(|a| a.update.sha256 == sha256) {
            Some(a) => Ok((a, s.file.clone())),
            None => Err(format!("relay: a download of {sha256} the broker did not ask for")),
        }
    }

    /// The relay downloaded the binary: the broker copies and checks it in the background.
    fn staged(&self, sha256: &str) -> Result<(), String> {
        let (a, file) = self.take(sha256)?;
        tokio::spawn(async move {
            let result = crate::update::import(&file, &a.bin, &a.update).await;
            let _ = a.done.send(Fetched::new(a.update, result)).await;
        });
        Ok(())
    }

    fn failed(&self, sha256: &str, message: String) -> Result<(), String> {
        let (a, _) = self.take(sha256)?;
        a.finish(Err(format!("download by the relay: {message}")));
        Ok(())
    }
}

/// Creates the socket `path`: its directory 0750 and the socket 0660, both of group `group` (the relay's) when given,
/// replacing a socket left by an earlier broker.
pub fn bind(path: &Path, group: Option<u32>) -> Result<UnixListener, String> {
    use std::os::unix::fs::PermissionsExt;
    let at = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let dir = path.parent().ok_or("the broker's socket has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| at(dir, e))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750)).map_err(|e| at(dir, e))?;
    if group.is_some() {
        std::os::unix::fs::chown(dir, None, group).map_err(|e| at(dir, e))?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(at(path, e)),
    }
    let listener = UnixListener::bind(path).map_err(|e| at(path, e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).map_err(|e| at(path, e))?;
    if group.is_some() {
        std::os::unix::fs::chown(path, None, group).map_err(|e| at(path, e))?;
    }
    Ok(listener)
}

/// `owdeploy-agent broker`: serves relays on the socket until the broker must restart (Ok: a new binary installed).
pub async fn run(agent: Agent, staging: Staging) -> Result<(), String> {
    let relay = crate::split::lookup_user(ipc::RELAY_USER);
    if relay.is_none() {
        tracing::warn!("no user {}: only root may attach a relay", ipc::RELAY_USER);
    }
    let path = ipc::socket_path();
    let listener = bind(&path, relay.map(|(_, gid)| gid))?;
    tracing::info!("broker listening on {}", path.display());
    serve(listener, relay.map(|(uid, _)| uid), agent, staging).await
}

enum Served {
    /// The relay disconnected (or broke the protocol): wait for the next one.
    Detached,
    /// A new binary is installed: exit for systemd to start it.
    Restart,
}

/// Serves relays, one at a time, and status queries. `relay_uid`: the relay's user, served besides root.
pub async fn serve(
    listener: UnixListener,
    relay_uid: Option<u32>,
    mut agent: Agent,
    staging: Staging,
) -> Result<(), String> {
    let attached = Arc::new(AtomicBool::new(false));
    let (relays_tx, mut relays) = mpsc::channel::<UnixStream>(1);
    let accept = tokio::spawn(accept_loop(listener, relay_uid, attached.clone(), relays_tx, agent.live.clone()));
    let r = loop {
        let Some(conn) = relays.recv().await else { break Err("the broker's socket failed".to_string()) };
        attached.store(true, Ordering::SeqCst);
        tracing::info!("relay attached");
        let r = serve_relay(conn, &mut agent, &staging).await;
        attached.store(false, Ordering::SeqCst);
        match r {
            Ok(Served::Restart) => break Ok(()),
            Ok(Served::Detached) => tracing::info!("relay detached"),
            Err(e) => tracing::warn!("relay dropped: {e}"),
        }
    };
    accept.abort();
    r
}

async fn accept_loop(
    listener: UnixListener,
    relay_uid: Option<u32>,
    attached: Arc<AtomicBool>,
    relays: mpsc::Sender<UnixStream>,
    live: Live,
) {
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::warn!("broker socket: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        match stream.peer_cred() {
            Ok(c) if ipc::peer_allowed(c.uid(), relay_uid) => {}
            Ok(c) => {
                tracing::warn!(uid = c.uid(), pid = c.pid(), "broker socket: peer refused (not root or the relay)");
                continue;
            }
            Err(e) => {
                tracing::warn!("broker socket: peer credentials: {e}");
                continue;
            }
        }
        let (attached, relays, live) = (attached.clone(), relays.clone(), live.clone());
        tokio::spawn(async move {
            if let Err(e) = first_message(stream, &attached, &relays, &live).await {
                tracing::warn!("broker socket: {e}");
            }
        });
    }
}

/// A new connection: a status query is answered here; a relay is handed to the broker when none is attached.
async fn first_message(
    mut stream: UnixStream,
    attached: &AtomicBool,
    relays: &mpsc::Sender<UnixStream>,
    live: &Live,
) -> Result<(), String> {
    let first = tokio::time::timeout(FIRST_MESSAGE_WITHIN, ipc::read::<ToBroker, _>(&mut stream))
        .await
        .map_err(|_| "no first message in time".to_string())??;
    let refuse = |why: String| ToRelay::End { error: Some(why), restart: true };
    match first {
        None => Ok(()),
        Some(ToBroker::Status {}) => {
            let status = Status {
                agent_version: deploy_proto::build_version(),
                relay: attached.load(Ordering::SeqCst),
                session: live.lock().clone(),
            };
            ipc::write(&mut stream, &ToRelay::Status { status }).await
        }
        Some(ToBroker::Attach { version }) if version != ipc::VERSION => {
            let why = format!("the broker speaks IPC version {}, the relay {version}", ipc::VERSION);
            ipc::write(&mut stream, &refuse(why.clone())).await?;
            Err(why)
        }
        Some(ToBroker::Attach { .. }) => {
            if attached.load(Ordering::SeqCst) {
                ipc::write(&mut stream, &refuse("another relay is attached".into())).await?;
                return Err("a second relay refused: another one is attached".into());
            }
            if let Err(mpsc::error::TrySendError::Full(mut s) | mpsc::error::TrySendError::Closed(mut s)) =
                relays.try_send(stream)
            {
                ipc::write(&mut s, &refuse("another relay is attaching".into())).await?;
                return Err("a second relay refused: another one is attaching".into());
            }
            Ok(())
        }
        Some(m) => Err(format!("{} as first message: refused", m.name())),
    }
}

/// The attached relay: messages from it come through `rx` (read by a task of their own, so receiving is cancel-safe),
/// messages to it go through `tx` (written by another).
struct IpcLink {
    rx: mpsc::Receiver<Result<ToBroker, String>>,
    tx: mpsc::Sender<ToRelay>,
    staging: Staging,
    /// Why the relay is dropped: it broke the protocol during a session.
    broken: Option<String>,
}

impl IpcLink {
    async fn tell(&self, m: ToRelay) -> Result<(), String> {
        self.tx.send(m).await.map_err(|_| "the relay disconnected".to_string())
    }

    /// The next message of the relay that is not about staging (those are handled here): None once it disconnected.
    async fn next(&mut self) -> Result<Option<ToBroker>, String> {
        loop {
            match self.rx.recv().await {
                None => return Ok(None),
                Some(Err(e)) => return Err(e),
                Some(Ok(ToBroker::Staged { sha256 })) => self.staging.staged(&sha256)?,
                Some(Ok(ToBroker::StageFailed { sha256, message })) => self.staging.failed(&sha256, message)?,
                Some(Ok(m)) => return Ok(Some(m)),
            }
        }
    }
}

impl Link for IpcLink {
    async fn recv(&mut self) -> Option<Result<String, String>> {
        let e = match self.next().await {
            Ok(Some(ToBroker::FrameIn { text })) => return Some(Ok(text)),
            Ok(Some(ToBroker::Ended { error: None })) | Ok(None) => return None,
            Ok(Some(ToBroker::Ended { error: Some(e) })) => return Some(Err(e)),
            Ok(Some(m)) => format!("relay: {} out of protocol during a session", m.name()),
            Err(e) => e,
        };
        self.broken = Some(e.clone());
        Some(Err(e))
    }

    async fn send(&mut self, text: String) -> Result<(), String> {
        self.tell(ToRelay::FrameOut { text }).await
    }

    /// The broker tells the relay how the session ended once it ended ([`relay_loop`]).
    async fn close(&mut self) {}
}

async fn read_loop(rd: OwnedReadHalf, tx: mpsc::Sender<Result<ToBroker, String>>) {
    let mut rd = BufReader::new(rd);
    loop {
        let m = ipc::read::<ToBroker, _>(&mut rd).await;
        let stop = !matches!(m, Ok(Some(_)));
        let item = match m {
            Ok(Some(m)) => Ok(m),
            Ok(None) => break,
            Err(e) => Err(e),
        };
        if tx.send(item).await.is_err() || stop {
            break;
        }
    }
}

async fn write_loop(wr: OwnedWriteHalf, mut rx: mpsc::Receiver<ToRelay>) {
    let mut wr = BufWriter::new(wr);
    while let Some(m) = rx.recv().await {
        if let Err(e) = ipc::write(&mut wr, &m).await {
            tracing::warn!("to the relay: {e}");
            break;
        }
    }
}

async fn serve_relay(stream: UnixStream, agent: &mut Agent, staging: &Staging) -> Result<Served, String> {
    let (rd, wr) = stream.into_split();
    let (tx, out) = mpsc::channel(256);
    let writer = tokio::spawn(write_loop(wr, out));
    let (inbound, rx) = mpsc::channel(16);
    let reader = tokio::spawn(read_loop(rd, inbound));
    let mut link = IpcLink { rx, tx, staging: staging.clone(), broken: None };
    let attached = ToRelay::Attached { version: ipc::VERSION, agent_version: deploy_proto::build_version() };
    let r = match link.tell(attached).await {
        Ok(()) => {
            staging.attach(link.tx.clone());
            relay_loop(agent, &mut link).await
        }
        Err(e) => Err(e),
    };
    staging.detach();
    reader.abort();
    drop(link);
    // What is queued for the relay (the end of the session, the restart) still goes out.
    let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
    r
}

/// The relay's sessions: a connect request, the answer, then the session until it ends; again.
async fn relay_loop(agent: &mut Agent, link: &mut IpcLink) -> Result<Served, String> {
    let mut pending: Option<Handshake> = None;
    loop {
        let Some(m) = link.next().await? else { return Ok(Served::Detached) };
        match m {
            ToBroker::Connect {} => {
                let (headers, hs) = agent.connect_request();
                pending = Some(hs);
                link.tell(ToRelay::ConnectHeaders { url: agent.connect_url(), headers }).await?;
            }
            ToBroker::Answer { headers } => {
                let hs = pending.take().ok_or("relay: an answer without a connect request")?;
                let session = match ipc::answer_headers(&headers).and_then(|h| agent.accept(hs, &h)) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!("connection: {e}");
                        link.tell(ToRelay::End { error: Some(e), restart: false }).await?;
                        continue;
                    }
                };
                match agent.drive(session, link).await {
                    Ok(Flow::Restart) => {
                        link.tell(ToRelay::End { error: None, restart: true }).await?;
                        return Ok(Served::Restart);
                    }
                    Ok(Flow::Closed) => tracing::info!("connection closed"),
                    Err(e) => {
                        tracing::warn!("connection: {e}");
                        let _ = link.tell(ToRelay::End { error: Some(e), restart: false }).await;
                        if let Some(why) = link.broken.take() {
                            return Err(why);
                        }
                    }
                }
            }
            // A connection that failed or closed before its answer reached the broker.
            ToBroker::Ended { .. } => pending = None,
            // Frames the relay passed on before it learnt that their session ended: never opened, never acted upon.
            ToBroker::FrameIn { .. } => tracing::debug!("a frame outside a session dropped"),
            m => return Err(format!("relay: {} out of protocol", m.name())),
        }
    }
}

#[cfg(test)]
mod tests {
    use deploy_proto::msg::{Ping, Pong};
    use deploy_proto::session::{Exchange, Session, Transcript};
    use deploy_proto::{Direction, Frame, Sealer, connect};
    use ed25519_dalek::SigningKey;
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::git::TempDir;
    use crate::session::tests::{agent, answer};
    use crate::update::Fetcher;

    fn uid() -> u32 {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }

    /// A broker on a socket in `dir` whose agent pinned `control`; its relay user is the test's own.
    async fn broker(dir: &TempDir, control: &SigningKey) -> PathBuf {
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let staging = Staging::new(dir.path().join("agent.new"));
        let a = agent(&state, control, "ws://127.0.0.1:9/v1/agent/connect", Fetcher::Relay(staging.clone()));
        let sock = dir.path().join("run/broker.sock");
        let listener = bind(&sock, None).unwrap();
        tokio::spawn(serve(listener, Some(uid()), a, staging));
        sock
    }

    struct Relay(UnixStream);

    impl Relay {
        /// Attaches once the broker let the previous relay go.
        async fn attach(sock: &Path) -> Relay {
            for _ in 0..100 {
                let mut r = Relay(UnixStream::connect(sock).await.unwrap());
                r.tell(&ToBroker::Attach { version: ipc::VERSION }).await;
                match r.next().await {
                    Some(ToRelay::Attached { version: ipc::VERSION, .. }) => return r,
                    Some(ToRelay::End { .. }) => tokio::time::sleep(Duration::from_millis(50)).await,
                    other => panic!("not attached: {other:?}"),
                }
            }
            panic!("another relay stays attached")
        }

        async fn tell(&mut self, m: &ToBroker) {
            ipc::write(&mut self.0, m).await.unwrap();
        }

        async fn next(&mut self) -> Option<ToRelay> {
            tokio::time::timeout(Duration::from_secs(10), ipc::read(&mut self.0)).await.expect("in time").unwrap()
        }

        async fn frame(&mut self) -> Frame {
            match self.next().await {
                Some(ToRelay::FrameOut { text }) => serde_json::from_str(&text).unwrap(),
                other => panic!("not a frame: {other:?}"),
            }
        }

        /// Asks for a connect request and answers it as `control` would: the control plane's session.
        async fn session(&mut self, control: &SigningKey) -> Session {
            self.tell(&ToBroker::Connect {}).await;
            let Some(ToRelay::ConnectHeaders { url, headers }) = self.next().await else { panic!("no headers") };
            assert_eq!(url, "ws://127.0.0.1:9/v1/agent/connect");
            assert!(headers.iter().any(|(n, _)| n == connect::HDR_SIGNATURE), "signed by the broker");
            let (h, s) = answer(control, &headers);
            self.tell(&ToBroker::Answer { headers: h }).await;
            let proof = self.frame().await;
            assert_eq!(proof.kind, "session_proof");
            assert_eq!(self.frame().await.kind, "hello");
            s
        }
    }

    fn sealed(control: &SigningKey, s: &Session, nonce: u64) -> String {
        let mut s = Sealer::new(control.clone(), Direction::ControlToAgent).in_session(&s.keys);
        serde_json::to_string(&s.seal(&Ping { nonce }, crate::now())).unwrap()
    }

    /// The message of a frame the broker sealed in `s` (the control plane's view; the agent's key is not needed to
    /// decrypt).
    fn read(s: &Session, f: &Frame) -> String {
        s.keys.cipher(Direction::AgentToControl).open(f.seq, f.ts, &f.kind, &f.body).expect("sealed for the session")
    }

    /// Through the broker's socket, a frame that verifies for the session is acted upon; one sealed for another
    /// session, unsigned or signed by another key ends the session, as it would on the wire. What the relay carries
    /// out is encrypted for the session.
    #[tokio::test]
    async fn broker_acts_only_on_frames_of_its_session() {
        let dir = TempDir::new().unwrap();
        let control = deploy_proto::generate_key();
        let sock = broker(&dir, &control).await;
        let mut r = Relay::attach(&sock).await;

        let s = r.session(&control).await;
        r.tell(&ToBroker::FrameIn { text: sealed(&control, &s, 7) }).await;
        let pong = r.frame().await;
        assert!(pong.decode::<Pong>().is_err(), "the relay cannot read it");
        assert_eq!(serde_json::from_str::<Pong>(&read(&s, &pong)).unwrap().nonce, 7);

        // A frame of another session (a valid signature by the control key, recorded elsewhere).
        let other = Exchange::generate();
        let t = Transcript {
            control_nonce: deploy_proto::session::nonce(),
            control_exchange: other.public_key(),
            ..s.transcript.clone()
        };
        let other = Session { keys: other.finish(&t, Direction::ControlToAgent).unwrap(), transcript: t };
        r.tell(&ToBroker::FrameIn { text: sealed(&control, &other, 8) }).await;
        match r.next().await {
            Some(ToRelay::End { error: Some(e), restart: false }) => assert!(e.contains("refused"), "{e}"),
            other => panic!("the session did not end: {other:?}"),
        }

        // Signed by another key, and unsigned.
        let stranger = deploy_proto::generate_key();
        type Forge<'a> = &'a dyn Fn(&Session) -> String;
        let forged: [Forge; 2] = [&|s| sealed(&stranger, s, 1), &|s| {
            let mut f: Frame = serde_json::from_str(&sealed(&control, s, 1)).unwrap();
            f.sig = String::new();
            serde_json::to_string(&f).unwrap()
        }];
        for forge in forged {
            let s = r.session(&control).await;
            r.tell(&ToBroker::FrameIn { text: forge(&s) }).await;
            assert!(matches!(r.next().await, Some(ToRelay::End { error: Some(_), restart: false })));
        }

        // An answer not signed by a pinned key opens no session.
        r.tell(&ToBroker::Connect {}).await;
        let Some(ToRelay::ConnectHeaders { headers, .. }) = r.next().await else { panic!("no headers") };
        let (h, _) = answer(&stranger, &headers);
        r.tell(&ToBroker::Answer { headers: h }).await;
        match r.next().await {
            Some(ToRelay::End { error: Some(e), .. }) => assert!(e.contains("handshake refused"), "{e}"),
            other => panic!("accepted: {other:?}"),
        }

        // A relay that answers with its own exchange key in place of the control plane's (to read the session)
        // has no signature over it: refused.
        r.tell(&ToBroker::Connect {}).await;
        let Some(ToRelay::ConnectHeaders { headers, .. }) = r.next().await else { panic!("no headers") };
        let (mut h, _) = answer(&control, &headers);
        let mitm = deploy_proto::session::encode_exchange_key(&Exchange::generate().public_key());
        h.iter_mut().filter(|(n, _)| n == connect::HDR_CONTROL_EXCHANGE_KEY).for_each(|(_, v)| *v = mitm.clone());
        r.tell(&ToBroker::Answer { headers: h }).await;
        match r.next().await {
            Some(ToRelay::End { error: Some(e), .. }) => assert!(e.contains("does not verify"), "{e}"),
            other => panic!("accepted: {other:?}"),
        }
    }

    /// Out of protocol: an answer without a request, a second attach or status query, an unknown message: the broker
    /// drops the relay, which may attach again. A frame outside a session (one in flight when its session ended) is
    /// dropped without being opened.
    #[tokio::test]
    async fn broker_drops_a_relay_out_of_protocol() {
        let dir = TempDir::new().unwrap();
        let control = deploy_proto::generate_key();
        let sock = broker(&dir, &control).await;

        let mut r = Relay::attach(&sock).await;
        let (a, c) = (Exchange::generate(), Exchange::generate());
        let t = Transcript {
            protocol: 2,
            server_id: "srv_1".into(),
            agent_nonce: deploy_proto::session::nonce(),
            control_nonce: deploy_proto::session::nonce(),
            control_key: control.verifying_key(),
            agent_exchange: a.public_key(),
            control_exchange: c.public_key(),
        };
        let stray = Session { keys: c.finish(&t, Direction::ControlToAgent).unwrap(), transcript: t };
        r.tell(&ToBroker::FrameIn { text: sealed(&control, &stray, 1) }).await;
        r.session(&control).await;
        drop(r);
        for m in [ToBroker::Attach { version: ipc::VERSION }, ToBroker::Status {}] {
            let mut r = Relay::attach(&sock).await;
            r.tell(&m).await;
            assert_eq!(r.next().await, None, "dropped");
        }

        let mut r = Relay::attach(&sock).await;
        r.tell(&ToBroker::Answer { headers: vec![] }).await;
        assert_eq!(r.next().await, None, "dropped");

        let mut r = Relay::attach(&sock).await;
        let unknown = br#"{"type":"execute","op":"docker_info"}"#;
        r.0.write_all(&(unknown.len() as u32).to_be_bytes()).await.unwrap();
        r.0.write_all(unknown).await.unwrap();
        assert_eq!(r.next().await, None, "dropped");

        // During a session: the session ends and the relay is dropped.
        let mut r = Relay::attach(&sock).await;
        r.session(&control).await;
        r.tell(&ToBroker::Connect {}).await;
        assert!(matches!(r.next().await, Some(ToRelay::End { error: Some(e), .. }) if e.contains("out of protocol")));
        assert_eq!(r.next().await, None, "dropped");
    }

    /// A download is asked of the attached relay; its end is accepted only for what was asked, and a relay that goes
    /// away fails the download instead of leaving it pending.
    #[tokio::test]
    async fn staging_follows_the_brokers_requests() {
        let dir = TempDir::new().unwrap();
        let staging = Staging::new(dir.path().join("agent.new"));
        let bin = Binary { path: dir.path().join("owdeploy-agent"), sha256: "0".repeat(64) };
        let k = deploy_proto::generate_key();
        let u = deploy_proto::update::offer(&k, "linux-amd64", "0.2.0", &"a".repeat(64), false);
        let (done, mut fetched) = mpsc::channel(4);
        assert!(staging.request("http://x/b".into(), bin.clone(), u.clone(), done.clone()).is_err(), "no relay");

        let (relay, mut to_relay) = mpsc::channel(4);
        staging.attach(relay);
        staging.request("http://x/b".into(), bin.clone(), u.clone(), done.clone()).unwrap();
        assert_eq!(to_relay.recv().await, Some(ToRelay::Stage { url: "http://x/b".into(), sha256: u.sha256.clone() }));
        assert!(staging.staged(&"b".repeat(64)).is_err(), "not what was asked");
        staging.failed(&u.sha256, "HTTP 404".into()).unwrap();
        let f = fetched.recv().await.unwrap();
        assert_eq!(f.result, Err("download by the relay: HTTP 404".into()));
        assert!(staging.staged(&u.sha256).is_err(), "answered once");

        staging.request("http://x/b".into(), bin, u, done).unwrap();
        staging.detach();
        assert!(fetched.recv().await.unwrap().result.unwrap_err().contains("disconnected"));
    }

    /// One relay at a time; a status query is answered meanwhile; a relay of another IPC version is refused.
    #[tokio::test]
    async fn one_relay_at_a_time_and_status() {
        let dir = TempDir::new().unwrap();
        let control = deploy_proto::generate_key();
        let sock = broker(&dir, &control).await;
        let status = async || {
            let mut q = UnixStream::connect(&sock).await.unwrap();
            ipc::write(&mut q, &ToBroker::Status {}).await.unwrap();
            let Some(ToRelay::Status { status }) = ipc::read(&mut q).await.unwrap() else { panic!("no status") };
            status
        };
        assert_eq!((status().await.relay, status().await.session), (false, None));

        let mut r = Relay::attach(&sock).await;
        let mut second = Relay(UnixStream::connect(&sock).await.unwrap());
        second.tell(&ToBroker::Attach { version: ipc::VERSION }).await;
        assert!(matches!(second.next().await, Some(ToRelay::End { error: Some(_), restart: true })));
        r.session(&control).await;
        let s = status().await;
        assert!(s.relay);
        assert_eq!(s.session.as_ref().map(|s| (s.protocol, s.verified)), Some((2, false)));

        drop(r);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!((status().await.relay, status().await.session), (false, None), "the session ended with the relay");

        let mut old = Relay(UnixStream::connect(&sock).await.unwrap());
        old.tell(&ToBroker::Attach { version: ipc::VERSION + 1 }).await;
        assert!(matches!(old.next().await, Some(ToRelay::End { error: Some(_), restart: true })));
    }
}
