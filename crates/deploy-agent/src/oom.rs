//! Out-of-memory kills of Deploy's containers, from a permanent subscription to Docker's events (`oom`, `die` and
//! `destroy` of containers with Deploy's resource label), kept in memory for [`ContainerState::oom_at`].
//!
//! Docker clears a container's `OOMKilled` when it restarts it, and keeps only its last 256 events: on a server whose
//! health checks fill them (each check is three events), a kill drops out of that backlog within seconds. The
//! subscription sees every kill as it happens; when it breaks (Docker restarted, the stream cut), it reconnects with a
//! short backoff and first reads Docker's backlog from the last event it saw, so nothing still in that backlog is
//! lost. While it is not following the events, `AppStatus` reads Docker's backlog itself, as agents before 0.5.1 did.
//!
//! [`ContainerState::oom_at`]: deploy_proto::msg::ContainerState::oom_at

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use bollard::Docker;
use bollard::models::{EventMessage, EventMessageTypeEnum};
use bollard::query_parameters::EventsOptionsBuilder;
use deploy_proto::msg::{LABEL_RESOURCE, OOM_EVENTS_WINDOW_SECS};
use futures_util::StreamExt;

const NANOS: i64 = 1_000_000_000;
/// How long a container's kills and exits are remembered: the window `AppStatus` reports.
const RETENTION_NANOS: i64 = OOM_EVENTS_WINDOW_SECS * NANOS;
/// Containers remembered at most; past it, the one seen longest ago is forgotten.
pub const MAX_CONTAINERS: usize = 4096;
/// How long a read of Docker's backlog may take.
pub const BACKLOG_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest wait between two connections: Docker's backlog may hold as little as 30 s of events.
const BACKOFF_MAX: Duration = Duration::from_secs(8);
/// A kill and the exit it causes are a few milliseconds apart, in either order.
const EXIT_OF_KILL_NANOS: i64 = NANOS;

/// What happened to a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The kernel killed one of its processes for the container's memory limit.
    Oom,
    /// Its main process exited (137 when it was killed).
    Die { exit_code: Option<i64> },
    /// The container was removed.
    Destroy,
}

/// One of Docker's container events, as the store keeps them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub id: String,
    pub action: Action,
    /// Unix nanoseconds.
    pub nanos: i64,
}

impl Seen {
    pub fn from_event(e: EventMessage) -> Option<Seen> {
        if e.typ != Some(EventMessageTypeEnum::CONTAINER) {
            return None;
        }
        let actor = e.actor?;
        let action = match e.action.as_deref()? {
            "oom" => Action::Oom,
            "die" => Action::Die {
                exit_code: actor.attributes.as_ref().and_then(|a| a.get("exitCode")).and_then(|c| c.parse().ok()),
            },
            "destroy" => Action::Destroy,
            _ => return None,
        };
        let nanos = e.time_nano.or_else(|| e.time.map(|t| t * NANOS))?;
        Some(Seen { id: actor.id.filter(|id| !id.is_empty())?, action, nanos })
    }
}

/// A container's last out-of-memory kill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kill {
    /// Unix nanoseconds.
    pub at: i64,
    /// Kills seen in the window.
    pub count: u32,
    /// The exit code of the container's main process when the kill made it exit (137); None when another process
    /// was killed and the container kept running.
    pub exit_code: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Entry {
    oom: Option<(i64, u32)>,
    exit: Option<(i64, Option<i64>)>,
}

impl Entry {
    fn newest(&self) -> i64 {
        self.oom.map_or(i64::MIN, |o| o.0).max(self.exit.map_or(i64::MIN, |e| e.0))
    }
}

/// What a recorded event changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Already recorded (a backlog read again after a reconnection), or of no interest.
    None,
    Killed(Kill),
    /// The main process exited right after its kill.
    ExitedByKill(Kill),
}

/// The containers' kills and exits of the window, bounded by [`MAX_CONTAINERS`].
#[derive(Debug, Default)]
pub struct Store {
    entries: HashMap<String, Entry>,
    /// The newest event recorded: a reconnection reads Docker's backlog from it.
    last: Option<i64>,
}

impl Store {
    pub fn record(&mut self, s: &Seen) -> Change {
        self.last = Some(self.last.map_or(s.nanos, |l| l.max(s.nanos)));
        if s.action == Action::Destroy {
            self.entries.remove(&s.id);
            return Change::None;
        }
        if !self.entries.contains_key(&s.id) && self.entries.len() >= MAX_CONTAINERS {
            self.prune(s.nanos);
            if self.entries.len() >= MAX_CONTAINERS
                && let Some(oldest) = self.entries.iter().min_by_key(|(_, e)| e.newest()).map(|(id, _)| id.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        let e = self.entries.entry(s.id.clone()).or_default();
        match s.action {
            Action::Oom => match e.oom {
                Some((at, _)) if s.nanos <= at => Change::None,
                o => {
                    e.oom = Some((s.nanos, o.map_or(1, |(_, n)| n + 1)));
                    Self::kill(e).map_or(Change::None, Change::Killed)
                }
            },
            Action::Die { exit_code } => match e.exit {
                Some((at, _)) if s.nanos <= at => Change::None,
                _ => {
                    e.exit = Some((s.nanos, exit_code));
                    match Self::kill(e) {
                        Some(k) if k.exit_code.is_some() => Change::ExitedByKill(k),
                        _ => Change::None,
                    }
                }
            },
            Action::Destroy => unreachable!("handled above"),
        }
    }

    fn kill(e: &Entry) -> Option<Kill> {
        let (at, count) = e.oom?;
        let exit_code = e.exit.filter(|(t, _)| *t >= at - EXIT_OF_KILL_NANOS).and_then(|(_, c)| c);
        Some(Kill { at, count, exit_code })
    }

    /// Forgets what happened before the window.
    pub fn prune(&mut self, now: i64) {
        self.entries.retain(|_, e| e.newest() > now - RETENTION_NANOS);
    }

    /// The container's last kill in the window.
    pub fn kill_of(&self, id: &str, now: i64) -> Option<Kill> {
        self.entries.get(id).and_then(Self::kill).filter(|k| k.at > now - RETENTION_NANOS)
    }

    pub fn last(&self) -> Option<i64> {
        self.last
    }

    /// Containers remembered.
    #[cfg(test)]
    pub fn containers(&self) -> usize {
        self.entries.len()
    }
}

/// The agent's store, and whether its subscription follows Docker's events now.
#[derive(Debug, Default)]
pub struct Kills {
    store: Mutex<Store>,
    following: AtomicBool,
}

pub static KILLS: LazyLock<Kills> = LazyLock::new(Kills::default);

impl Kills {
    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn following(&self) -> bool {
        self.following.load(Ordering::SeqCst)
    }

    /// The last kill of each of `ids` in the window (Unix seconds), and whether the subscription is following
    /// Docker's events (else the caller also reads Docker's backlog).
    pub fn last_kills<'a>(&self, ids: impl IntoIterator<Item = &'a str>) -> (HashMap<String, i64>, bool) {
        let now = now_nanos();
        let mut st = self.store();
        st.prune(now);
        let kills = ids.into_iter().filter_map(|id| Some((id.to_string(), st.kill_of(id, now)?.at / NANOS))).collect();
        (kills, self.following())
    }

    #[cfg(test)]
    pub fn kill_of(&self, id: &str) -> Option<Kill> {
        self.store().kill_of(id, now_nanos())
    }

    #[cfg(test)]
    pub fn containers(&self) -> usize {
        self.store().containers()
    }

    fn record(&self, e: EventMessage) {
        let Some(s) = Seen::from_event(e) else { return };
        let change = self.store().record(&s);
        let id = s.id.get(..12).unwrap_or(&s.id);
        match change {
            Change::None => {}
            Change::Killed(k) => {
                tracing::warn!("container {id}: a process was killed for its memory ({} in the window)", k.count)
            }
            Change::ExitedByKill(k) => tracing::warn!(
                "container {id}: its main process exited with {} after its out-of-memory kill",
                k.exit_code.unwrap_or_default()
            ),
        }
    }
}

fn now_nanos() -> i64 {
    i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos()).unwrap_or(i64::MAX)
}

/// Docker's `since`/`until` with nanoseconds.
fn docker_time(nanos: i64) -> String {
    format!("{}.{:09}", nanos.div_euclid(NANOS), nanos.rem_euclid(NANOS))
}

/// The events of Deploy's containers the store keeps, between `since` and `until` (none: live).
fn events(
    d: &Docker,
    since: i64,
    until: Option<i64>,
) -> impl futures_util::Stream<Item = Result<EventMessage, bollard::errors::Error>> + use<> {
    let filters = HashMap::from([
        ("type", vec!["container"]),
        ("event", vec!["oom", "die", "destroy"]),
        ("label", vec![LABEL_RESOURCE]),
    ]);
    let mut opts = EventsOptionsBuilder::default().since(&docker_time(since)).filters(&filters);
    if let Some(u) = until {
        opts = opts.until(&docker_time(u));
    }
    d.events(Some(opts.build()))
}

/// Clears `following` when the subscription ends, also when its task is aborted.
struct Following<'a>(&'a Kills);

impl Drop for Following<'_> {
    fn drop(&mut self) {
        self.0.following.store(false, Ordering::SeqCst);
    }
}

/// The agent's subscription, for as long as the agent runs.
pub async fn watch() {
    follow(&KILLS, crate::docker::client).await
}

/// Follows Docker's events into `kills` through the clients `connect` makes, reconnecting forever.
pub async fn follow(kills: &Kills, connect: impl Fn() -> Result<Docker, String>) {
    let _following = Following(kills);
    let start = now_nanos() - RETENTION_NANOS;
    let mut failures = 0u32;
    let mut last_error: Option<String> = None;
    loop {
        // From the newest event seen: Docker's backlog may still hold what happened since.
        let since = kills.store().last().unwrap_or(start).max(now_nanos() - RETENTION_NANOS);
        let error = match connect() {
            Ok(d) => {
                let (followed, error) = subscribe(kills, &d, since).await;
                kills.following.store(false, Ordering::SeqCst);
                if followed {
                    failures = 0;
                    tracing::info!("docker events: {error}; reconnecting");
                    last_error = None;
                }
                error
            }
            Err(e) => e,
        };
        if last_error.as_ref() != Some(&error) {
            tracing::warn!("docker events: {error}");
            last_error = Some(error);
        }
        let wait = Duration::from_secs(1 << failures.min(3)).min(BACKOFF_MAX);
        failures = failures.saturating_add(1);
        tokio::time::sleep(wait).await;
    }
}

/// One connection: Docker's backlog since `since` to its end, then the live events. Whether it followed the live
/// events, and why it ended.
async fn subscribe(kills: &Kills, d: &Docker, since: i64) -> (bool, String) {
    let until = now_nanos();
    let mut backlog = events(d, since, Some(until));
    let read = async {
        while let Some(e) = backlog.next().await {
            kills.record(e.map_err(|e| crate::docker::message(&e))?);
        }
        Ok::<(), String>(())
    };
    match tokio::time::timeout(BACKLOG_TIMEOUT, read).await {
        Err(_) => return (false, "no end of the backlog in time".into()),
        Ok(Err(e)) => return (false, e),
        Ok(Ok(())) => {}
    }
    let mut live = events(d, until, None);
    kills.following.store(true, Ordering::SeqCst);
    while let Some(e) = live.next().await {
        match e {
            Ok(e) => kills.record(e),
            Err(e) => return (true, crate::docker::message(&e)),
        }
    }
    (true, "the stream ended".into())
}

#[cfg(test)]
mod tests {
    use bollard::models::EventActor;

    use super::*;

    fn seen(id: &str, action: Action, secs: i64) -> Seen {
        Seen { id: id.into(), action, nanos: secs * NANOS }
    }

    const T: i64 = 1_800_000_000;

    #[test]
    fn events_are_read_from_dockers_messages() {
        let msg = |action: &str, attributes: &[(&str, &str)]| EventMessage {
            typ: Some(EventMessageTypeEnum::CONTAINER),
            action: Some(action.into()),
            actor: Some(EventActor {
                id: Some("c1".into()),
                attributes: Some(attributes.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()),
            }),
            time: Some(T),
            time_nano: Some(T * NANOS + 5),
            ..Default::default()
        };
        let s = |action, attributes| Seen::from_event(msg(action, attributes)).map(|s| (s.action, s.nanos));
        assert_eq!(s("oom", &[]), Some((Action::Oom, T * NANOS + 5)));
        assert_eq!(s("die", &[("exitCode", "137")]), Some((Action::Die { exit_code: Some(137) }, T * NANOS + 5)));
        assert_eq!(s("die", &[]), Some((Action::Die { exit_code: None }, T * NANOS + 5)));
        assert_eq!(s("destroy", &[]), Some((Action::Destroy, T * NANOS + 5)));
        assert_eq!(s("health_status: healthy", &[]), None);
        assert_eq!(s("exec_die", &[("exitCode", "0")]), None);
        let mut m = msg("oom", &[]);
        m.time_nano = None;
        assert_eq!(Seen::from_event(m).map(|s| s.nanos), Some(T * NANOS));
        let mut m = msg("oom", &[]);
        m.typ = Some(EventMessageTypeEnum::NETWORK);
        assert_eq!(Seen::from_event(m), None);
    }

    #[test]
    fn a_kill_of_the_main_process_carries_its_exit_in_either_order() {
        let mut st = Store::default();
        assert_eq!(
            st.record(&seen("c1", Action::Oom, T)),
            Change::Killed(Kill { at: T * NANOS, count: 1, exit_code: None })
        );
        let k = Kill { at: T * NANOS, count: 1, exit_code: Some(137) };
        assert_eq!(st.record(&seen("c1", Action::Die { exit_code: Some(137) }, T)), Change::ExitedByKill(k));
        assert_eq!(st.kill_of("c1", T * NANOS), Some(k));
        // The exit reported before the kill.
        st.record(&seen("c2", Action::Die { exit_code: Some(137) }, T));
        assert_eq!(st.kill_of("c2", T * NANOS), None);
        st.record(&seen("c2", Action::Oom, T));
        assert_eq!(st.kill_of("c2", T * NANOS).and_then(|k| k.exit_code), Some(137));
        // A secondary process killed: the container keeps running; an exit long before tells nothing.
        st.record(&seen("c3", Action::Die { exit_code: Some(1) }, T - 60));
        st.record(&seen("c3", Action::Oom, T));
        assert_eq!(st.kill_of("c3", T * NANOS), Some(Kill { at: T * NANOS, count: 1, exit_code: None }));
        // Restarted and killed again: a new kill, without the exit of the first.
        st.record(&seen("c1", Action::Oom, T + 30));
        assert_eq!(st.kill_of("c1", (T + 30) * NANOS), Some(Kill { at: (T + 30) * NANOS, count: 2, exit_code: None }));
    }

    #[test]
    fn a_backlog_read_again_counts_nothing_twice() {
        let mut st = Store::default();
        let events = [
            seen("c1", Action::Oom, T),
            seen("c1", Action::Die { exit_code: Some(137) }, T),
            seen("c2", Action::Die { exit_code: Some(0) }, T + 1),
        ];
        for e in &events {
            st.record(e);
        }
        assert_eq!(st.last(), Some((T + 1) * NANOS));
        for e in &events {
            assert_eq!(st.record(e), Change::None, "{e:?}");
        }
        assert_eq!(st.kill_of("c1", T * NANOS), Some(Kill { at: T * NANOS, count: 1, exit_code: Some(137) }));
        assert_eq!(st.kill_of("c2", T * NANOS), None);
    }

    #[test]
    fn kills_are_kept_for_the_window_and_forgotten_with_their_container() {
        let mut st = Store::default();
        st.record(&seen("c1", Action::Oom, T));
        st.record(&seen("c2", Action::Oom, T));
        let end = T + OOM_EVENTS_WINDOW_SECS;
        assert!(st.kill_of("c1", (end - 1) * NANOS).is_some());
        assert_eq!(st.kill_of("c1", end * NANOS), None);
        st.record(&seen("c2", Action::Destroy, T + 1));
        assert_eq!(st.kill_of("c2", T * NANOS), None);
        st.prune(end * NANOS);
        assert_eq!(st.containers(), 0);
        assert_eq!(st.last(), Some((T + 1) * NANOS));
    }

    #[test]
    fn many_events_keep_the_store_bounded() {
        let mut st = Store::default();
        // Short-lived containers: an exit each, some killed.
        for i in 0..3 * MAX_CONTAINERS as i64 {
            let id = format!("c{i}");
            st.record(&seen(&id, Action::Die { exit_code: Some(1) }, T + i / 100));
            if i % 7 == 0 {
                st.record(&seen(&id, Action::Oom, T + i / 100));
            }
            assert!(st.containers() <= MAX_CONTAINERS);
        }
        // The newest kill survives; the ones seen longest ago went first.
        let newest = 3 * MAX_CONTAINERS as i64 - 7;
        let newest = newest - newest % 7;
        assert!(st.kill_of(&format!("c{newest}"), (T + newest / 100) * NANOS).is_some());
        assert_eq!(st.kill_of("c0", T * NANOS), None);
        // One container's events, however many, are one entry.
        let mut st = Store::default();
        for i in 0..100_000 {
            st.record(&seen("c1", Action::Die { exit_code: Some(0) }, T + i));
        }
        assert_eq!(st.containers(), 1);
    }

    #[test]
    fn docker_times_carry_nanoseconds() {
        assert_eq!(docker_time(T * NANOS + 5), format!("{T}.000000005"));
        assert_eq!(docker_time(T * NANOS), format!("{T}.000000000"));
    }
}
