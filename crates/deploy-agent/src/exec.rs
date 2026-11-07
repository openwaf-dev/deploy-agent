//! `docker exec`: commands in running containers. Builds and Compose deployments run their steps this way in their
//! helper container; the `Exec` operation runs scheduled tasks in an application's container.

use std::pin::Pin;
use std::time::Duration;

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::models::ContainerSummary;
use deploy_proto::msg::{ExecOutput, ExecSpec, LogStream, MAX_EXEC_OUTPUT};
use futures_util::{Stream, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::CANCELLED;
use crate::docker::{COMPOSE_SERVICE, app_containers, check_container, client, is_running, message, valid_id};
use crate::events::{Events, Lines};

/// How long a killed command may take to close its output before the agent stops waiting for it.
const KILL_GRACE: Duration = Duration::from_secs(5);

type Output = Pin<Box<dyn Stream<Item = Result<LogOutput, bollard::errors::Error>> + Send>>;

/// A started exec whose output is read with [`Running::next`].
pub struct Running {
    pub id: String,
    // Only ever used through `&mut self` (`get_mut`, no locking): the mutex makes `Running` `Sync`, so futures
    // holding `&Running` across an await stay `Send`.
    output: std::sync::Mutex<Output>,
}

/// Starts `cmd` in `container`. `env` reaches the process only (not argv, not the container's configuration);
/// `stdin`, when given, is written then closed and wiped from memory.
pub async fn start(
    d: &Docker,
    container: &str,
    cmd: Vec<String>,
    env: Vec<String>,
    stdin: Option<Vec<u8>>,
) -> Result<Running, String> {
    let opts = CreateExecOptions {
        cmd: Some(cmd),
        env: Some(env),
        attach_stdin: Some(stdin.is_some()),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        tty: Some(false),
        ..Default::default()
    };
    let id = d.create_exec(container, opts).await.map_err(|e| format!("exec: {}", message(&e)))?.id;
    let started = d
        .start_exec(&id, Some(StartExecOptions { detach: false, tty: false, output_capacity: None }))
        .await
        .map_err(|e| format!("exec: {}", message(&e)))?;
    let StartExecResults::Attached { output, mut input } = started else {
        return Err("exec: the Engine detached the command".into());
    };
    if let Some(mut data) = stdin {
        let w = input.write_all(&data).await.and(input.shutdown().await);
        data.iter_mut().for_each(|b| *b = 0);
        w.map_err(|e| format!("exec stdin: {e}"))?;
    }
    Ok(Running { id, output: std::sync::Mutex::new(output) })
}

impl Running {
    /// The next chunk of output; None once the command closed it (it ended, or was killed).
    pub async fn next(&mut self) -> Option<Result<(LogStream, bytes::Bytes), String>> {
        loop {
            let output = self.output.get_mut().unwrap_or_else(std::sync::PoisonError::into_inner);
            return match output.next().await? {
                Ok(LogOutput::StdErr { message }) => Some(Ok((LogStream::Stderr, message))),
                Ok(LogOutput::StdOut { message } | LogOutput::Console { message }) => {
                    Some(Ok((LogStream::Stdout, message)))
                }
                Ok(LogOutput::StdIn { .. }) => continue,
                Err(e) => Some(Err(format!("exec output: {}", message(&e)))),
            };
        }
    }

    /// Exit code once the command ended (None while it runs, or when the Engine does not know it).
    pub async fn exit_code(&self, d: &Docker) -> Result<Option<i64>, String> {
        let i = d.inspect_exec(&self.id).await.map_err(|e| format!("exec: {}", message(&e)))?;
        Ok(if i.running == Some(true) { None } else { i.exit_code })
    }

    /// Kills the command: its process group, then the process itself. The Engine has no call for this, so the agent
    /// signals the host PID the Engine reports (it runs as root in the host's PID namespace).
    pub async fn kill(&self, d: &Docker) -> Result<(), String> {
        let i = d.inspect_exec(&self.id).await.map_err(|e| format!("exec: {}", message(&e)))?;
        if i.running != Some(true) {
            return Ok(());
        }
        let pid = i.pid.filter(|p| *p > 1 && *p <= i64::from(i32::MAX)).ok_or("exec: no process id")? as i32;
        // SAFETY: plain signal delivery to a PID read from the Engine just above; no memory is shared.
        let group = unsafe { libc::kill(-pid, libc::SIGKILL) };
        let own = unsafe { libc::kill(pid, libc::SIGKILL) };
        if group != 0 && own != 0 {
            return Err(format!("kill {pid}: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

/// Reads an exec to its end, sending its lines to `ev` except those `keep` turns down (markers a script prints for
/// the agent). Returns the exit code; a cancel kills nothing by itself (helpers are removed by their owner).
pub async fn pump(
    d: &Docker,
    mut r: Running,
    ev: &Events,
    cancel: &CancellationToken,
    keep: &mut (dyn FnMut(LogStream, &str) -> bool + Send),
) -> Result<i64, String> {
    let (mut out, mut err) = (Lines::default(), Lines::default());
    loop {
        let item = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(CANCELLED.into()),
            i = r.next() => i,
        };
        let Some(item) = item else { break };
        let (stream, chunk) = item?;
        let buf = if stream == LogStream::Stderr { &mut err } else { &mut out };
        for l in buf.push(&chunk) {
            if keep(stream, &l) {
                ev.line(stream, l).await;
            }
        }
    }
    for (stream, buf) in [(LogStream::Stdout, &mut out), (LogStream::Stderr, &mut err)] {
        if let Some(l) = buf.finish()
            && keep(stream, &l)
        {
            ev.line(stream, l).await;
        }
    }
    Ok(r.exit_code(d).await?.unwrap_or(-1))
}

/// Keeps the last `cap` bytes of a byte stream, on a character boundary when decoded.
struct Tail {
    buf: Vec<u8>,
    cap: usize,
    dropped: bool,
}

impl Tail {
    fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
        if self.buf.len() > self.cap {
            let cut = self.buf.len() - self.cap;
            self.buf.drain(..cut);
            self.dropped = true;
        }
    }

    fn text(&self) -> String {
        // A cut may land inside a multi-byte character: skip its continuation bytes.
        let start = self.buf.iter().position(|b| (b & 0xC0) != 0x80).unwrap_or(self.buf.len());
        String::from_utf8_lossy(&self.buf[start..]).into_owned()
    }
}

/// The container a command runs in: the application's newest running container, or the newest running container
/// of the Compose service. Only the application's own containers ([`app_containers`]): never another
/// application's, the router, a helper or a container of someone else.
async fn target(d: &Docker, resource: &str, service: Option<&str>) -> Result<String, String> {
    choose(resource, &app_containers(d, resource).await?, service)
}

/// [`target`] among `list` (newest first), each checked again to be one of `resource`'s containers.
fn choose(resource: &str, list: &[ContainerSummary], service: Option<&str>) -> Result<String, String> {
    let c = list.iter().filter(|c| is_running(c)).find(|c| match service {
        Some(s) => c.labels.as_ref().and_then(|l| l.get(COMPOSE_SERVICE)).is_some_and(|v| v == s),
        None => true,
    });
    let c = c.ok_or_else(|| match service {
        Some(s) => format!("the service {s} has no running container"),
        None => "the application has no running container".to_string(),
    })?;
    check_container(resource, c.names.as_deref().unwrap_or_default(), c.labels.as_ref())?;
    c.id.clone().ok_or_else(|| "the container has no id".to_string())
}

/// The `Exec` operation: streams the command's output, kills it on timeout or cancel.
pub async fn exec(spec: &ExecSpec, ev: &Events, cancel: &CancellationToken) -> Result<ExecOutput, String> {
    if !valid_id(&spec.resource) {
        return Err("invalid resource id".into());
    }
    if spec.command.is_empty() || spec.command.iter().any(|a| a.contains('\0')) {
        return Err("the command is empty or contains NUL".into());
    }
    if spec.service.as_deref().is_some_and(|s| !valid_id(s)) {
        return Err("invalid service name".into());
    }
    let d = client()?;
    let container = target(&d, &spec.resource, spec.service.as_deref()).await?;
    let mut r = start(&d, &container, spec.command.clone(), Vec::new(), None).await?;
    let deadline = tokio::time::sleep(Duration::from_secs(u64::from(spec.timeout_secs.max(1))));
    tokio::pin!(deadline);
    let mut tail = Tail { buf: Vec::new(), cap: MAX_EXEC_OUTPUT, dropped: false };
    let (mut out, mut err) = (Lines::default(), Lines::default());
    let mut stopped: Option<&str> = None;
    let mut grace = Box::pin(tokio::time::sleep(Duration::MAX));
    loop {
        let item = tokio::select! {
            biased;
            _ = cancel.cancelled(), if stopped.is_none() => {
                stopped = Some(CANCELLED);
                r.kill(&d).await?;
                grace.as_mut().reset(tokio::time::Instant::now() + KILL_GRACE);
                continue;
            }
            _ = &mut deadline, if stopped.is_none() => {
                stopped = Some("timeout");
                ev.system(format!("Timed out after {}s: killing the command", spec.timeout_secs.max(1))).await;
                r.kill(&d).await?;
                grace.as_mut().reset(tokio::time::Instant::now() + KILL_GRACE);
                continue;
            }
            // Children of a killed command may keep its output open: stop reading rather than wait for them.
            _ = &mut grace => break,
            i = r.next() => i,
        };
        let Some(item) = item else { break };
        let (stream, chunk) = item?;
        tail.push(&chunk);
        let buf = if stream == LogStream::Stderr { &mut err } else { &mut out };
        for l in buf.push(&chunk) {
            ev.line(stream, l).await;
        }
    }
    for (stream, buf) in [(LogStream::Stdout, &mut out), (LogStream::Stderr, &mut err)] {
        if let Some(l) = buf.finish() {
            ev.line(stream, l).await;
        }
    }
    if stopped == Some(CANCELLED) {
        return Err(CANCELLED.into());
    }
    Ok(ExecOutput {
        exit_code: r.exit_code(&d).await?,
        timed_out: stopped.is_some(),
        output: tail.text(),
        truncated: tail.dropped,
        container_id: container,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_the_end_on_a_character_boundary() {
        let mut t = Tail { buf: Vec::new(), cap: 5, dropped: false };
        t.push(b"ab");
        assert_eq!((t.text().as_str(), t.dropped), ("ab", false));
        t.push("cdé".as_bytes());
        // "abcdé" is 6 bytes: the cut drops "a" and keeps "bcdé".
        assert_eq!((t.text().as_str(), t.dropped), ("bcdé", true));
        t.push(b"zyw");
        // "bcdézyw" keeps "ézyw"; one more byte and the window starts inside "é", whose remainder is skipped.
        assert_eq!(t.text(), "ézyw");
        t.push(b"v");
        assert_eq!(t.text(), "zywv");
    }

    fn container(id: &str, name: &str, labels: &[(&str, &str)]) -> ContainerSummary {
        ContainerSummary {
            id: Some(id.into()),
            names: Some(vec![format!("/{name}")]),
            labels: Some(labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()),
            state: Some(bollard::models::ContainerSummaryStateEnum::RUNNING),
            ..Default::default()
        }
    }

    /// Exec only enters a running container of the application named in the command.
    #[test]
    fn exec_enters_only_the_applications_containers() {
        use deploy_proto::msg::LABEL_RESOURCE;
        let own = container("c1", "owd-app_1-23456789", &[(LABEL_RESOURCE, "app_1")]);
        assert_eq!(choose("app_1", std::slice::from_ref(&own), None).unwrap(), "c1");
        // Named in the command for another application: refused even though it runs.
        assert!(choose("app_2", std::slice::from_ref(&own), None).is_err());
        let forged = container("c2", "postgres", &[(LABEL_RESOURCE, "app_1")]);
        let e = choose("app_1", &[forged, own.clone()], None).unwrap_err();
        assert!(e.contains("postgres"), "{e}");
        let web = container(
            "c3",
            "owd-app_1-web-1",
            &[(LABEL_RESOURCE, "app_1"), (COMPOSE_SERVICE, "web"), (crate::docker::COMPOSE_PROJECT, "owd-app_1")],
        );
        assert_eq!(choose("app_1", &[own.clone(), web.clone()], Some("web")).unwrap(), "c3");
        assert!(choose("app_1", &[own, web], Some("db")).unwrap_err().contains("no running container"));
    }
}
