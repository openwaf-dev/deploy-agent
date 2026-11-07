//! Progress of a running command: steps and log lines, batched into `CommandEvent`s so a chatty build does not turn
//! into one signed frame per line.

use std::time::Duration;

use deploy_proto::msg::{
    CommandEvent, CommandResult, CommitInfo, Event, LogStream, MAX_EVENT_LINES, MAX_LINE_BYTES, Step,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How long buffered lines may wait before they are sent.
const FLUSH_EVERY: Duration = Duration::from_millis(250);

/// What the session sends for running commands, in the order each command produced it.
#[derive(Debug)]
pub enum Outgoing {
    Event(CommandEvent),
    Result(CommandResult),
}

enum Item {
    Line(LogStream, String),
    Step(Step, Option<CommitInfo>),
}

/// Handle a command uses to report progress. Cheap to clone; the batcher ends once every clone is dropped.
#[derive(Clone)]
pub struct Events {
    tx: mpsc::Sender<Item>,
}

impl Events {
    /// Events of command `id`, batched into `out`. Await the returned task after the last `Events` clone is dropped:
    /// it then has flushed everything, so the command's result can follow its events.
    pub fn start(id: String, out: mpsc::Sender<Outgoing>) -> (Events, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(1024);
        (Events { tx }, tokio::spawn(batch(id, rx, out)))
    }

    pub async fn step(&self, step: Step) {
        let _ = self.tx.send(Item::Step(step, None)).await;
    }

    /// A step that follows a fetch, with what the agent read from the commit fetched.
    pub async fn step_after_fetch(&self, step: Step, commit: CommitInfo) {
        let _ = self.tx.send(Item::Step(step, Some(commit))).await;
    }

    pub async fn line(&self, stream: LogStream, line: impl Into<String>) {
        let _ = self.tx.send(Item::Line(stream, line.into())).await;
    }

    /// The agent's own message about the command.
    pub async fn system(&self, line: impl Into<String>) {
        self.line(LogStream::System, line).await;
    }
}

/// Cuts `line` to at most [`MAX_LINE_BYTES`] on a character boundary.
fn cut(mut line: String) -> String {
    if line.len() > MAX_LINE_BYTES {
        let mut end = MAX_LINE_BYTES;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
    }
    line
}

async fn batch(id: String, mut rx: mpsc::Receiver<Item>, out: mpsc::Sender<Outgoing>) {
    let mut stream = LogStream::System;
    // Every line is tagged with the step it was written in: a step change flushes the lines of the one before.
    let mut step: Option<Step> = None;
    let mut lines: Vec<String> = Vec::new();
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + FLUSH_EVERY, FLUSH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let flush = |stream: LogStream, step: Option<Step>, lines: &mut Vec<String>| {
        (!lines.is_empty()).then(|| {
            let event = Event::Log { stream, lines: std::mem::take(lines), step };
            Outgoing::Event(CommandEvent { id: id.clone(), event })
        })
    };
    loop {
        tokio::select! {
            item = rx.recv() => match item {
                Some(Item::Line(s, l)) => {
                    // One event carries one stream: a change of stream sends what was buffered first.
                    if s != stream || lines.len() >= MAX_EVENT_LINES {
                        if let Some(e) = flush(stream, step, &mut lines) {
                            let _ = out.send(e).await;
                        }
                        stream = s;
                    }
                    lines.push(cut(l));
                }
                Some(Item::Step(next, commit)) => {
                    if let Some(e) = flush(stream, step, &mut lines) {
                        let _ = out.send(e).await;
                    }
                    step = Some(next);
                    let event = Event::Step { step: next, commit };
                    let _ = out.send(Outgoing::Event(CommandEvent { id: id.clone(), event })).await;
                }
                None => {
                    if let Some(e) = flush(stream, step, &mut lines) {
                        let _ = out.send(e).await;
                    }
                    return;
                }
            },
            _ = tick.tick() => {
                if let Some(e) = flush(stream, step, &mut lines) {
                    let _ = out.send(e).await;
                }
            }
        }
    }
}

/// Splits a byte stream into lines, keeping a partial last line until its end arrives.
#[derive(Default)]
pub struct Lines {
    buf: Vec<u8>,
}

impl Lines {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
            let rest = self.buf.split_off(i + 1);
            let line = std::mem::replace(&mut self.buf, rest);
            out.push(decode(&line[..i]));
        }
        // A line longer than the limit is sent in pieces rather than buffered without bound.
        while self.buf.len() > MAX_LINE_BYTES {
            let rest = self.buf.split_off(MAX_LINE_BYTES);
            out.push(decode(&std::mem::replace(&mut self.buf, rest)));
        }
        out
    }

    pub fn finish(&mut self) -> Option<String> {
        (!self.buf.is_empty()).then(|| decode(&std::mem::take(&mut self.buf)))
    }
}

fn decode(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches('\r').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn batches_by_stream_and_size_then_flushes_before_steps() {
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (ev, done) = Events::start("c1".into(), out_tx);
        for i in 0..(MAX_EVENT_LINES + 5) {
            ev.line(LogStream::Stdout, format!("l{i}")).await;
        }
        ev.line(LogStream::Stderr, "e").await;
        ev.step(Step::Building).await;
        ev.line(LogStream::System, "x".repeat(MAX_LINE_BYTES + 10)).await;
        drop(ev);
        done.await.unwrap();
        let mut got = Vec::new();
        while let Ok(Outgoing::Event(e)) = out_rx.try_recv() {
            assert_eq!(e.id, "c1");
            got.push(e.event);
        }
        let shape: Vec<(String, usize, Option<Step>)> = got
            .iter()
            .map(|e| match e {
                Event::Log { stream, lines, step } => (format!("{stream:?}"), lines.len(), *step),
                Event::Step { step, .. } => (format!("{step:?}"), 0, None),
            })
            .collect();
        assert_eq!(
            shape,
            [
                ("Stdout".into(), MAX_EVENT_LINES, None),
                ("Stdout".into(), 5, None),
                ("Stderr".into(), 1, None),
                ("Building".into(), 0, None),
                ("System".into(), 1, Some(Step::Building))
            ]
        );
        let Event::Log { lines, .. } = &got[4] else { unreachable!() };
        assert_eq!(lines[0].len(), MAX_LINE_BYTES);
    }

    #[test]
    fn lines_keep_partial_tail_and_cut_multibyte_safely() {
        let mut l = Lines::default();
        assert_eq!(l.push(b"a\r\nb"), ["a"]);
        assert_eq!(l.push(b"c\n"), ["bc"]);
        assert_eq!(l.finish(), None);
        assert_eq!(cut("é".repeat(MAX_LINE_BYTES)).len(), MAX_LINE_BYTES);
        let long = l.push(&vec![b'z'; MAX_LINE_BYTES + 3]);
        assert_eq!(long.len(), 1);
        assert_eq!(l.finish().as_deref(), Some("zzz"));
    }
}
