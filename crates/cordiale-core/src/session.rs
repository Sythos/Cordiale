// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Realtime session orchestration over `PhoenixSocket`.
//!
//! Owns one WebSocket connection for the whole app: joins the user topic,
//! sends a periodic heartbeat (standard Phoenix client convention — every
//! 30s on the dedicated `"phoenix"` topic; not Grappa-specific, and not
//! spelled out in `docs/protocol-notes.md`, which flags heartbeat/backoff
//! as undocumented — see its §6.1/§7), lets callers join and leave
//! additional topics (network/channel), and reconnects on disconnect with an
//! exponential, jittered back-off (see `crate::backoff`) that honours the
//! server's `Retry-After`, rejoining whatever was joined before.
//!
//! Runs as a plain `tokio::spawn`ed task, talking to its caller over two
//! channels, so `cordiale-ui` never has to hold the socket itself.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{interval, sleep, MissedTickBehavior};

use crate::backoff::{random_unit, Backoff};
use crate::e2e_device_routes::{InboxRow, IncomingEvent, IncomingLostEvent};
use crate::e2e_pacing::{SendBook, SendDropped};
use crate::e2e_pairing::{PairingOffer, PairingPush};
use crate::phoenix::{PhoenixMessage, RefCounter, HEARTBEAT_EVENT, HEARTBEAT_TOPIC};
use crate::websocket::{PhoenixSocket, PhoenixSocketError};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
/// The longest wait for the reply to a heartbeat. A connection with no reply
/// by then is treated as dead and the session reconnects.
const HEARTBEAT_REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// The heartbeat of one connection: the ref of the heartbeat that has no
/// reply yet, and the time it was sent. Every connection makes a new one, so
/// a late reply of an older socket never reaches it. Pure bookkeeping, so the
/// rules are testable without a socket.
#[derive(Debug, Default)]
struct HeartbeatWatch {
    pending: Option<(String, Instant)>,
}

impl HeartbeatWatch {
    /// Records a heartbeat sent at `now`. An older heartbeat that still has
    /// no reply keeps its time, so a new heartbeat never extends the wait.
    fn sent(&mut self, message_ref: Option<String>, now: Instant) {
        if self.pending.is_none() {
            if let Some(message_ref) = message_ref {
                self.pending = Some((message_ref, now));
            }
        }
    }

    /// Clears the wait when `message` is the reply to the pending heartbeat.
    fn reply(&mut self, message: &PhoenixMessage) -> bool {
        let matches = message.topic == HEARTBEAT_TOPIC
            && message.event == "phx_reply"
            && matches!(
                (&self.pending, message.message_ref.as_deref()),
                (Some((pending, _)), Some(received)) if pending == received
            );
        if matches {
            self.pending = None;
        }
        matches
    }

    /// The time after which the pending heartbeat counts as lost.
    fn deadline(&self, timeout: Duration) -> Option<Instant> {
        self.pending.as_ref().map(|(_, sent_at)| *sent_at + timeout)
    }
}

/// Heartbeat timing of a session.
#[derive(Debug, Clone, Copy)]
struct HeartbeatTiming {
    interval: Duration,
    reply_timeout: Duration,
}

impl Default for HeartbeatTiming {
    fn default() -> Self {
        Self {
            interval: HEARTBEAT_INTERVAL,
            reply_timeout: HEARTBEAT_REPLY_TIMEOUT,
        }
    }
}

/// How often a foreground report is repeated. Grappa stops trusting a
/// `visible` report after about 60 s, so this has to stay at or under half
/// of that.
const VISIBILITY_RESEND_INTERVAL: Duration = Duration::from_secs(30);

/// A request the UI side can make of the running session.
#[derive(Debug)]
pub enum SessionCommand {
    /// Joins a topic (network or channel), optionally muting join/part/quit
    /// presence noise for it (see `docs/protocol-notes.md` §2).
    JoinTopic {
        topic: String,
        presence: bool,
    },
    /// Leaves a topic previously joined by this session. The current
    /// `join_ref` is attached to the `phx_leave` frame, and the topic is
    /// removed from the reconnect set.
    LeaveTopic {
        topic: String,
    },
    /// Sends an arbitrary `GrappaChannel` command (e.g. `/links`, `whois`)
    /// on a topic the session has already joined. `topic` is the caller's
    /// responsibility to get right — this layer doesn't validate it.
    Send {
        topic: String,
        event: String,
        payload: serde_json::Value,
        /// A ref chosen by the caller to recognise the reply, or `None` for
        /// the session's own counter.
        message_ref: Option<String>,
    },
    /// The window went to (or left) the foreground. Reported to Grappa on the
    /// user topic, and repeated while it stays in the foreground.
    SetForeground(bool),
    /// Tells Grappa this client is leaving, then ends the session. `flushed`
    /// fires once the hint has been written to the socket (or is dropped
    /// when there was nothing to write).
    Close {
        flushed: oneshot::Sender<()>,
    },
    Shutdown,
}

/// A topic the session currently has joined, and the `join_ref` the
/// server assigned that join — re-established with a fresh ref on every
/// reconnect.
#[derive(Debug, Clone)]
struct JoinedTopic {
    join_ref: String,
    presence: bool,
}

/// Something the running session wants the UI side to know about.
/// `Disconnected` and `Reconnecting` carry in `retry_in` how long the session
/// waits before it connects again.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// The user-topic join succeeded; echoes `protocol_version` again per
    /// the documented handshake.
    Connected {
        protocol_version: Option<u32>,
    },
    /// Any frame Cordiale doesn't already interpret at this layer — the
    /// caller matches on `frame.event`/`frame.topic`, ignoring what it
    /// doesn't recognize (see `docs/protocol-notes.md` §3).
    Frame(PhoenixMessage),
    /// `reason` is a `Debug`-formatted underlying error where one exists
    /// (a closed/errored socket) — empty for a clean close. Never shown
    /// to the user directly, only logged, so it doesn't need to be
    /// translated or pretty.
    Disconnected {
        reason: String,
        retry_in: Duration,
    },
    Reconnecting {
        reason: String,
        retry_in: Duration,
    },
    /// Terminal: Grappa refused the user-topic join for good (`forbidden`,
    /// `unknown_topic`): retrying with the same topic can't succeed, so the
    /// session has stopped.
    JoinRefused {
        reason: String,
    },
    /// Terminal: the WebSocket upgrade was refused with 401/403, so the
    /// bearer is missing, invalid or revoked. The session has stopped and
    /// will not retry with that bearer.
    AuthRejected {
        reason: String,
    },
    /// Terminal: the TLS handshake failed on the server's certificate (not
    /// trusted by this machine's store, expired, wrong name, ...). The REST
    /// calls use the same trust, so retrying can't help until the store or
    /// the server changes: the session has stopped. `reason` is the short
    /// cause (e.g. `invalid peer certificate: UnknownIssuer`).
    CertificateRejected {
        reason: String,
    },
    /// Terminal: the WebSocket upgrade was refused with 426, the server's
    /// `client_proto` floor is above what this build declares. The session
    /// has stopped: only an updated Cordiale can connect.
    UpgradeRequired {
        protocol_version: Option<u32>,
        min_protocol_version: Option<u32>,
    },
}

/// A handle to a running session: send commands, nothing else. Drop it (or
/// call `shutdown`) to end the session.
pub struct SessionHandle {
    commands: mpsc::UnboundedSender<SessionCommand>,
    /// Observed during the reconnect back-off too, where the command queue
    /// isn't read; dropping the handle also stops the session.
    shutdown: watch::Sender<bool>,
    /// Source of caller-visible refs for `send_tracked_command`; prefixed so
    /// they never collide with the session's numeric refs.
    tracked_refs: Arc<AtomicU64>,
}

impl SessionHandle {
    pub fn join_topic(&self, topic: impl Into<String>, presence: bool) {
        let _ = self.commands.send(SessionCommand::JoinTopic {
            topic: topic.into(),
            presence,
        });
    }

    pub fn leave_topic(&self, topic: impl Into<String>) {
        let _ = self.commands.send(SessionCommand::LeaveTopic {
            topic: topic.into(),
        });
    }

    /// Sends an arbitrary `GrappaChannel` command on `topic` (must already
    /// be joined). Fire-and-forget: the reply, if any, arrives as a
    /// `SessionEvent::Frame` the caller matches on its `event` field.
    pub fn send_command(
        &self,
        topic: impl Into<String>,
        event: impl Into<String>,
        payload: serde_json::Value,
    ) {
        let _ = self.commands.send(SessionCommand::Send {
            topic: topic.into(),
            event: event.into(),
            payload,
            message_ref: None,
        });
    }

    /// Like `send_command`, but returns the ref the push goes out with, so
    /// the caller can pick its `phx_reply` out of the frame stream (for
    /// verbs whose reply carries the answer, like `resolve_userhost`).
    pub fn send_tracked_command(
        &self,
        topic: impl Into<String>,
        event: impl Into<String>,
        payload: serde_json::Value,
    ) -> String {
        let message_ref = tracked_ref(&self.tracked_refs);
        let _ = self.commands.send(SessionCommand::Send {
            topic: topic.into(),
            event: event.into(),
            payload,
            message_ref: Some(message_ref.clone()),
        });
        message_ref
    }

    /// Reports whether the window is in the foreground. Grappa starts every
    /// new socket as "hidden", so the session resends the current value on
    /// its own after each join of the user topic.
    pub fn set_foreground(&self, foreground: bool) {
        let _ = self
            .commands
            .send(SessionCommand::SetForeground(foreground));
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        let _ = self.commands.send(SessionCommand::Shutdown);
    }

    /// Like `shutdown`, but first tells Grappa the client is leaving, so it
    /// doesn't wait out the visibility timeout before auto-away. The returned
    /// receiver resolves once the hint is written (or the session is gone),
    /// for a caller that is about to exit the process.
    pub fn close(&self) -> oneshot::Receiver<()> {
        let (flushed, done) = oneshot::channel();
        let _ = self.shutdown.send(true);
        let _ = self.commands.send(SessionCommand::Close { flushed });
        done
    }
}

/// Route one session frame into the local E2E send book. Call it for every
/// `SessionEvent::Frame`. Return the drop event when the frame is an
/// `e2e_send_dropped` that changed a send; any other frame, an unknown send
/// and a repeated event return `None` and change nothing.
pub fn route_e2e_send_dropped(book: &mut SendBook, frame: &PhoenixMessage) -> Option<SendDropped> {
    book.apply_payload(&frame.payload)
}

/// Read one session frame as an `e2e_message` row. Call it for every
/// `SessionEvent::Frame`, then give the row to the E2E engine. Any other
/// frame, and a row that does not read, return `None`. `server_protocol` is
/// the version of the server, which sets whether `own` is allowed.
pub fn route_e2e_message(frame: &PhoenixMessage, server_protocol: Option<u32>) -> Option<InboxRow> {
    if frame.payload.get("kind")?.as_str()? != "e2e_message" {
        return None;
    }
    InboxRow::from_value(&frame.payload, server_protocol).ok()
}

/// Read one session frame as an `e2e_incoming` event (protocol 59). Any other
/// frame, and an event that does not read, return `None`.
pub fn route_e2e_incoming(frame: &PhoenixMessage) -> Option<IncomingEvent> {
    if frame.payload.get("kind")?.as_str()? != "e2e_incoming" {
        return None;
    }
    IncomingEvent::from_value(&frame.payload).ok()
}

/// Read one session frame as an `e2e_incoming_lost` event (protocol 59). Any
/// other frame, and an event that does not read, return `None`.
pub fn route_e2e_incoming_lost(frame: &PhoenixMessage) -> Option<IncomingLostEvent> {
    if frame.payload.get("kind")?.as_str()? != "e2e_incoming_lost" {
        return None;
    }
    IncomingLostEvent::from_value(&frame.payload).ok()
}

/// Read one session frame as a pairing event (`e2e_pairing_message` or
/// `e2e_pairing_closed`). Call it for every `SessionEvent::Frame`. The event
/// has no payload: the client fetches the messages after its last sequence.
/// Any other frame, and a frame of the wrong shape, return `None`. A pairing
/// frame is never a chat line.
pub fn route_e2e_pairing(frame: &PhoenixMessage) -> Option<PairingPush> {
    PairingPush::from_value(&frame.payload)
}

/// Read one session frame as a pairing offer (`e2e_pairing_offered`, protocol
/// 55). The caller checks that the frame came on the own user topic. Any other
/// frame, and a frame of the wrong shape, return `None`. An offer is never a
/// chat line.
pub fn route_e2e_pairing_offer(frame: &PhoenixMessage) -> Option<PairingOffer> {
    PairingOffer::from_value(&frame.payload)
}

/// Starts a session: connects, joins `grappa:user:{user}`, and spawns the
/// task that keeps it alive. Returns immediately — connection failures
/// show up as `SessionEvent`s on the returned receiver, not as an `Err`
/// here, since the task keeps retrying.
pub fn spawn_session(
    ws_url: String,
    token: String,
    user: String,
) -> (SessionHandle, mpsc::UnboundedReceiver<SessionEvent>) {
    spawn_session_timed(ws_url, token, user, HeartbeatTiming::default())
}

fn spawn_session_timed(
    ws_url: String,
    token: String,
    user: String,
    timing: HeartbeatTiming,
) -> (SessionHandle, mpsc::UnboundedReceiver<SessionEvent>) {
    let (command_tx, command_rx) = mpsc::unbounded_channel();
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(run_session(
        ws_url,
        token,
        user,
        command_rx,
        event_tx,
        shutdown_rx,
        timing,
    ));

    (
        SessionHandle {
            commands: command_tx,
            shutdown: shutdown_tx,
            tracked_refs: Arc::new(AtomicU64::new(0)),
        },
        event_rx,
    )
}

/// The next caller-visible ref: `t1`, `t2`, ...
fn tracked_ref(counter: &AtomicU64) -> String {
    format!("t{}", counter.fetch_add(1, Ordering::Relaxed) + 1)
}

/// Waits out the reconnect delay. Returns `false` when the session was shut
/// down, or its handle dropped, in the meantime: no further reconnect then.
async fn wait_before_reconnect(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return false;
    }
    let stopped = tokio::select! {
        _ = sleep(delay) => false,
        _ = shutdown.changed() => true,
    };
    !stopped && !*shutdown.borrow()
}

/// How long the last connection stayed joined: zero when it never got that
/// far.
fn uptime(joined_at: Option<Instant>) -> Duration {
    joined_at.map_or(Duration::ZERO, |at| at.elapsed())
}

/// What the session knows about the window's foreground state, and whether
/// Grappa can be told about it yet (the user topic is joined). Pure
/// bookkeeping: each method answers with the value to report, if any, so the
/// timing rules are testable without a socket.
#[derive(Debug, Default)]
struct Presence {
    foreground: bool,
    user_topic_joined: bool,
}

impl Presence {
    /// The report owed after a change: only when the value actually changed
    /// and the topic is joined (the join reports the current value anyway).
    fn set_foreground(&mut self, foreground: bool) -> Option<bool> {
        if self.foreground == foreground {
            return None;
        }
        self.foreground = foreground;
        self.user_topic_joined.then_some(foreground)
    }

    /// The user-topic join was acknowledged. Returns the value to report at
    /// once, since a new socket starts out hidden on the server.
    fn topic_joined(&mut self) -> bool {
        self.user_topic_joined = true;
        self.foreground
    }

    /// The socket is gone; nothing can be reported until the next join.
    fn topic_lost(&mut self) {
        self.user_topic_joined = false;
    }

    /// The periodic refresh. Only a foreground window needs one: a hidden
    /// report doesn't go stale in a way that matters.
    fn resend(&self) -> Option<bool> {
        (self.user_topic_joined && self.foreground).then_some(true)
    }
}

/// First wait before a topic is joined again after a `phx_error`.
const REJOIN_BASE_DELAY: Duration = Duration::from_secs(1);
/// The wait never grows past this.
const REJOIN_MAX_DELAY: Duration = Duration::from_secs(30);
/// A topic that stayed joined this long starts its rejoin wait over.
const REJOIN_STABLE_AFTER: Duration = Duration::from_secs(60);

/// The wait before the `attempt`-th rejoin (zero based): doubles from
/// `REJOIN_BASE_DELAY` and stops at `REJOIN_MAX_DELAY`.
fn rejoin_delay(attempt: u32) -> Duration {
    REJOIN_BASE_DELAY
        .saturating_mul(2u32.saturating_pow(attempt.min(16)))
        .min(REJOIN_MAX_DELAY)
}

/// Topics that got a `phx_error` and wait for a new join, with a bounded,
/// growing delay for each. Pure bookkeeping, so the timing rules are
/// testable without a socket.
#[derive(Debug, Default)]
struct RejoinBook {
    /// Topic to (due time, presence flag).
    pending: HashMap<String, (Instant, bool)>,
    /// Topic to (failed attempts in a row, time of the last schedule).
    history: HashMap<String, (u32, Instant)>,
    /// Topic to (`join_ref` of the rejoin sent, presence flag), until the
    /// server answers it.
    awaiting: HashMap<String, (String, bool)>,
}

impl RejoinBook {
    /// Plans a new join for `topic` and returns the wait.
    fn schedule(&mut self, topic: &str, presence: bool, now: Instant) -> Duration {
        let attempts = match self.history.get(topic) {
            Some(&(attempts, last))
                if now.saturating_duration_since(last) < REJOIN_STABLE_AFTER =>
            {
                attempts
            }
            _ => 0,
        };
        let delay = rejoin_delay(attempts);
        self.awaiting.remove(topic);
        self.history
            .insert(topic.to_string(), (attempts.saturating_add(1), now));
        self.pending
            .insert(topic.to_string(), (now + delay, presence));
        delay
    }

    fn next_due(&self) -> Option<Instant> {
        self.pending.values().map(|(due, _)| *due).min()
    }

    /// Removes and returns the topics whose wait is over.
    fn take_due(&mut self, now: Instant) -> Vec<(String, bool)> {
        let due: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, (at, _))| *at <= now)
            .map(|(topic, _)| topic.clone())
            .collect();
        due.into_iter()
            .filter_map(|topic| {
                self.pending
                    .remove(&topic)
                    .map(|(_, presence)| (topic, presence))
            })
            .collect()
    }

    /// A rejoin frame went out with `join_ref`: its reply is still to come.
    fn sent(&mut self, topic: &str, join_ref: &str, presence: bool) {
        self.awaiting
            .insert(topic.to_string(), (join_ref.to_string(), presence));
    }

    /// Takes the open rejoin of `topic` when `message_ref` is the ref of its
    /// join frame. Returns the presence flag of that join. A reply with any
    /// other ref is not the answer to the rejoin and returns `None`.
    fn take_reply(&mut self, topic: &str, message_ref: &str) -> Option<bool> {
        match self.awaiting.get(topic) {
            Some((join_ref, _)) if join_ref == message_ref => {
                self.awaiting.remove(topic).map(|(_, presence)| presence)
            }
            _ => None,
        }
    }

    /// The topic is left on purpose or joined again by the caller.
    fn cancel(&mut self, topic: &str) {
        self.pending.remove(topic);
        self.awaiting.remove(topic);
    }

    /// Removes every waiting topic, for a new connection that joins them all.
    fn drain(&mut self) -> Vec<(String, bool)> {
        // The refs of the next connection start again: an old one could match.
        self.awaiting.clear();
        self.pending
            .drain()
            .map(|(topic, (_, presence))| (topic, presence))
            .collect()
    }
}

/// What a topic-level `phx_error` or `phx_close` frame asks of the session.
#[derive(Debug, PartialEq, Eq)]
enum TopicEnd {
    /// The channel process crashed: join the topic again.
    Error,
    /// The channel closed on purpose: do not join it again.
    Close,
}

/// Reads a topic-level end frame for a topic the session has joined. A frame
/// of an older join (its `join_ref` differs) is stale and returns `None`.
fn topic_end(message: &PhoenixMessage, joined: &HashMap<String, JoinedTopic>) -> Option<TopicEnd> {
    let end = match message.event.as_str() {
        "phx_error" => TopicEnd::Error,
        "phx_close" => TopicEnd::Close,
        _ => return None,
    };
    let current = joined.get(&message.topic)?;
    match message.join_ref.as_deref() {
        Some(join_ref) if join_ref != current.join_ref => None,
        _ => Some(end),
    }
}

fn visibility_message(
    user_topic: &str,
    join_ref: &str,
    visible: bool,
    refs: &mut RefCounter,
) -> PhoenixMessage {
    PhoenixMessage {
        join_ref: Some(join_ref.to_string()),
        message_ref: Some(refs.next_ref()),
        topic: user_topic.to_string(),
        event: "visibility".to_string(),
        // Strictly a boolean: Grappa answers anything else `invalid_payload`.
        payload: serde_json::json!({ "visible": visible }),
    }
}

fn client_closing_message(
    user_topic: &str,
    join_ref: &str,
    refs: &mut RefCounter,
) -> PhoenixMessage {
    PhoenixMessage {
        join_ref: Some(join_ref.to_string()),
        message_ref: Some(refs.next_ref()),
        topic: user_topic.to_string(),
        event: "client_closing".to_string(),
        payload: serde_json::json!({}),
    }
}

async fn run_session(
    ws_url: String,
    token: String,
    user: String,
    mut commands: mpsc::UnboundedReceiver<SessionCommand>,
    events: mpsc::UnboundedSender<SessionEvent>,
    mut shutdown: watch::Receiver<bool>,
    timing: HeartbeatTiming,
) {
    let user_topic = format!("grappa:user:{user}");
    // Every joined topic, including the user topic itself, keyed to the
    // `join_ref` the server assigned it — required on any subsequent
    // command frame for that topic, and re-established with a fresh ref
    // on every reconnect (see `SessionCommand::Send`'s doc comment).
    let mut joined_topics: HashMap<String, JoinedTopic> = HashMap::new();
    // Outlives reconnects: the window's state doesn't change because the
    // socket did.
    let mut presence = Presence::default();
    // Grows with every attempt that fails; a connection that stays joined
    // long enough starts it over.
    let mut backoff = Backoff::default();
    // Topics that got a `phx_error` and wait for a new join.
    let mut rejoins = RejoinBook::default();

    'reconnect: loop {
        if *shutdown.borrow() {
            return;
        }
        presence.topic_lost();
        // A new connection joins every topic anyway: hand the waiting ones
        // back to the set it rejoins.
        for (topic, topic_presence) in rejoins.drain() {
            joined_topics.insert(
                topic,
                JoinedTopic {
                    join_ref: String::new(),
                    presence: topic_presence,
                },
            );
        }
        // Set once the user topic is joined: the back-off only resets for a
        // connection that stayed up, not for one that was dropped right after
        // the handshake.
        let mut joined_at: Option<Instant> = None;
        let mut socket = match PhoenixSocket::connect(&ws_url, &token).await {
            Ok(socket) => socket,
            Err(err) if err.is_auth_rejection() => {
                let _ = events.send(SessionEvent::AuthRejected {
                    reason: format!("connect refused: {err}"),
                });
                return;
            }
            Err(err) => {
                if let Some(cause) = err.certificate_error() {
                    let _ = events.send(SessionEvent::CertificateRejected {
                        reason: cause.to_string(),
                    });
                    return;
                }
                if let Some(refusal) = err.upgrade_required() {
                    let _ = events.send(SessionEvent::UpgradeRequired {
                        protocol_version: refusal.protocol_version,
                        min_protocol_version: refusal.min_protocol_version,
                    });
                    return;
                }
                let retry_in = backoff.next_delay(
                    Duration::ZERO,
                    err.retry_after(SystemTime::now()),
                    random_unit(),
                );
                let _ = events.send(SessionEvent::Reconnecting {
                    reason: format!("connect failed: {err}"),
                    retry_in,
                });
                if !wait_before_reconnect(retry_in, &mut shutdown).await {
                    return;
                }
                continue 'reconnect;
            }
        };

        let mut refs = RefCounter::new();

        let mut user_join_ref = match join(&mut socket, &mut refs, &user_topic, true).await {
            Ok(join_ref) => join_ref,
            Err(err) => {
                let retry_in = backoff.next_delay(Duration::ZERO, None, random_unit());
                let _ = events.send(SessionEvent::Reconnecting {
                    reason: format!("user topic join failed: {err}"),
                    retry_in,
                });
                if !wait_before_reconnect(retry_in, &mut shutdown).await {
                    return;
                }
                continue 'reconnect;
            }
        };
        joined_topics.insert(
            user_topic.clone(),
            JoinedTopic {
                join_ref: user_join_ref.clone(),
                presence: true,
            },
        );

        for (topic, joined) in joined_topics.clone() {
            if topic == user_topic {
                continue;
            }
            if let Ok(join_ref) = join(&mut socket, &mut refs, &topic, joined.presence).await {
                joined_topics.insert(
                    topic,
                    JoinedTopic {
                        join_ref,
                        presence: joined.presence,
                    },
                );
            }
        }

        let mut heartbeat = interval(timing.interval);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut heartbeat_watch = HeartbeatWatch::default();
        let mut visibility_resend = interval(VISIBILITY_RESEND_INTERVAL);
        visibility_resend.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    let heartbeat_msg = PhoenixMessage {
                        join_ref: None,
                        message_ref: Some(refs.next_ref()),
                        topic: HEARTBEAT_TOPIC.to_string(),
                        event: HEARTBEAT_EVENT.to_string(),
                        payload: serde_json::json!({}),
                    };
                    if let Err(err) = socket.send(&heartbeat_msg).await {
                        let retry_in =
                            backoff.next_delay(uptime(joined_at), None, random_unit());
                        let _ = events.send(SessionEvent::Disconnected {
                            reason: format!("heartbeat send failed: {err}"),
                            retry_in,
                        });
                        if !wait_before_reconnect(retry_in, &mut shutdown).await {
                            return;
                        }
                        continue 'reconnect;
                    }
                    heartbeat_watch.sent(heartbeat_msg.message_ref.clone(), Instant::now());
                }

                // No reply to a heartbeat in time: the path is dead even
                // though the socket is still open.
                _ = async {
                    match heartbeat_watch.deadline(timing.reply_timeout) {
                        Some(due) => tokio::time::sleep_until(due.into()).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let retry_in = backoff.next_delay(uptime(joined_at), None, random_unit());
                    let _ = events.send(SessionEvent::Disconnected {
                        reason: "heartbeat reply missing".to_string(),
                        retry_in,
                    });
                    if !wait_before_reconnect(retry_in, &mut shutdown).await {
                        return;
                    }
                    continue 'reconnect;
                }

                _ = async {
                    match rejoins.next_due() {
                        Some(due) => tokio::time::sleep_until(due.into()).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    for (topic, topic_presence) in rejoins.take_due(Instant::now()) {
                        match join(&mut socket, &mut refs, &topic, topic_presence).await {
                            Ok(join_ref) => {
                                if topic == user_topic {
                                    user_join_ref = join_ref.clone();
                                } else {
                                    // The reply is read in the frame branch: a
                                    // refusal schedules the next attempt.
                                    rejoins.sent(&topic, &join_ref, topic_presence);
                                }
                                joined_topics.insert(
                                    topic,
                                    JoinedTopic { join_ref, presence: topic_presence },
                                );
                            }
                            // The socket is broken: the read side ends the
                            // connection, and the next one joins this topic.
                            Err(_) => {
                                joined_topics.insert(
                                    topic,
                                    JoinedTopic {
                                        join_ref: String::new(),
                                        presence: topic_presence,
                                    },
                                );
                            }
                        }
                    }
                }

                _ = visibility_resend.tick() => {
                    if let Some(visible) = presence.resend() {
                        let message =
                            visibility_message(&user_topic, &user_join_ref, visible, &mut refs);
                        let _ = socket.send(&message).await;
                    }
                }

                command = commands.recv() => {
                    match command {
                        None | Some(SessionCommand::Shutdown) => return,
                        Some(SessionCommand::SetForeground(foreground)) => {
                            if let Some(visible) = presence.set_foreground(foreground) {
                                let message = visibility_message(
                                    &user_topic,
                                    &user_join_ref,
                                    visible,
                                    &mut refs,
                                );
                                let _ = socket.send(&message).await;
                            }
                        }
                        Some(SessionCommand::Close { flushed }) => {
                            if presence.user_topic_joined {
                                let message = client_closing_message(
                                    &user_topic,
                                    &user_join_ref,
                                    &mut refs,
                                );
                                let _ = socket.send(&message).await;
                            }
                            let _ = flushed.send(());
                            return;
                        }
                        Some(SessionCommand::JoinTopic { topic, presence }) => {
                            rejoins.cancel(&topic);
                            let joined = join(&mut socket, &mut refs, &topic, presence).await;
                            if let Ok(join_ref) = joined {
                                joined_topics.insert(topic, JoinedTopic { join_ref, presence });
                            }
                        }
                        Some(SessionCommand::LeaveTopic { topic }) => {
                            rejoins.cancel(&topic);
                            if let Some(joined) = joined_topics.remove(&topic) {
                                let message = leave_message(&topic, &joined, &mut refs);
                                let _ = socket.send(&message).await;
                            }
                        }
                        Some(SessionCommand::Send { topic, event, payload, message_ref }) => {
                            if let Some(joined) = joined_topics.get(&topic) {
                                let message = PhoenixMessage {
                                    join_ref: Some(joined.join_ref.clone()),
                                    message_ref: Some(message_ref.unwrap_or_else(|| refs.next_ref())),
                                    topic,
                                    event,
                                    payload,
                                };
                                let _ = socket.send(&message).await;
                            }
                        }
                    }
                }

                frame = socket.next_message() => {
                    match frame {
                        Ok(Some(message)) => {
                            heartbeat_watch.reply(&message);
                            // The answer to an automatic rejoin of a topic
                            // other than the user topic.
                            if message.topic != user_topic && message.event == "phx_reply" {
                                if let Some(topic_presence) = message
                                    .message_ref
                                    .as_deref()
                                    .and_then(|message_ref| {
                                        rejoins.take_reply(&message.topic, message_ref)
                                    })
                                {
                                    let join_ref = message.message_ref.clone().unwrap_or_default();
                                    if let Some(Err(reason)) =
                                        user_join_outcome(&message, &message.topic, &join_ref)
                                    {
                                        joined_topics.remove(&message.topic);
                                        // A refusal that no retry can fix ends
                                        // the attempts for this topic.
                                        if !is_permanent_join_refusal(&reason) {
                                            rejoins.schedule(
                                                &message.topic,
                                                topic_presence,
                                                Instant::now(),
                                            );
                                        }
                                    }
                                }
                            }
                            match topic_end(&message, &joined_topics) {
                                // The channel process of one topic crashed
                                // while the socket stays open: mark the topic
                                // as not joined and join it again later.
                                Some(TopicEnd::Error) => {
                                    if let Some(lost) = joined_topics.remove(&message.topic) {
                                        if message.topic == user_topic {
                                            presence.topic_lost();
                                        }
                                        rejoins.schedule(&message.topic, lost.presence, Instant::now());
                                    }
                                }
                                // A close is final for that join: the topic
                                // leaves the set, with no automatic rejoin.
                                Some(TopicEnd::Close) if message.topic != user_topic => {
                                    joined_topics.remove(&message.topic);
                                }
                                _ => {}
                            }
                            match user_join_outcome(&message, &user_topic, &user_join_ref) {
                                Some(Ok(protocol_version)) => {
                                    joined_at = Some(Instant::now());
                                    let _ = events.send(SessionEvent::Connected { protocol_version });
                                    let visible = presence.topic_joined();
                                    let report = visibility_message(
                                        &user_topic,
                                        &user_join_ref,
                                        visible,
                                        &mut refs,
                                    );
                                    let _ = socket.send(&report).await;
                                }
                                Some(Err(reason)) if is_permanent_join_refusal(&reason) => {
                                    let _ = events.send(SessionEvent::JoinRefused { reason });
                                    return;
                                }
                                Some(Err(reason)) => {
                                    let retry_in =
                                        backoff.next_delay(uptime(joined_at), None, random_unit());
                                    let _ = events.send(SessionEvent::Reconnecting {
                                        reason: format!("user topic join rejected: {reason}"),
                                        retry_in,
                                    });
                                    if !wait_before_reconnect(retry_in, &mut shutdown).await {
                                        return;
                                    }
                                    continue 'reconnect;
                                }
                                None => {}
                            }
                            let _ = events.send(SessionEvent::Frame(message));
                        }
                        Ok(None) => {
                            let retry_in =
                                backoff.next_delay(uptime(joined_at), None, random_unit());
                            let _ = events.send(SessionEvent::Disconnected {
                                reason: "socket closed".to_string(),
                                retry_in,
                            });
                            if !wait_before_reconnect(retry_in, &mut shutdown).await {
                                return;
                            }
                            continue 'reconnect;
                        }
                        Err(err) => {
                            let retry_in =
                                backoff.next_delay(uptime(joined_at), None, random_unit());
                            let _ = events.send(SessionEvent::Disconnected {
                                reason: format!("read failed: {err}"),
                                retry_in,
                            });
                            if !wait_before_reconnect(retry_in, &mut shutdown).await {
                                return;
                            }
                            continue 'reconnect;
                        }
                    }
                }
            }
        }
    }
}

/// Joins `topic`, returning the `join_ref` the server now associates with
/// it — required on every subsequent command frame for that topic.
/// Grappa's join refusals that no retry can fix: the topic's user segment
/// isn't this socket's subject, or the topic doesn't parse.
fn is_permanent_join_refusal(reason: &str) -> bool {
    matches!(reason, "forbidden" | "unknown_topic")
}

/// Reads the server's answer to the user-topic join: `None` for any other
/// frame (replies to later commands on the same topic included), the
/// advertised protocol version on `status: "ok"`, and the server's reason
/// otherwise: Grappa's `error` (`forbidden`, `unknown_topic`), a `reason`,
/// or the status itself.
fn user_join_outcome(
    message: &PhoenixMessage,
    user_topic: &str,
    join_ref: &str,
) -> Option<Result<Option<u32>, String>> {
    if message.topic != user_topic
        || message.event != "phx_reply"
        || message.message_ref.as_deref() != Some(join_ref)
    {
        return None;
    }
    let status = message
        .payload
        .get("status")
        .and_then(|status| status.as_str())
        .unwrap_or("missing");
    let response = message.payload.get("response");
    if status != "ok" {
        let reason = response
            .and_then(|response| response.get("error").or_else(|| response.get("reason")))
            .and_then(|reason| reason.as_str())
            .unwrap_or(status);
        return Some(Err(reason.to_string()));
    }
    let protocol_version = response
        .and_then(|response| response.get("protocol_version"))
        .and_then(|version| version.as_u64())
        .and_then(|version| u32::try_from(version).ok());
    Some(Ok(protocol_version))
}

async fn join(
    socket: &mut PhoenixSocket,
    refs: &mut RefCounter,
    topic: &str,
    presence: bool,
) -> Result<String, PhoenixSocketError> {
    let join_ref = refs.next_ref();
    let payload = if presence {
        serde_json::json!({})
    } else {
        serde_json::json!({ "presence": false })
    };
    let message = PhoenixMessage {
        join_ref: Some(join_ref.clone()),
        message_ref: Some(join_ref.clone()),
        topic: topic.to_string(),
        event: "phx_join".to_string(),
        payload,
    };
    socket.send(&message).await.map(|()| join_ref)
}

fn leave_message(topic: &str, joined: &JoinedTopic, refs: &mut RefCounter) -> PhoenixMessage {
    PhoenixMessage {
        join_ref: Some(joined.join_ref.clone()),
        message_ref: Some(refs.next_ref()),
        topic: topic.to_string(),
        event: "phx_leave".to_string(),
        payload: serde_json::json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(message_ref: &str, payload: serde_json::Value) -> PhoenixMessage {
        PhoenixMessage {
            join_ref: Some("1".to_string()),
            message_ref: Some(message_ref.to_string()),
            topic: "grappa:user:vjt".to_string(),
            event: "phx_reply".to_string(),
            payload,
        }
    }

    #[test]
    fn pairing_frames_are_routed_and_other_frames_are_not() {
        use crate::e2e_pairing::{ClosedReason, PairingRole};
        let id = "AbCdEfGhIjKlMnOpQrStUv";
        let message = reply(
            "1",
            serde_json::json!({
                "kind": "e2e_pairing_message",
                "rendezvous_id": id,
                "seq": 3,
                "from": "joiner"
            }),
        );
        assert_eq!(
            route_e2e_pairing(&message),
            Some(PairingPush::Message {
                rendezvous_id: id.to_string(),
                seq: 3,
                from: PairingRole::Joiner
            })
        );
        let closed = reply(
            "2",
            serde_json::json!({
                "kind": "e2e_pairing_closed",
                "rendezvous_id": id,
                "reason": "expired"
            }),
        );
        assert_eq!(
            route_e2e_pairing(&closed),
            Some(PairingPush::Closed {
                rendezvous_id: id.to_string(),
                reason: ClosedReason::Expired
            })
        );
        let other = reply("3", serde_json::json!({"kind": "message"}));
        assert!(route_e2e_pairing(&other).is_none());
    }

    #[test]
    fn offer_frames_are_routed_apart_from_the_pairing_pushes() {
        let offer = reply(
            "1",
            serde_json::json!({
                "kind": "e2e_pairing_offered",
                "rendezvous_id": "AbCdEfGhIjKlMnOpQrStUv",
                "curve": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                "expires_at": "2026-10-23T10:00:00Z"
            }),
        );
        let routed = route_e2e_pairing_offer(&offer).expect("routed");
        assert_eq!(routed.rendezvous_id(), "AbCdEfGhIjKlMnOpQrStUv");
        assert!(route_e2e_pairing(&offer).is_none());
        let other = reply("2", serde_json::json!({"kind": "message"}));
        assert!(route_e2e_pairing_offer(&other).is_none());
    }

    #[test]
    fn frame_with_a_drop_event_updates_only_its_send() {
        use crate::e2e_pacing::{DropReason, SendKey, SendStatus};
        let mut book = SendBook::new();
        let first = SendKey::new("libera", "bob", "m1");
        let second = SendKey::new("libera", "bob", "m2");
        book.start(first.clone());
        book.start(second.clone());
        let frame = reply(
            "1",
            serde_json::json!({
                "kind": "e2e_send_dropped",
                "network": "libera",
                "target": "bob",
                "msgid": "m1",
                "reason": "send_failed"
            }),
        );
        let event = route_e2e_send_dropped(&mut book, &frame).expect("routed");
        assert_eq!(event.reason, DropReason::SendFailed);
        assert_eq!(
            book.status(&first),
            Some(SendStatus::Dropped(DropReason::SendFailed))
        );
        assert_eq!(book.status(&second), Some(SendStatus::Pending));
        // The same frame again changes nothing.
        assert!(route_e2e_send_dropped(&mut book, &frame).is_none());
        // A frame of another kind is ignored.
        let other = reply("2", serde_json::json!({"kind": "message"}));
        assert!(route_e2e_send_dropped(&mut book, &other).is_none());
    }

    #[test]
    fn frames_with_incoming_events_route_only_their_own_kind() {
        let incoming = reply(
            "1",
            serde_json::json!({
                "kind": "e2e_incoming", "network": "azzurra", "from": "Alice",
                "from_did": "AaZaARRDyBk", "to": "*", "msgid": "q83vEjRWeJA"
            }),
        );
        let lost = reply(
            "2",
            serde_json::json!({
                "kind": "e2e_incoming_lost", "network": "azzurra",
                "from_did": "AaZaARRDyBk", "to": "*", "msgid": "q83vEjRWeJA"
            }),
        );
        let old = reply("3", serde_json::json!({"kind": "message"}));
        assert_eq!(route_e2e_incoming(&incoming).expect("event").from, "Alice");
        assert_eq!(
            route_e2e_incoming_lost(&lost).expect("event").msgid,
            "q83vEjRWeJA"
        );
        // Each router reads only its own kind. Other kinds are ignored.
        assert!(route_e2e_incoming(&lost).is_none());
        assert!(route_e2e_incoming_lost(&incoming).is_none());
        assert!(route_e2e_incoming(&old).is_none());
        assert!(route_e2e_incoming_lost(&old).is_none());
        assert!(route_e2e_message(&incoming, Some(59)).is_none());
    }

    #[test]
    fn tracked_refs_are_prefixed_and_distinct() {
        let counter = AtomicU64::new(0);
        assert_eq!(tracked_ref(&counter), "t1");
        assert_eq!(tracked_ref(&counter), "t2");
    }

    #[test]
    fn user_join_outcome_reads_only_the_join_reply() {
        let ok = reply(
            "1",
            serde_json::json!({"status": "ok", "response": {"protocol_version": 26}}),
        );
        assert_eq!(
            user_join_outcome(&ok, "grappa:user:vjt", "1"),
            Some(Ok(Some(26)))
        );
        // A reply to a later command on the same topic is not the join.
        let verb_reply = reply("7", serde_json::json!({"status": "ok", "response": {}}));
        assert_eq!(user_join_outcome(&verb_reply, "grappa:user:vjt", "1"), None);
        let rejected = reply(
            "1",
            serde_json::json!({"status": "error", "response": {"reason": "unauthorized"}}),
        );
        assert_eq!(
            user_join_outcome(&rejected, "grappa:user:vjt", "1"),
            Some(Err("unauthorized".to_string()))
        );
        let forbidden = reply(
            "1",
            serde_json::json!({"status": "error", "response": {"error": "forbidden"}}),
        );
        assert_eq!(
            user_join_outcome(&forbidden, "grappa:user:vjt", "1"),
            Some(Err("forbidden".to_string()))
        );
        assert!(is_permanent_join_refusal("forbidden"));
        assert!(is_permanent_join_refusal("unknown_topic"));
        assert!(!is_permanent_join_refusal("unauthorized"));
        let bare_error = reply("1", serde_json::json!({"status": "error"}));
        assert_eq!(
            user_join_outcome(&bare_error, "grappa:user:vjt", "1"),
            Some(Err("error".to_string()))
        );
        assert_eq!(user_join_outcome(&ok, "grappa:user:other", "1"), None);
    }

    #[test]
    fn presence_reports_the_current_state_on_every_join() {
        let mut presence = Presence::default();
        // A new socket starts hidden on the server: a background window
        // still reports once, so both sides agree.
        assert!(!presence.topic_joined());
        presence.topic_lost();
        assert_eq!(presence.set_foreground(true), None);
        assert!(presence.topic_joined());
        // The rejoin after a reconnect reports again.
        presence.topic_lost();
        assert!(presence.topic_joined());
    }

    #[test]
    fn presence_reports_changes_only_while_joined() {
        let mut presence = Presence::default();
        // Before the join the value is only remembered.
        assert_eq!(presence.set_foreground(true), None);
        assert!(presence.topic_joined());
        assert_eq!(presence.set_foreground(true), None);
        assert_eq!(presence.set_foreground(false), Some(false));
        assert_eq!(presence.set_foreground(false), None);
        assert_eq!(presence.set_foreground(true), Some(true));
        presence.topic_lost();
        assert_eq!(presence.set_foreground(false), None);
    }

    #[test]
    fn presence_resends_only_a_joined_foreground_window() {
        let mut presence = Presence::default();
        assert_eq!(presence.resend(), None);
        presence.set_foreground(true);
        assert_eq!(presence.resend(), None);
        presence.topic_joined();
        assert_eq!(presence.resend(), Some(true));
        presence.set_foreground(false);
        assert_eq!(presence.resend(), None);
        presence.set_foreground(true);
        presence.topic_lost();
        assert_eq!(presence.resend(), None);
    }

    #[test]
    fn visibility_frame_carries_a_strict_boolean_on_the_user_topic() {
        let mut refs = RefCounter::new();
        let message = visibility_message("grappa:user:vjt", "join-1", true, &mut refs);
        assert_eq!(message.topic, "grappa:user:vjt");
        assert_eq!(message.join_ref.as_deref(), Some("join-1"));
        assert_eq!(message.message_ref.as_deref(), Some("1"));
        assert_eq!(message.event, "visibility");
        assert_eq!(message.payload, serde_json::json!({"visible": true}));
        let hidden = visibility_message("grappa:user:vjt", "join-1", false, &mut refs);
        assert_eq!(hidden.payload, serde_json::json!({"visible": false}));
        assert_eq!(hidden.message_ref.as_deref(), Some("2"));
    }

    #[test]
    fn client_closing_frame_has_an_empty_payload() {
        let mut refs = RefCounter::new();
        let message = client_closing_message("grappa:user:vjt", "join-1", &mut refs);
        assert_eq!(message.topic, "grappa:user:vjt");
        assert_eq!(message.join_ref.as_deref(), Some("join-1"));
        assert_eq!(message.event, "client_closing");
        assert_eq!(message.payload, serde_json::json!({}));
    }

    #[tokio::test]
    async fn reconnect_wait_stops_immediately_once_shut_down() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        shutdown_tx.send(true).expect("receiver alive");
        assert!(!wait_before_reconnect(Duration::from_secs(60), &mut shutdown_rx).await);
    }

    #[tokio::test]
    async fn reconnect_wait_stops_when_the_handle_is_dropped() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        drop(shutdown_tx);
        assert!(!wait_before_reconnect(Duration::from_secs(60), &mut shutdown_rx).await);
    }

    #[tokio::test]
    async fn reconnect_wait_runs_its_course_while_the_session_stays_up() {
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        assert!(wait_before_reconnect(Duration::from_millis(10), &mut shutdown_rx).await);
    }

    #[test]
    fn uptime_is_zero_before_the_user_topic_is_joined() {
        assert_eq!(uptime(None), Duration::ZERO);
        let joined = Instant::now();
        assert!(uptime(Some(joined)) < Duration::from_secs(30));
    }

    #[test]
    fn leave_frame_uses_join_ref_and_a_fresh_message_ref() {
        let joined = JoinedTopic {
            join_ref: "join-7".to_string(),
            presence: false,
        };
        let mut refs = RefCounter::new();

        let message = leave_message(
            "grappa:user:vjt/network:libera/channel:oldnick",
            &joined,
            &mut refs,
        );

        assert_eq!(message.join_ref.as_deref(), Some("join-7"));
        assert_eq!(message.message_ref.as_deref(), Some("1"));
        assert_eq!(
            message.topic,
            "grappa:user:vjt/network:libera/channel:oldnick"
        );
        assert_eq!(message.event, "phx_leave");
        assert_eq!(message.payload, serde_json::json!({}));
    }

    #[test]
    fn rejoin_delay_grows_and_stops_at_the_maximum() {
        assert_eq!(rejoin_delay(0), Duration::from_secs(1));
        assert_eq!(rejoin_delay(1), Duration::from_secs(2));
        assert_eq!(rejoin_delay(4), Duration::from_secs(16));
        assert_eq!(rejoin_delay(5), REJOIN_MAX_DELAY);
        assert_eq!(rejoin_delay(u32::MAX), REJOIN_MAX_DELAY);
    }

    #[test]
    fn rejoin_book_waits_longer_after_each_failure_and_resets_when_stable() {
        let mut book = RejoinBook::default();
        let start = Instant::now();
        assert_eq!(book.schedule("t", true, start), Duration::from_secs(1));
        assert_eq!(book.schedule("t", true, start), Duration::from_secs(2));
        // Another topic has its own count.
        assert_eq!(book.schedule("u", false, start), Duration::from_secs(1));
        // A topic that stayed joined for a long time starts over.
        let later = start + REJOIN_STABLE_AFTER;
        assert_eq!(book.schedule("t", true, later), Duration::from_secs(1));
    }

    #[test]
    fn rejoin_book_returns_only_the_due_topics() {
        let mut book = RejoinBook::default();
        let start = Instant::now();
        book.schedule("t", true, start);
        book.schedule("u", false, start);
        book.schedule("u", false, start);
        assert_eq!(book.next_due(), Some(start + Duration::from_secs(1)));
        assert!(book.take_due(start).is_empty());
        let due = book.take_due(start + Duration::from_secs(1));
        assert_eq!(due, vec![("t".to_string(), true)]);
        book.cancel("u");
        assert_eq!(book.next_due(), None);
    }

    #[test]
    fn topic_end_tells_error_from_close_and_ignores_stale_frames() {
        let mut joined = HashMap::new();
        joined.insert(
            "net".to_string(),
            JoinedTopic {
                join_ref: "5".to_string(),
                presence: true,
            },
        );
        let frame = |event: &str, topic: &str, join_ref: Option<&str>| PhoenixMessage {
            join_ref: join_ref.map(str::to_string),
            message_ref: None,
            topic: topic.to_string(),
            event: event.to_string(),
            payload: serde_json::json!({}),
        };
        assert_eq!(
            topic_end(&frame("phx_error", "net", Some("5")), &joined),
            Some(TopicEnd::Error)
        );
        assert_eq!(
            topic_end(&frame("phx_close", "net", Some("5")), &joined),
            Some(TopicEnd::Close)
        );
        // A frame of an older join, a topic that is not joined and another
        // event are all ignored.
        assert_eq!(
            topic_end(&frame("phx_error", "net", Some("4")), &joined),
            None
        );
        assert_eq!(
            topic_end(&frame("phx_error", "other", Some("5")), &joined),
            None
        );
        assert_eq!(topic_end(&frame("event", "net", Some("5")), &joined), None);
    }

    /// A mock Grappa socket for one connection. It acknowledges every
    /// `phx_join`, reports each join as `(topic, join_ref)` on the returned
    /// channel, and sends `end_event` on the network topic after its first
    /// join. After a later accepted join of that topic it pushes a `marker`
    /// event on it. The user topic gets a `marker` push after the first end
    /// frame. `net_statuses` sets the reply status of each join of the
    /// network topic in turn; a join past the list gets `ok`, and a join
    /// that is not `ok` pushes nothing.
    async fn mock_session_server(
        end_event: &'static str,
        net_statuses: &'static [&'static str],
    ) -> (
        String,
        mpsc::UnboundedReceiver<(String, String)>,
        tokio::task::JoinHandle<()>,
    ) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
        use tokio_tungstenite::tungstenite::http::HeaderValue;
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!(
            "ws://{}/socket/websocket",
            listener.local_addr().expect("address")
        );
        let (joins_tx, joins_rx) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            #[allow(clippy::result_large_err)]
            let select_phoenix =
                |_request: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert(
                        "sec-websocket-protocol",
                        HeaderValue::from_static("phoenix"),
                    );
                    Ok(response)
                };
            let mut socket = tokio_tungstenite::accept_hdr_async(stream, select_phoenix)
                .await
                .expect("handshake");
            let mut net_joins = 0;
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let frame = PhoenixMessage::from_json(text.as_str()).expect("frame");
                if frame.event != "phx_join" {
                    continue;
                }
                let join_ref = frame.join_ref.clone().unwrap_or_default();
                let _ = joins_tx.send((frame.topic.clone(), join_ref.clone()));
                let mut status = "ok";
                if frame.topic == "net" {
                    net_joins += 1;
                    status = net_statuses.get(net_joins - 1).copied().unwrap_or("ok");
                }
                let payload = if status == "ok" {
                    serde_json::json!({"status": "ok", "response": {}})
                } else {
                    serde_json::json!({"status": status, "response": {"reason": "join crashed"}})
                };
                let mut outgoing = vec![PhoenixMessage {
                    join_ref: frame.join_ref.clone(),
                    message_ref: frame.message_ref.clone(),
                    topic: frame.topic.clone(),
                    event: "phx_reply".to_string(),
                    payload,
                }];
                if frame.topic == "net" && status == "ok" {
                    let event = if net_joins == 1 { end_event } else { "marker" };
                    outgoing.push(PhoenixMessage {
                        join_ref: frame.join_ref.clone(),
                        message_ref: None,
                        topic: "net".to_string(),
                        event: event.to_string(),
                        payload: serde_json::json!({}),
                    });
                    if net_joins == 1 {
                        outgoing.push(PhoenixMessage {
                            join_ref: None,
                            message_ref: None,
                            topic: "grappa:user:bob".to_string(),
                            event: "marker".to_string(),
                            payload: serde_json::json!({}),
                        });
                    }
                }
                for message in outgoing {
                    let _ = socket
                        .send(Message::from(message.to_json().expect("json")))
                        .await;
                }
            }
        });
        (url, joins_rx, server)
    }

    async fn next_event(events: &mut mpsc::UnboundedReceiver<SessionEvent>) -> SessionEvent {
        tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("a session event in time")
            .expect("the session is open")
    }

    #[tokio::test]
    async fn phx_error_on_one_topic_joins_it_again_on_the_same_socket() {
        let (url, mut joins, server) = mock_session_server("phx_error", &[]).await;
        let (handle, mut events) = spawn_session(url, "token".to_string(), "bob".to_string());
        handle.join_topic("net", true);

        let mut seen_error = false;
        loop {
            match next_event(&mut events).await {
                SessionEvent::Connected { .. } => {}
                SessionEvent::Frame(frame) if frame.event == "phx_error" => seen_error = true,
                SessionEvent::Frame(frame) if frame.event == "marker" && frame.topic == "net" => {
                    break
                }
                SessionEvent::Frame(_) => {}
                other => panic!("the socket must stay open: {other:?}"),
            }
        }
        assert!(seen_error);

        let mut net_refs = Vec::new();
        let mut user_joins = 0;
        while let Ok((topic, join_ref)) = joins.try_recv() {
            if topic == "net" {
                net_refs.push(join_ref);
            } else {
                user_joins += 1;
            }
        }
        // One user join only: the socket did not reconnect.
        assert_eq!(user_joins, 1);
        assert_eq!(net_refs.len(), 2);
        assert_ne!(net_refs[0], net_refs[1]);

        handle.shutdown();
        server.abort();
    }

    #[tokio::test]
    async fn a_refused_rejoin_is_tried_again_with_a_new_ref() {
        // Join 1 works and then fails with phx_error, join 2 is refused,
        // join 3 works.
        let (url, mut joins, server) =
            mock_session_server("phx_error", &["ok", "error", "ok"]).await;
        let (handle, mut events) = spawn_session(url, "token".to_string(), "bob".to_string());
        handle.join_topic("net", true);

        loop {
            match next_event(&mut events).await {
                SessionEvent::Connected { .. } => {}
                SessionEvent::Frame(frame) if frame.event == "marker" && frame.topic == "net" => {
                    break
                }
                SessionEvent::Frame(_) => {}
                other => panic!("the socket must stay open: {other:?}"),
            }
        }

        let mut net_refs = Vec::new();
        let mut user_joins = 0;
        while let Ok((topic, join_ref)) = joins.try_recv() {
            if topic == "net" {
                net_refs.push(join_ref);
            } else {
                user_joins += 1;
            }
        }
        assert_eq!(user_joins, 1);
        assert_eq!(net_refs.len(), 3);
        assert_ne!(net_refs[0], net_refs[1]);
        assert_ne!(net_refs[1], net_refs[2]);

        handle.shutdown();
        server.abort();
    }

    #[test]
    fn rejoin_book_matches_a_reply_only_by_the_ref_of_the_sent_join() {
        let mut book = RejoinBook::default();
        book.sent("t", "7", true);
        assert_eq!(book.take_reply("t", "8"), None);
        assert_eq!(book.take_reply("u", "7"), None);
        assert_eq!(book.take_reply("t", "7"), Some(true));
        // The reply is taken once.
        assert_eq!(book.take_reply("t", "7"), None);

        book.sent("t", "9", false);
        book.cancel("t");
        assert_eq!(book.take_reply("t", "9"), None);

        book.sent("t", "10", false);
        assert!(book.drain().is_empty());
        assert_eq!(book.take_reply("t", "10"), None);
    }

    #[tokio::test]
    async fn phx_close_on_one_topic_does_not_join_it_again() {
        let (url, mut joins, server) = mock_session_server("phx_close", &[]).await;
        let (handle, mut events) = spawn_session(url, "token".to_string(), "bob".to_string());
        handle.join_topic("net", true);

        // The server sends the close, then a marker on the user topic.
        loop {
            match next_event(&mut events).await {
                SessionEvent::Connected { .. } => {}
                SessionEvent::Frame(frame) if frame.topic == "grappa:user:bob" => break,
                SessionEvent::Frame(_) => {}
                other => panic!("the socket must stay open: {other:?}"),
            }
        }
        // Wait longer than the first rejoin delay: nothing may come.
        tokio::time::sleep(REJOIN_BASE_DELAY * 2).await;
        let mut net_joins = 0;
        while let Ok((topic, _)) = joins.try_recv() {
            if topic == "net" {
                net_joins += 1;
            }
        }
        assert_eq!(net_joins, 1);

        handle.shutdown();
        server.abort();
    }

    fn heartbeat_reply(message_ref: &str) -> PhoenixMessage {
        PhoenixMessage {
            join_ref: None,
            message_ref: Some(message_ref.to_string()),
            topic: HEARTBEAT_TOPIC.to_string(),
            event: "phx_reply".to_string(),
            payload: serde_json::json!({"status": "ok", "response": {}}),
        }
    }

    #[test]
    fn a_timely_heartbeat_reply_clears_the_wait() {
        let timeout = Duration::from_secs(15);
        let now = Instant::now();
        let mut watch = HeartbeatWatch::default();
        assert!(watch.deadline(timeout).is_none());
        watch.sent(Some("7".to_string()), now);
        assert_eq!(watch.deadline(timeout), Some(now + timeout));
        assert!(watch.reply(&heartbeat_reply("7")));
        assert!(watch.deadline(timeout).is_none());
    }

    #[test]
    fn a_missing_heartbeat_reply_keeps_its_deadline() {
        let timeout = Duration::from_secs(15);
        let now = Instant::now();
        let mut watch = HeartbeatWatch::default();
        watch.sent(Some("7".to_string()), now);
        // A later heartbeat does not move the deadline.
        watch.sent(Some("8".to_string()), now + Duration::from_secs(5));
        assert_eq!(watch.deadline(timeout), Some(now + timeout));
    }

    #[test]
    fn a_reply_of_another_heartbeat_or_topic_is_ignored() {
        let now = Instant::now();
        let mut watch = HeartbeatWatch::default();
        watch.sent(Some("7".to_string()), now);
        // The ref of a heartbeat of an older connection.
        assert!(!watch.reply(&heartbeat_reply("3")));
        let mut other_topic = heartbeat_reply("7");
        other_topic.topic = "grappa:user:bob".to_string();
        assert!(!watch.reply(&other_topic));
        assert!(watch.deadline(Duration::from_secs(1)).is_some());
        // A new connection has a new watch: an old reply finds no wait.
        let mut fresh = HeartbeatWatch::default();
        assert!(!fresh.reply(&heartbeat_reply("7")));
        assert!(fresh.deadline(Duration::from_secs(1)).is_none());
    }

    /// A mock Grappa that accepts connections one after the other. It
    /// acknowledges every join. It ignores heartbeats on the first
    /// connection and answers them on later ones. It reports the number of
    /// each accepted connection.
    async fn mock_silent_then_answering_server() -> (
        String,
        mpsc::UnboundedReceiver<u32>,
        tokio::task::JoinHandle<()>,
    ) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
        use tokio_tungstenite::tungstenite::http::HeaderValue;
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!(
            "ws://{}/socket/websocket",
            listener.local_addr().expect("address")
        );
        let (connections_tx, connections_rx) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut number = 0;
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                number += 1;
                let _ = connections_tx.send(number);
                #[allow(clippy::result_large_err)]
                let select_phoenix = |_request: &Request,
                                      mut response: Response|
                 -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert(
                        "sec-websocket-protocol",
                        HeaderValue::from_static("phoenix"),
                    );
                    Ok(response)
                };
                let mut socket = tokio_tungstenite::accept_hdr_async(stream, select_phoenix)
                    .await
                    .expect("handshake");
                let answers = number >= 2;
                tokio::spawn(async move {
                    while let Some(Ok(Message::Text(text))) = socket.next().await {
                        let frame = PhoenixMessage::from_json(text.as_str()).expect("frame");
                        let reply = if frame.event == "phx_join" {
                            PhoenixMessage {
                                join_ref: frame.join_ref.clone(),
                                message_ref: frame.message_ref.clone(),
                                topic: frame.topic.clone(),
                                event: "phx_reply".to_string(),
                                payload: serde_json::json!({"status": "ok", "response": {}}),
                            }
                        } else if frame.event == HEARTBEAT_EVENT && answers {
                            heartbeat_reply(&frame.message_ref.clone().unwrap_or_default())
                        } else {
                            continue;
                        };
                        let _ = socket
                            .send(Message::from(reply.to_json().expect("json")))
                            .await;
                    }
                });
            }
        });
        (url, connections_rx, server)
    }

    #[tokio::test]
    async fn a_missing_heartbeat_reply_reconnects_once_and_recovers() {
        let (url, mut connections, server) = mock_silent_then_answering_server().await;
        let timing = HeartbeatTiming {
            interval: Duration::from_millis(100),
            reply_timeout: Duration::from_millis(300),
        };
        let (handle, mut events) =
            spawn_session_timed(url, "token".to_string(), "bob".to_string(), timing);

        // The first connection joins, then gets no heartbeat reply.
        assert!(matches!(
            next_event(&mut events).await,
            SessionEvent::Connected { .. }
        ));
        match next_event(&mut events).await {
            SessionEvent::Disconnected { reason, .. } => {
                assert_eq!(reason, "heartbeat reply missing")
            }
            other => panic!("expected a disconnect: {other:?}"),
        }
        // The existing reconnect path restores the session.
        assert!(matches!(
            next_event(&mut events).await,
            SessionEvent::Connected { .. }
        ));
        // The second connection answers: it stays up for several intervals.
        let end = tokio::time::Instant::now() + Duration::from_millis(1200);
        while let Ok(event) = tokio::time::timeout_at(end, next_event(&mut events)).await {
            match event {
                SessionEvent::Frame(frame) if frame.topic == HEARTBEAT_TOPIC => {}
                other => panic!("the answered session must stay up: {other:?}"),
            }
        }
        let mut accepted = 0;
        while let Ok(number) = connections.try_recv() {
            accepted = number;
        }
        assert_eq!(accepted, 2);

        handle.shutdown();
        server.abort();
    }
}
