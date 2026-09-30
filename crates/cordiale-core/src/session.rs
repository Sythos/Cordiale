// MIT License
//
// Copyright (c) 2026 Sythos
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
//! additional topics (network/channel), and reconnects with a fixed delay
//! on disconnect, rejoining whatever was joined before.
//!
//! Runs as a plain `tokio::spawn`ed task, talking to its caller over two
//! channels, so `cordiale-ui` never has to hold the socket itself.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{interval, sleep, MissedTickBehavior};

use crate::phoenix::{PhoenixMessage, RefCounter, HEARTBEAT_EVENT, HEARTBEAT_TOPIC};
use crate::websocket::{PhoenixSocket, PhoenixSocketError};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
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
    },
    Reconnecting {
        reason: String,
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

/// Starts a session: connects, joins `grappa:user:{user}`, and spawns the
/// task that keeps it alive. Returns immediately — connection failures
/// show up as `SessionEvent`s on the returned receiver, not as an `Err`
/// here, since the task keeps retrying.
pub fn spawn_session(
    ws_url: String,
    token: String,
    user: String,
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
async fn wait_before_reconnect(shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return false;
    }
    let stopped = tokio::select! {
        _ = sleep(RECONNECT_DELAY) => false,
        _ = shutdown.changed() => true,
    };
    !stopped && !*shutdown.borrow()
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

    'reconnect: loop {
        if *shutdown.borrow() {
            return;
        }
        presence.topic_lost();
        let mut socket = match PhoenixSocket::connect(&ws_url, &token).await {
            Ok(socket) => socket,
            Err(err) if err.is_auth_rejection() => {
                let _ = events.send(SessionEvent::AuthRejected {
                    reason: format!("connect refused: {err}"),
                });
                return;
            }
            Err(err) => {
                if let Some(refusal) = err.upgrade_required() {
                    let _ = events.send(SessionEvent::UpgradeRequired {
                        protocol_version: refusal.protocol_version,
                        min_protocol_version: refusal.min_protocol_version,
                    });
                    return;
                }
                let _ = events.send(SessionEvent::Reconnecting {
                    reason: format!("connect failed: {err}"),
                });
                if !wait_before_reconnect(&mut shutdown).await {
                    return;
                }
                continue 'reconnect;
            }
        };

        let mut refs = RefCounter::new();

        let user_join_ref = match join(&mut socket, &mut refs, &user_topic, true).await {
            Ok(join_ref) => join_ref,
            Err(err) => {
                let _ = events.send(SessionEvent::Reconnecting {
                    reason: format!("user topic join failed: {err}"),
                });
                if !wait_before_reconnect(&mut shutdown).await {
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

        let mut heartbeat = interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
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
                        let _ = events.send(SessionEvent::Disconnected {
                            reason: format!("heartbeat send failed: {err}"),
                        });
                        if !wait_before_reconnect(&mut shutdown).await {
                            return;
                        }
                        continue 'reconnect;
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
                            let joined = join(&mut socket, &mut refs, &topic, presence).await;
                            if let Ok(join_ref) = joined {
                                joined_topics.insert(topic, JoinedTopic { join_ref, presence });
                            }
                        }
                        Some(SessionCommand::LeaveTopic { topic }) => {
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
                            match user_join_outcome(&message, &user_topic, &user_join_ref) {
                                Some(Ok(protocol_version)) => {
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
                                    let _ = events.send(SessionEvent::Reconnecting {
                                        reason: format!("user topic join rejected: {reason}"),
                                    });
                                    if !wait_before_reconnect(&mut shutdown).await {
                                        return;
                                    }
                                    continue 'reconnect;
                                }
                                None => {}
                            }
                            let _ = events.send(SessionEvent::Frame(message));
                        }
                        Ok(None) => {
                            let _ = events.send(SessionEvent::Disconnected {
                                reason: "socket closed".to_string(),
                            });
                            if !wait_before_reconnect(&mut shutdown).await {
                                return;
                            }
                            continue 'reconnect;
                        }
                        Err(err) => {
                            let _ = events.send(SessionEvent::Disconnected {
                                reason: format!("read failed: {err}"),
                            });
                            if !wait_before_reconnect(&mut shutdown).await {
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
        assert!(!wait_before_reconnect(&mut shutdown_rx).await);
    }

    #[tokio::test]
    async fn reconnect_wait_stops_when_the_handle_is_dropped() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        drop(shutdown_tx);
        assert!(!wait_before_reconnect(&mut shutdown_rx).await);
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
}
