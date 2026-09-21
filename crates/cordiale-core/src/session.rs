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
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{interval, sleep, MissedTickBehavior};

use crate::phoenix::{PhoenixMessage, RefCounter, HEARTBEAT_EVENT, HEARTBEAT_TOPIC};
use crate::websocket::{PhoenixSocket, PhoenixSocketError};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// A request the UI side can make of the running session.
#[derive(Debug, Clone)]
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
}

/// A handle to a running session: send commands, nothing else. Drop it (or
/// call `shutdown`) to end the session.
pub struct SessionHandle {
    commands: mpsc::UnboundedSender<SessionCommand>,
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
        });
    }

    pub fn shutdown(&self) {
        let _ = self.commands.send(SessionCommand::Shutdown);
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

    tokio::spawn(run_session(ws_url, token, user, command_rx, event_tx));

    (
        SessionHandle {
            commands: command_tx,
        },
        event_rx,
    )
}

async fn run_session(
    ws_url: String,
    token: String,
    user: String,
    mut commands: mpsc::UnboundedReceiver<SessionCommand>,
    events: mpsc::UnboundedSender<SessionEvent>,
) {
    let user_topic = format!("grappa:user:{user}");
    // Every joined topic, including the user topic itself, keyed to the
    // `join_ref` the server assigned it — required on any subsequent
    // command frame for that topic, and re-established with a fresh ref
    // on every reconnect (see `SessionCommand::Send`'s doc comment).
    let mut joined_topics: HashMap<String, JoinedTopic> = HashMap::new();

    'reconnect: loop {
        let mut socket = match PhoenixSocket::connect(&ws_url, &token).await {
            Ok(socket) => socket,
            Err(err) => {
                let _ = events.send(SessionEvent::Reconnecting {
                    reason: format!("connect failed: {err}"),
                });
                sleep(RECONNECT_DELAY).await;
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
                sleep(RECONNECT_DELAY).await;
                continue 'reconnect;
            }
        };
        joined_topics.insert(
            user_topic.clone(),
            JoinedTopic {
                join_ref: user_join_ref,
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
                        sleep(RECONNECT_DELAY).await;
                        continue 'reconnect;
                    }
                }

                command = commands.recv() => {
                    match command {
                        None | Some(SessionCommand::Shutdown) => return,
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
                        Some(SessionCommand::Send { topic, event, payload }) => {
                            if let Some(joined) = joined_topics.get(&topic) {
                                let message = PhoenixMessage {
                                    join_ref: Some(joined.join_ref.clone()),
                                    message_ref: Some(refs.next_ref()),
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
                            if message.topic == user_topic && message.event == "phx_reply" {
                                let protocol_version = message
                                    .payload
                                    .get("response")
                                    .and_then(|response| response.get("protocol_version"))
                                    .and_then(|version| version.as_u64())
                                    .map(|version| version as u32);
                                let _ = events.send(SessionEvent::Connected { protocol_version });
                            }
                            let _ = events.send(SessionEvent::Frame(message));
                        }
                        Ok(None) => {
                            let _ = events.send(SessionEvent::Disconnected {
                                reason: "socket closed".to_string(),
                            });
                            sleep(RECONNECT_DELAY).await;
                            continue 'reconnect;
                        }
                        Err(err) => {
                            let _ = events.send(SessionEvent::Disconnected {
                                reason: format!("read failed: {err}"),
                            });
                            sleep(RECONNECT_DELAY).await;
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
