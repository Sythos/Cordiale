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
//! as undocumented — see its §6.1/§7), lets callers join additional topics
//! (network/channel), and reconnects with a fixed delay on disconnect,
//! rejoining whatever was joined before.
//!
//! Runs as a plain `tokio::spawn`ed task, talking to its caller over two
//! channels, so `cordiale-ui` never has to hold the socket itself.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{interval, sleep, MissedTickBehavior};

use crate::phoenix::{PhoenixMessage, RefCounter, HEARTBEAT_EVENT, HEARTBEAT_TOPIC};
use crate::websocket::PhoenixSocket;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// A request the UI side can make of the running session.
#[derive(Debug, Clone)]
pub enum SessionCommand {
    /// Joins a topic (network or channel), optionally muting join/part/quit
    /// presence noise for it (see `docs/protocol-notes.md` §2).
    JoinTopic { topic: String, presence: bool },
    Shutdown,
}

/// Something the running session wants the UI side to know about.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// The user-topic join succeeded; echoes `protocol_version` again per
    /// the documented handshake.
    Connected { protocol_version: Option<u32> },
    /// Any frame Cordiale doesn't already interpret at this layer — the
    /// caller matches on `frame.event`/`frame.topic`, ignoring what it
    /// doesn't recognize (see `docs/protocol-notes.md` §3).
    Frame(PhoenixMessage),
    Disconnected,
    Reconnecting,
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
    let mut joined_topics: HashMap<String, bool> = HashMap::new();

    'reconnect: loop {
        let mut socket = match PhoenixSocket::connect(&ws_url, &token).await {
            Ok(socket) => socket,
            Err(_) => {
                let _ = events.send(SessionEvent::Reconnecting);
                sleep(RECONNECT_DELAY).await;
                continue 'reconnect;
            }
        };

        let mut refs = RefCounter::new();

        if join(&mut socket, &mut refs, &user_topic, true)
            .await
            .is_err()
        {
            let _ = events.send(SessionEvent::Reconnecting);
            sleep(RECONNECT_DELAY).await;
            continue 'reconnect;
        }

        for (topic, presence) in joined_topics.clone() {
            let _ = join(&mut socket, &mut refs, &topic, presence).await;
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
                    if socket.send(&heartbeat_msg).await.is_err() {
                        let _ = events.send(SessionEvent::Disconnected);
                        sleep(RECONNECT_DELAY).await;
                        continue 'reconnect;
                    }
                }

                command = commands.recv() => {
                    match command {
                        None | Some(SessionCommand::Shutdown) => return,
                        Some(SessionCommand::JoinTopic { topic, presence }) => {
                            if join(&mut socket, &mut refs, &topic, presence).await.is_ok() {
                                joined_topics.insert(topic, presence);
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
                        Ok(None) | Err(_) => {
                            let _ = events.send(SessionEvent::Disconnected);
                            sleep(RECONNECT_DELAY).await;
                            continue 'reconnect;
                        }
                    }
                }
            }
        }
    }
}

async fn join(
    socket: &mut PhoenixSocket,
    refs: &mut RefCounter,
    topic: &str,
    presence: bool,
) -> Result<(), ()> {
    let join_ref = refs.next_ref();
    let payload = if presence {
        serde_json::json!({})
    } else {
        serde_json::json!({ "presence": false })
    };
    let message = PhoenixMessage {
        join_ref: Some(join_ref.clone()),
        message_ref: Some(join_ref),
        topic: topic.to_string(),
        event: "phx_join".to_string(),
        payload,
    };
    socket.send(&message).await.map_err(|_| ())
}
