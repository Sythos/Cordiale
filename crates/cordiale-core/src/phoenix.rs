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

//! Phoenix Channels wire format (v2 JSON serializer).
//!
//! No transport lives here: this module only knows how to turn a Phoenix
//! message into the 5-element JSON array the wire actually uses, and back.
//! Verified against the serializer source in the official
//! `phoenixframework/phoenix` repository (`assets/js/phoenix/serializer.js`)
//! — the v1 object-shaped format is legacy, v2 (what `vsn=2.0.0` on the
//! socket URL asks for) is always `[join_ref, ref, topic, event, payload]`.

use serde_json::Value;

/// A single Phoenix Channels frame, in either direction.
#[derive(Debug, Clone, PartialEq)]
pub struct PhoenixMessage {
    /// Set on every message belonging to a still-open channel join; `None`
    /// for messages that aren't tied to a channel (e.g. a heartbeat on the
    /// dedicated `"phoenix"` topic).
    pub join_ref: Option<String>,
    /// Correlates a request with its reply; `None` for a server-initiated
    /// push that isn't a reply to anything the client sent.
    pub message_ref: Option<String>,
    pub topic: String,
    pub event: String,
    pub payload: Value,
}

type WireTuple = (Option<String>, Option<String>, String, String, Value);

impl PhoenixMessage {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let wire: WireTuple = (
            self.join_ref.clone(),
            self.message_ref.clone(),
            self.topic.clone(),
            self.event.clone(),
            self.payload.clone(),
        );
        serde_json::to_string(&wire)
    }

    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        let (join_ref, message_ref, topic, event, payload): WireTuple = serde_json::from_str(text)?;
        Ok(PhoenixMessage {
            join_ref,
            message_ref,
            topic,
            event,
            payload,
        })
    }
}

/// Monotonically increasing message refs, scoped to one Phoenix connection.
///
/// Phoenix doesn't require refs to be numeric or globally unique, only
/// unique per-connection and non-empty; a simple incrementing counter
/// satisfies that.
#[derive(Debug, Default)]
pub struct RefCounter(u64);

impl RefCounter {
    pub fn new() -> Self {
        RefCounter(0)
    }

    pub fn next_ref(&mut self) -> String {
        self.0 += 1;
        self.0.to_string()
    }
}

/// The dedicated topic Phoenix uses for heartbeats, distinct from any user
/// or channel topic.
pub const HEARTBEAT_TOPIC: &str = "phoenix";
pub const HEARTBEAT_EVENT: &str = "heartbeat";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_round_trips_as_a_five_element_array() {
        let message = PhoenixMessage {
            join_ref: Some("1".to_string()),
            message_ref: Some("2".to_string()),
            topic: "grappa:user:vjt".to_string(),
            event: "phx_join".to_string(),
            payload: serde_json::json!({}),
        };

        let json = message.to_json().expect("serialize");
        assert_eq!(json, r#"["1","2","grappa:user:vjt","phx_join",{}]"#);

        let decoded = PhoenixMessage::from_json(&json).expect("deserialize");
        assert_eq!(decoded, message);
    }

    #[test]
    fn message_round_trips_with_null_refs() {
        let message = PhoenixMessage {
            join_ref: None,
            message_ref: None,
            topic: HEARTBEAT_TOPIC.to_string(),
            event: HEARTBEAT_EVENT.to_string(),
            payload: serde_json::json!({}),
        };

        let json = message.to_json().expect("serialize");
        assert_eq!(json, r#"[null,null,"phoenix","heartbeat",{}]"#);

        let decoded = PhoenixMessage::from_json(&json).expect("deserialize");
        assert_eq!(decoded, message);
    }

    #[test]
    fn message_decodes_an_unrecognized_payload_shape_without_error() {
        // Additive/unknown fields inside `payload` must never fail parsing.
        let json = r#"[
            null, "3", "grappa:user:vjt", "session_identity_changed",
            {"identified": true, "future_field": 42}
        ]"#;
        let decoded = PhoenixMessage::from_json(json).expect("deserialize");
        assert_eq!(decoded.event, "session_identity_changed");
        assert_eq!(
            decoded.payload.get("identified").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn ref_counter_increments_from_one() {
        let mut counter = RefCounter::new();
        assert_eq!(counter.next_ref(), "1");
        assert_eq!(counter.next_ref(), "2");
        assert_eq!(counter.next_ref(), "3");
    }
}
