//! Grappa wire protocol compatibility contract.
//!
//! See `docs/protocol-notes.md` §3 for the full rationale. Two rules drive
//! everything here: compare `protocol_version` with `>=`, never `==`; and
//! never fail to parse a message just because it carries a field or event
//! kind we don't recognize yet.

use serde::{Deserialize, Serialize};

/// The lowest Grappa `protocol_version` this build of Cordiale can talk to.
///
/// Cordiale doesn't rely on any field the server only started sending at a
/// later version, so this starts at the protocol's own floor. Raise it only
/// when Cordiale starts requiring a field a server below some version might
/// not send — and record the `protocol_version` that introduced it (see
/// `docs/protocol-notes.md` §7).
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 1;

/// The bootstrap compatibility fields from `GET /api/config`, and echoed
/// again in the WebSocket user-topic join response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCompatibility {
    /// What the server speaks right now.
    pub protocol_version: u32,
    /// The floor the server enforces on `client_proto` during the WS
    /// handshake; unrelated to what Cordiale itself requires.
    pub min_protocol_version: u32,
}

impl ServerCompatibility {
    /// Whether this build of Cordiale can understand what the server emits.
    ///
    /// Deliberately ignores `min_protocol_version`: that field constrains
    /// what a *client* must declare over the wire, not whether Cordiale can
    /// parse the server's current shape.
    pub fn supported_by_cordiale(&self) -> bool {
        self.protocol_version >= MIN_SUPPORTED_PROTOCOL_VERSION
    }
}

/// A parsed but not-yet-interpreted event from the wire (REST echo or
/// WebSocket push).
///
/// `kind` identifies the event; `fields` carries every other field
/// untouched as JSON. Callers match on `kind` and decode `fields` into a
/// specific typed payload only for kinds they know about — an unrecognized
/// `kind`, or unrecognized fields inside a known one, are never a parse
/// error.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct EventEnvelope {
    pub kind: String,
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_protocol_version_is_supported() {
        let compat = ServerCompatibility {
            protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION,
            min_protocol_version: 1,
        };
        assert!(compat.supported_by_cordiale());
    }

    #[test]
    fn newer_protocol_version_is_still_supported() {
        let compat = ServerCompatibility {
            protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION + 25,
            min_protocol_version: 1,
        };
        assert!(compat.supported_by_cordiale());
    }

    #[test]
    fn older_protocol_version_is_not_supported() {
        let compat = ServerCompatibility {
            protocol_version: 0,
            min_protocol_version: 0,
        };
        assert!(!compat.supported_by_cordiale());
    }

    #[test]
    fn event_envelope_ignores_unknown_fields() {
        let json = r#"{
            "kind": "session_identity_changed",
            "network_id": 3,
            "identified": true,
            "account": null,
            "some_future_field": "should not break parsing"
        }"#;

        let event: EventEnvelope = serde_json::from_str(json).expect("deserialize");
        assert_eq!(event.kind, "session_identity_changed");
        assert_eq!(
            event.fields.get("identified").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn event_envelope_accepts_a_completely_unknown_kind() {
        let json = r#"{"kind": "something_cordiale_has_never_heard_of", "whatever": 1}"#;
        let event: EventEnvelope = serde_json::from_str(json).expect("deserialize");
        assert_eq!(event.kind, "something_cordiale_has_never_heard_of");
    }
}
