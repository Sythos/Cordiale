//! Typed payloads for the Grappa REST bootstrap and login endpoints.
//!
//! These are data shapes only: no HTTP transport lives here yet (see
//! `docs/protocol-notes.md` §1 for the endpoints and §7 for the bootstrap
//! sequencing this crate will eventually drive). Fields not explicitly
//! documented by the client protocol are kept as opaque JSON rather than
//! guessed at, per the project's rule that Grappa's actual contract is the
//! only authority for shape and capability.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Response body of `GET /api/config`, the first, unauthenticated call a
/// client makes.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ConfigResponse {
    pub server: String,
    /// Diagnostic only — never use this for compatibility decisions, use
    /// `protocol_version`/`min_protocol_version` instead.
    pub version: String,
    pub protocol_version: u32,
    pub min_protocol_version: u32,
    /// Absent on servers older than 2026-08-14: a missing value means "too
    /// old for encrypted push", not a decoding failure.
    #[serde(default)]
    pub push_content_encoding: Option<String>,
}

/// Request body of `POST /auth/login`.
///
/// `password` carries either an actual password or a per-client token —
/// both travel on the same wire field (see `docs/protocol-notes.md` §1 and
/// `crate::domain::AuthMethod`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoginRequest {
    pub identifier: String,
    pub password: String,
}

/// Successful (`200`) response body of `POST /auth/login`.
///
/// `subject`'s shape isn't documented by the client protocol, so it's kept
/// as opaque JSON rather than guessed at.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    #[serde(default)]
    pub subject: Value,
}

/// Response body of `GET /boot`, the cold-start aggregate endpoint.
///
/// `networks`, `channels` and `heads` don't have a fully published field
/// schema (see `docs/protocol-notes.md` §4), so each entry is kept as
/// opaque JSON: Cordiale reads what it needs from a specific entry once
/// that shape is confirmed, rather than guessing a rigid struct now.
#[derive(Debug, Clone, Deserialize)]
pub struct BootResponse {
    pub networks: Vec<Value>,
    /// Keyed by network slug; only present for a network the account owns.
    #[serde(default)]
    pub channels: HashMap<String, Vec<Value>>,
    /// Keyed by network slug, then channel; only present for a channel that
    /// actually has history.
    #[serde(default)]
    pub heads: HashMap<String, HashMap<String, Vec<Value>>>,
}

/// Response body of `GET /me`: read cursors, unread counts and badge count
/// in bulk. None of the three have a published field schema, so they stay
/// opaque JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct MeResponse {
    #[serde(default)]
    pub read_cursors: Value,
    #[serde(default)]
    pub unread_counts: Value,
    #[serde(default)]
    pub badge_count: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_response_parses_without_push_content_encoding() {
        let json = r#"{
            "server": "grappa",
            "version": "1.4.2-abc1234",
            "protocol_version": 26,
            "min_protocol_version": 1
        }"#;

        let config: ConfigResponse = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.protocol_version, 26);
        assert_eq!(config.push_content_encoding, None);
    }

    #[test]
    fn config_response_parses_with_push_content_encoding() {
        let json = r#"{
            "server": "grappa",
            "version": "1.4.2-abc1234",
            "protocol_version": 26,
            "min_protocol_version": 1,
            "push_content_encoding": "aes128gcm"
        }"#;

        let config: ConfigResponse = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.push_content_encoding, Some("aes128gcm".to_string()));
    }

    #[test]
    fn login_request_serializes_password_field_for_either_auth_method() {
        let request = LoginRequest {
            identifier: "vjt".to_string(),
            password: "either-a-password-or-a-client-token".to_string(),
        };

        let json = serde_json::to_string(&request).expect("serialize");
        assert!(json.contains("\"identifier\":\"vjt\""));
        assert!(json.contains("\"password\":\"either-a-password-or-a-client-token\""));
    }

    #[test]
    fn login_response_keeps_subject_opaque() {
        let json = r#"{"token": "abc123", "subject": {"nick": "vjt", "extra_future_field": 1}}"#;
        let response: LoginResponse = serde_json::from_str(json).expect("deserialize");
        assert_eq!(response.token, "abc123");
        assert_eq!(
            response.subject.get("nick").and_then(|v| v.as_str()),
            Some("vjt")
        );
    }

    #[test]
    fn boot_response_tolerates_missing_channels_and_heads() {
        let json = r#"{"networks": [{"slug": "libera"}]}"#;
        let boot: BootResponse = serde_json::from_str(json).expect("deserialize");
        assert_eq!(boot.networks.len(), 1);
        assert!(boot.channels.is_empty());
        assert!(boot.heads.is_empty());
    }

    #[test]
    fn boot_response_parses_channels_and_heads() {
        let json = r#"{
            "networks": [{"slug": "libera"}],
            "channels": {"libera": [{"name": "#rust"}]},
            "heads": {"libera": {"#rust": [{"kind": "privmsg"}]}}
        }"#;
        let boot: BootResponse = serde_json::from_str(json).expect("deserialize");
        assert_eq!(boot.channels.get("libera").map(Vec::len), Some(1));
        assert!(boot.heads.contains_key("libera"));
    }

    #[test]
    fn me_response_tolerates_a_fully_empty_body() {
        let me: MeResponse = serde_json::from_str("{}").expect("deserialize");
        assert!(me.read_cursors.is_null());
        assert!(me.unread_counts.is_null());
        assert!(me.badge_count.is_null());
    }
}
