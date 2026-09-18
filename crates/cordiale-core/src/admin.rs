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

//! Typed payloads for the subset of Grappa's `/admin/*` REST surface that
//! Cordiale actually implements.
//!
//! `/admin/*` isn't documented in `CLIENT_PROTOCOL.md` at all — this
//! module's shapes come from reading Grappa's own Elixir source
//! (`lib/grappa_web/controllers/admin/*_controller.ex` and the
//! corresponding `*.AdminWire` modules) and Cicchetto's admin UI
//! (`cicchetto/src/AdminPane.tsx`, `cicchetto/src/lib/api.ex`) directly,
//! since no other authority exists. See `docs/protocol-notes.md` §4ter
//! for the full endpoint inventory, including the considerably larger set
//! of endpoints this module deliberately does not cover yet (visitors,
//! vhosts, credentials, server-wide settings, the admin WebSocket event
//! stream, and every mutating network/user endpoint beyond session
//! disconnect).
//!
//! Every entry (`AdminSession`, `AdminUser`, `AdminNetwork`) is kept as
//! opaque JSON rather than a fully-typed struct: the source confirms
//! field *names* but not every nested field's exact type, and this
//! project's rule is to never guess a field shape it hasn't verified
//! character-for-character. Callers extract what they need defensively,
//! the same discipline already used for `boot.channels`/`boot.networks`.

use serde::Deserialize;
use serde_json::Value;

/// Response body of `GET /admin/overview` — `Grappa.AdminOverview.snapshot/0`,
/// pushed unwrapped (not nested under a key), per
/// `lib/grappa/admin_overview.ex`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminOverview {
    pub sessions: i64,
    pub visitors: AdminVisitorsSummary,
    pub hostname: String,
    #[serde(default)]
    pub loadavg: Option<f64>,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminVisitorsSummary {
    pub total: i64,
    pub live: i64,
}

/// Response body of `GET /admin/sessions`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminSessionsResponse {
    pub sessions: Vec<Value>,
}

/// Response body of `GET /admin/users`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminUsersResponse {
    pub users: Vec<Value>,
}

/// Response body of `GET /admin/networks`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminNetworksResponse {
    pub networks: Vec<Value>,
}

/// Reads a human-readable label out of one opaque `AdminSession` entry:
/// `subject_label` if present, else `subject_kind:subject_id`, else a
/// placeholder — never a crash on an unexpected shape.
pub fn admin_session_label(entry: &Value) -> String {
    if let Some(label) = entry.get("subject_label").and_then(Value::as_str) {
        return label.to_string();
    }
    let kind = entry
        .get("subject_kind")
        .and_then(Value::as_str)
        .unwrap_or("session");
    let id = entry
        .get("subject_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    format!("{kind}:{id}")
}

/// Reads the `sessions/:id` path segment for a disconnect/reconnect call
/// out of one opaque `AdminSession` entry. Per
/// `lib/grappa_web/controllers/admin/sessions_controller.ex`, that segment
/// is `"<user|visitor>:<uuid>:<network_id>"` — built from `subject_kind`,
/// `subject_id` and `network_id` rather than trusting an `id` field the
/// entry may or may not carry directly.
pub fn admin_session_id(entry: &Value) -> Option<String> {
    let kind = entry.get("subject_kind").and_then(Value::as_str)?;
    let id = entry.get("subject_id").and_then(Value::as_str)?;
    let network_id = entry.get("network_id")?;
    let network_id = network_id
        .as_str()
        .map(str::to_string)
        .or_else(|| network_id.as_i64().map(|n| n.to_string()))?;
    Some(format!("{kind}:{id}:{network_id}"))
}

/// Whether the session's `live_state` reports an alive process — `false`
/// for a `null` `live_state` too (the documented "U-0 honesty signal":
/// the database still lists the session but no live process backs it).
pub fn admin_session_is_alive(entry: &Value) -> bool {
    entry
        .get("live_state")
        .and_then(|state| state.get("alive"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Reads a display name out of one opaque `AdminUser` entry.
pub fn admin_user_label(entry: &Value) -> String {
    entry
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("(unknown)")
        .to_string()
}

pub fn admin_user_is_admin(entry: &Value) -> bool {
    entry
        .get("is_admin")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Reads a display name out of one opaque `AdminNetwork` entry.
pub fn admin_network_label(entry: &Value) -> String {
    entry
        .get("slug")
        .and_then(Value::as_str)
        .unwrap_or("(unknown)")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_session_label_prefers_subject_label() {
        let entry = serde_json::json!({"subject_label": "vjt", "subject_kind": "user"});
        assert_eq!(admin_session_label(&entry), "vjt");
    }

    #[test]
    fn admin_session_label_falls_back_to_kind_and_id() {
        let entry = serde_json::json!({"subject_kind": "visitor", "subject_id": "abc123"});
        assert_eq!(admin_session_label(&entry), "visitor:abc123");
    }

    #[test]
    fn admin_session_id_builds_the_documented_composite_key() {
        let entry = serde_json::json!({
            "subject_kind": "user",
            "subject_id": "abc-123",
            "network_id": 7
        });
        assert_eq!(
            admin_session_id(&entry),
            Some("user:abc-123:7".to_string())
        );
    }

    #[test]
    fn admin_session_id_is_none_when_a_field_is_missing() {
        let entry = serde_json::json!({"subject_kind": "user"});
        assert_eq!(admin_session_id(&entry), None);
    }

    #[test]
    fn admin_session_is_alive_is_false_for_null_live_state() {
        let entry = serde_json::json!({"live_state": null});
        assert!(!admin_session_is_alive(&entry));
    }

    #[test]
    fn admin_session_is_alive_reads_the_nested_flag() {
        let entry = serde_json::json!({"live_state": {"alive": true}});
        assert!(admin_session_is_alive(&entry));
    }
}
