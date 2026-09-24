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
//! for the full endpoint inventory. Covered: overview, sessions (list +
//! disconnect), users (list + toggle `is_admin` + delete), networks
//! (list + circuit reset), visitors (list + delete), session log (read),
//! reaper (run). Still deliberately out of scope: vhosts (+ grants),
//! credentials, server-wide settings write, network create/patch/delete,
//! user create/password-change, and the admin WebSocket event stream
//! (`grappa:admin:events`) — each is a form-heavy or genuinely
//! destructive surface that needs a real server to validate against,
//! not something to build blind.
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

/// Response body of `GET /admin/visitors`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminVisitorsResponse {
    pub visitors: Vec<Value>,
}

/// Response body of `GET /admin/session_log` and
/// `GET /admin/session_log/sessions`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminSessionLogResponse {
    #[serde(default)]
    pub session_log: Vec<Value>,
}

/// Response body of `POST /admin/reaper/run`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminReaperRunResponse {
    pub swept_count: i64,
    #[serde(default)]
    pub swept_at: Option<String>,
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

/// Reads the `:id` path segment for `PATCH`/`DELETE /admin/users/:id` out
/// of one opaque `AdminUser` entry.
pub fn admin_user_id(entry: &Value) -> Option<String> {
    let id = entry.get("id")?;
    id.as_str()
        .map(str::to_string)
        .or_else(|| id.as_i64().map(|n| n.to_string()))
}

/// Reads the `:id`/`:network_id` path segment for
/// `POST /admin/circuit/:network_id/reset` out of one opaque
/// `AdminNetwork` entry.
pub fn admin_network_id(entry: &Value) -> Option<String> {
    let id = entry.get("id")?;
    id.as_str()
        .map(str::to_string)
        .or_else(|| id.as_i64().map(|n| n.to_string()))
}

/// The per-network caps and visitor switch the admin editor shows:
/// `(visitor_enabled, visitor sessions, user sessions, per IP)`, each cap
/// as text with `""` for unlimited (`null`).
pub fn admin_network_settings(entry: &Value) -> (bool, String, String, String) {
    let cap = |key: &str| {
        entry
            .get(key)
            .and_then(Value::as_i64)
            .map(|cap| cap.to_string())
            .unwrap_or_default()
    };
    (
        entry
            .get("visitor_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        cap("max_concurrent_visitor_sessions"),
        cap("max_concurrent_user_sessions"),
        cap("max_per_ip"),
    )
}

/// Parses a cap typed in the admin editor: empty is unlimited (`null`),
/// otherwise a non-negative whole number. `None` for anything else.
pub fn parse_admin_cap(text: &str) -> Option<Value> {
    let text = text.trim();
    if text.is_empty() {
        return Some(Value::Null);
    }
    text.parse::<u32>().ok().map(Value::from)
}

/// Reads a display name out of one opaque `AdminNetwork` entry.
pub fn admin_network_label(entry: &Value) -> String {
    entry
        .get("slug")
        .and_then(Value::as_str)
        .unwrap_or("(unknown)")
        .to_string()
}

/// Reads a short circuit-breaker/live-count status suffix out of one
/// opaque `AdminNetwork` entry — `""` if the fields aren't present.
pub fn admin_network_status(entry: &Value) -> String {
    let circuit = entry
        .get("circuit_state")
        .and_then(|circuit| circuit.get("state"))
        .and_then(Value::as_str);
    let users = entry
        .get("live_counts")
        .and_then(|counts| counts.get("users"))
        .and_then(Value::as_i64);
    let visitors = entry
        .get("live_counts")
        .and_then(|counts| counts.get("visitors"))
        .and_then(Value::as_i64);

    match (circuit, users, visitors) {
        (Some(circuit), Some(users), Some(visitors)) => {
            format!(" ({circuit}, {users} user(s), {visitors} visitor(s))")
        }
        (Some(circuit), _, _) => format!(" ({circuit})"),
        _ => String::new(),
    }
}

/// Reads a human-readable label out of one opaque `AdminVisitor` entry.
pub fn admin_visitor_label(entry: &Value) -> String {
    let id = entry.get("id").and_then(Value::as_str).unwrap_or("?");
    let ip = entry.get("ip").and_then(Value::as_str).unwrap_or("");
    if ip.is_empty() {
        id.to_string()
    } else {
        format!("{id} ({ip})")
    }
}

/// Reads the `:id` path segment for `DELETE /admin/visitors/:id`.
pub fn admin_visitor_id(entry: &Value) -> Option<String> {
    entry.get("id").and_then(Value::as_str).map(str::to_string)
}

/// Reads a one-line summary out of one opaque `SessionLog.Wire` entry.
pub fn admin_session_log_line(entry: &Value) -> String {
    let at = entry.get("at").and_then(Value::as_str).unwrap_or("");
    let event = entry.get("event").and_then(Value::as_str).unwrap_or("?");
    let nick = entry
        .get("nick")
        .and_then(Value::as_str)
        .or_else(|| entry.get("subject_kind").and_then(Value::as_str))
        .unwrap_or("?");
    let network = entry
        .get("network_slug")
        .and_then(Value::as_str)
        .unwrap_or("");
    if network.is_empty() {
        format!("{at} · {event} · {nick}")
    } else {
        format!("{at} · {event} · {nick}@{network}")
    }
}

/// One line for a network's IRC server endpoint (`GET
/// /admin/networks/:id/servers`): `host:port`, TLS and disabled markers.
pub fn admin_server_label(entry: &Value) -> String {
    let host = entry.get("host").and_then(Value::as_str).unwrap_or("?");
    let port = entry.get("port").and_then(Value::as_i64).unwrap_or(0);
    let mut label = format!("{host}:{port}");
    if entry.get("tls").and_then(Value::as_bool) == Some(true) {
        label.push_str(" · TLS");
    }
    if entry.get("enabled").and_then(Value::as_bool) == Some(false) {
        label.push_str(" · off");
    }
    label
}

/// The byte sizes of Grappa's server settings, as MiB text for the
/// editor: whole numbers when exact, else two decimals.
pub fn bytes_to_mib_text(bytes: Option<u64>) -> String {
    const MIB: u64 = 1024 * 1024;
    match bytes {
        None => String::new(),
        Some(bytes) if bytes % MIB == 0 => (bytes / MIB).to_string(),
        Some(bytes) => format!("{:.2}", bytes as f64 / MIB as f64),
    }
}

/// Parses a MiB size typed in the editor back into a positive byte count.
pub fn mib_text_to_bytes(text: &str) -> Option<u64> {
    let mib: f64 = text.trim().parse().ok()?;
    let bytes = (mib * 1024.0 * 1024.0).round();
    (bytes >= 1.0 && bytes.is_finite()).then_some(bytes as u64)
}

/// Phoenix topic of Grappa's live admin feed (admins with a full web
/// session only): a `snapshot` of recent events on join, then one push per
/// event, `session_log_event`s and periodic `overview` pushes.
pub const ADMIN_EVENTS_TOPIC: &str = "grappa:admin:events";

/// One line for an admin audit event (`user_created`, `circuit_open`,
/// `network_caps_updated`, ...): time, kind, what it's about and who did it.
pub fn admin_event_line(entry: &Value) -> String {
    let text = |key: &str| entry.get(key).and_then(Value::as_str);
    let at = text("at").unwrap_or("");
    let kind = text("kind").unwrap_or("?");
    let subject = [
        "user_name",
        "network_slug",
        "visitor_nick",
        "source_ip",
        "subject_kind",
    ]
    .iter()
    .find_map(|key| text(key))
    .unwrap_or("");
    let mut line = format!("{at} · {kind}");
    if !subject.is_empty() {
        line.push_str(" · ");
        line.push_str(subject);
    }
    if let (Some(host), Some(port)) = (text("host"), entry.get("port").and_then(Value::as_i64)) {
        line.push_str(&format!(" · {host}:{port}"));
    }
    if let Some(actor) = text("actor_user_name") {
        line.push_str(&format!(" · by {actor}"));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_labels_and_mib_sizes() {
        assert_eq!(
            admin_server_label(&serde_json::json!({
                "host": "irc.libera.chat", "port": 6697, "tls": true, "enabled": false
            })),
            "irc.libera.chat:6697 · TLS · off"
        );
        assert_eq!(bytes_to_mib_text(Some(10 * 1024 * 1024)), "10");
        assert_eq!(bytes_to_mib_text(Some(1536 * 1024)), "1.50");
        assert_eq!(bytes_to_mib_text(None), "");
        assert_eq!(mib_text_to_bytes("1.5"), Some(1536 * 1024));
        assert_eq!(mib_text_to_bytes("0"), None);
        assert_eq!(mib_text_to_bytes("lots"), None);
    }

    #[test]
    fn admin_event_line_names_subject_and_actor() {
        let line = admin_event_line(&serde_json::json!({
            "kind": "user_created",
            "user_name": "ada",
            "actor_user_name": "vjt",
            "at": "2026-09-24T10:00:00Z"
        }));
        assert_eq!(line, "2026-09-24T10:00:00Z · user_created · ada · by vjt");
        let line = admin_event_line(&serde_json::json!({
            "kind": "server_added",
            "network_slug": "libera",
            "host": "irc.libera.chat",
            "port": 6697,
            "at": "t"
        }));
        assert_eq!(line, "t · server_added · libera · irc.libera.chat:6697");
    }

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
        assert_eq!(admin_session_id(&entry), Some("user:abc-123:7".to_string()));
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

    #[test]
    fn admin_user_id_reads_an_integer_id_as_a_string() {
        let entry = serde_json::json!({"id": 42});
        assert_eq!(admin_user_id(&entry), Some("42".to_string()));
    }

    #[test]
    fn admin_network_status_formats_circuit_and_live_counts() {
        let entry = serde_json::json!({
            "circuit_state": {"state": "closed"},
            "live_counts": {"users": 3, "visitors": 1}
        });
        assert_eq!(
            admin_network_status(&entry),
            " (closed, 3 user(s), 1 visitor(s))"
        );
    }

    #[test]
    fn admin_network_id_reads_an_integer_id_as_a_string() {
        let entry = serde_json::json!({"id": 7});
        assert_eq!(admin_network_id(&entry), Some("7".to_string()));
    }

    #[test]
    fn admin_network_status_is_empty_without_circuit_data() {
        assert_eq!(admin_network_status(&serde_json::json!({})), "");
    }

    #[test]
    fn admin_visitor_label_includes_ip_when_present() {
        let entry = serde_json::json!({"id": "abc", "ip": "203.0.113.1"});
        assert_eq!(admin_visitor_label(&entry), "abc (203.0.113.1)");
    }

    #[test]
    fn admin_session_log_line_formats_event_and_network() {
        let entry = serde_json::json!({
            "at": "2026-09-19T10:00:00Z",
            "event": "join",
            "nick": "vjt",
            "network_slug": "libera"
        });
        assert_eq!(
            admin_session_log_line(&entry),
            "2026-09-19T10:00:00Z · join · vjt@libera"
        );
    }
}
