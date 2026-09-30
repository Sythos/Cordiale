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
//! for the full endpoint inventory, which lists what Cordiale covers and
//! what it leaves out.
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

/// Response body of `GET /admin/networks/:id/message_count`: the scrollback
/// rows a network delete takes with it.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminNetworkMessageCount {
    pub message_count: u64,
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

/// One row of `GET /admin/uploads`, the operator's registry. Soft-deleted
/// rows stay listed with their `deleted_at` as the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AdminUpload {
    #[serde(deserialize_with = "string_or_number")]
    pub id: String,
    pub slug: String,
    #[serde(default)]
    pub mime: String,
    #[serde(default)]
    pub bytes: u64,
    /// Best effort: the uploader may not have sent one.
    #[serde(default)]
    pub original_filename: Option<String>,
    /// `user` or `visitor`.
    #[serde(default)]
    pub subject_kind: String,
    #[serde(default, deserialize_with = "string_or_number")]
    pub subject_id: String,
    /// When the reaper means to sweep it; `None` is never.
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub deleted_at: Option<String>,
    #[serde(default)]
    pub inserted_at: Option<String>,
}

impl AdminUpload {
    /// Live while it carries no soft-delete marker. Expiry is not part of
    /// it: an expired row is still served and still counts against the cap
    /// until the reaper unlinks it, which is when an early delete matters.
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none()
    }

    /// The uploader's file name, or the slug (what a channel link shows)
    /// when there is none.
    pub fn display_name(&self) -> &str {
        match self.original_filename.as_deref().map(str::trim) {
            Some(name) if !name.is_empty() => name,
            _ => &self.slug,
        }
    }
}

/// Response body of `GET /admin/uploads`: the registry and the disk budget.
/// The per-user and per-visitor caps are deliberately not here: they're an
/// operator knob, never a personal quota meter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct AdminUploadsResponse {
    #[serde(default)]
    pub uploads: Vec<AdminUpload>,
    #[serde(default)]
    pub live_bytes_sum: u64,
    #[serde(default)]
    pub global_cap_bytes: u64,
}

fn string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::String(text) => text,
        Value::Null => String::new(),
        other => other.to_string(),
    })
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

/// What an IRC server endpoint row carries for the editor: `(host, port,
/// tls, enabled)`, with the port as text.
pub fn admin_server_fields(entry: &Value) -> (String, String, bool, bool) {
    (
        entry
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        entry
            .get("port")
            .and_then(Value::as_i64)
            .map(|port| port.to_string())
            .unwrap_or_default(),
        entry.get("tls").and_then(Value::as_bool) == Some(true),
        entry.get("enabled").and_then(Value::as_bool) != Some(false),
    )
}

/// The body of `PUT /admin/networks/:id/servers/:server_id` for what the
/// editor holds, or `None` for an empty host or a port outside 1-65535.
pub fn admin_server_changes(host: &str, port: &str, tls: bool, enabled: bool) -> Option<Value> {
    let host = host.trim();
    let port = port.trim().parse::<u16>().ok().filter(|port| *port > 0)?;
    if host.is_empty() {
        return None;
    }
    Some(serde_json::json!({ "host": host, "port": port, "tls": tls, "enabled": enabled }))
}

/// One curated channel of a network (`GET
/// /admin/networks/:id/featured_channels`): name, description, and a
/// marker for one that is switched off.
pub fn admin_featured_label(entry: &Value) -> String {
    let name = entry.get("name").and_then(Value::as_str).unwrap_or("?");
    let mut label = name.to_string();
    if let Some(description) = entry
        .get("description")
        .and_then(Value::as_str)
        .filter(|description| !description.is_empty())
    {
        label.push_str(" · ");
        label.push_str(description);
    }
    if entry.get("enabled").and_then(Value::as_bool) == Some(false) {
        label.push_str(" · off");
    }
    label
}

/// The `:channel_id` segment of a featured channel, and whether it is on.
pub fn admin_featured_state(entry: &Value) -> Option<(String, bool)> {
    let id = entry.get("id").and_then(Value::as_i64)?.to_string();
    let enabled = entry.get("enabled").and_then(Value::as_bool) != Some(false);
    Some((id, enabled))
}

/// The body of `POST /admin/networks/:id/featured_channels` for what was
/// typed, or `None` when the name is empty. A blank description is left
/// out rather than sent empty.
pub fn admin_featured_body(name: &str, description: &str) -> Option<Value> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut body = serde_json::json!({ "name": name });
    let description = description.trim();
    if !description.is_empty() {
        body["description"] = Value::from(description);
    }
    Some(body)
}

/// One per-network session of a visitor, as the Visitors tab lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminVisitorSession {
    /// `nick @ network`, plus the connection state Grappa holds for it.
    pub label: String,
    /// The composite `visitor:<id>:<network_id>` key of `/admin/sessions/:id`.
    pub session_id: String,
    /// Whether a live process backs it. Reconnect is offered when not,
    /// judged on this and never on `connection_state`: a credential still
    /// marked connected whose process died needs the reconnect most.
    pub alive: bool,
}

/// The per-network sessions of one opaque `AdminVisitor` entry; a visitor
/// with no credentials has none.
pub fn admin_visitor_sessions(entry: &Value) -> Vec<AdminVisitorSession> {
    let Some(visitor_id) = entry.get("id").and_then(Value::as_str) else {
        return Vec::new();
    };
    let networks = entry
        .get("networks")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    networks
        .iter()
        .filter_map(|network| {
            let network_id = network.get("network_id").and_then(Value::as_i64)?;
            let text = |key: &str| network.get(key).and_then(Value::as_str).unwrap_or("?");
            Some(AdminVisitorSession {
                label: format!(
                    "{} @ {} · {}",
                    text("nick"),
                    text("network_slug"),
                    text("connection_state")
                ),
                session_id: format!("visitor:{visitor_id}:{network_id}"),
                alive: admin_session_is_alive(network),
            })
        })
        .collect()
}

/// Whether the session belongs to an account, not a visitor. Only accounts
/// get Terminate in the session list, like Cicchetto's row actions.
pub fn admin_session_is_user(entry: &Value) -> bool {
    entry.get("subject_kind").and_then(Value::as_str) == Some("user")
}

/// What a bound credential carries for the editor: `(nick, ident,
/// realname, sasl_user)`, each `""` when unset.
pub fn admin_credential_fields(entry: &Value) -> (String, String, String, String) {
    let text = |key: &str| {
        entry
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    (
        text("nick"),
        text("ident"),
        text("realname"),
        text("sasl_user"),
    )
}

/// The body of `PATCH /admin/credentials/:user_id/:network_id` for what the
/// editor holds, or `None` for an empty nick. A password is sent only when
/// one was typed: it ends a live session, so an empty field must never
/// rotate anything.
pub fn admin_credential_changes(
    nick: &str,
    ident: &str,
    realname: &str,
    sasl_user: &str,
    password: &str,
) -> Option<Value> {
    let nick = nick.trim();
    if nick.is_empty() {
        return None;
    }
    let mut body = serde_json::json!({
        "nick": nick,
        "ident": ident.trim(),
        "realname": realname.trim(),
        "sasl_user": sasl_user.trim(),
    });
    if !password.is_empty() {
        body["password"] = Value::from(password);
    }
    Some(body)
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

/// Auth methods an admin can bind a credential with, in Grappa's order.
pub const CREDENTIAL_AUTH_METHODS: [&str; 5] =
    ["auto", "sasl", "server_pass", "nickserv_identify", "none"];

/// One line for a bound credential: account, network, nick, auth method
/// and connection state.
pub fn admin_credential_label(entry: &Value) -> String {
    let text = |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or("?");
    format!(
        "{} @ {} · {} · {} · {}",
        text("user_name"),
        text("network_slug"),
        text("nick"),
        text("auth_method"),
        text("connection_state")
    )
}

/// One line for a vhost: its address and pool/availability flags.
pub fn admin_vhost_label(entry: &Value) -> String {
    let flag = |key: &str| entry.get(key).and_then(Value::as_bool) == Some(true);
    let mut label = entry
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    if flag("in_pool") {
        label.push_str(" · pool");
    }
    if flag("generally_available") {
        label.push_str(" · all");
    }
    label
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
    fn credential_and_vhost_labels() {
        assert_eq!(
            admin_credential_label(&serde_json::json!({
                "user_name": "ada", "network_slug": "libera", "nick": "ada_",
                "auth_method": "sasl", "connection_state": "connected"
            })),
            "ada @ libera · ada_ · sasl · connected"
        );
        assert_eq!(
            admin_vhost_label(&serde_json::json!({
                "address": "2001:db8::1", "in_pool": true, "generally_available": false
            })),
            "2001:db8::1 · pool"
        );
    }

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
    fn server_editor_fields_and_body() {
        let entry = serde_json::json!({
            "id": 3, "host": "irc.libera.chat", "port": 6697, "tls": true, "enabled": false
        });
        assert_eq!(
            admin_server_fields(&entry),
            ("irc.libera.chat".into(), "6697".into(), true, false)
        );
        // A row that doesn't say it is disabled is enabled.
        assert!(admin_server_fields(&serde_json::json!({"host": "h", "port": 1})).3);
        assert_eq!(
            admin_server_changes(" irc2.example ", "6667", false, true),
            Some(serde_json::json!({
                "host": "irc2.example", "port": 6667, "tls": false, "enabled": true
            }))
        );
        assert_eq!(admin_server_changes("", "6667", true, true), None);
        assert_eq!(admin_server_changes("h", "0", true, true), None);
        assert_eq!(admin_server_changes("h", "70000", true, true), None);
        assert_eq!(admin_server_changes("h", "irc", true, true), None);
    }

    #[test]
    fn featured_channel_label_state_and_body() {
        let entry = serde_json::json!({
            "id": 4, "name": "#grappa", "description": "Support", "enabled": false
        });
        assert_eq!(admin_featured_label(&entry), "#grappa · Support · off");
        assert_eq!(admin_featured_state(&entry), Some(("4".to_string(), false)));
        let plain = serde_json::json!({"id": 5, "name": "#lobby", "description": null});
        assert_eq!(admin_featured_label(&plain), "#lobby");
        assert_eq!(admin_featured_state(&plain), Some(("5".to_string(), true)));
        assert_eq!(
            admin_featured_state(&serde_json::json!({"name": "#x"})),
            None
        );
        assert_eq!(
            admin_featured_body(" #lobby ", "  "),
            Some(serde_json::json!({"name": "#lobby"}))
        );
        assert_eq!(
            admin_featured_body("#lobby", " Hello "),
            Some(serde_json::json!({"name": "#lobby", "description": "Hello"}))
        );
        assert_eq!(admin_featured_body("  ", "Hello"), None);
    }

    #[test]
    fn visitor_sessions_follow_live_truth_not_connection_state() {
        let entry = serde_json::json!({
            "id": "v-1",
            "networks": [
                {"network_id": 7, "network_slug": "libera", "nick": "ada",
                 "connection_state": "connected", "live_state": null},
                {"network_id": 8, "network_slug": "oftc", "nick": "ada2",
                 "connection_state": "connected", "live_state": {"alive": true}}
            ]
        });
        assert_eq!(
            admin_visitor_sessions(&entry),
            vec![
                AdminVisitorSession {
                    label: "ada @ libera · connected".into(),
                    session_id: "visitor:v-1:7".into(),
                    alive: false,
                },
                AdminVisitorSession {
                    label: "ada2 @ oftc · connected".into(),
                    session_id: "visitor:v-1:8".into(),
                    alive: true,
                },
            ]
        );
        assert!(
            admin_visitor_sessions(&serde_json::json!({"id": "v-2", "networks": []})).is_empty()
        );
        assert!(admin_visitor_sessions(&serde_json::json!({"networks": []})).is_empty());
    }

    #[test]
    fn only_account_sessions_are_user_sessions() {
        assert!(admin_session_is_user(
            &serde_json::json!({"subject_kind": "user"})
        ));
        assert!(!admin_session_is_user(
            &serde_json::json!({"subject_kind": "visitor"})
        ));
        assert!(!admin_session_is_user(&serde_json::json!({})));
    }

    #[test]
    fn credential_editor_fields_and_body() {
        let entry = serde_json::json!({
            "nick": "ada", "ident": null, "realname": "Ada L", "sasl_user": "ada"
        });
        assert_eq!(
            admin_credential_fields(&entry),
            ("ada".into(), "".into(), "Ada L".into(), "ada".into())
        );
        // Built at run time: the value is only passed through.
        let typed = format!("pw-{}", std::process::id());
        assert_eq!(
            admin_credential_changes(" ada ", "", "Ada", "ada", &typed),
            Some(serde_json::json!({
                "nick": "ada", "ident": "", "realname": "Ada", "sasl_user": "ada",
                "password": typed
            }))
        );
        // No password typed: none is sent, since it would end a live session.
        // Built without a literal: nothing is typed, so nothing is sent.
        let no_password = String::new();
        let body = admin_credential_changes("ada", "", "Ada", "", &no_password).expect("body");
        assert!(body.get("password").is_none());
        assert_eq!(
            admin_credential_changes("  ", "", "", "", &no_password),
            None
        );
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
