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
/// both travel on the same wire field (see `docs/protocol-notes.md` §1).
/// The bearer returned by Grappa after a successful login is a separate
/// credential and must be sent directly as `Authorization: Bearer`, never
/// placed in this request field. An empty `password` is left out of the
/// body: that's a guest sign-in under the `identifier` nickname, the same
/// `{identifier}` body Cicchetto sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoginRequest {
    pub identifier: String,
    #[serde(skip_serializing_if = "String::is_empty")]
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

/// Response body of `POST /me/share-token`: a single-use credential that
/// signs a second device into this same identity. `expires_at` is the
/// absolute ISO 8601 instant after which Grappa refuses it (ten minutes
/// after minting).
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct ShareTokenMint {
    pub token: String,
    pub expires_at: String,
}

// A share token is a credential: keep it out of any `{:?}` that ends up in
// a log line.
impl std::fmt::Debug for ShareTokenMint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareTokenMint")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A WebAuthn ceremony Grappa started (`{challenge_id, public_key}`): the
/// id goes back with the authenticator's answer, `public_key` holds the
/// options in Grappa's snake_case spelling. Binary values are base64url
/// without padding, on the way in and out.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PasskeyOptions<T> {
    pub challenge_id: String,
    pub public_key: T,
}

/// A credential the authenticator may answer with.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PasskeyDescriptor {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub transports: Vec<String>,
}

/// `public_key` of an assertion (sign-in or mode change). The
/// `clientDataJSON` challenge must be `challenge` as sent, and its origin
/// Grappa's passkey origin exactly, whose host is `rp_id`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PasskeyRequestOptions {
    pub challenge: String,
    pub rp_id: String,
    /// Milliseconds.
    pub timeout: Option<u64>,
    pub user_verification: Option<String>,
    /// Empty on the passwordless door, which only a discoverable credential
    /// can answer.
    #[serde(default)]
    pub allow_credentials: Vec<PasskeyDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PasskeyRelyingParty {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PasskeyUser {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// An accepted key type: `-7` (ES256) or `-257` (RS256) today.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PasskeyCredentialParameter {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PasskeyAuthenticatorSelection {
    pub resident_key: Option<String>,
    pub user_verification: Option<String>,
}

/// `public_key` of a registration. Grappa asks for `attestation: "none"`
/// and accepts nothing else in practice, so an attestation straight from
/// a device must be rewritten to the `none` format before it's sent.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PasskeyCreationOptions {
    pub challenge: String,
    pub rp: PasskeyRelyingParty,
    pub user: PasskeyUser,
    pub pub_key_cred_params: Vec<PasskeyCredentialParameter>,
    /// Milliseconds.
    pub timeout: Option<u64>,
    pub attestation: Option<String>,
    #[serde(default)]
    pub authenticator_selection: PasskeyAuthenticatorSelection,
}

/// An authenticator's assertion, as the passkey sign-in and mode doors
/// take it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeyAssertion {
    pub challenge_id: String,
    pub raw_id: String,
    pub authenticator_data: String,
    /// The exact bytes the authenticator signed the hash of.
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

/// A newly created credential, for `POST /me/passkeys/registration`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeyCredential {
    pub challenge_id: String,
    pub raw_id: String,
    pub attestation_object: String,
    pub client_data_json: String,
    pub transports: Vec<String>,
}

/// How the account uses its passkeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyMode {
    Disabled,
    SecondFactor,
    Passwordless,
}

/// `GET /me/passkeys`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PasskeyStatus {
    pub mode: PasskeyMode,
    #[serde(default)]
    pub passkeys: Vec<PasskeySummary>,
}

/// One registered passkey; timestamps are ISO 8601 (UTC).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PasskeySummary {
    pub id: String,
    pub name: Option<String>,
    pub inserted_at: String,
    /// `None` until the passkey is first used.
    pub last_used_at: Option<String>,
}

/// `POST /me/passkeys/passwordless/recovery`: the recovery codes to show
/// before passwordless is armed, and the token (valid ten minutes) that
/// proves they were shown. The codes only become valid once the mode
/// change completes. No `Debug`: both fields are credentials.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct PasswordlessRecovery {
    pub recovery_codes: Vec<String>,
    pub recovery_token: String,
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
/// in bulk, plus admin status. The first three have no published field
/// schema, so they stay opaque JSON. `is_admin` does have a confirmed
/// source: Cicchetto's real `MeResponse` type and its own comment pointing
/// at the server implementation (`lib/grappa_web/controllers/me_json.ex`,
/// `MeJSON.show/1`) — a top-level boolean here, never under `subject` on
/// the login/boot response, which doesn't carry it at all.
#[derive(Debug, Clone, Deserialize)]
pub struct MeResponse {
    #[serde(default)]
    pub read_cursors: Value,
    #[serde(default)]
    pub unread_counts: Value,
    #[serde(default)]
    pub badge_count: Value,
    #[serde(default)]
    pub is_admin: bool,
    /// `"user"` or `"visitor"`.
    #[serde(default)]
    pub kind: Option<String>,
    /// The subject id: a visitor's is the stable key of its topics.
    #[serde(default)]
    pub id: Option<Value>,
    /// The account name, for a user subject.
    #[serde(default)]
    pub name: Option<String>,
    /// A visitor's services registration (identity-wide: true when any of
    /// its networks holds a credential with a committed secret). Absent for
    /// a user.
    #[serde(default)]
    pub registered: Option<bool>,
    /// The home page's data (`home_data`), populated for both subject kinds.
    #[serde(default)]
    pub home_data: Option<HomeData>,
}

/// `home_data` on `GET /me`: the subject's attached networks as home rows,
/// plus the networks it may attach with one tap (`POST /session/networks`),
/// which includes its own detached bindings (protocol v28).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct HomeData {
    #[serde(default)]
    pub networks: Vec<HomeNetworkRow>,
    #[serde(default)]
    pub available_networks: Vec<AvailableNetworkRow>,
}

/// One attached network on the home page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct HomeNetworkRow {
    pub slug: String,
    #[serde(default)]
    pub nick: String,
    /// `connected`, `failing`, `parked` or `failed`.
    #[serde(default)]
    pub connection_state: String,
    #[serde(default)]
    pub connection_state_reason: Option<String>,
    /// The credential carries a NickServ secret, so `/recover` has
    /// something to identify with.
    #[serde(default)]
    pub recoverable: bool,
}

/// A network the subject can attach from the home page.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AvailableNetworkRow {
    pub slug: String,
}

/// One operator-curated channel of `GET /networks/:slug/featured`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FeaturedChannel {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Response body of `GET /networks/:slug/featured`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FeaturedChannelsResponse {
    #[serde(default)]
    pub(crate) channels: Vec<FeaturedChannel>,
}

impl MeResponse {
    /// The label Grappa builds the subject's realtime topics from
    /// (`grappa:user:<label>/...`, `Grappa.Subject.label/1`): the account
    /// name as stored for a user, `visitor:<id>` for a visitor. `None`
    /// when `/me` doesn't say.
    pub fn topic_label(&self) -> Option<String> {
        match self.kind.as_deref()? {
            "user" => self.name.clone().filter(|name| !name.is_empty()),
            "visitor" => {
                let id = match self.id.as_ref()? {
                    Value::String(id) => id.clone(),
                    Value::Number(id) => id.to_string(),
                    _ => return None,
                };
                (!id.is_empty()).then(|| format!("visitor:{id}"))
            }
            _ => None,
        }
    }
}

/// `GET .../messages/count` answer. A server without the `cap` parameter
/// also sends `messages` and `events`; only `count` matters here, the rest
/// is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct MessageCountResponse {
    pub count: u64,
}

/// Request body of `POST /networks/:network_id/channels/:channel_id/messages`.
///
/// `body` isn't documented in `CLIENT_PROTOCOL.md` itself — confirmed by
/// reading Cicchetto's real `sendMessage` call (`cicchetto/src/lib/api.ts`)
/// against the same endpoint, since the reference client necessarily gets
/// this right. `ctcp_target`/`notice_target` are documented and mutually
/// exclusive with each other (never both set); `statusmsg_target` is a
/// third relay kind seen in Cicchetto's code but not in the documented
/// contract — included for parity, not guaranteed stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SendMessageRequest {
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctcp_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statusmsg_target: Option<String>,
}

impl SendMessageRequest {
    /// A plain message, no CTCP/notice/statusmsg relay.
    pub fn plain(body: impl Into<String>) -> Self {
        SendMessageRequest {
            body: body.into(),
            ctcp_target: None,
            notice_target: None,
            statusmsg_target: None,
        }
    }

    /// A CTCP query (`VERSION`, `TIME`, `PING`, `CLIENTINFO`, `USERINFO`,
    /// `SOURCE`, ...) to `target` — wire shape confirmed from Cicchetto's
    /// own source (`lib/ctcpQuery.ts` + `lib/api.ts`): the CTCP framing
    /// (`\x01VERB[ args]\x01`) goes in `body` like any other message,
    /// with `ctcp_target` naming who it's actually for.
    pub fn ctcp(target: impl Into<String>, verb: &str, args: Option<&str>) -> Self {
        let body = match args {
            Some(args) => format!("\u{1}{verb} {args}\u{1}"),
            None => format!("\u{1}{verb}\u{1}"),
        };
        SendMessageRequest {
            body,
            ctcp_target: Some(target.into()),
            notice_target: None,
            statusmsg_target: None,
        }
    }
}

/// Body of `GET`/`PUT /me/settings/display-prefs`, per
/// `docs/protocol-notes.md` §1: 8 keys (v29), absent-tolerant in both directions
/// (a `GET` response may omit any of them, and a `PUT` only needs to carry
/// the ones being changed). `time_format` and `presence_filter` aren't
/// touched by Cordiale's Settings UI yet (their exact value shapes aren't
/// confirmed — see §7 open point 8), so this struct only round-trips the
/// five boolean prefs Cordiale actually reads and writes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayPrefs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub colored_nicklist: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_bottom_bar: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_formatting: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_event_badge: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bold_mentions: Option<bool>,
    /// Date notation (protocol v29). `None` when the server doesn't send
    /// it or sends a value outside the closed set: an unknown key is one
    /// the client drops, never a reason to lose the other preferences.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient_date_format"
    )]
    pub date_format: Option<DateFormat>,
}

/// `display_prefs.date_format` (protocol v29): the ORDER of a date's
/// fields, never its language. `Auto` is a real choice meaning "follow the
/// viewer's locale", not the absence of one; Grappa rejects anything else
/// with a 422 instead of coercing it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DateFormat {
    #[default]
    Auto,
    Dmy,
    Mdy,
    Ymd,
}

impl DateFormat {
    /// Settings order, which is also the order Grappa's contract lists.
    pub const ALL: [DateFormat; 4] = [
        DateFormat::Auto,
        DateFormat::Dmy,
        DateFormat::Mdy,
        DateFormat::Ymd,
    ];

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "dmy" => Some(Self::Dmy),
            "mdy" => Some(Self::Mdy),
            "ymd" => Some(Self::Ymd),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Dmy => "dmy",
            Self::Mdy => "mdy",
            Self::Ymd => "ymd",
        }
    }
}

fn lenient_date_format<'de, D>(deserializer: D) -> Result<Option<DateFormat>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(value
        .as_ref()
        .and_then(Value::as_str)
        .and_then(DateFormat::parse))
}

/// One channel of `GET /networks/:slug/directory`, as captured from the
/// ircd's `LIST` reply.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub topic: Option<String>,
    pub user_count: i64,
    #[serde(default)]
    pub featured: bool,
}

/// Response body of `GET /networks/:slug/directory`: one keyset page of the
/// last completed `LIST` snapshot. `status` stays the raw wire token
/// (`fresh | stale | no_results | unknown | loading`) so an additive value
/// doesn't fail the whole page; `captured_at` is ISO-8601 or `null`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DirectoryPage {
    pub entries: Vec<DirectoryEntry>,
    pub next_cursor: Option<String>,
    pub total: u64,
    pub captured_at: Option<String>,
    pub status: String,
}

/// One archived window of `GET /networks/:slug/archive`: a channel or query
/// target that still has scrollback but is no longer joined or open.
/// `kind` is the wire string (`channel` or `query`); `last_activity` is the
/// newest message's `server_time` in epoch milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ArchiveEntry {
    pub target: String,
    pub kind: String,
    pub last_activity: i64,
}

/// Response body of `GET /networks/:slug/archive`, newest activity first.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ArchiveResponse {
    pub archive: Vec<ArchiveEntry>,
}

/// Response body of `POST /api/uploads` (201): the public URL carries the
/// file extension (`/uploads/<slug>.<ext>`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UploadResponse {
    pub slug: String,
    pub url: String,
    pub expires_at: String,
}

/// One theme of `GET /themes` or `GET /me/theme`. Only the fields Cordiale
/// uses are read; `payload.colors` is Grappa's closed 27-color map.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ThemeWire {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub built_in: bool,
    /// Whether the viewer owns it (and so may edit, delete or publish it).
    #[serde(default)]
    pub mine: bool,
    #[serde(default)]
    pub published: bool,
    pub payload: ThemePayloadWire,
}

/// The token payload of a theme.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ThemePayloadWire {
    pub colors: HashMap<String, String>,
    #[serde(default)]
    pub font_family: String,
    #[serde(default)]
    pub background: Option<ThemeBackgroundWire>,
}

/// A theme's wallpaper: an uploaded image (`image_id`, served at
/// `/uploads/<id>`) or a built-in one (`builtin`, served at
/// `/backgrounds/<key>.webp`), drawn full-bleed (`size: "cover"`) or tiled
/// (`"repeat"`) at `opacity` (0 to 1).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct ThemeBackgroundWire {
    #[serde(default)]
    pub image_id: Option<String>,
    #[serde(default)]
    pub builtin: Option<String>,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub opacity: Option<serde_json::Number>,
}

/// Response body of `GET /themes`: the public gallery.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ThemeIndex {
    pub themes: Vec<ThemeWire>,
}

/// Response body of `GET`/`PUT /me/theme`: the active day/night pair. A
/// `null` dark slot means the light theme applies in both modes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ActiveThemePair {
    pub light: Option<ThemeWire>,
    pub dark: Option<ThemeWire>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_wires_parse_and_ignore_unused_fields() {
        let json = r##"{"light": {"id": 3, "name": "sux", "author": "vjt", "built_in": true,
            "published": true, "apply_count": 9, "in_use": 2, "mine": false,
            "payload": {"colors": {"bg": "#000000"}, "font_family": "mono-default",
            "background": {"image_id": null}}, "inserted_at": "2026-09-23T10:00:00Z"},
            "dark": null}"##;
        let pair: ActiveThemePair = serde_json::from_str(json).expect("deserialize");
        let light = pair.light.expect("light");
        assert_eq!(light.id, 3);
        assert!(light.built_in);
        assert_eq!(
            light.payload.colors.get("bg").map(String::as_str),
            Some("#000000")
        );
        assert_eq!(pair.dark, None);
    }

    #[test]
    fn archive_response_parses_entries_in_order() {
        let json = r##"{"archive": [
            {"target": "#old", "kind": "channel", "last_activity": 1790000000000},
            {"target": "alice", "kind": "query", "last_activity": 1780000000000}
        ]}"##;

        let response: ArchiveResponse = serde_json::from_str(json).expect("deserialize");
        assert_eq!(response.archive.len(), 2);
        assert_eq!(response.archive[0].target, "#old");
        assert_eq!(response.archive[1].kind, "query");
    }

    #[test]
    fn directory_page_parses_rows_and_null_fields() {
        let json = r##"{
            "entries": [
                {"name": "#rust", "topic": null, "user_count": 42, "featured": true},
                {"name": "#cafe", "topic": "coffee", "user_count": 3, "featured": false}
            ],
            "next_cursor": null,
            "total": 2,
            "captured_at": "2026-09-23T10:00:00Z",
            "status": "fresh"
        }"##;

        let page: DirectoryPage = serde_json::from_str(json).expect("deserialize");
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].topic, None);
        assert!(page.entries[0].featured);
        assert_eq!(page.entries[1].topic.as_deref(), Some("coffee"));
        assert_eq!(page.next_cursor, None);
        assert_eq!(page.status, "fresh");
    }

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
    fn guest_login_request_sends_only_the_nickname() {
        let request = LoginRequest {
            identifier: "ada_guest".to_string(),
            password: String::new(),
        };

        let json = serde_json::to_string(&request).expect("serialize");
        assert_eq!(json, r#"{"identifier":"ada_guest"}"#);
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
        let json = r##"{
            "networks": [{"slug": "libera"}],
            "channels": {"libera": [{"name": "#rust"}]},
            "heads": {"libera": {"#rust": [{"kind": "privmsg"}]}}
        }"##;
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

    #[test]
    fn display_prefs_read_every_date_format_and_drop_an_unknown_one() {
        for format in DateFormat::ALL {
            let prefs: DisplayPrefs =
                serde_json::from_value(serde_json::json!({"date_format": format.as_str()}))
                    .expect("prefs");
            assert_eq!(prefs.date_format, Some(format));
        }
        let absent: DisplayPrefs = serde_json::from_str("{}").expect("absent");
        assert_eq!(absent.date_format, None);
        let unknown: DisplayPrefs = serde_json::from_value(serde_json::json!({
            "date_format": "dd-mm",
            "bold_mentions": false
        }))
        .expect("unknown value keeps the rest");
        assert_eq!(unknown.date_format, None);
        assert_eq!(unknown.bold_mentions, Some(false));
    }

    #[test]
    fn display_prefs_send_the_date_format_only_when_set() {
        let unset = serde_json::to_value(DisplayPrefs::default()).expect("serialize");
        assert_eq!(unset, serde_json::json!({}));
        let set = serde_json::to_value(DisplayPrefs {
            date_format: Some(DateFormat::Ymd),
            ..DisplayPrefs::default()
        })
        .expect("serialize");
        assert_eq!(set, serde_json::json!({"date_format": "ymd"}));
    }

    #[test]
    fn me_response_reads_home_data_rows_and_available_networks() {
        let me: MeResponse = serde_json::from_value(serde_json::json!({
            "kind": "visitor",
            "id": "v1",
            "registered": true,
            "home_data": {
                "networks": [{
                    "slug": "azzurra",
                    "nick": "guest",
                    "connection_state": "parked",
                    "connection_state_reason": "user requested",
                    "connection_state_changed_at": "2026-09-27T10:00:00Z",
                    "recoverable": true
                }],
                "available_networks": [{"slug": "libera"}]
            }
        }))
        .expect("deserialize");
        assert_eq!(me.registered, Some(true));
        let home = me.home_data.expect("home_data");
        assert_eq!(
            home.networks,
            vec![HomeNetworkRow {
                slug: "azzurra".into(),
                nick: "guest".into(),
                connection_state: "parked".into(),
                connection_state_reason: Some("user requested".into()),
                recoverable: true,
            }]
        );
        assert_eq!(
            home.available_networks,
            vec![AvailableNetworkRow {
                slug: "libera".into()
            }]
        );
    }

    #[test]
    fn me_response_without_home_data_has_none() {
        let me: MeResponse = serde_json::from_str(r#"{"kind":"user","name":"vjt"}"#).expect("me");
        assert_eq!(me.home_data, None);
        assert_eq!(me.registered, None);
    }

    #[test]
    fn send_message_request_plain_omits_relay_targets() {
        let request = SendMessageRequest::plain("hello there");
        let json = serde_json::to_string(&request).expect("serialize");
        assert_eq!(json, r#"{"body":"hello there"}"#);
    }

    #[test]
    fn send_message_request_includes_ctcp_target_when_set() {
        let request = SendMessageRequest {
            body: "\u{1}ACTION waves\u{1}".to_string(),
            ctcp_target: Some("vjt".to_string()),
            notice_target: None,
            statusmsg_target: None,
        };
        let json = serde_json::to_string(&request).expect("serialize");
        assert!(json.contains("\"ctcp_target\":\"vjt\""));
        assert!(!json.contains("notice_target"));
    }

    #[test]
    fn send_message_request_ctcp_frames_the_body_with_args() {
        let request = SendMessageRequest::ctcp("vjt", "PING", Some("123456"));
        assert_eq!(request.body, "\u{1}PING 123456\u{1}");
        assert_eq!(request.ctcp_target, Some("vjt".to_string()));
    }

    #[test]
    fn send_message_request_ctcp_frames_the_body_without_args() {
        let request = SendMessageRequest::ctcp("vjt", "VERSION", None);
        assert_eq!(request.body, "\u{1}VERSION\u{1}");
    }

    #[test]
    fn display_prefs_tolerates_a_fully_empty_body() {
        let prefs: DisplayPrefs = serde_json::from_str("{}").expect("deserialize");
        assert_eq!(prefs, DisplayPrefs::default());
    }

    #[test]
    fn display_prefs_omits_unset_fields_when_serialized() {
        let prefs = DisplayPrefs {
            colored_nicklist: Some(false),
            ..DisplayPrefs::default()
        };
        let json = serde_json::to_string(&prefs).expect("serialize");
        assert_eq!(json, r#"{"colored_nicklist":false}"#);
    }
}
