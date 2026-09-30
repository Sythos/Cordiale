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

//! Typed payloads for Grappa's self-service (non-admin) settings surface:
//! a user's own per-network identity, vhost selection, ignores, aliases,
//! perform list and notify (presence) watchlist.
//!
//! None of this is documented in `CLIENT_PROTOCOL.md` or covered by
//! `cordiale_core::admin` (which is the `/admin/*`, operator-only
//! surface). Every shape here was confirmed by reading Cicchetto's own
//! `SettingsDrawer.tsx`/`lib/*.ts` call sites and the matching Elixir
//! router/controllers directly — see `docs/protocol-notes.md` §4quater.
//! Grappa is a standalone, single-tenant deployment: there is no
//! server-wide settings-write or user-provisioning surface for a normal
//! client to expose (confirmed by the project owner), which is why this
//! module is scoped to "edit my own profile", not admin-style management
//! of other accounts.
//!
//! `sasl_user`/`auth_command_template`/`autojoin_channels` are
//! deliberately **not** exposed here: Cicchetto's own self-service
//! identity endpoint only accepts `{nick, ident, realname}` — those three
//! fields live only in the admin credential surface, confirmed by reading
//! the real request-body whitelist server-side, not assumed.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request body of `PATCH /networks/:slug/identity`. Every field is
/// optional; omitting one leaves it unchanged, `Some("")` clears it back
/// to the network's default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NetworkIdentityRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nick: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ident: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realname: Option<String>,
}

/// Byte cap Grappa puts on each free-text profile field.
pub const PROFILE_FIELD_MAX_BYTES: usize = 100;

/// The values Grappa accepts for `gender` (besides `""`, which clears it),
/// in the order the editor lists them.
pub const PROFILE_GENDERS: [&str; 3] = ["male", "female", "nonbinary"];

/// Request body of `PATCH /networks/:slug/profile`. Every field is
/// optional; omitting one leaves it unchanged, `Some("")` clears it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NetworkProfileRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub languages: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<String>,
}

impl NetworkProfileRequest {
    /// True when nothing would change, so there is nothing to send.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The CTCP USERINFO fields of one credential, as the editor holds them
/// (`""` for unset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileFields {
    pub age: String,
    pub gender: String,
    pub location: String,
    pub languages: String,
    pub custom: String,
}

impl ProfileFields {
    /// Reads the fields off a credential JSON object (a `GET /networks`
    /// row, or the response of the profile and avatar calls). Missing or
    /// null ones are unset.
    pub fn from_credential(row: &Value) -> Self {
        let text = |key: &str| {
            row.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Self {
            age: text("age"),
            gender: text("gender"),
            location: text("location"),
            languages: text("languages"),
            custom: text("custom"),
        }
    }

    /// Whether Grappa would accept these values: a known gender (or none)
    /// and free-text fields that are single-line and within the byte cap.
    pub fn is_valid(&self) -> bool {
        let gender_ok = self.gender.is_empty() || PROFILE_GENDERS.contains(&self.gender.as_str());
        let text_ok = [&self.age, &self.location, &self.languages, &self.custom]
            .into_iter()
            .all(|value| {
                value.len() <= PROFILE_FIELD_MAX_BYTES && !value.contains(['\r', '\n', '\0'])
            });
        gender_ok && text_ok
    }

    /// The request that turns `self` (what the server has) into `edited`:
    /// only the fields that differ, a cleared one as `Some("")`.
    pub fn changes_to(&self, edited: &Self) -> NetworkProfileRequest {
        let changed = |old: &str, new: &str| (old != new).then(|| new.to_string());
        NetworkProfileRequest {
            age: changed(&self.age, &edited.age),
            gender: changed(&self.gender, &edited.gender),
            location: changed(&self.location, &edited.location),
            languages: changed(&self.languages, &edited.languages),
            custom: changed(&self.custom, &edited.custom),
        }
    }

    /// Position of `gender` in the editor's list: 0 is "unset", then
    /// `PROFILE_GENDERS` in order.
    pub fn gender_index(&self) -> usize {
        PROFILE_GENDERS
            .iter()
            .position(|gender| *gender == self.gender)
            .map_or(0, |index| index + 1)
    }
}

/// The wire value for an editor list position (see
/// `ProfileFields::gender_index`); out of range means unset.
pub fn gender_for_index(index: usize) -> &'static str {
    index
        .checked_sub(1)
        .and_then(|index| PROFILE_GENDERS.get(index))
        .copied()
        .unwrap_or("")
}

/// True when a credential JSON object carries an avatar.
pub fn has_avatar(row: &Value) -> bool {
    row.get("avatar_url")
        .and_then(Value::as_str)
        .is_some_and(|url| !url.is_empty())
}

/// One vhost a user could select, from `GET /me/settings/vhost`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct VhostOption {
    pub address: String,
    pub in_pool: bool,
    pub granted: bool,
    #[serde(default)]
    pub name: Option<String>,
}

/// Response body of `GET`/`PUT /me/settings/vhost`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct VhostSettingsView {
    pub available: Vec<VhostOption>,
    pub selection: Vec<String>,
}

/// Request body of `PUT /me/settings/vhost`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VhostSelectionRequest {
    pub selection: Vec<String>,
}

/// One ignore rule (protocol v31). Its identity is the PAIR: two rules may
/// share a mask with different text patterns (a relay bot's authors), so
/// nothing may key on the mask alone. `text_pattern` is an anchored,
/// ASCII-case-insensitive glob over the message text that Grappa applies;
/// `None` is the plain mask rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IgnoreEntry {
    pub mask: String,
    #[serde(default)]
    pub text_pattern: Option<String>,
}

/// Mask-only entries, from a server older than `entries`.
fn entries_from_masks(masks: Vec<String>) -> Vec<IgnoreEntry> {
    masks
        .into_iter()
        .map(|mask| IgnoreEntry {
            mask,
            text_pattern: None,
        })
        .collect()
}

/// Response body of `GET /networks/:slug/ignores`: `masks` always, and
/// `entries` from v31.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct IgnoresResponse {
    #[serde(default)]
    pub masks: Vec<String>,
    #[serde(default)]
    pub entries: Option<Vec<IgnoreEntry>>,
}

impl IgnoresResponse {
    /// `entries` when the server sends them, else the masks as plain rules.
    pub fn into_entries(self) -> Vec<IgnoreEntry> {
        match self.entries {
            Some(entries) => entries,
            None => entries_from_masks(self.masks),
        }
    }
}

/// Response body of `POST /networks/:slug/ignores` and
/// `DELETE /networks/:slug/ignores/:mask`: the resulting list plus the
/// normalised entry acted on.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct IgnoreMutationResponse {
    #[serde(default)]
    pub masks: Vec<String>,
    #[serde(default)]
    pub entries: Option<Vec<IgnoreEntry>>,
    pub mask: String,
    #[serde(default)]
    pub text_pattern: Option<String>,
    pub outcome: String,
}

impl IgnoreMutationResponse {
    /// The resulting list, as pairs (see `IgnoresResponse::into_entries`).
    pub fn entries(&self) -> Vec<IgnoreEntry> {
        match &self.entries {
            Some(entries) => entries.clone(),
            None => entries_from_masks(self.masks.clone()),
        }
    }
}

/// Request body of `POST /networks/:slug/ignores`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddIgnoreRequest {
    pub mask: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_pattern: Option<String>,
}

/// Response body of `GET /me/settings/aliases`, and the request body of
/// `PUT` (same shape — a full-map replace, not a diff/patch).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasesView {
    #[serde(default)]
    pub aliases: HashMap<String, String>,
}

/// Response body of `GET /networks/:slug/perform`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PerformView {
    #[serde(default)]
    pub perform_list: Option<String>,
    #[serde(default)]
    pub oper_pass_set: bool,
}

/// Request body of `PUT /networks/:slug/perform`. `oper_pass` is
/// write-only: omit it to leave the stored one unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PerformUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perform_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oper_pass: Option<String>,
}

/// Request body of `POST /networks/:slug/notify` (presence watchlist).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotifyAddRequest {
    pub nicks: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_identity_request_omits_unset_fields() {
        let request = NetworkIdentityRequest {
            nick: Some("vjt".to_string()),
            ..NetworkIdentityRequest::default()
        };
        let json = serde_json::to_string(&request).expect("serialize");
        assert_eq!(json, r#"{"nick":"vjt"}"#);
    }

    #[test]
    fn profile_request_omits_unset_fields_and_keeps_clears() {
        let request = NetworkProfileRequest {
            age: Some(String::new()),
            location: Some("Rome".to_string()),
            ..NetworkProfileRequest::default()
        };
        let json = serde_json::to_string(&request).expect("serialize");
        assert_eq!(json, r#"{"age":"","location":"Rome"}"#);
        assert!(NetworkProfileRequest::default().is_empty());
        assert!(!request.is_empty());
    }

    #[test]
    fn profile_fields_read_a_credential_row() {
        let row = serde_json::json!({
            "age": "42",
            "gender": "nonbinary",
            "location": null,
            "custom": "hi",
            "avatar_url": "https://irc.example/uploads/abc.png"
        });
        let fields = ProfileFields::from_credential(&row);
        assert_eq!(fields.age, "42");
        assert_eq!(fields.gender, "nonbinary");
        assert_eq!(fields.location, "");
        assert_eq!(fields.languages, "");
        assert_eq!(fields.custom, "hi");
        assert!(has_avatar(&row));
        assert!(!has_avatar(&serde_json::json!({"avatar_url": null})));
        assert!(!has_avatar(&serde_json::json!({})));
    }

    #[test]
    fn profile_changes_only_carry_what_differs() {
        let server = ProfileFields {
            age: "42".to_string(),
            location: "Rome".to_string(),
            ..ProfileFields::default()
        };
        let edited = ProfileFields {
            age: String::new(),
            gender: "female".to_string(),
            location: "Rome".to_string(),
            ..ProfileFields::default()
        };
        let request = server.changes_to(&edited);
        assert_eq!(request.age.as_deref(), Some(""));
        assert_eq!(request.gender.as_deref(), Some("female"));
        assert_eq!(request.location, None);
        assert_eq!(request.languages, None);
        assert!(server.changes_to(&server).is_empty());
    }

    #[test]
    fn profile_validation_follows_the_server_limits() {
        assert!(ProfileFields::default().is_valid());
        let at_cap = ProfileFields {
            custom: "x".repeat(PROFILE_FIELD_MAX_BYTES),
            ..ProfileFields::default()
        };
        assert!(at_cap.is_valid());
        let too_long = ProfileFields {
            custom: "x".repeat(PROFILE_FIELD_MAX_BYTES + 1),
            ..ProfileFields::default()
        };
        assert!(!too_long.is_valid());
        // The cap counts bytes, not characters.
        let wide = ProfileFields {
            location: "è".repeat(PROFILE_FIELD_MAX_BYTES / 2 + 1),
            ..ProfileFields::default()
        };
        assert!(!wide.is_valid());
        let multiline = ProfileFields {
            languages: "it\nen".to_string(),
            ..ProfileFields::default()
        };
        assert!(!multiline.is_valid());
        let bad_gender = ProfileFields {
            gender: "other".to_string(),
            ..ProfileFields::default()
        };
        assert!(!bad_gender.is_valid());
    }

    #[test]
    fn gender_positions_round_trip() {
        for gender in ["", "male", "female", "nonbinary"] {
            let fields = ProfileFields {
                gender: gender.to_string(),
                ..ProfileFields::default()
            };
            assert_eq!(gender_for_index(fields.gender_index()), gender);
        }
        assert_eq!(gender_for_index(9), "");
    }

    #[test]
    fn vhost_settings_view_parses_the_documented_shape() {
        let json = r#"{
            "available": [{"address": "1.2.3.4", "in_pool": true, "granted": true, "name": "eu-1"}],
            "selection": ["1.2.3.4"]
        }"#;
        let view: VhostSettingsView = serde_json::from_str(json).expect("deserialize");
        assert_eq!(view.available.len(), 1);
        assert_eq!(view.selection, vec!["1.2.3.4".to_string()]);
    }

    #[test]
    fn aliases_view_round_trips_the_wrapped_map() {
        let mut aliases = HashMap::new();
        aliases.insert("hi".to_string(), "PRIVMSG $1 :hello!".to_string());
        let view = AliasesView { aliases };
        let json = serde_json::to_string(&view).expect("serialize");
        let decoded: AliasesView = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, view);
    }

    #[test]
    fn perform_update_request_omits_oper_pass_when_unset() {
        let request = PerformUpdateRequest {
            perform_list: Some("MODE $me +i".to_string()),
            oper_pass: None,
        };
        let json = serde_json::to_string(&request).expect("serialize");
        assert_eq!(json, r#"{"perform_list":"MODE $me +i"}"#);
    }
}
