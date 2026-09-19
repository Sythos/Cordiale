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

/// Response body of `GET /networks/:slug/ignores`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct IgnoresResponse {
    pub masks: Vec<String>,
}

/// Response body of `POST /networks/:slug/ignores` and
/// `DELETE /networks/:slug/ignores/:mask`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct IgnoreMutationResponse {
    pub masks: Vec<String>,
    pub mask: String,
    pub outcome: String,
}

/// Request body of `POST /networks/:slug/ignores`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddIgnoreRequest {
    pub mask: String,
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
