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

//! Thin async REST client for the Grappa bootstrap and login endpoints.
//!
//! Plain `async fn`s only: no runtime, no threading model, no Slint
//! dependency here. `cordiale-ui` owns the tokio runtime and the thread
//! this eventually runs on.

use std::time::Duration;

use reqwest::{Client, StatusCode};

use serde_json::Value;

use crate::admin::{
    AdminNetworksResponse, AdminOverview, AdminReaperRunResponse, AdminSessionLogResponse,
    AdminSessionsResponse, AdminUsersResponse, AdminVisitorsResponse,
};
use crate::profile::{
    AddIgnoreRequest, AliasesView, IgnoreMutationResponse, IgnoresResponse, NetworkIdentityRequest,
    NotifyAddRequest, PerformUpdateRequest, PerformView, VhostSelectionRequest, VhostSettingsView,
};
use crate::rest::{
    ActiveThemePair, ArchiveEntry, ArchiveResponse, BootResponse, ConfigResponse, DirectoryPage,
    DisplayPrefs, LoginRequest, LoginResponse, MeResponse, SendMessageRequest, ThemeIndex,
    ThemeWire, UploadResponse,
};

/// A Grappa server reached over REST, identified by its base URL.
#[derive(Clone)]
pub struct GrappaClient {
    http: Client,
    base_url: String,
}

#[derive(Debug)]
pub enum GrappaClientError {
    Http(reqwest::Error),
    InvalidUrl(String),
}

impl GrappaClientError {
    /// HTTP status when the server returned a non-success response.
    ///
    /// Callers use this only when the protocol assigns meaning to a
    /// specific status (for example, 401 means a presented bearer was
    /// rejected). Transport and URL errors have no status.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            GrappaClientError::Http(err) => err.status(),
            GrappaClientError::InvalidUrl(_) => None,
        }
    }
}

impl From<reqwest::Error> for GrappaClientError {
    fn from(err: reqwest::Error) -> Self {
        GrappaClientError::Http(err)
    }
}

/// Outcome of `POST /auth/login`, per `docs/protocol-notes.md` §1.
#[derive(Debug)]
pub enum LoginError {
    /// `202 two_factor_required`: needs a browser, Cordiale can't resolve
    /// TOTP/passkey itself.
    TwoFactorRequired,
    /// `401 invalid_credentials`: also returned for a wrong per-client
    /// token — indistinguishable from a wrong password on the wire.
    InvalidCredentials,
    /// `429 too_many_attempts`: throttled, don't retry immediately.
    TooManyAttempts,
    Http(reqwest::Error),
    UnexpectedStatus(StatusCode),
}

impl From<reqwest::Error> for LoginError {
    fn from(err: reqwest::Error) -> Self {
        LoginError::Http(err)
    }
}

/// Longest time to establish a connection to the server.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest time for a whole request, so a server that stops answering
/// can't stall the app's single worker indefinitely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest time for a file upload (up to the server's 50 MiB video cap).
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);

impl GrappaClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        // Building only fails if the TLS backend can't initialise; the
        // default client then fails its first request the same way.
        let http = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .unwrap_or_else(|_| Client::new());
        GrappaClient {
            http,
            base_url: base_url.into(),
        }
    }

    /// The normalized server URL this client was built with — the same key
    /// the remembered-profile store uses.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// `GET /api/config` — the first, unauthenticated call to a server.
    pub async fn fetch_config(&self) -> Result<ConfigResponse, GrappaClientError> {
        let url = format!("{}/api/config", self.base_url);
        let response = self.http.get(url).send().await?.error_for_status()?;
        Ok(response.json::<ConfigResponse>().await?)
    }

    /// `POST /auth/login` — `request.password` may hold either a real
    /// password or a per-client token (see `crate::domain::AuthMethod`).
    pub async fn login(&self, request: &LoginRequest) -> Result<LoginResponse, LoginError> {
        let url = format!("{}/auth/login", self.base_url);
        let response = self.http.post(url).json(request).send().await?;

        match response.status() {
            StatusCode::OK => Ok(response.json::<LoginResponse>().await?),
            StatusCode::ACCEPTED => Err(LoginError::TwoFactorRequired),
            StatusCode::UNAUTHORIZED => Err(LoginError::InvalidCredentials),
            StatusCode::TOO_MANY_REQUESTS => Err(LoginError::TooManyAttempts),
            other => Err(LoginError::UnexpectedStatus(other)),
        }
    }

    /// `GET /boot` — authenticated cold-start aggregate. Call `GET /me` in
    /// parallel, per `docs/protocol-notes.md` §7.
    pub async fn fetch_boot(&self, token: &str) -> Result<BootResponse, GrappaClientError> {
        let url = format!("{}/boot", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<BootResponse>().await?)
    }

    /// `GET /me` — authenticated bulk read-cursors/unread-counts/badge.
    pub async fn fetch_me(&self, token: &str) -> Result<MeResponse, GrappaClientError> {
        let url = format!("{}/me", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<MeResponse>().await?)
    }

    /// `GET /networks` — refreshes server-authoritative home-network rows
    /// after `connection_state_changed`. A link transition does not change
    /// the attachment set or channel projection, so this is distinct from
    /// refreshing `/boot` and `/me`.
    pub async fn fetch_networks(&self, token: &str) -> Result<Vec<Value>, GrappaClientError> {
        let url = format!("{}/networks", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<Vec<Value>>().await?)
    }

    /// `GET /networks/:network_slug/channels` — returns the authoritative
    /// channel envelopes for one network. Entries stay opaque until their
    /// complete server schema is published.
    pub async fn fetch_channels(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<Vec<Value>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "channels"]);

        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<Vec<Value>>().await?)
    }

    /// `POST /networks/:network_id/channels/:channel_id/messages` — sends a
    /// message, echoed back as opaque JSON (row shape not fully documented,
    /// see `docs/protocol-notes.md` §4).
    ///
    /// `network_id` and `channel_id` are percent-encoded as URL path
    /// segments (via `Url::path_segments_mut`), not string-interpolated:
    /// channel names routinely contain `#`, which is a URL fragment
    /// delimiter if left raw.
    pub async fn send_message(
        &self,
        token: &str,
        network_id: &str,
        channel_id: &str,
        request: &SendMessageRequest,
    ) -> Result<Value, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_id, "channels", channel_id, "messages"]);

        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(request)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<Value>().await?)
    }

    /// `GET /networks/:network_slug/channels/:channel_name/messages` —
    /// returns a page of message rows as opaque JSON values. With no cursor,
    /// Grappa returns the latest page (used when opening a query/channel for
    /// the first time). With `after_id`, Grappa returns rows after that
    /// message ID in ascending order; callers commonly set `limit` to 200
    /// after a Phoenix join/rejoin ACK.
    pub async fn fetch_messages(
        &self,
        token: &str,
        network_slug: &str,
        channel_name: &str,
        after_id: Option<i64>,
        limit: Option<usize>,
    ) -> Result<Vec<Value>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend([
                "networks",
                network_slug,
                "channels",
                channel_name,
                "messages",
            ]);

        if after_id.is_some() || limit.is_some() {
            let mut query = url.query_pairs_mut();
            if let Some(after_id) = after_id {
                query.append_pair("after", &after_id.to_string());
            }
            if let Some(limit) = limit {
                query.append_pair("limit", &limit.to_string());
            }
        }

        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<Vec<Value>>().await?)
    }

    /// `GET /networks/:slug/channels/:channel/messages?before=<id>&limit=`
    /// — the page of history just older than message `before_id`, newest
    /// first (Grappa caps `limit` at 200). An empty page means the start of
    /// the history was reached.
    pub async fn fetch_messages_before(
        &self,
        token: &str,
        network_slug: &str,
        channel_name: &str,
        before_id: i64,
        limit: usize,
    ) -> Result<Vec<Value>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend([
                "networks",
                network_slug,
                "channels",
                channel_name,
                "messages",
            ]);
        url.query_pairs_mut()
            .append_pair("before", &before_id.to_string())
            .append_pair("limit", &limit.to_string());
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<Vec<Value>>().await?)
    }

    /// `DELETE /networks/:network_slug/channels/:channel` — parts from an
    /// IRC channel and removes the joined/pseudo window on the server. A
    /// non-empty optional reason is sent as a query parameter, never a DELETE
    /// body; channel names are encoded as URL path segments because they
    /// commonly start with `#`.
    pub async fn part_channel(
        &self,
        token: &str,
        network_slug: &str,
        channel: &str,
        reason: Option<&str>,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "channels", channel]);
        if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
            url.query_pairs_mut().append_pair("reason", reason);
        }

        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /me/settings/display-prefs` — absent-tolerant, per
    /// `docs/protocol-notes.md` §1.
    pub async fn fetch_display_prefs(
        &self,
        token: &str,
    ) -> Result<DisplayPrefs, GrappaClientError> {
        let url = format!("{}/me/settings/display-prefs", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        // Grappa wraps the prefs: `{"display_prefs": {...}, "persisted": bool}`.
        let body = response.json::<Value>().await?;
        let prefs = body.get("display_prefs").cloned().unwrap_or(body);
        Ok(serde_json::from_value(prefs).unwrap_or_default())
    }

    /// `PUT /me/settings/display-prefs` — only the fields set on `prefs` are
    /// sent, so this can update a single preference without clobbering the
    /// others.
    pub async fn update_display_prefs(
        &self,
        token: &str,
        prefs: &DisplayPrefs,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/me/settings/display-prefs", self.base_url);
        // The PUT replaces the whole stored map (wrapped under
        // `display_prefs`), so the keys Cordiale doesn't edit (time format,
        // presence filter, ...) are read back first and sent unchanged.
        let current = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        let mut merged = match current.get("display_prefs") {
            Some(Value::Object(map)) => map.clone(),
            _ => serde_json::Map::new(),
        };
        if let Ok(Value::Object(changes)) = serde_json::to_value(prefs) {
            merged.extend(changes);
        }
        self.http
            .put(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "display_prefs": merged }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /me/settings/<key>` for a single-value setting; the response is
    /// `{"<field>": value}`.
    async fn fetch_setting(
        &self,
        token: &str,
        key: &str,
        field: &str,
    ) -> Result<Value, GrappaClientError> {
        let url = format!("{}/me/settings/{key}", self.base_url);
        let body = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        Ok(body.get(field).cloned().unwrap_or(Value::Null))
    }

    /// `PUT /me/settings/<key>` with `{"<field>": value}`.
    async fn put_setting(
        &self,
        token: &str,
        key: &str,
        field: &str,
        value: Value,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/me/settings/{key}", self.base_url);
        let mut body = serde_json::Map::new();
        body.insert(field.to_string(), value);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// The remembered QUIT/PART message (`None`: the server's own).
    pub async fn fetch_quit_part_reason(
        &self,
        token: &str,
    ) -> Result<Option<String>, GrappaClientError> {
        let value = self
            .fetch_setting(token, "quit-part-reason", "quit_part_reason")
            .await?;
        Ok(value.as_str().map(str::to_string))
    }

    /// Stores the QUIT/PART message; `None` clears it.
    pub async fn set_quit_part_reason(
        &self,
        token: &str,
        reason: Option<&str>,
    ) -> Result<(), GrappaClientError> {
        self.put_setting(token, "quit-part-reason", "quit_part_reason", reason.into())
            .await
    }

    /// The text sent when the bouncer marks the user away (`None`: the
    /// server's own).
    pub async fn fetch_auto_away_reason(
        &self,
        token: &str,
    ) -> Result<Option<String>, GrappaClientError> {
        let value = self
            .fetch_setting(token, "auto-away-reason", "auto_away_reason")
            .await?;
        Ok(value.as_str().map(str::to_string))
    }

    /// Stores the auto-away text; `None` clears it. Live sessions already
    /// away pick it up at once.
    pub async fn set_auto_away_reason(
        &self,
        token: &str,
        reason: Option<&str>,
    ) -> Result<(), GrappaClientError> {
        self.put_setting(token, "auto-away-reason", "auto_away_reason", reason.into())
            .await
    }

    /// The auto-away delay: `None` for the server default, `Some(0)` when
    /// auto-away is off, otherwise seconds.
    pub async fn fetch_auto_away_debounce(
        &self,
        token: &str,
    ) -> Result<Option<i64>, GrappaClientError> {
        let value = self
            .fetch_setting(
                token,
                "auto-away-debounce-seconds",
                "auto_away_debounce_seconds",
            )
            .await?;
        Ok(value.as_i64())
    }

    /// Stores the auto-away delay, with the same `None`/`0` meanings.
    pub async fn set_auto_away_debounce(
        &self,
        token: &str,
        seconds: Option<i64>,
    ) -> Result<(), GrappaClientError> {
        self.put_setting(
            token,
            "auto-away-debounce-seconds",
            "auto_away_debounce_seconds",
            seconds.into(),
        )
        .await
    }

    /// Whether Grappa looks up other users' CTCP USERINFO profiles.
    pub async fn fetch_show_peer_profiles(&self, token: &str) -> Result<bool, GrappaClientError> {
        let value = self
            .fetch_setting(token, "show-peer-profiles", "show_peer_profiles")
            .await?;
        Ok(value.as_bool().unwrap_or(false))
    }

    /// Stores the peer-profile opt-in; it applies from the next session.
    pub async fn set_show_peer_profiles(
        &self,
        token: &str,
        enabled: bool,
    ) -> Result<(), GrappaClientError> {
        self.put_setting(
            token,
            "show-peer-profiles",
            "show_peer_profiles",
            enabled.into(),
        )
        .await
    }

    /// `GET /networks/:slug/dcc-auto-accept` — whether DCC files from peers
    /// with an open private window are accepted without asking.
    pub async fn fetch_dcc_auto_accept(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<bool, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "dcc-auto-accept"]);
        let body = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        Ok(body
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    }

    /// `PUT /networks/:slug/dcc-auto-accept {enabled}`.
    pub async fn set_dcc_auto_accept(
        &self,
        token: &str,
        network_slug: &str,
        enabled: bool,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "dcc-auto-accept"]);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "enabled": enabled }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /admin/overview` — requires `is_admin` and a full web session
    /// (a per-client token gets `403`, see `docs/protocol-notes.md` §4ter).
    pub async fn fetch_admin_overview(
        &self,
        token: &str,
    ) -> Result<AdminOverview, GrappaClientError> {
        let url = format!("{}/admin/overview", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<AdminOverview>().await?)
    }

    /// `GET /admin/sessions`.
    pub async fn fetch_admin_sessions(&self, token: &str) -> Result<Vec<Value>, GrappaClientError> {
        let url = format!("{}/admin/sessions", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<AdminSessionsResponse>().await?.sessions)
    }

    /// `POST /admin/sessions/:id/disconnect` — `id` is the composite
    /// `"<kind>:<subject_id>:<network_id>"` key, see
    /// `crate::admin::admin_session_id`.
    pub async fn disconnect_admin_session(
        &self,
        token: &str,
        session_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "sessions", session_id, "disconnect"]);

        self.http
            .post(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /admin/users`.
    pub async fn fetch_admin_users(&self, token: &str) -> Result<Vec<Value>, GrappaClientError> {
        let url = format!("{}/admin/users", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<AdminUsersResponse>().await?.users)
    }

    /// `GET /admin/networks`.
    pub async fn fetch_admin_networks(&self, token: &str) -> Result<Vec<Value>, GrappaClientError> {
        let url = format!("{}/admin/networks", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<AdminNetworksResponse>().await?.networks)
    }

    /// `GET /admin/visitors`.
    pub async fn fetch_admin_visitors(&self, token: &str) -> Result<Vec<Value>, GrappaClientError> {
        let url = format!("{}/admin/visitors", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<AdminVisitorsResponse>().await?.visitors)
    }

    /// `DELETE /admin/visitors/:id`.
    pub async fn delete_admin_visitor(
        &self,
        token: &str,
        visitor_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "visitors", visitor_id]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /admin/session_log?limit=N`.
    pub async fn fetch_admin_session_log(
        &self,
        token: &str,
        limit: u32,
    ) -> Result<Vec<Value>, GrappaClientError> {
        let url = format!("{}/admin/session_log?limit={limit}", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response
            .json::<AdminSessionLogResponse>()
            .await?
            .session_log)
    }

    /// `POST /admin/reaper/run`.
    pub async fn run_admin_reaper(
        &self,
        token: &str,
    ) -> Result<AdminReaperRunResponse, GrappaClientError> {
        let url = format!("{}/admin/reaper/run", self.base_url);
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<AdminReaperRunResponse>().await?)
    }

    /// `POST /admin/circuit/:network_id/reset`.
    pub async fn reset_admin_circuit(
        &self,
        token: &str,
        network_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "circuit", network_id, "reset"]);
        self.http
            .post(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `PATCH /admin/users/:id` — whitelist is just `is_admin` server-side.
    pub async fn set_admin_user_is_admin(
        &self,
        token: &str,
        user_id: &str,
        is_admin: bool,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "users", user_id]);
        self.http
            .patch(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "is_admin": is_admin }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `DELETE /admin/users/:id`.
    pub async fn delete_admin_user(
        &self,
        token: &str,
        user_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "users", user_id]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `PATCH /networks/:slug/identity` — self-service, own profile only
    /// (scoped by the bearer token server-side, never an explicit user
    /// id). Only `nick`/`ident`/`realname`: SASL/autojoin stay admin-only,
    /// see `cordiale_core::profile`.
    pub async fn update_network_identity(
        &self,
        token: &str,
        network_slug: &str,
        request: &NetworkIdentityRequest,
    ) -> Result<Value, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "identity"]);
        let response = self
            .http
            .patch(url)
            .bearer_auth(token)
            .json(request)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<Value>().await?)
    }

    /// `GET /me/settings/vhost`.
    pub async fn fetch_vhost_settings(
        &self,
        token: &str,
    ) -> Result<VhostSettingsView, GrappaClientError> {
        let url = format!("{}/me/settings/vhost", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<VhostSettingsView>().await?)
    }

    /// `PUT /me/settings/vhost` — the user always self-selects from the
    /// granted set; there's no separate admin "pin" to fight with.
    pub async fn update_vhost_selection(
        &self,
        token: &str,
        selection: Vec<String>,
    ) -> Result<VhostSettingsView, GrappaClientError> {
        let url = format!("{}/me/settings/vhost", self.base_url);
        let response = self
            .http
            .put(url)
            .bearer_auth(token)
            .json(&VhostSelectionRequest { selection })
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<VhostSettingsView>().await?)
    }

    /// `GET /networks/:slug/ignores`.
    pub async fn fetch_ignores(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<Vec<String>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "ignores"]);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<IgnoresResponse>().await?.masks)
    }

    /// `POST /networks/:slug/ignores`.
    pub async fn add_ignore(
        &self,
        token: &str,
        network_slug: &str,
        mask: &str,
    ) -> Result<IgnoreMutationResponse, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "ignores"]);
        let request = AddIgnoreRequest {
            mask: mask.to_string(),
        };
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<IgnoreMutationResponse>().await?)
    }

    /// `DELETE /networks/:slug/ignores/:mask`.
    pub async fn remove_ignore(
        &self,
        token: &str,
        network_slug: &str,
        mask: &str,
    ) -> Result<IgnoreMutationResponse, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "ignores", mask]);
        let response = self
            .http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<IgnoreMutationResponse>().await?)
    }

    /// `GET /me/settings/aliases`.
    pub async fn fetch_aliases(
        &self,
        token: &str,
    ) -> Result<std::collections::HashMap<String, String>, GrappaClientError> {
        let url = format!("{}/me/settings/aliases", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<AliasesView>().await?.aliases)
    }

    /// `PUT /me/settings/aliases` — full-map replace, not a diff.
    pub async fn update_aliases(
        &self,
        token: &str,
        aliases: std::collections::HashMap<String, String>,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/me/settings/aliases", self.base_url);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(&AliasesView { aliases })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /networks/:slug/perform`.
    pub async fn fetch_perform(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<PerformView, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "perform"]);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<PerformView>().await?)
    }

    /// `PUT /networks/:slug/perform`.
    pub async fn update_perform(
        &self,
        token: &str,
        network_slug: &str,
        request: &PerformUpdateRequest,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "perform"]);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(request)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `POST /networks/:slug/notify` — adds nicks to the presence
    /// watchlist. There's no self-service `GET`: the current list arrives
    /// over the WS `notify_list` snapshot instead (Cicchetto has no REST
    /// read path either, by design — see `docs/protocol-notes.md` §4quater).
    pub async fn add_notify_nicks(
        &self,
        token: &str,
        network_slug: &str,
        nicks: Vec<String>,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "notify"]);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&NotifyAddRequest { nicks })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /networks/:slug/directory` — one page of the last completed
    /// `LIST` snapshot, sorted by `sort` (`users` or `name`), filtered by
    /// `query` when non-empty and continued from `cursor`. The server starts
    /// the first capture on its own when it has none yet.
    pub async fn fetch_directory(
        &self,
        token: &str,
        network_slug: &str,
        sort: &str,
        query: &str,
        cursor: Option<&str>,
    ) -> Result<DirectoryPage, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "directory"]);
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("sort", sort);
            if !query.is_empty() {
                pairs.append_pair("q", query);
            }
            if let Some(cursor) = cursor {
                pairs.append_pair("cursor", cursor);
            }
        }
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<DirectoryPage>().await?)
    }

    /// `POST /networks/:slug/directory/refresh` — asks for a fresh `LIST`
    /// capture. `202` both when it starts and when one is already running;
    /// progress then arrives as `directory_*` pushes.
    pub async fn refresh_directory(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "directory", "refresh"]);
        self.http
            .post(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `POST /networks/:slug/dcc_offers/:offer_id/accept` — consents to a
    /// held DCC offer. `202`: the transfer runs on the server and the offer
    /// leaves the held set through a `dcc_offer_resolved` push, never here.
    pub async fn accept_dcc_offer(
        &self,
        token: &str,
        network_slug: &str,
        offer_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "dcc_offers", offer_id, "accept"]);
        self.http
            .post(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `DELETE /networks/:slug/dcc_offers/:offer_id` — refuses a held DCC
    /// offer. Nothing is sent to the peer; the removal still arrives as a
    /// `dcc_offer_resolved` push.
    pub async fn refuse_dcc_offer(
        &self,
        token: &str,
        network_slug: &str,
        offer_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "dcc_offers", offer_id]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /networks/:slug/archive` — windows with scrollback that are no
    /// longer joined or open, newest first. Metered by the server: an empty
    /// bucket answers `429`.
    pub async fn fetch_archive(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<Vec<ArchiveEntry>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "archive"]);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<ArchiveResponse>().await?.archive)
    }

    /// `DELETE /networks/:slug/archive/:target` — drops the bouncer's
    /// scrollback for one archived target (`204`). The IRC channel itself
    /// is untouched; the change arrives as an `archive_purged` push.
    pub async fn delete_archive_target(
        &self,
        token: &str,
        network_slug: &str,
        target: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "archive", target]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /me/settings/notification-prefs` — the full push-notification
    /// map (the server fills in its defaults), as the object under
    /// `notification_prefs`.
    pub async fn fetch_notification_prefs(
        &self,
        token: &str,
    ) -> Result<serde_json::Map<String, Value>, GrappaClientError> {
        let url = format!("{}/me/settings/notification-prefs", self.base_url);
        let body = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        Ok(match body.get("notification_prefs") {
            Some(Value::Object(prefs)) => prefs.clone(),
            _ => serde_json::Map::new(),
        })
    }

    /// `PUT /me/settings/notification-prefs` — the full map, NOT wrapped.
    /// Every boolean must be present, and at least one message trigger
    /// must stay on, else 422.
    pub async fn set_notification_prefs(
        &self,
        token: &str,
        prefs: &serde_json::Map<String, Value>,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/me/settings/notification-prefs", self.base_url);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(prefs)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /themes` — the public theme gallery (published themes and
    /// Grappa's built-ins, which include irssi-derived color sets).
    pub async fn fetch_themes(&self, token: &str) -> Result<Vec<ThemeWire>, GrappaClientError> {
        let url = format!("{}/themes", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<ThemeIndex>().await?.themes)
    }

    /// `GET /me/theme` — the account's active theme pair.
    pub async fn fetch_active_theme(
        &self,
        token: &str,
    ) -> Result<ActiveThemePair, GrappaClientError> {
        let url = format!("{}/me/theme", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<ActiveThemePair>().await?)
    }

    /// `PUT /me/theme` with a single pick: `theme_id` becomes the light slot
    /// and the dark slot is cleared, so it applies in both modes.
    pub async fn set_active_theme(
        &self,
        token: &str,
        theme_id: i64,
    ) -> Result<ActiveThemePair, GrappaClientError> {
        let url = format!("{}/me/theme", self.base_url);
        let response = self
            .http
            .put(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "light": theme_id, "dark": null }))
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<ActiveThemePair>().await?)
    }

    /// `POST /api/uploads` — uploads one file (multipart field `file`),
    /// kept for `expire` seconds or the server's default lifetime. `mime`
    /// must be one of Grappa's allowlisted types (else 415); the per-file
    /// cap by category gives 413 and the storage quota 507. Large files get
    /// a longer timeout than the client default.
    pub async fn upload_file(
        &self,
        token: &str,
        filename: &str,
        mime: &str,
        bytes: Vec<u8>,
        expire: Option<i64>,
    ) -> Result<UploadResponse, GrappaClientError> {
        let url = format!("{}/api/uploads", self.base_url);
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename.to_string())
            .mime_str(mime)?;
        let mut form = reqwest::multipart::Form::new().part("file", part);
        if let Some(expire) = expire {
            form = form.text("expire", expire.to_string());
        }
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .timeout(UPLOAD_TIMEOUT)
            .multipart(form)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<UploadResponse>().await?)
    }

    /// `GET /me/settings/upload-ttl-seconds` — the lifetime given to new
    /// uploads, `None` for the server's default.
    pub async fn fetch_upload_ttl(&self, token: &str) -> Result<Option<i64>, GrappaClientError> {
        let url = format!("{}/me/settings/upload-ttl-seconds", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        let body = response.json::<Value>().await?;
        Ok(body.get("upload_ttl_seconds").and_then(Value::as_i64))
    }

    /// `PUT /me/settings/upload-ttl-seconds`; `None` restores the default.
    pub async fn set_upload_ttl(
        &self,
        token: &str,
        seconds: Option<i64>,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/me/settings/upload-ttl-seconds", self.base_url);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "upload_ttl_seconds": seconds }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /me/settings/upload-confirm-enabled` — whether to ask before
    /// each upload (off by default).
    pub async fn fetch_upload_confirm(&self, token: &str) -> Result<bool, GrappaClientError> {
        let url = format!("{}/me/settings/upload-confirm-enabled", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        let body = response.json::<Value>().await?;
        Ok(body
            .get("upload_confirm_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    }

    /// `PUT /me/settings/upload-confirm-enabled`.
    pub async fn set_upload_confirm(
        &self,
        token: &str,
        enabled: bool,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/me/settings/upload-confirm-enabled", self.base_url);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "upload_confirm_enabled": enabled }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `POST /networks/:slug/channels` — joins one channel, or a
    /// comma-separated list, with an optional key. Grappa answers 202 and
    /// the join itself arrives as channel events.
    pub async fn join_channel(
        &self,
        token: &str,
        network_slug: &str,
        name: &str,
        key: Option<&str>,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "channels"]);
        let mut body = serde_json::json!({ "name": name });
        if let Some(key) = key.filter(|key| !key.is_empty()) {
            body["key"] = Value::from(key);
        }
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `POST /networks/:slug/channels/:channel/topic` — sets the topic.
    pub async fn set_topic(
        &self,
        token: &str,
        network_slug: &str,
        channel: &str,
        topic: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "channels", channel, "topic"]);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "body": topic }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `POST /networks/:slug/nick` — asks the network for a new nick.
    pub async fn change_nick(
        &self,
        token: &str,
        network_slug: &str,
        nick: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "nick"]);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "nick": nick }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `PATCH /networks/:slug` with `connection_state` `"parked"` or
    /// `"connected"`; a reason goes with a park only.
    pub async fn set_connection_state(
        &self,
        token: &str,
        network_slug: &str,
        connection_state: &str,
        reason: Option<&str>,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug]);
        let mut body = serde_json::json!({ "connection_state": connection_state });
        if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
            body["reason"] = Value::from(reason);
        }
        self.http
            .patch(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `POST /networks/:slug/channels/:channel/read-cursor` — marks the
    /// window read up to `message_id` (a query window uses the peer's nick
    /// as `channel`). Grappa answers with the stored cursor and broadcasts
    /// `read_cursor_set` on the window's topic.
    pub async fn set_read_cursor(
        &self,
        token: &str,
        network_slug: &str,
        channel: &str,
        message_id: i64,
    ) -> Result<i64, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "channels", channel, "read-cursor"]);
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "message_id": message_id }))
            .send()
            .await?
            .error_for_status()?;
        let body = response.json::<Value>().await?;
        Ok(body
            .get("last_read_message_id")
            .and_then(Value::as_i64)
            .unwrap_or(message_id))
    }

    /// `DELETE /networks/:slug/notify/:nick`.
    pub async fn remove_notify_nick(
        &self,
        token: &str,
        network_slug: &str,
        nick: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "notify", nick]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn fetch_config_parses_a_successful_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "server": "grappa",
                "version": "1.4.2-abc1234",
                "protocol_version": 26,
                "min_protocol_version": 1
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let config = client.fetch_config().await.expect("fetch_config");

        assert_eq!(config.protocol_version, 26);
        assert_eq!(config.server, "grappa");
    }

    #[tokio::test]
    async fn login_returns_token_on_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "abc123",
                "subject": {"nick": "vjt"}
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "vjt".to_string(),
            password: "s3cr3t".to_string(),
        };
        let response = client.login(&request).await.expect("login");

        assert_eq!(response.token, "abc123");
    }

    #[tokio::test]
    async fn login_maps_401_to_invalid_credentials() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "vjt".to_string(),
            password: "wrong".to_string(),
        };
        let error = client.login(&request).await.expect_err("should fail");

        assert!(matches!(error, LoginError::InvalidCredentials));
    }

    #[tokio::test]
    async fn login_maps_202_to_two_factor_required() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "vjt".to_string(),
            password: "s3cr3t".to_string(),
        };
        let error = client.login(&request).await.expect_err("should fail");

        assert!(matches!(error, LoginError::TwoFactorRequired));
    }

    #[tokio::test]
    async fn login_maps_429_to_too_many_attempts() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "vjt".to_string(),
            password: "s3cr3t".to_string(),
        };
        let error = client.login(&request).await.expect_err("should fail");

        assert!(matches!(error, LoginError::TooManyAttempts));
    }

    #[tokio::test]
    async fn fetch_boot_sends_the_bearer_token_and_parses_the_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/boot"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "networks": [{"slug": "libera"}],
                "channels": {"libera": [{"name": "#rust"}]}
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let boot = client.fetch_boot("abc123").await.expect("fetch_boot");

        assert_eq!(boot.networks.len(), 1);
        assert_eq!(boot.channels.get("libera").map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn fetch_networks_sends_the_bearer_token_and_parses_network_rows() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "id": 7,
                    "slug": "libera",
                    "connection_state": "connected",
                    "connection_state_reason": null,
                    "connection_state_changed_at": null
                }
            ])))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let networks = client
            .fetch_networks("abc123")
            .await
            .expect("fetch_networks");

        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0]["slug"], "libera");
        assert_eq!(networks[0]["connection_state"], "connected");
    }

    #[tokio::test]
    async fn fetch_channels_uses_the_slug_path_and_bearer_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera%20chat/channels"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "#rust", "joined": true},
                {"name": "#cordiale", "joined": false}
            ])))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let channels = client
            .fetch_channels("abc123", "libera chat")
            .await
            .expect("fetch_channels");

        assert_eq!(channels.len(), 2);
        assert_eq!(channels[0]["name"], "#rust");
    }

    #[tokio::test]
    async fn fetch_me_sends_the_bearer_token_and_parses_the_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "badge_count": 3
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let me = client.fetch_me("abc123").await.expect("fetch_me");

        assert_eq!(me.badge_count, serde_json::json!(3));
    }

    #[tokio::test]
    async fn send_message_percent_encodes_a_channel_name_with_a_hash() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/channels/%23rust/messages"))
            .and(header("authorization", "Bearer abc123"))
            .and(body_json(serde_json::json!({"body": "hello there"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "privmsg"
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = crate::rest::SendMessageRequest::plain("hello there");
        let response = client
            .send_message("abc123", "libera", "#rust", &request)
            .await
            .expect("send_message");

        assert_eq!(
            response.get("kind").and_then(|k| k.as_str()),
            Some("privmsg")
        );
    }

    #[tokio::test]
    async fn fetch_messages_without_cursor_requests_the_latest_page() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/channels/%23rust/messages"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 812, "body": "latest"},
                {"id": 811, "body": "older"}
            ])))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let messages = client
            .fetch_messages("abc123", "libera", "#rust", None, None)
            .await
            .expect("fetch latest messages");

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["id"], 812);
    }

    #[tokio::test]
    async fn fetch_messages_after_cursor_sends_cursor_and_limit() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/channels/vjt/messages"))
            .and(query_param("after", "812"))
            .and(query_param("limit", "200"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 813, "body": "newer"}
            ])))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let messages = client
            .fetch_messages("abc123", "libera", "vjt", Some(812), Some(200))
            .await
            .expect("fetch messages after cursor");

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["id"], 813);
    }

    #[tokio::test]
    async fn part_channel_uses_encoded_path_and_omits_empty_reason() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/channels/%23rust"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .part_channel("abc123", "libera", "#rust", None)
            .await
            .expect("part_channel");
    }

    #[tokio::test]
    async fn part_channel_percent_encodes_optional_reason() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/channels/%23rust"))
            .and(query_param("reason", "away for now & later"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .part_channel("abc123", "libera", "#rust", Some("away for now & later"))
            .await
            .expect("part_channel with reason");
    }

    #[tokio::test]
    async fn fetch_display_prefs_tolerates_a_partial_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/display-prefs"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "display_prefs": {"colored_nicklist": false},
                "persisted": true
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let prefs = client
            .fetch_display_prefs("abc123")
            .await
            .expect("fetch_display_prefs");

        assert_eq!(prefs.colored_nicklist, Some(false));
        assert_eq!(prefs.bold_mentions, None);
    }

    #[tokio::test]
    async fn update_display_prefs_keeps_the_keys_it_does_not_edit() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/display-prefs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "display_prefs": {"time_format": "24h", "bold_mentions": false},
                "persisted": true
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/display-prefs"))
            .and(header("authorization", "Bearer abc123"))
            .and(body_json(serde_json::json!({
                "display_prefs": {"time_format": "24h", "bold_mentions": true}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let prefs = crate::rest::DisplayPrefs {
            bold_mentions: Some(true),
            ..crate::rest::DisplayPrefs::default()
        };
        client
            .update_display_prefs("abc123", &prefs)
            .await
            .expect("update_display_prefs");
    }

    #[tokio::test]
    async fn personal_settings_use_their_wire_keys() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/auto-away-debounce-seconds"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "auto_away_debounce_seconds": 0 })),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/quit-part-reason"))
            .and(body_json(serde_json::json!({ "quit_part_reason": null })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "quit_part_reason": null })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/networks/libera/dcc-auto-accept"))
            .and(body_json(serde_json::json!({ "enabled": true })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "enabled": true })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        assert_eq!(
            client
                .fetch_auto_away_debounce("t")
                .await
                .expect("debounce"),
            Some(0)
        );
        client
            .set_quit_part_reason("t", None)
            .await
            .expect("quit reason");
        client
            .set_dcc_auto_accept("t", "libera", true)
            .await
            .expect("dcc");
    }

    #[tokio::test]
    async fn fetch_admin_overview_parses_the_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/overview"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sessions": 3,
                "visitors": {"total": 2, "live": 1},
                "hostname": "grappa-01",
                "loadavg": 0.42,
                "version": "1.4.2-abc1234"
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let overview = client
            .fetch_admin_overview("abc123")
            .await
            .expect("fetch_admin_overview");

        assert_eq!(overview.sessions, 3);
        assert_eq!(overview.visitors.total, 2);
        assert_eq!(overview.hostname, "grappa-01");
    }

    #[tokio::test]
    async fn fetch_admin_sessions_unwraps_the_sessions_array() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/sessions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sessions": [{"subject_kind": "user", "subject_id": "vjt"}]
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let sessions = client
            .fetch_admin_sessions("abc123")
            .await
            .expect("fetch_admin_sessions");

        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn disconnect_admin_session_posts_to_the_composite_key_path() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/admin/sessions/user:vjt:1/disconnect"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .disconnect_admin_session("abc123", "user:vjt:1")
            .await
            .expect("disconnect_admin_session");
    }

    #[tokio::test]
    async fn run_admin_reaper_parses_the_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/admin/reaper/run"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "swept_count": 3,
                "swept_at": "2026-09-19T10:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let result = client
            .run_admin_reaper("abc123")
            .await
            .expect("run_admin_reaper");

        assert_eq!(result.swept_count, 3);
    }

    #[tokio::test]
    async fn set_admin_user_is_admin_sends_the_whitelisted_field() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/admin/users/42"))
            .and(body_json(serde_json::json!({"is_admin": true})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .set_admin_user_is_admin("abc123", "42", true)
            .await
            .expect("set_admin_user_is_admin");
    }

    #[tokio::test]
    async fn delete_admin_visitor_deletes_by_id() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/admin/visitors/abc"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .delete_admin_visitor("abc123", "abc")
            .await
            .expect("delete_admin_visitor");
    }

    #[tokio::test]
    async fn update_network_identity_sends_only_set_fields() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/networks/libera/identity"))
            .and(body_json(serde_json::json!({"nick": "vjt2"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = crate::profile::NetworkIdentityRequest {
            nick: Some("vjt2".to_string()),
            ..crate::profile::NetworkIdentityRequest::default()
        };
        client
            .update_network_identity("abc123", "libera", &request)
            .await
            .expect("update_network_identity");
    }

    #[tokio::test]
    async fn fetch_vhost_settings_parses_the_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/vhost"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "available": [
                    {"address": "1.2.3.4", "in_pool": true, "granted": true, "name": "eu-1"}
                ],
                "selection": []
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let view = client
            .fetch_vhost_settings("abc123")
            .await
            .expect("fetch_vhost_settings");
        assert_eq!(view.available.len(), 1);
    }

    #[tokio::test]
    async fn update_vhost_selection_sends_the_selection_list() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/vhost"))
            .and(body_json(serde_json::json!({"selection": ["1.2.3.4"]})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "available": [],
                "selection": ["1.2.3.4"]
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .update_vhost_selection("abc123", vec!["1.2.3.4".to_string()])
            .await
            .expect("update_vhost_selection");
    }

    #[tokio::test]
    async fn add_ignore_posts_the_mask() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/ignores"))
            .and(body_json(
                serde_json::json!({"mask": "*!*@spammer.example"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "masks": ["*!*@spammer.example"],
                "mask": "*!*@spammer.example",
                "outcome": "added"
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let response = client
            .add_ignore("abc123", "libera", "*!*@spammer.example")
            .await
            .expect("add_ignore");
        assert_eq!(response.outcome, "added");
    }

    #[tokio::test]
    async fn fetch_aliases_unwraps_the_map() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/aliases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "aliases": {"hi": "PRIVMSG $1 :hello!"}
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let aliases = client.fetch_aliases("abc123").await.expect("fetch_aliases");
        assert_eq!(aliases.get("hi"), Some(&"PRIVMSG $1 :hello!".to_string()));
    }

    #[tokio::test]
    async fn fetch_perform_parses_the_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/perform"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "perform_list": "MODE $me +i",
                "oper_pass_set": false
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let view = client
            .fetch_perform("abc123", "libera")
            .await
            .expect("fetch_perform");
        assert_eq!(view.perform_list, Some("MODE $me +i".to_string()));
    }

    #[tokio::test]
    async fn add_notify_nicks_posts_to_the_network_scoped_path() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/notify"))
            .and(body_json(serde_json::json!({"nicks": ["vjt"]})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .add_notify_nicks("abc123", "libera", vec!["vjt".to_string()])
            .await
            .expect("add_notify_nicks");
    }
    #[tokio::test]
    async fn fetch_directory_sends_sort_query_and_cursor() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/directory"))
            .and(query_param("sort", "name"))
            .and(query_param("q", "rust"))
            .and(query_param("cursor", "c2"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "entries": [{"name": "#rust", "topic": null, "user_count": 9, "featured": false}],
                "next_cursor": null,
                "total": 1,
                "captured_at": null,
                "status": "loading"
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let page = client
            .fetch_directory("abc123", "libera", "name", "rust", Some("c2"))
            .await
            .expect("fetch_directory");
        assert_eq!(page.entries[0].name, "#rust");
        assert_eq!(page.status, "loading");
    }

    #[tokio::test]
    async fn dcc_offer_answers_use_the_offer_path() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/dcc_offers/off-1/accept"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({"ok": true})))
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/dcc_offers/off-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/dcc_offers/gone"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .accept_dcc_offer("abc123", "libera", "off-1")
            .await
            .expect("accept_dcc_offer");
        client
            .refuse_dcc_offer("abc123", "libera", "off-2")
            .await
            .expect("refuse_dcc_offer");
        let err = client
            .refuse_dcc_offer("abc123", "libera", "gone")
            .await
            .expect_err("404");
        assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn archive_list_and_delete_encode_the_target() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/archive"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "archive": [{"target": "#old", "kind": "channel", "last_activity": 1790000000000_i64}]
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/archive/%23old"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let entries = client
            .fetch_archive("abc123", "libera")
            .await
            .expect("fetch_archive");
        assert_eq!(entries[0].target, "#old");
        client
            .delete_archive_target("abc123", "libera", "#old")
            .await
            .expect("delete_archive_target");
    }

    #[tokio::test]
    async fn notification_prefs_read_wrapped_and_write_bare() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/notification-prefs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "notification_prefs": {"channel_mentions": true, "muted_targets": {}}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/notification-prefs"))
            .and(body_json(
                serde_json::json!({"channel_mentions": false, "muted_targets": {}}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let mut prefs = client
            .fetch_notification_prefs("t")
            .await
            .expect("notification prefs");
        assert_eq!(prefs["channel_mentions"], serde_json::json!(true));
        prefs.insert("channel_mentions".to_string(), Value::Bool(false));
        client
            .set_notification_prefs("t", &prefs)
            .await
            .expect("save");
    }

    #[tokio::test]
    async fn theme_endpoints_use_the_documented_paths() {
        let mock_server = MockServer::start().await;
        let theme = serde_json::json!({
            "id": 7, "name": "irssi-dark", "author": "system", "built_in": true,
            "payload": {"colors": {}, "font_family": "mono-default"}
        });
        Mock::given(method("GET"))
            .and(path("/themes"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"themes": [theme]})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/theme"))
            .and(body_json(serde_json::json!({"light": 7, "dark": null})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"light": theme, "dark": null})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let themes = client.fetch_themes("abc123").await.expect("fetch_themes");
        assert_eq!(themes[0].name, "irssi-dark");
        let pair = client
            .set_active_theme("abc123", 7)
            .await
            .expect("set_active_theme");
        assert_eq!(pair.light.map(|theme| theme.id), Some(7));
    }

    #[tokio::test]
    async fn slash_command_endpoints_send_the_documented_bodies() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/channels"))
            .and(body_json(
                serde_json::json!({ "name": "#a,#b", "key": "k" }),
            ))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({"ok": true})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/channels/%23rust/topic"))
            .and(body_json(serde_json::json!({ "body": "new topic" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/nick"))
            .and(body_json(serde_json::json!({ "nick": "neo" })))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/networks/libera"))
            .and(body_json(
                serde_json::json!({ "connection_state": "parked", "reason": "bye" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .join_channel("t", "libera", "#a,#b", Some("k"))
            .await
            .expect("join");
        client
            .set_topic("t", "libera", "#rust", "new topic")
            .await
            .expect("topic");
        client
            .change_nick("t", "libera", "neo")
            .await
            .expect("nick");
        client
            .set_connection_state("t", "libera", "parked", Some("bye"))
            .await
            .expect("park");
    }

    #[tokio::test]
    async fn upload_prefs_round_trip() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/upload-ttl-seconds"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "upload_ttl_seconds": null })),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/upload-ttl-seconds"))
            .and(body_json(serde_json::json!({ "upload_ttl_seconds": 3600 })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "upload_ttl_seconds": 3600 })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/me/settings/upload-confirm-enabled"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "upload_confirm_enabled": true })),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/upload-confirm-enabled"))
            .and(body_json(
                serde_json::json!({ "upload_confirm_enabled": false }),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "upload_confirm_enabled": false })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        assert_eq!(client.fetch_upload_ttl("t").await.expect("ttl"), None);
        client
            .set_upload_ttl("t", Some(3600))
            .await
            .expect("set ttl");
        assert!(client.fetch_upload_confirm("t").await.expect("confirm"));
        client
            .set_upload_confirm("t", false)
            .await
            .expect("set confirm");
    }

    #[tokio::test]
    async fn set_read_cursor_posts_the_message_id() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/channels/%23rust/read-cursor"))
            .and(body_json(serde_json::json!({ "message_id": 42 })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "last_read_message_id": 42 })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let cursor = client
            .set_read_cursor("t", "libera", "#rust", 42)
            .await
            .expect("read cursor");
        assert_eq!(cursor, 42);
    }

    #[tokio::test]
    async fn upload_file_posts_multipart_to_api_uploads() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/uploads"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "slug": "abcd",
                "url": "https://irc.example/uploads/abcd.png",
                "expires_at": "2026-09-25T10:00:00Z"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/uploads"))
            .and(header("authorization", "Bearer toolarge"))
            .respond_with(ResponseTemplate::new(413))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let uploaded = client
            .upload_file("abc123", "cat.png", "image/png", vec![1, 2, 3], None)
            .await
            .expect("upload_file");
        assert_eq!(uploaded.url, "https://irc.example/uploads/abcd.png");
        let err = client
            .upload_file(
                "toolarge",
                "cat.png",
                "image/png",
                vec![1, 2, 3],
                Some(3600),
            )
            .await
            .expect_err("413");
        assert_eq!(err.status(), Some(StatusCode::PAYLOAD_TOO_LARGE));
    }

    #[tokio::test]
    async fn fetch_messages_before_sends_the_cursor() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/channels/%23rust/messages"))
            .and(query_param("before", "120"))
            .and(query_param("limit", "100"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{ "id": 119 }])),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let rows = client
            .fetch_messages_before("t", "libera", "#rust", 120, 100)
            .await
            .expect("older page");
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn refresh_directory_accepts_202() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/directory/refresh"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .refresh_directory("abc123", "libera")
            .await
            .expect("refresh_directory");
    }
}
