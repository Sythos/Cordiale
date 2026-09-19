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
//! this eventually runs on — see the networking architecture note in
//! `MEMORY.md`.

use reqwest::{Client, StatusCode};

use serde_json::Value;

use crate::admin::{
    AdminNetworksResponse, AdminOverview, AdminReaperRunResponse, AdminSessionLogResponse,
    AdminSessionsResponse, AdminUsersResponse, AdminVisitorsResponse,
};
use crate::rest::{
    BootResponse, ConfigResponse, DisplayPrefs, LoginRequest, LoginResponse, MeResponse,
    SendMessageRequest,
};

/// A Grappa server reached over REST, identified by its base URL.
pub struct GrappaClient {
    http: Client,
    base_url: String,
}

#[derive(Debug)]
pub enum GrappaClientError {
    Http(reqwest::Error),
    InvalidUrl(String),
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

impl GrappaClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        GrappaClient {
            http: Client::new(),
            base_url: base_url.into(),
        }
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
        Ok(response.json::<DisplayPrefs>().await?)
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
        self.http
            .put(url)
            .bearer_auth(token)
            .json(prefs)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
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
    async fn fetch_display_prefs_tolerates_a_partial_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/display-prefs"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"colored_nicklist": false})),
            )
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
    async fn update_display_prefs_sends_only_the_set_fields() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/display-prefs"))
            .and(header("authorization", "Bearer abc123"))
            .and(body_json(serde_json::json!({"bold_mentions": true})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
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
}
