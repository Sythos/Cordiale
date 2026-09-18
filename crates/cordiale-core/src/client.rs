//! Thin async REST client for the Grappa bootstrap and login endpoints.
//!
//! Plain `async fn`s only: no runtime, no threading model, no Slint
//! dependency here. `cordiale-ui` owns the tokio runtime and the thread
//! this eventually runs on — see the networking architecture note in
//! `MEMORY.md`.

use reqwest::{Client, StatusCode};

use crate::rest::{ConfigResponse, LoginRequest, LoginResponse};

/// A Grappa server reached over REST, identified by its base URL.
pub struct GrappaClient {
    http: Client,
    base_url: String,
}

#[derive(Debug)]
pub enum GrappaClientError {
    Http(reqwest::Error),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
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
}
