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

//! The REST bootstrap sequence: config → login → boot + me.
//!
//! Sequencing per `docs/protocol-notes.md` §7: check `protocol_version`
//! before doing anything else, then authenticate, then fetch `/boot` and
//! `/me`. The WebSocket join of the user topic (which echoes
//! `protocol_version` again) is a separate step, not done here — this
//! module only covers the REST leg.

use serde_json::Value;

use crate::client::{GrappaClient, GrappaClientError, LoginError};
use crate::protocol::ServerCompatibility;
use crate::rest::{BootResponse, LoginRequest, MeResponse};

#[derive(Debug)]
pub struct BootstrapOutcome {
    pub compatibility: ServerCompatibility,
    /// Bearer token to use for `/boot`, `/me` and the WebSocket handshake.
    pub token: String,
    /// Opaque `subject` from the login response — shape isn't documented,
    /// see `docs/protocol-notes.md` §5. Does **not** carry `is_admin`
    /// despite an earlier assumption here that it did (confirmed by
    /// reading Cicchetto's real `Subject`/`MeResponse` types) — that field
    /// lives on `me` instead.
    /// `None` when bootstrapping directly with a previously saved bearer,
    /// because that path deliberately skips `/auth/login`.
    pub subject: Option<Value>,
    pub boot: BootResponse,
    pub me: MeResponse,
}

#[derive(Debug)]
pub enum BootstrapError {
    /// The server's `protocol_version` is below what this build of
    /// Cordiale requires — see `ServerCompatibility::supported_by_cordiale`.
    IncompatibleServer(ServerCompatibility),
    Config(GrappaClientError),
    Login(LoginError),
    /// A saved bearer was rejected by an authenticated bootstrap endpoint.
    /// Callers must ask the user to authenticate again; never retry it as a
    /// password or silently switch identities.
    BearerRejected,
    Boot(GrappaClientError),
    Me(GrappaClientError),
}

async fn check_server_compatibility(
    client: &GrappaClient,
) -> Result<ServerCompatibility, BootstrapError> {
    let config = client
        .fetch_config()
        .await
        .map_err(BootstrapError::Config)?;
    let compatibility = ServerCompatibility {
        protocol_version: config.protocol_version,
        min_protocol_version: config.min_protocol_version,
    };
    if !compatibility.supported_by_cordiale() {
        return Err(BootstrapError::IncompatibleServer(compatibility));
    }
    Ok(compatibility)
}

/// Runs the full REST bootstrap sequence against `client`, or fails at the
/// first step that doesn't check out.
pub async fn bootstrap(
    client: &GrappaClient,
    login_request: &LoginRequest,
) -> Result<BootstrapOutcome, BootstrapError> {
    bootstrap_with_login_bearer(client, login_request, None).await
}

/// Bootstrap a returning anonymous visitor. The previous bearer is sent to
/// `/auth/login`, where Grappa verifies the nickname and rotates the token.
pub async fn bootstrap_with_login_bearer(
    client: &GrappaClient,
    login_request: &LoginRequest,
    previous_bearer: Option<&str>,
) -> Result<BootstrapOutcome, BootstrapError> {
    let compatibility = check_server_compatibility(client).await?;

    let login = client
        .login_with_bearer(login_request, previous_bearer)
        .await
        .map_err(BootstrapError::Login)?;

    // Fetched sequentially rather than in parallel for now: correctness
    // over the minor latency win, until there's a real/mocked server to
    // benchmark the parallel version against.
    let boot = client
        .fetch_boot(&login.token)
        .await
        .map_err(BootstrapError::Boot)?;
    let me = client
        .fetch_me(&login.token)
        .await
        .map_err(BootstrapError::Me)?;

    Ok(BootstrapOutcome {
        compatibility,
        token: login.token,
        subject: Some(login.subject),
        boot,
        me,
    })
}

/// Runs the authenticated cold-start sequence using a bearer already
/// returned by Grappa. The documented protocol permits presenting that
/// bearer directly to REST, so this path intentionally skips `/auth/login`
/// (and in particular never sends the bearer in the `password` field).
pub async fn bootstrap_with_bearer(
    client: &GrappaClient,
    bearer: &str,
) -> Result<BootstrapOutcome, BootstrapError> {
    let compatibility = check_server_compatibility(client).await?;

    let boot = client.fetch_boot(bearer).await.map_err(|err| {
        if err.status() == Some(reqwest::StatusCode::UNAUTHORIZED) {
            BootstrapError::BearerRejected
        } else {
            BootstrapError::Boot(err)
        }
    })?;
    let me = client.fetch_me(bearer).await.map_err(|err| {
        if err.status() == Some(reqwest::StatusCode::UNAUTHORIZED) {
            BootstrapError::BearerRejected
        } else {
            BootstrapError::Me(err)
        }
    })?;

    Ok(BootstrapOutcome {
        compatibility,
        token: bearer.to_string(),
        subject: None,
        boot,
        me,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_config(mock_server: &MockServer, protocol_version: u32) {
        Mock::given(method("GET"))
            .and(path("/api/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "server": "grappa",
                "version": "1.4.2-abc1234",
                "protocol_version": protocol_version,
                "min_protocol_version": 1
            })))
            .mount(mock_server)
            .await;
    }

    #[tokio::test]
    async fn bootstrap_runs_the_full_sequence_on_a_compatible_server() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "abc123",
                "subject": {"nick": "vjt"}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/boot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "networks": []
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "badge_count": 0
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "vjt".to_string(),
            password: "s3cr3t".to_string(),
        };
        let outcome = bootstrap(&client, &request).await.expect("bootstrap");

        assert_eq!(outcome.token, "abc123");
        assert_eq!(outcome.subject, Some(serde_json::json!({"nick": "vjt"})));
        assert!(outcome.boot.networks.is_empty());
    }

    #[tokio::test]
    async fn bootstrap_with_bearer_skips_login_and_uses_authorization_header() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/boot"))
            .and(header("authorization", "Bearer saved-bearer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "networks": []
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .and(header("authorization", "Bearer saved-bearer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "badge_count": 0
            })))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let outcome = bootstrap_with_bearer(&client, "saved-bearer")
            .await
            .expect("bootstrap with saved bearer");

        assert_eq!(outcome.token, "saved-bearer");
        assert_eq!(outcome.subject, None);
        assert!(outcome.boot.networks.is_empty());
    }

    #[tokio::test]
    async fn returning_guest_bootstrap_uses_the_rotated_bearer_for_rest() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .and(header("authorization", "Bearer previous-bearer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "rotated-bearer",
                "subject": {"kind": "visitor"}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        for endpoint in ["/boot", "/me"] {
            let body = if endpoint == "/boot" {
                serde_json::json!({"networks": []})
            } else {
                serde_json::json!({"badge_count": 0})
            };
            Mock::given(method("GET"))
                .and(path(endpoint))
                .and(header("authorization", "Bearer rotated-bearer"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&mock_server)
                .await;
        }

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "guest_nick".to_string(),
            password: String::new(),
        };
        let outcome = bootstrap_with_login_bearer(&client, &request, Some("previous-bearer"))
            .await
            .expect("returning guest bootstrap");
        assert_eq!(outcome.token, "rotated-bearer");
    }

    #[tokio::test]
    async fn bootstrap_with_bearer_reports_unauthorized_without_password_retry() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/boot"))
            .and(header("authorization", "Bearer revoked-bearer"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let error = bootstrap_with_bearer(&client, "revoked-bearer")
            .await
            .expect_err("revoked bearer must be rejected");

        assert!(matches!(error, BootstrapError::BearerRejected));
    }

    #[tokio::test]
    async fn bootstrap_rejects_a_server_below_the_minimum_protocol_version() {
        let mock_server = MockServer::start().await;
        mock_config(&mock_server, 0).await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "vjt".to_string(),
            password: "s3cr3t".to_string(),
        };
        let error = bootstrap(&client, &request).await.expect_err("should fail");

        assert!(matches!(error, BootstrapError::IncompatibleServer(_)));
    }

    #[tokio::test]
    async fn bootstrap_stops_at_login_on_invalid_credentials() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
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
        let error = bootstrap(&client, &request).await.expect_err("should fail");

        assert!(matches!(
            error,
            BootstrapError::Login(LoginError::InvalidCredentials)
        ));
    }
}
