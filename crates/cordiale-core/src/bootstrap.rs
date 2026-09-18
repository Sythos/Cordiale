//! The REST bootstrap sequence: config → login → boot + me.
//!
//! Sequencing per `docs/protocol-notes.md` §7: check `protocol_version`
//! before doing anything else, then authenticate, then fetch `/boot` and
//! `/me`. The WebSocket join of the user topic (which echoes
//! `protocol_version` again) is a separate step, not done here — this
//! module only covers the REST leg.

use crate::client::{GrappaClient, GrappaClientError, LoginError};
use crate::protocol::ServerCompatibility;
use crate::rest::{BootResponse, LoginRequest, MeResponse};

pub struct BootstrapOutcome {
    pub compatibility: ServerCompatibility,
    /// Bearer token to use for `/boot`, `/me` and the WebSocket handshake.
    pub token: String,
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
    Boot(GrappaClientError),
    Me(GrappaClientError),
}

/// Runs the full REST bootstrap sequence against `client`, or fails at the
/// first step that doesn't check out.
pub async fn bootstrap(
    client: &GrappaClient,
    login_request: &LoginRequest,
) -> Result<BootstrapOutcome, BootstrapError> {
    let config = client.fetch_config().await.map_err(BootstrapError::Config)?;
    let compatibility = ServerCompatibility {
        protocol_version: config.protocol_version,
        min_protocol_version: config.min_protocol_version,
    };
    if !compatibility.supported_by_cordiale() {
        return Err(BootstrapError::IncompatibleServer(compatibility));
    }

    let login = client
        .login(login_request)
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
        boot,
        me,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
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
        mock_config(&mock_server, crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION).await;
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
        assert!(outcome.boot.networks.is_empty());
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
        mock_config(&mock_server, crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION).await;
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
