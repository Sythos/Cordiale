// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)
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

use std::future::Future;
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::Value;

use crate::client::{GrappaClient, GrappaClientError, LoginError};
use crate::persistence;
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
    /// `POST /auth/totp/verify` refused the code: see
    /// `GrappaClient::verify_totp_login` for the codes it carries.
    TwoFactor(GrappaClientError),
    /// `POST /auth/passkeys/recover` refused the recovery code: see
    /// `GrappaClient::recover_passkey_login` for the codes it carries.
    Recovery(GrappaClientError),
    /// `POST /auth/share/consume` refused the share token: see
    /// `GrappaClient::consume_share_token` for the codes it carries.
    ShareToken(GrappaClientError),
    /// A saved bearer was rejected by an authenticated bootstrap endpoint.
    /// Callers must ask the user to authenticate again; never retry it as a
    /// password or silently switch identities.
    BearerRejected,
    Boot(GrappaClientError),
    Me(GrappaClientError),
}

impl BootstrapError {
    /// Why a `/boot` or `/me` request failed, for the variants that carry
    /// that failure. Every other variant answers `None`.
    pub fn boot_failure_kind(&self) -> Option<FailureKind> {
        match self {
            BootstrapError::Boot(err) | BootstrapError::Me(err) => Some(FailureKind::of(err)),
            _ => None,
        }
    }
}

/// The kind of failure of one request, kept for the UI and for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The server answered with this HTTP status.
    Status(u16),
    /// The server did not answer in time.
    Timeout,
    /// The connection to the server failed.
    Connect,
    /// Any other failure, such as an unreadable body.
    Other,
}

impl FailureKind {
    pub fn of(err: &GrappaClientError) -> Self {
        if let Some(status) = err.status() {
            return FailureKind::Status(status.as_u16());
        }
        match err {
            GrappaClientError::Http(err) if err.is_timeout() => FailureKind::Timeout,
            GrappaClientError::Http(err) if err.is_connect() => FailureKind::Connect,
            _ => FailureKind::Other,
        }
    }

    /// Whether a new attempt can help: a server fault (500, 502, 503, 504),
    /// a timeout or a connect error. Any other status is final.
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            FailureKind::Status(500 | 502 | 503 | 504)
                | FailureKind::Timeout
                | FailureKind::Connect
        )
    }
}

impl std::fmt::Display for FailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureKind::Status(code) => write!(f, "{code}"),
            FailureKind::Timeout => f.write_str("timeout"),
            FailureKind::Connect => f.write_str("connect"),
            FailureKind::Other => f.write_str("other"),
        }
    }
}

/// Waits before the second and the third attempt of `/boot` and `/me`.
/// Tests use no wait.
const RETRY_DELAYS: [Duration; 2] = if cfg!(test) {
    [Duration::ZERO, Duration::ZERO]
} else {
    [Duration::from_secs(2), Duration::from_secs(5)]
};

type RetryNotice = Box<dyn Fn() + Send + Sync>;

static RETRY_NOTICE: OnceLock<RetryNotice> = OnceLock::new();

/// Sets the function that runs each time `/boot` or `/me` waits for a new
/// attempt. The first call wins; a later call does nothing.
pub fn set_retry_notice(notice: impl Fn() + Send + Sync + 'static) {
    let _ = RETRY_NOTICE.set(Box::new(notice));
}

/// The log line of one failed attempt. It holds the endpoint, the attempt
/// number and the failure kind. It never holds a token or a body.
fn attempt_log_line(endpoint: &str, attempt: usize, total: usize, kind: FailureKind) -> String {
    format!("boot request failed: endpoint={endpoint} attempt={attempt}/{total} result={kind}")
}

/// Runs `call` again after a transient failure, one more time for each
/// entry of `delays`. Only `call` repeats: the sign-in is never part of it.
async fn fetch_with_retry<T, F, Fut>(
    endpoint: &str,
    delays: &[Duration],
    mut call: F,
) -> Result<T, GrappaClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, GrappaClientError>>,
{
    let total = delays.len() + 1;
    let mut attempt = 1;
    loop {
        let err = match call().await {
            Ok(value) => return Ok(value),
            Err(err) => err,
        };
        let kind = FailureKind::of(&err);
        persistence::log_line(&attempt_log_line(endpoint, attempt, total, kind));
        if attempt >= total || !kind.is_transient() {
            persistence::log_line(&format!(
                "boot request gave up: endpoint={endpoint} attempts={attempt} result={kind}"
            ));
            return Err(err);
        }
        if let Some(notice) = RETRY_NOTICE.get() {
            notice();
        }
        tokio::time::sleep(delays[attempt - 1]).await;
        attempt += 1;
    }
}

/// `GET /boot` then `GET /me` with the token, each one repeated on a
/// transient failure. With `saved_bearer`, a 401 means the bearer is dead.
async fn boot_and_me(
    client: &GrappaClient,
    token: &str,
    saved_bearer: bool,
) -> Result<(BootResponse, MeResponse), BootstrapError> {
    let rejected = |err: &GrappaClientError| {
        saved_bearer && err.status() == Some(reqwest::StatusCode::UNAUTHORIZED)
    };
    let boot = fetch_with_retry("/boot", &RETRY_DELAYS, || client.fetch_boot(token))
        .await
        .map_err(|err| {
            if rejected(&err) {
                BootstrapError::BearerRejected
            } else {
                BootstrapError::Boot(err)
            }
        })?;
    let me = fetch_with_retry("/me", &RETRY_DELAYS, || client.fetch_me(token))
        .await
        .map_err(|err| {
            if rejected(&err) {
                BootstrapError::BearerRejected
            } else {
                BootstrapError::Me(err)
            }
        })?;
    Ok((boot, me))
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
    let (boot, me) = boot_and_me(client, &login.token, false).await?;

    Ok(BootstrapOutcome {
        compatibility,
        token: login.token,
        subject: Some(login.subject),
        boot,
        me,
    })
}

/// Completes a `202 two_factor_required` sign-in: verifies the TOTP (or
/// recovery) code against the challenge, then runs the same `/boot` and
/// `/me` sequence as a password sign-in with the full-session bearer.
pub async fn bootstrap_with_totp(
    client: &GrappaClient,
    challenge_token: &str,
    code: &str,
) -> Result<BootstrapOutcome, BootstrapError> {
    let compatibility = check_server_compatibility(client).await?;
    let login = client
        .verify_totp_login(challenge_token, code)
        .await
        .map_err(BootstrapError::TwoFactor)?;
    let (boot, me) = boot_and_me(client, &login.token, false).await?;
    Ok(BootstrapOutcome {
        compatibility,
        token: login.token,
        subject: Some(login.subject),
        boot,
        me,
    })
}

/// Signs a passwordless account in with one of its recovery codes (which is
/// spent), then runs the same `/boot` and `/me` sequence as a password
/// sign-in with the full-session bearer Grappa answers with.
pub async fn bootstrap_with_recovery_code(
    client: &GrappaClient,
    identifier: &str,
    recovery_code: &str,
) -> Result<BootstrapOutcome, BootstrapError> {
    let compatibility = check_server_compatibility(client).await?;
    let login = client
        .recover_passkey_login(identifier, recovery_code)
        .await
        .map_err(BootstrapError::Recovery)?;
    let (boot, me) = boot_and_me(client, &login.token, false).await?;
    Ok(BootstrapOutcome {
        compatibility,
        token: login.token,
        subject: Some(login.subject),
        boot,
        me,
    })
}

/// Signs in with a share token minted on another device: consumes it (it
/// works once), then runs the same `/boot` and `/me` sequence as any other
/// sign-in with the full-session bearer Grappa answers with.
pub async fn bootstrap_with_share_token(
    client: &GrappaClient,
    share_token: &str,
) -> Result<BootstrapOutcome, BootstrapError> {
    let compatibility = check_server_compatibility(client).await?;
    let login = client
        .consume_share_token(share_token)
        .await
        .map_err(BootstrapError::ShareToken)?;
    let (boot, me) = boot_and_me(client, &login.token, false).await?;
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

    let (boot, me) = boot_and_me(client, bearer, true).await?;

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
    use wiremock::matchers::{body_json, header, method, path};
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
    async fn bootstrap_with_totp_verifies_then_boots_with_the_new_bearer() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/auth/totp/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "full",
                "subject": {"kind": "user", "name": "vjt"}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/boot"))
            .and(header("authorization", "Bearer full"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "networks": []
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .and(header("authorization", "Bearer full"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"kind": "user", "name": "vjt"})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let outcome = bootstrap_with_totp(&client, "ch", "123456")
            .await
            .expect("bootstrap");
        assert_eq!(outcome.token, "full");
        assert_eq!(outcome.me.name.as_deref(), Some("vjt"));
    }

    #[tokio::test]
    async fn bootstrap_with_totp_reports_a_refused_code_as_two_factor() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/auth/totp/verify"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"error": "invalid_two_factor"})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        match bootstrap_with_totp(&client, "ch", "000000").await {
            Err(BootstrapError::TwoFactor(err)) => {
                assert_eq!(err.code(), Some("invalid_two_factor"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn bootstrap_with_recovery_code_spends_it_then_boots_with_the_new_bearer() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/auth/passkeys/recover"))
            .and(body_json(serde_json::json!({
                "identifier": "vjt",
                "recovery_code": "abcd-efgh"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "recovered",
                "subject": {"kind": "user", "name": "vjt"}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/boot"))
            .and(header("authorization", "Bearer recovered"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "networks": []
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .and(header("authorization", "Bearer recovered"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"kind": "user", "name": "vjt"})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let outcome = bootstrap_with_recovery_code(&client, "vjt", "abcd-efgh")
            .await
            .expect("bootstrap");
        assert_eq!(outcome.token, "recovered");
        assert_eq!(outcome.me.name.as_deref(), Some("vjt"));
    }

    #[tokio::test]
    async fn bootstrap_with_recovery_code_keeps_the_refusal_and_never_boots() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/auth/passkeys/recover"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"error": "invalid_two_factor"})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/boot"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        match bootstrap_with_recovery_code(&client, "vjt", "wrong").await {
            Err(BootstrapError::Recovery(err)) => {
                assert_eq!(err.status().map(|status| status.as_u16()), Some(401));
                assert_eq!(err.code(), Some("invalid_two_factor"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn bootstrap_with_recovery_code_reports_a_throttle() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/auth/passkeys/recover"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(serde_json::json!({"error": "too_many_attempts"})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        match bootstrap_with_recovery_code(&client, "vjt", "abcd-efgh").await {
            Err(BootstrapError::Recovery(err)) => {
                assert_eq!(err.code(), Some("too_many_attempts"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn bootstrap_with_share_token_consumes_then_boots_with_the_new_bearer() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/auth/share/consume"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "shared-session",
                "subject": {"kind": "user", "id": "u-1", "name": "vjt"}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/boot"))
            .and(header("authorization", "Bearer shared-session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "networks": []
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .and(header("authorization", "Bearer shared-session"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"kind": "user", "name": "vjt"})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let outcome = bootstrap_with_share_token(&client, "share-1")
            .await
            .expect("bootstrap");
        assert_eq!(outcome.token, "shared-session");
        assert_eq!(
            outcome.subject,
            Some(serde_json::json!({"kind": "user", "id": "u-1", "name": "vjt"}))
        );
        assert_eq!(outcome.me.name.as_deref(), Some("vjt"));
    }

    #[tokio::test]
    async fn bootstrap_with_share_token_reports_a_refused_token_as_share_token() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/auth/share/consume"))
            .respond_with(
                ResponseTemplate::new(410)
                    .set_body_json(serde_json::json!({"error": "share_token_consumed"})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        match bootstrap_with_share_token(&client, "used").await {
            Err(BootstrapError::ShareToken(err)) => {
                assert_eq!(err.code(), Some("share_token_consumed"));
            }
            other => panic!("unexpected {other:?}"),
        }
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

    const RETRY_TOKEN: &str = "fixed-retry-token-8f3a";

    async fn mount_login(mock_server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": RETRY_TOKEN,
                "subject": {"nick": "vjt"}
            })))
            .mount(mock_server)
            .await;
    }

    /// Mounts `failures` answers with `status`, then a good answer.
    async fn mount_flaky(mock_server: &MockServer, route: &str, status: u16, failures: u64) {
        if failures > 0 {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(status))
                .up_to_n_times(failures)
                .mount(mock_server)
                .await;
        }
        let body = if route == "/boot" {
            serde_json::json!({"networks": []})
        } else {
            serde_json::json!({"badge_count": 0})
        };
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(mock_server)
            .await;
    }

    async fn calls(mock_server: &MockServer, route: &str, http_method: &str) -> usize {
        mock_server
            .received_requests()
            .await
            .expect("recording")
            .iter()
            .filter(|request| request.url.path() == route && request.method.as_str() == http_method)
            .count()
    }

    fn login_request() -> LoginRequest {
        LoginRequest {
            identifier: "vjt".to_string(),
            password: "pw".to_string(),
        }
    }

    #[tokio::test]
    async fn boot_is_repeated_after_two_server_errors_and_login_is_sent_once() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        mount_login(&mock_server).await;
        mount_flaky(&mock_server, "/boot", 500, 2).await;
        mount_flaky(&mock_server, "/me", 200, 0).await;

        let client = GrappaClient::new(mock_server.uri());
        bootstrap(&client, &login_request())
            .await
            .expect("sign-in succeeds on the third attempt");

        assert_eq!(calls(&mock_server, "/boot", "GET").await, 3);
        assert_eq!(calls(&mock_server, "/me", "GET").await, 1);
        assert_eq!(calls(&mock_server, "/auth/login", "POST").await, 1);
    }

    #[tokio::test]
    async fn boot_gives_up_after_three_server_errors() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        mount_login(&mock_server).await;
        mount_flaky(&mock_server, "/boot", 500, 10).await;

        let client = GrappaClient::new(mock_server.uri());
        let error = bootstrap(&client, &login_request())
            .await
            .expect_err("three errors end the sign-in");

        assert!(matches!(error, BootstrapError::Boot(_)));
        assert_eq!(error.boot_failure_kind(), Some(FailureKind::Status(500)));
        assert_eq!(calls(&mock_server, "/boot", "GET").await, 3);
        assert_eq!(calls(&mock_server, "/auth/login", "POST").await, 1);
    }

    #[tokio::test]
    async fn boot_repeats_on_502_503_and_504() {
        for status in [502, 503, 504] {
            let mock_server = MockServer::start().await;
            mock_config(
                &mock_server,
                crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
            )
            .await;
            mount_flaky(&mock_server, "/boot", status, 1).await;
            mount_flaky(&mock_server, "/me", 200, 0).await;

            let client = GrappaClient::new(mock_server.uri());
            bootstrap_with_bearer(&client, RETRY_TOKEN)
                .await
                .expect("second attempt succeeds");
            assert_eq!(calls(&mock_server, "/boot", "GET").await, 2, "{status}");
        }
    }

    #[tokio::test]
    async fn boot_does_not_repeat_on_404_and_403() {
        for status in [404, 403] {
            let mock_server = MockServer::start().await;
            mock_config(
                &mock_server,
                crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
            )
            .await;
            mount_flaky(&mock_server, "/boot", status, 10).await;

            let client = GrappaClient::new(mock_server.uri());
            let error = bootstrap_with_bearer(&client, RETRY_TOKEN)
                .await
                .expect_err("final status");
            assert_eq!(
                error.boot_failure_kind(),
                Some(FailureKind::Status(status)),
                "{status}"
            );
            assert_eq!(calls(&mock_server, "/boot", "GET").await, 1, "{status}");
        }
    }

    #[tokio::test]
    async fn saved_bearer_rejected_by_boot_is_not_repeated() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        mount_flaky(&mock_server, "/boot", 401, 10).await;

        let client = GrappaClient::new(mock_server.uri());
        let error = bootstrap_with_bearer(&client, RETRY_TOKEN)
            .await
            .expect_err("revoked bearer");

        assert!(matches!(error, BootstrapError::BearerRejected));
        assert_eq!(calls(&mock_server, "/boot", "GET").await, 1);
    }

    #[tokio::test]
    async fn me_follows_the_same_rules_and_boot_is_not_asked_again() {
        let mock_server = MockServer::start().await;
        mock_config(
            &mock_server,
            crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
        )
        .await;
        mount_flaky(&mock_server, "/boot", 200, 0).await;
        mount_flaky(&mock_server, "/me", 503, 2).await;

        let client = GrappaClient::new(mock_server.uri());
        bootstrap_with_bearer(&client, RETRY_TOKEN)
            .await
            .expect("third attempt of /me succeeds");
        assert_eq!(calls(&mock_server, "/boot", "GET").await, 1);
        assert_eq!(calls(&mock_server, "/me", "GET").await, 3);

        let failing = MockServer::start().await;
        mock_config(&failing, crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION).await;
        mount_flaky(&failing, "/boot", 200, 0).await;
        mount_flaky(&failing, "/me", 500, 10).await;
        let client = GrappaClient::new(failing.uri());
        let error = bootstrap_with_bearer(&client, RETRY_TOKEN)
            .await
            .expect_err("three errors end the sign-in");
        assert!(matches!(error, BootstrapError::Me(_)));
        assert_eq!(calls(&failing, "/me", "GET").await, 3);
        assert_eq!(calls(&failing, "/boot", "GET").await, 1);

        let refused = MockServer::start().await;
        mock_config(&refused, crate::protocol::MIN_SUPPORTED_PROTOCOL_VERSION).await;
        mount_flaky(&refused, "/boot", 200, 0).await;
        mount_flaky(&refused, "/me", 404, 10).await;
        let client = GrappaClient::new(refused.uri());
        bootstrap_with_bearer(&client, RETRY_TOKEN)
            .await
            .expect_err("404 is final");
        assert_eq!(calls(&refused, "/me", "GET").await, 1);
    }

    #[tokio::test]
    async fn a_timeout_is_repeated_and_reported_as_a_timeout() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(1500)))
            .mount(&mock_server)
            .await;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .expect("client");
        let url = format!("{}/slow", mock_server.uri());

        let error = fetch_with_retry::<(), _, _>("/boot", &RETRY_DELAYS, || {
            let request = http.get(&url).send();
            async move {
                request.await?;
                Ok(())
            }
        })
        .await
        .expect_err("every attempt times out");

        assert_eq!(FailureKind::of(&error), FailureKind::Timeout);
        assert_eq!(calls(&mock_server, "/slow", "GET").await, 3);
    }

    #[tokio::test]
    async fn a_connect_error_is_repeated() {
        let http = reqwest::Client::new();
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        // Port 1 on the loopback address refuses connections.
        let error = fetch_with_retry::<(), _, _>("/me", &RETRY_DELAYS, || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let request = http.get("http://127.0.0.1:1/me").send();
            async move {
                request.await?;
                Ok(())
            }
        })
        .await
        .expect_err("connection refused");

        assert_eq!(FailureKind::of(&error), FailureKind::Connect);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn only_server_faults_timeouts_and_connect_errors_are_transient() {
        for status in [500, 502, 503, 504] {
            assert!(FailureKind::Status(status).is_transient(), "{status}");
        }
        for status in [400, 401, 403, 404, 429, 501] {
            assert!(!FailureKind::Status(status).is_transient(), "{status}");
        }
        assert!(FailureKind::Timeout.is_transient());
        assert!(FailureKind::Connect.is_transient());
        assert!(!FailureKind::Other.is_transient());
    }

    #[tokio::test]
    async fn the_attempt_log_line_holds_the_endpoint_and_never_the_token() {
        let mock_server = MockServer::start().await;
        mount_flaky(&mock_server, "/boot", 500, 10).await;
        let client = GrappaClient::new(mock_server.uri());
        let error = client
            .fetch_boot(RETRY_TOKEN)
            .await
            .expect_err("server error");

        let line = attempt_log_line("/boot", 2, 3, FailureKind::of(&error));

        assert_eq!(
            line,
            "boot request failed: endpoint=/boot attempt=2/3 result=500"
        );
        assert!(!line.contains(RETRY_TOKEN));
    }
}
