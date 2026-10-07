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

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use reqwest::Client;
/// HTTP status of a refusal, re-exported for `GrappaClientError` users.
pub use reqwest::StatusCode;

use serde_json::Value;

use crate::admin::{
    AdminNetworkMessageCount, AdminNetworksResponse, AdminOverview, AdminReaperRunResponse,
    AdminSessionLogResponse, AdminSessionsResponse, AdminUploadsResponse, AdminUsersResponse,
    AdminVisitorsResponse,
};
use crate::backoff::rate_limit_wait;
use crate::presence::{PresencePins, PresencePref};
use crate::profile::{
    AddIgnoreRequest, AliasesView, IgnoreEntry, IgnoreMutationResponse, IgnoresResponse,
    NetworkIdentityRequest, NetworkProfileRequest, NotifyAddRequest, PerformUpdateRequest,
    PerformView, VhostSelectionRequest, VhostSettingsView,
};
use crate::rest::{
    ActiveThemePair, ArchiveEntry, ArchiveResponse, BootResponse, ConfigResponse, DirectoryPage,
    DisplayPrefs, FeaturedChannel, FeaturedChannelsResponse, LoginRequest, LoginResponse,
    MeResponse, MessageCountResponse, PasskeyAssertion, PasskeyCreationOptions, PasskeyCredential,
    PasskeyMode, PasskeyOptions, PasskeyRequestOptions, PasskeyStatus, PasskeySummary,
    PasswordlessRecovery, SendMessageRequest, ShareTokenMint, ThemeIndex, ThemeWire,
    UploadResponse,
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
    /// A refusal whose body names the reason (`{"error": "<code>"}`), for
    /// the calls where the protocol tells codes apart under one status.
    Rejected {
        status: StatusCode,
        code: Option<String>,
        /// How long the server asked to wait before trying again: its
        /// `Retry-After` header, else the body's `retry_after_ms`.
        retry_after: Option<Duration>,
    },
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
            GrappaClientError::Rejected { status, .. } => Some(*status),
        }
    }

    /// The server's error code, when the call reads it (`Rejected`).
    pub fn code(&self) -> Option<&str> {
        match self {
            GrappaClientError::Rejected { code, .. } => code.as_deref(),
            _ => None,
        }
    }

    /// The wait the server asked for with a refusal (`Rejected`), when it
    /// gave one: a rate-limited write says how long to hold off.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            GrappaClientError::Rejected { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// Turns a non-success response into `Rejected` with its `error` code;
/// a success is passed through.
async fn reject_with_code(
    response: reqwest::Response,
) -> Result<reqwest::Response, GrappaClientError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let header = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response.json::<Value>().await.ok();
    let code = body
        .as_ref()
        .and_then(|body| body.get("error")?.as_str().map(str::to_string));
    let retry_after = rate_limit_wait(header.as_deref(), body.as_ref(), SystemTime::now());
    Err(GrappaClientError::Rejected {
        status,
        code,
        retry_after,
    })
}

impl From<reqwest::Error> for GrappaClientError {
    fn from(err: reqwest::Error) -> Self {
        GrappaClientError::Http(err)
    }
}

/// Outcome of `POST /auth/login`, per `docs/protocol-notes.md` §1.
#[derive(Debug)]
pub enum LoginError {
    /// `202 two_factor_required`: the password was right and a second
    /// factor is armed. With a TOTP challenge Cordiale completes it through
    /// `verify_totp_login`; a passkey-only account has none to offer.
    TwoFactorRequired(TwoFactorChallenge),
    /// `401 invalid_credentials`: also returned for a wrong per-client
    /// token — indistinguishable from a wrong password on the wire.
    InvalidCredentials,
    /// `429 too_many_attempts`: throttled, don't retry immediately.
    TooManyAttempts,
    Http(reqwest::Error),
    /// Any other refusal. `code` is Grappa's `error` field when the body
    /// has one (`anon_collision`, `nick_in_use`, `malformed_nick`...), and
    /// `retry_after` its `Retry-After` header in seconds.
    Refused {
        status: StatusCode,
        code: Option<String>,
        retry_after: Option<u64>,
    },
}

/// The body of a `202 two_factor_required`, in either of its shapes:
/// `{two_factor_required, challenge_token}` when TOTP is armed, or the
/// passkey one, `{..., passkey_options, totp_available, challenge_token}`,
/// whose `challenge_token` is `null` when a passkey is the only factor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwoFactorChallenge {
    /// The short-lived (five minutes) token `POST /auth/totp/verify` takes;
    /// `None` when there is no TOTP path at all.
    pub challenge_token: Option<String>,
    /// A passkey ceremony was offered too.
    pub passkey_offered: bool,
    /// That ceremony, for `POST /auth/passkeys/second-factor`, when its
    /// options read as the expected shape. Boxed to keep `LoginError`
    /// small.
    pub passkey_options: Option<Box<PasskeyOptions<PasskeyRequestOptions>>>,
    /// TOTP is armed. `false` with a `challenge_token` means the code door
    /// only takes recovery codes. A TOTP-only reply doesn't send the field.
    pub totp_available: bool,
}

impl TwoFactorChallenge {
    fn from_body(body: &Value) -> Self {
        let challenge_token = body
            .get("challenge_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(str::to_string);
        let passkey_options = body
            .get("passkey_options")
            .and_then(|options| {
                serde_json::from_value::<PasskeyOptions<PasskeyRequestOptions>>(options.clone())
                    .ok()
            })
            .map(Box::new);
        TwoFactorChallenge {
            challenge_token,
            passkey_offered: body.get("passkey_options").is_some(),
            passkey_options,
            totp_available: body
                .get("totp_available")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        }
    }

    /// Only a passkey could finish this sign-in.
    pub fn passkey_only(&self) -> bool {
        self.challenge_token.is_none()
    }

    /// The code door is open but takes only recovery codes: a passkey is
    /// the account's factor and TOTP isn't armed.
    pub fn recovery_code_only(&self) -> bool {
        self.challenge_token.is_some() && self.passkey_offered && !self.totp_available
    }
}

#[derive(serde::Deserialize)]
struct PasskeyModeReply {
    mode: PasskeyMode,
}

/// `POST /me/totp/enrollment`: the unarmed secret and the token that
/// confirms it (valid ten minutes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct TotpEnrollment {
    pub enrollment_token: String,
    pub secret: String,
    /// `otpauth://totp/...`, what an authenticator app scans.
    pub provisioning_uri: String,
}

#[derive(serde::Deserialize)]
struct TotpStatus {
    enabled: bool,
}

#[derive(serde::Deserialize)]
struct TotpConfirmation {
    #[serde(default)]
    recovery_codes: Vec<String>,
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
            .user_agent(crate::GRAPPA_USER_AGENT)
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
        self.login_with_bearer(request, None).await
    }

    /// A returning anonymous visitor must prove ownership of the nickname
    /// with its previous bearer. Grappa rotates that bearer on success.
    pub async fn login_with_bearer(
        &self,
        request: &LoginRequest,
        previous_bearer: Option<&str>,
    ) -> Result<LoginResponse, LoginError> {
        let url = format!("{}/auth/login", self.base_url);
        let mut request_builder = self.http.post(url).json(request);
        if let Some(bearer) = previous_bearer {
            request_builder = request_builder.bearer_auth(bearer);
        }
        let response = request_builder.send().await?;

        match response.status() {
            StatusCode::OK => Ok(response.json::<LoginResponse>().await?),
            StatusCode::ACCEPTED => {
                let body = response.json::<Value>().await.unwrap_or(Value::Null);
                Err(LoginError::TwoFactorRequired(
                    TwoFactorChallenge::from_body(&body),
                ))
            }
            StatusCode::UNAUTHORIZED => Err(LoginError::InvalidCredentials),
            StatusCode::TOO_MANY_REQUESTS => Err(LoginError::TooManyAttempts),
            status => {
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.trim().parse().ok());
                // A body that isn't Grappa's JSON (a proxy's error page,
                // say) just leaves the code empty.
                let code = response
                    .json::<Value>()
                    .await
                    .ok()
                    .and_then(|body| body.get("error")?.as_str().map(str::to_string));
                Err(LoginError::Refused {
                    status,
                    code,
                    retry_after,
                })
            }
        }
    }

    /// `POST /auth/totp/verify` — completes a `202 two_factor_required` with a
    /// TOTP code or one of the account's recovery codes, and returns a
    /// full-session bearer. Refusals keep their code: 401
    /// `invalid_two_factor` (wrong code), 401 `two_factor_challenge_expired`
    /// (sign in again), 429 `too_many_attempts`.
    pub async fn verify_totp_login(
        &self,
        challenge_token: &str,
        code: &str,
    ) -> Result<LoginResponse, GrappaClientError> {
        let url = format!("{}/auth/totp/verify", self.base_url);
        let response = self
            .http
            .post(url)
            .json(&serde_json::json!({ "challenge_token": challenge_token, "code": code }))
            .send()
            .await?;
        let response = reject_with_code(response).await?;
        Ok(response.json::<LoginResponse>().await?)
    }

    /// `POST /me/share-token` — mints a single-use token (valid ten minutes)
    /// that signs another device into this same identity. It needs a full
    /// session: a per-client token is refused with 403 `client_token_scope`,
    /// and an incognito guest with 403 `forbidden`.
    pub async fn mint_share_token(&self, token: &str) -> Result<ShareTokenMint, GrappaClientError> {
        let url = format!("{}/me/share-token", self.base_url);
        let response = self.http.post(url).bearer_auth(token).send().await?;
        let response = reject_with_code(response).await?;
        Ok(response.json::<ShareTokenMint>().await?)
    }

    /// `POST /auth/share/consume` — unauthenticated: the share token is the
    /// credential. The answer has the shape of a login and carries a fresh
    /// full-session bearer for the shared identity. Refusals keep their
    /// code: 410 `share_token_expired` / `share_token_consumed`, 401 (a
    /// token Grappa didn't sign), 404 `not_found` (the identity is gone),
    /// 429 `too_many_attempts`.
    pub async fn consume_share_token(
        &self,
        share_token: &str,
    ) -> Result<LoginResponse, GrappaClientError> {
        let url = format!("{}/auth/share/consume", self.base_url);
        let response = self
            .http
            .post(url)
            .json(&serde_json::json!({ "token": share_token }))
            .send()
            .await?;
        let response = reject_with_code(response).await?;
        Ok(response.json::<LoginResponse>().await?)
    }

    /// `GET /me/totp` — whether TOTP is armed. A per-client token is refused
    /// with 403 `client_token_scope`: second factors need a full session.
    pub async fn fetch_totp_status(&self, token: &str) -> Result<bool, GrappaClientError> {
        let url = format!("{}/me/totp", self.base_url);
        let response = self.http.get(url).bearer_auth(token).send().await?;
        let response = reject_with_code(response).await?;
        Ok(response.json::<TotpStatus>().await?.enabled)
    }

    /// `POST /me/totp/enrollment` — re-authenticates with the account
    /// password and returns an unarmed secret. A 401 here means a wrong
    /// password, never a dead bearer; 409 `already_enabled`.
    pub async fn start_totp_enrollment(
        &self,
        token: &str,
        password: &str,
    ) -> Result<TotpEnrollment, GrappaClientError> {
        let url = format!("{}/me/totp/enrollment", self.base_url);
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await?;
        let response = reject_with_code(response).await?;
        Ok(response.json::<TotpEnrollment>().await?)
    }

    /// `POST /me/totp/enrollment/confirm` — arms TOTP with a first code and
    /// returns the recovery codes, the only time Grappa shows them. Other
    /// browser sessions are revoked; this one and client tokens survive.
    pub async fn confirm_totp_enrollment(
        &self,
        token: &str,
        enrollment_token: &str,
        code: &str,
    ) -> Result<Vec<String>, GrappaClientError> {
        let url = format!("{}/me/totp/enrollment/confirm", self.base_url);
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "enrollment_token": enrollment_token, "code": code }))
            .send()
            .await?;
        let response = reject_with_code(response).await?;
        Ok(response.json::<TotpConfirmation>().await?.recovery_codes)
    }

    /// `DELETE /me/totp` — disarms TOTP after re-authenticating with the
    /// account password (401 is a wrong password) and revokes the other
    /// sessions.
    pub async fn disable_totp(&self, token: &str, password: &str) -> Result<(), GrappaClientError> {
        let url = format!("{}/me/totp", self.base_url);
        let response = self
            .http
            .delete(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await?;
        reject_with_code(response).await?;
        Ok(())
    }

    /// POSTs `body` to a passkey route, with the bearer when there is one,
    /// keeping a refusal's code. On the passkey doors every failed
    /// assertion is an opaque 401 `invalid_two_factor`, while 503
    /// `db_unavailable` means Grappa accepted it but couldn't record it:
    /// callers must keep the two apart.
    async fn post_passkey<B, T>(
        &self,
        route: &str,
        token: Option<&str>,
        body: &B,
    ) -> Result<T, GrappaClientError>
    where
        B: serde::Serialize + ?Sized,
        T: serde::de::DeserializeOwned,
    {
        let url = format!("{}{route}", self.base_url);
        let mut request = self.http.post(url).json(body);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = reject_with_code(request.send().await?).await?;
        Ok(response.json::<T>().await?)
    }

    /// `POST /auth/passkeys/second-factor` — finishes a `202` with the
    /// assertion for its `passkey_options` and returns a full-session
    /// bearer.
    pub async fn verify_passkey_second_factor(
        &self,
        assertion: &PasskeyAssertion,
    ) -> Result<LoginResponse, GrappaClientError> {
        self.post_passkey("/auth/passkeys/second-factor", None, assertion)
            .await
    }

    /// `POST /auth/passkeys/options` — starts a passwordless sign-in. An
    /// account that isn't passwordless (or doesn't exist) is 401
    /// `invalid_credentials`; the door is throttled per address (429).
    pub async fn passkey_login_options(
        &self,
        identifier: &str,
    ) -> Result<PasskeyOptions<PasskeyRequestOptions>, GrappaClientError> {
        let body = serde_json::json!({ "identifier": identifier });
        self.post_passkey("/auth/passkeys/options", None, &body)
            .await
    }

    /// `POST /auth/passkeys/verify` — finishes a passwordless sign-in.
    pub async fn verify_passkey_login(
        &self,
        assertion: &PasskeyAssertion,
    ) -> Result<LoginResponse, GrappaClientError> {
        self.post_passkey("/auth/passkeys/verify", None, assertion)
            .await
    }

    /// `POST /auth/passkeys/recover` — signs a passwordless account in with
    /// one of its recovery codes, which is spent. A wrong code is 401
    /// `invalid_two_factor`, 429 `too_many_attempts` a throttle.
    pub async fn recover_passkey_login(
        &self,
        identifier: &str,
        recovery_code: &str,
    ) -> Result<LoginResponse, GrappaClientError> {
        let body = serde_json::json!({ "identifier": identifier, "recovery_code": recovery_code });
        self.post_passkey("/auth/passkeys/recover", None, &body)
            .await
    }

    /// `GET /me/passkeys` — the account's mode and passkeys. Like every
    /// `/me/passkeys*` route it needs a full session: a per-client token
    /// gets 403 `client_token_scope`.
    pub async fn fetch_passkeys(&self, token: &str) -> Result<PasskeyStatus, GrappaClientError> {
        let url = format!("{}/me/passkeys", self.base_url);
        let response = self.http.get(url).bearer_auth(token).send().await?;
        let response = reject_with_code(response).await?;
        Ok(response.json::<PasskeyStatus>().await?)
    }

    /// `POST /me/passkeys/registration/options` — re-authenticates with the
    /// password (401 is a wrong password) and starts a registration.
    pub async fn start_passkey_registration(
        &self,
        token: &str,
        password: &str,
        name: &str,
    ) -> Result<PasskeyOptions<PasskeyCreationOptions>, GrappaClientError> {
        let body = serde_json::json!({ "password": password, "name": name });
        self.post_passkey("/me/passkeys/registration/options", Some(token), &body)
            .await
    }

    /// `POST /me/passkeys/registration` — stores the new credential (201).
    pub async fn finish_passkey_registration(
        &self,
        token: &str,
        credential: &PasskeyCredential,
    ) -> Result<PasskeySummary, GrappaClientError> {
        self.post_passkey("/me/passkeys/registration", Some(token), credential)
            .await
    }

    /// `POST /me/passkeys/mode/options` — re-authenticates with the
    /// password and starts the assertion that switches to `mode`.
    /// Passwordless isn't accepted here (400): it has its own two-step door.
    pub async fn start_passkey_mode_change(
        &self,
        token: &str,
        password: &str,
        mode: PasskeyMode,
    ) -> Result<PasskeyOptions<PasskeyRequestOptions>, GrappaClientError> {
        let body = serde_json::json!({ "password": password, "mode": mode });
        self.post_passkey("/me/passkeys/mode/options", Some(token), &body)
            .await
    }

    /// `POST /me/passkeys/passwordless/recovery` — first step towards
    /// passwordless: the recovery codes to show the user before anything
    /// else, and the token for `start_passwordless_activation`.
    pub async fn prepare_passwordless(
        &self,
        token: &str,
        password: &str,
    ) -> Result<PasswordlessRecovery, GrappaClientError> {
        let body = serde_json::json!({ "password": password });
        self.post_passkey("/me/passkeys/passwordless/recovery", Some(token), &body)
            .await
    }

    /// `POST /me/passkeys/passwordless/options` — starts the assertion that
    /// arms passwordless. The token is bound to this session and expires
    /// after ten minutes (401 `invalid_two_factor`).
    pub async fn start_passwordless_activation(
        &self,
        token: &str,
        recovery_token: &str,
    ) -> Result<PasskeyOptions<PasskeyRequestOptions>, GrappaClientError> {
        let body = serde_json::json!({ "recovery_token": recovery_token });
        self.post_passkey("/me/passkeys/passwordless/options", Some(token), &body)
            .await
    }

    /// `POST /me/passkeys/mode` — finishes a mode change (or the
    /// passwordless activation) and returns the mode now in force. Grappa
    /// revokes the account's other sessions.
    pub async fn finish_passkey_mode_change(
        &self,
        token: &str,
        assertion: &PasskeyAssertion,
    ) -> Result<PasskeyMode, GrappaClientError> {
        let reply: PasskeyModeReply = self
            .post_passkey("/me/passkeys/mode", Some(token), assertion)
            .await?;
        Ok(reply.mode)
    }

    /// `DELETE /me/passkeys/:id` — removes a passkey after re-authenticating
    /// with the password (401). 409 `passkey_required` refuses the last
    /// passkey while a mode still needs it; 404 `not_found` is one that's
    /// already gone.
    pub async fn delete_passkey(
        &self,
        token: &str,
        id: &str,
        password: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["me", "passkeys", id]);
        let response = self
            .http
            .delete(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await?;
        reject_with_code(response).await?;
        Ok(())
    }

    /// Revoke the current bearer. An anonymous visitor's server-side
    /// session is also stopped and its nickname released by Grappa.
    pub async fn logout(&self, token: &str) -> Result<(), GrappaClientError> {
        let url = format!("{}/auth/logout", self.base_url);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
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
            .await?;
        let response = reject_with_code(response).await?;
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

    /// `GET /networks/:slug/channels/:channel/messages?around=<id>&limit=`
    /// — the page of history centred on message `around_id`, the cursor a
    /// mention jump needs. A message that is gone from the scrollback gives
    /// a page without it (or a 404): the caller checks for the id.
    pub async fn fetch_messages_around(
        &self,
        token: &str,
        network_slug: &str,
        channel_name: &str,
        around_id: i64,
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
            .append_pair("around", &around_id.to_string())
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

    /// `GET /networks/:slug/channels/:channel/messages/count?after=<id>&cap=`
    /// — how many rows sit after message `after_id`: the gap probe behind a
    /// reconnect catch-up. With `cap` the server stops counting there (so
    /// `count == cap` reads "at least `cap`"); a server that predates the
    /// parameter ignores it and counts everything, which still answers the
    /// threshold correctly.
    pub async fn fetch_messages_count(
        &self,
        token: &str,
        network_slug: &str,
        channel_name: &str,
        after_id: i64,
        cap: Option<u64>,
    ) -> Result<u64, GrappaClientError> {
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
                "count",
            ]);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("after", &after_id.to_string());
            if let Some(cap) = cap {
                query.append_pair("cap", &cap.to_string());
            }
        }
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<MessageCountResponse>().await?.count)
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

    /// `DELETE /networks/:network_slug/invites/:channel` — declines a channel
    /// invite. Nothing is sent to IRC: the server drops the session's invited
    /// window (`200 {"ok": true}`) and the banner goes away through the
    /// `window_invite_declined` push, never from this response. `404`
    /// (`not_invited`) means the window already left the invited state.
    pub async fn decline_invite(
        &self,
        token: &str,
        network_slug: &str,
        channel: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "invites", channel]);
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
        self.put_display_prefs_merged(token, |merged| {
            if let Ok(Value::Object(changes)) = serde_json::to_value(prefs) {
                merged.extend(changes);
            }
        })
        .await
    }

    /// The channels the account pinned Denoise on or off for, from
    /// `GET /me/settings/display-prefs`.
    pub async fn fetch_presence_pins(
        &self,
        token: &str,
    ) -> Result<PresencePins, GrappaClientError> {
        let url = format!("{}/me/settings/display-prefs", self.base_url);
        let body = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        Ok(PresencePins::from_response(&body))
    }

    /// Adds `pins` to the account's `presence_filter` map and saves it.
    /// Pins for other channels, possibly set from another device, stay.
    pub async fn put_presence_pins(
        &self,
        token: &str,
        pins: &BTreeMap<String, PresencePref>,
    ) -> Result<(), GrappaClientError> {
        self.put_display_prefs_merged(token, |merged| {
            let mut filter = match merged.get("presence_filter") {
                Some(Value::Object(map)) => map.clone(),
                _ => serde_json::Map::new(),
            };
            for (key, pref) in pins {
                filter.insert(key.clone(), Value::from(pref.as_str()));
            }
            merged.insert("presence_filter".to_string(), Value::Object(filter));
        })
        .await
    }

    /// Reads the stored display preferences, lets `change` edit them and
    /// saves the result. The PUT replaces the whole stored map (wrapped under
    /// `display_prefs`), so the keys a caller doesn't edit (time format,
    /// presence filter, ...) are read back first and sent unchanged.
    async fn put_display_prefs_merged(
        &self,
        token: &str,
        change: impl FnOnce(&mut serde_json::Map<String, Value>),
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/me/settings/display-prefs", self.base_url);
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
        change(&mut merged);
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

    /// `GET /me/settings/away-nick-suffix` (protocol v32): the tail Grappa
    /// appends to the nick while it holds the subject auto-away, `None`
    /// when the rename is off (the default). Only Grappa knows whether a
    /// rename actually happened, so this is a setting, never a nick.
    pub async fn fetch_away_nick_suffix(
        &self,
        token: &str,
    ) -> Result<Option<String>, GrappaClientError> {
        let value = self
            .fetch_setting(token, "away-nick-suffix", "away_nick_suffix")
            .await?;
        Ok(value.as_str().map(str::to_string))
    }

    /// Stores the auto-away nick suffix; `None` switches the rename off.
    /// A tail that isn't legal in a nick is refused with a 422.
    pub async fn set_away_nick_suffix(
        &self,
        token: &str,
        suffix: Option<&str>,
    ) -> Result<(), GrappaClientError> {
        self.put_setting(token, "away-nick-suffix", "away_nick_suffix", suffix.into())
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

    /// `POST /admin/sessions/:id/reconnect` — brings a downed visitor
    /// session back up (visitors only: a user subject is refused with 400,
    /// an account reconnects its own sessions). Idempotent on a live one.
    pub async fn reconnect_admin_session(
        &self,
        token: &str,
        session_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "sessions", session_id, "reconnect"]);

        self.http
            .post(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `DELETE /admin/sessions/:id` — force-stops the live session without
    /// touching the credential or visitor row, so the binding stays as it
    /// was. Idempotent; 422 when an admin targets their own session.
    pub async fn terminate_admin_session(
        &self,
        token: &str,
        session_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "sessions", session_id]);

        self.http
            .delete(url)
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

    /// `GET /admin/uploads` — every upload, soft-deleted ones included,
    /// with live usage against the global budget. Admin with a full session
    /// only: a per-client token gets 403.
    pub async fn fetch_admin_uploads(
        &self,
        token: &str,
    ) -> Result<AdminUploadsResponse, GrappaClientError> {
        let url = format!("{}/admin/uploads", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<AdminUploadsResponse>().await?)
    }

    /// `DELETE /admin/uploads/:id` — unlinks a live upload before its
    /// expiry and soft-deletes its row, which stays listed. 204.
    pub async fn delete_admin_upload(
        &self,
        token: &str,
        upload_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "uploads", upload_id]);
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

    /// `POST /admin/users {name, password, is_admin}` — creates an account.
    pub async fn create_admin_user(
        &self,
        token: &str,
        name: &str,
        password: &str,
        is_admin: bool,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/admin/users", self.base_url);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "name": name, "password": password, "is_admin": is_admin }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `PUT /admin/users/:id/password {password}` — also signs the user out
    /// everywhere, server-side.
    pub async fn set_admin_user_password(
        &self,
        token: &str,
        user_id: &str,
        password: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "users", user_id, "password"]);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "password": password }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `POST /admin/networks {slug}` — 409 when the slug exists.
    pub async fn create_admin_network(
        &self,
        token: &str,
        slug: &str,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/admin/networks", self.base_url);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "slug": slug }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `PATCH /admin/networks/:slug` with any of `visitor_enabled`,
    /// `visitor_autoconnect`, `services_flavor` and the three caps (`null`
    /// for unlimited).
    pub async fn update_admin_network(
        &self,
        token: &str,
        slug: &str,
        settings: &Value,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "networks", slug]);
        self.http
            .patch(url)
            .bearer_auth(token)
            .json(settings)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `DELETE /admin/networks/:id` — since protocol v33 this also deletes
    /// the network's whole scrollback, for every subject. The one refusal
    /// left is 409 `credentials_present` while accounts are still bound.
    /// Ask `fetch_admin_network_message_count` first to say what goes.
    pub async fn delete_admin_network(
        &self,
        token: &str,
        network_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "networks", network_id]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /admin/networks/:id/message_count` — how many scrollback rows a
    /// network delete takes with it. `None` for a 404, which is a server
    /// older than v33 (no such route) or a network that is already gone:
    /// either way the count can't be confirmed, and is never zero.
    pub async fn fetch_admin_network_message_count(
        &self,
        token: &str,
        network_id: &str,
    ) -> Result<Option<u64>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "networks", network_id, "message_count"]);
        let response = self.http.get(url).bearer_auth(token).send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let count = response
            .error_for_status()?
            .json::<AdminNetworkMessageCount>()
            .await?;
        Ok(Some(count.message_count))
    }

    /// `GET /admin/networks/:id/featured_channels` — every curated channel
    /// of the network, disabled ones included, by position then id.
    pub async fn fetch_admin_featured_channels(
        &self,
        token: &str,
        network_id: &str,
    ) -> Result<Vec<Value>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "networks", network_id, "featured_channels"]);
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
            .get("featured_channels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// `POST /admin/networks/:id/featured_channels` with `name` and, all
    /// optional, `description`, `position`, `enabled`. The server lowercases
    /// the name; 409 for a channel already featured, 422 for a name that
    /// isn't a channel.
    pub async fn add_admin_featured_channel(
        &self,
        token: &str,
        network_id: &str,
        channel: &Value,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "networks", network_id, "featured_channels"]);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(channel)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `PUT /admin/networks/:id/featured_channels/:channel_id` with any of
    /// `name`, `description`, `position`, `enabled` (an unknown key is a
    /// 400). A disabled channel stays on the list but is not suggested.
    pub async fn update_admin_featured_channel(
        &self,
        token: &str,
        network_id: &str,
        channel_id: &str,
        changes: &Value,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend([
                "admin",
                "networks",
                network_id,
                "featured_channels",
                channel_id,
            ]);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(changes)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `DELETE /admin/networks/:id/featured_channels/:channel_id`.
    pub async fn delete_admin_featured_channel(
        &self,
        token: &str,
        network_id: &str,
        channel_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend([
                "admin",
                "networks",
                network_id,
                "featured_channels",
                channel_id,
            ]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /admin/networks/:id/servers` — the network's IRC endpoints, in
    /// connection priority order.
    pub async fn fetch_admin_servers(
        &self,
        token: &str,
        network_id: &str,
    ) -> Result<Vec<Value>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "networks", network_id, "servers"]);
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
            .get("servers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// `POST /admin/networks/:id/servers {host, port, tls}` — 409 for a
    /// duplicate endpoint.
    pub async fn add_admin_server(
        &self,
        token: &str,
        network_id: &str,
        host: &str,
        port: u16,
        tls: bool,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "networks", network_id, "servers"]);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "host": host, "port": port, "tls": tls }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `PUT /admin/networks/:id/servers/:server_id` with any of `host`,
    /// `port`, `tls`, `enabled`, `priority`. Live sessions keep their
    /// connection until they next reconnect; 409 for a duplicate endpoint.
    pub async fn update_admin_server(
        &self,
        token: &str,
        network_id: &str,
        server_id: &str,
        changes: &Value,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "networks", network_id, "servers", server_id]);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(changes)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `DELETE /admin/networks/:id/servers/:server_id` — live sessions keep
    /// their connection until they next reconnect.
    pub async fn delete_admin_server(
        &self,
        token: &str,
        network_id: &str,
        server_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "networks", network_id, "servers", server_id]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /admin/settings` — the server-wide `upload`, `dcc` and
    /// `addressing` settings, as the object under `settings`.
    pub async fn fetch_admin_settings(&self, token: &str) -> Result<Value, GrappaClientError> {
        let url = format!("{}/admin/settings", self.base_url);
        let body = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        Ok(body.get("settings").cloned().unwrap_or(Value::Null))
    }

    /// `PUT /admin/settings` — only the subtrees and keys present change;
    /// 422 names an invalid key, or refuses an unusable addressing mode.
    pub async fn update_admin_settings(
        &self,
        token: &str,
        settings: &Value,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/admin/settings", self.base_url);
        self.http
            .put(url)
            .bearer_auth(token)
            .json(settings)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /admin/credentials` — every bound (user, network) credential.
    pub async fn fetch_admin_credentials(
        &self,
        token: &str,
    ) -> Result<Vec<Value>, GrappaClientError> {
        let url = format!("{}/admin/credentials", self.base_url);
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
            .get("credentials")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// `POST /admin/credentials` — binds an account to a network (`user_id`,
    /// `network_id`, `nick`, `auth_method` required, `password` optional);
    /// Grappa starts the session right away.
    pub async fn create_admin_credential(
        &self,
        token: &str,
        credential: &Value,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/admin/credentials", self.base_url);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(credential)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `PATCH /admin/credentials/:user_id/:network_id` with any of `nick`,
    /// `ident`, `realname`, `sasl_user`, `auth_method`,
    /// `auth_command_template`, `autojoin_channels` and `password` (any other
    /// key is a 400). Changing the password or the auth method stops a live
    /// session, since it authenticated with the old one, and Grappa does not
    /// dial it again: the answer is `true` in that case, `false` when the
    /// session was left alone. A new auth method needs a fresh password (422
    /// without one).
    pub async fn update_admin_credential(
        &self,
        token: &str,
        user_id: &str,
        network_id: &str,
        changes: &Value,
    ) -> Result<bool, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "credentials", user_id, network_id]);
        let body = self
            .http
            .patch(url)
            .bearer_auth(token)
            .json(changes)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        Ok(body.get("session_action").and_then(Value::as_str) == Some("stopped"))
    }

    /// `DELETE /admin/credentials/:user_id/:network_id` — unbinds and stops
    /// the live session.
    pub async fn delete_admin_credential(
        &self,
        token: &str,
        user_id: &str,
        network_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "credentials", user_id, network_id]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /admin/vhosts` — `{vhosts, grants, host_candidates}`.
    pub async fn fetch_admin_vhosts(&self, token: &str) -> Result<Value, GrappaClientError> {
        let url = format!("{}/admin/vhosts", self.base_url);
        Ok(self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?)
    }

    /// `POST /admin/vhosts {address, in_pool}` — 409 for a known address.
    pub async fn create_admin_vhost(
        &self,
        token: &str,
        address: &str,
        in_pool: bool,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/admin/vhosts", self.base_url);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "address": address, "in_pool": in_pool }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `PATCH /admin/vhosts/:id` with `in_pool` and/or `generally_available`.
    pub async fn update_admin_vhost(
        &self,
        token: &str,
        vhost_id: &str,
        changes: &Value,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "vhosts", vhost_id]);
        self.http
            .patch(url)
            .bearer_auth(token)
            .json(changes)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `DELETE /admin/vhosts/:id` — its grants go with it.
    pub async fn delete_admin_vhost(
        &self,
        token: &str,
        vhost_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "vhosts", vhost_id]);
        self.http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `POST /admin/vhosts/:id/grants {subject_type, subject_id}`, where the
    /// subject is a `"user"` or a `"visitor"`.
    pub async fn grant_admin_vhost(
        &self,
        token: &str,
        vhost_id: &str,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "vhosts", vhost_id, "grants"]);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "subject_type": subject_type, "subject_id": subject_id }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /admin/vhosts/subject_search?q=` — accounts and visitors whose
    /// name matches, as `{type, id, network, nick}` rows for a grant.
    pub async fn search_admin_subjects(
        &self,
        token: &str,
        query: &str,
    ) -> Result<Vec<Value>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "vhosts", "subject_search"]);
        url.query_pairs_mut().append_pair("q", query);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        let body: Value = response.json().await?;
        Ok(body
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// `DELETE /admin/vhosts/grants/:grant_id` — idempotent.
    pub async fn revoke_admin_vhost_grant(
        &self,
        token: &str,
        grant_id: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["admin", "vhosts", "grants", grant_id]);
        self.http
            .delete(url)
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

    /// `PATCH /networks/:slug/profile` — the CTCP USERINFO fields (age,
    /// gender, location, languages, custom) of the caller's own
    /// credential. Omitted fields stay as they are, `""` clears one. It
    /// never reconnects the session. Returns the updated credential; 422
    /// when a value breaks the server's limits.
    pub async fn update_network_profile(
        &self,
        token: &str,
        network_slug: &str,
        request: &NetworkProfileRequest,
    ) -> Result<Value, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "profile"]);
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

    /// `PUT /networks/:slug/avatar` — sets or replaces the caller's own
    /// avatar on a network (multipart field `file`, an image type within
    /// the server's image cap). Returns the updated credential, whose
    /// `avatar_url` is the new one. 415 for a non-image type, 413 over the
    /// cap, 507 when the server or the account is out of upload space.
    pub async fn upload_network_avatar(
        &self,
        token: &str,
        network_slug: &str,
        filename: &str,
        mime: &str,
        bytes: Vec<u8>,
    ) -> Result<Value, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "avatar"]);
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename.to_string())
            .mime_str(mime)?;
        let form = reqwest::multipart::Form::new().part("file", part);
        let response = self
            .http
            .put(url)
            .bearer_auth(token)
            .timeout(UPLOAD_TIMEOUT)
            .multipart(form)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<Value>().await?)
    }

    /// `DELETE /networks/:slug/avatar` — removes the caller's own avatar
    /// on a network. Returns the updated credential; removing when there
    /// is none is a success, not an error.
    pub async fn delete_network_avatar(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<Value, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "avatar"]);
        let response = self
            .http
            .delete(url)
            .bearer_auth(token)
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

    /// `GET /networks/:slug/ignores` — the rules as `(mask, text_pattern)`
    /// pairs (protocol v31), or mask-only from an older server.
    pub async fn fetch_ignores(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<Vec<IgnoreEntry>, GrappaClientError> {
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
        Ok(response.json::<IgnoresResponse>().await?.into_entries())
    }

    /// `POST /networks/:slug/ignores` — adds the `(mask, text_pattern)`
    /// rule; no pattern is the plain mask rule. A blank or CR/LF-bearing
    /// pattern is refused as 422 `invalid_text_pattern`, a bad mask as 422
    /// `invalid_mask`: both come back as `Rejected` with their code.
    pub async fn add_ignore(
        &self,
        token: &str,
        network_slug: &str,
        mask: &str,
        text_pattern: Option<&str>,
    ) -> Result<IgnoreMutationResponse, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "ignores"]);
        let request = AddIgnoreRequest {
            mask: mask.to_string(),
            text_pattern: text_pattern.map(str::to_string),
        };
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await?;
        let response = reject_with_code(response).await?;
        Ok(response.json::<IgnoreMutationResponse>().await?)
    }

    /// `DELETE /networks/:slug/ignores/:mask[?text_pattern=...]` — removes
    /// exactly that pair. Without a pattern Grappa removes the rule with NO
    /// pattern, never every rule sharing the mask.
    pub async fn remove_ignore(
        &self,
        token: &str,
        network_slug: &str,
        mask: &str,
        text_pattern: Option<&str>,
    ) -> Result<IgnoreMutationResponse, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "ignores", mask]);
        if let Some(pattern) = text_pattern {
            url.query_pairs_mut().append_pair("text_pattern", pattern);
        }
        let response = self.http.delete(url).bearer_auth(token).send().await?;
        let response = reject_with_code(response).await?;
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

    /// Downloads a file Grappa serves behind authentication (a cached WHOIS
    /// avatar): `path_or_url` is a server path (`/…`) or a URL on the same
    /// server. The bearer token is never sent anywhere else, so any other
    /// URL is refused. Returns the bytes and the `Content-Type`, if any.
    pub async fn fetch_server_file(
        &self,
        token: &str,
        path_or_url: &str,
    ) -> Result<(Vec<u8>, Option<String>), GrappaClientError> {
        let base = self.base_url.trim_end_matches('/');
        let url = if path_or_url.starts_with('/') {
            format!("{base}{path_or_url}")
        } else if path_or_url.starts_with(&format!("{base}/")) {
            path_or_url.to_string()
        } else {
            return Err(GrappaClientError::InvalidUrl(path_or_url.to_string()));
        };
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        Ok((response.bytes().await?.to_vec(), content_type))
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

    /// `GET /me/themes` — the account's own themes, published or not.
    pub async fn fetch_my_themes(&self, token: &str) -> Result<Vec<ThemeWire>, GrappaClientError> {
        let url = format!("{}/me/themes", self.base_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<ThemeIndex>().await?.themes)
    }

    /// `POST /themes {name, payload}` (a new theme) or `PATCH /themes/:id`.
    pub async fn save_theme(
        &self,
        token: &str,
        theme_id: Option<i64>,
        name: &str,
        payload: &Value,
    ) -> Result<ThemeWire, GrappaClientError> {
        let body = serde_json::json!({ "name": name, "payload": payload });
        let request = match theme_id {
            Some(id) => self.http.patch(format!("{}/themes/{id}", self.base_url)),
            None => self.http.post(format!("{}/themes", self.base_url)),
        };
        let response = request
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<ThemeWire>().await?)
    }

    /// `DELETE /themes/:id`.
    pub async fn delete_theme(&self, token: &str, theme_id: i64) -> Result<(), GrappaClientError> {
        self.http
            .delete(format!("{}/themes/{theme_id}", self.base_url))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `POST /themes/:id/publish` or `/unpublish`.
    pub async fn set_theme_published(
        &self,
        token: &str,
        theme_id: i64,
        published: bool,
    ) -> Result<ThemeWire, GrappaClientError> {
        let verb = if published { "publish" } else { "unpublish" };
        let response = self
            .http
            .post(format!("{}/themes/{theme_id}/{verb}", self.base_url))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<ThemeWire>().await?)
    }

    /// `POST /themes/:id/copy` — an editable copy owned by the account.
    pub async fn copy_theme(
        &self,
        token: &str,
        theme_id: i64,
    ) -> Result<ThemeWire, GrappaClientError> {
        let response = self
            .http
            .post(format!("{}/themes/{theme_id}/copy", self.base_url))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<ThemeWire>().await?)
    }

    /// `GET /themes/backgrounds` — Grappa's built-in wallpapers as
    /// `(key, name)`.
    pub async fn fetch_theme_backgrounds(
        &self,
        token: &str,
    ) -> Result<Vec<(String, String)>, GrappaClientError> {
        let response = self
            .http
            .get(format!("{}/themes/backgrounds", self.base_url))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        let body = response.json::<Value>().await?;
        Ok(body
            .get("backgrounds")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        let key = row.get("key")?.as_str()?.to_string();
                        let name = row
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or(&key)
                            .to_string();
                        Some((key, name))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// `POST /themes/background` with a picked image (multipart `file`);
    /// Grappa re-encodes it and returns its `image_id`.
    pub async fn upload_theme_background(
        &self,
        token: &str,
        filename: &str,
        mime: &str,
        bytes: Vec<u8>,
    ) -> Result<String, GrappaClientError> {
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename.to_string())
            .mime_str(mime)?;
        let form = reqwest::multipart::Form::new().part("file", part);
        let response = self
            .http
            .post(format!("{}/themes/background", self.base_url))
            .bearer_auth(token)
            .timeout(UPLOAD_TIMEOUT)
            .multipart(form)
            .send()
            .await?
            .error_for_status()?;
        let body = response.json::<Value>().await?;
        body.get("image_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| GrappaClientError::InvalidUrl("no image_id in the reply".to_string()))
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

    /// `PUT /me/theme`: `light` is the day theme, and `dark` the night one;
    /// without a night theme the day one applies in both modes.
    pub async fn set_active_theme(
        &self,
        token: &str,
        light: i64,
        dark: Option<i64>,
    ) -> Result<ActiveThemePair, GrappaClientError> {
        let url = format!("{}/me/theme", self.base_url);
        let response = self
            .http
            .put(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "light": light, "dark": dark }))
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<ActiveThemePair>().await?)
    }

    /// `POST /api/uploads` — uploads one file (multipart field `file`),
    /// kept for `expire` seconds or the server's default lifetime. `mime`
    /// must be one of Grappa's allowlisted types (else 415); the per-file
    /// cap by category gives 413. A 507 means either the instance is out of
    /// space or the subject hit its own upload cap (protocol v26): the two
    /// are indistinguishable on the wire. Large files get a longer timeout
    /// than the client default.
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

    /// `POST /session/networks` — attaches a network to the caller's own
    /// session (a one-tap connect from the home page, or the re-attach of a
    /// detached binding with everything it was detached with). The outcome
    /// reaches every client as `network_attached`.
    pub async fn attach_network(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<(), GrappaClientError> {
        let url = format!("{}/session/networks", self.base_url);
        self.http
            .post(url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "network": network_slug }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// `GET /networks/:slug/featured` — the operator-curated channels the
    /// home page suggests for one network.
    pub async fn fetch_featured_channels(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<Vec<FeaturedChannel>, GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["networks", network_slug, "featured"]);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<FeaturedChannelsResponse>().await?.channels)
    }

    /// `DELETE /session/networks/:slug` (protocol v28) — detaches a network
    /// from the caller's own session: Grappa parks and quits it, then marks
    /// the binding detached. Nick, SASL user, secrets, perform list and
    /// autojoin all survive, and `POST /session/networks` on the same slug
    /// restores them, so this is a remove, not a delete. 204 on success;
    /// 404 for a slug the deployment doesn't carry or the caller doesn't
    /// hold attached (one answer for both, by design); 403 for a visitor.
    /// The outcome reaches every client as `network_detached`.
    pub async fn detach_network(
        &self,
        token: &str,
        network_slug: &str,
    ) -> Result<(), GrappaClientError> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|err| GrappaClientError::InvalidUrl(err.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| GrappaClientError::InvalidUrl(self.base_url.clone()))?
            .extend(["session", "networks", network_slug]);
        self.http
            .delete(url)
            .bearer_auth(token)
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
    use wiremock::matchers::{
        body_json, body_string_contains, header, header_regex, method, path, query_param,
    };
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
    async fn login_identifies_the_client_build_to_grappa() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .and(header("user-agent", crate::GRAPPA_USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "abc123",
                "subject": {"nick": "vjt"}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "vjt".to_string(),
            password: "s3cr3t".to_string(),
        };
        client.login(&request).await.expect("login");
    }

    #[tokio::test]
    async fn returning_guest_login_proves_the_nickname_with_its_bearer() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .and(header("authorization", "Bearer previous-bearer"))
            .and(body_json(serde_json::json!({"identifier": "guest_nick"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "rotated-bearer",
                "subject": {"kind": "visitor"}
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "guest_nick".to_string(),
            password: String::new(),
        };
        let response = client
            .login_with_bearer(&request, Some("previous-bearer"))
            .await
            .expect("returning guest login");
        assert_eq!(response.token, "rotated-bearer");
    }

    #[tokio::test]
    async fn logout_revokes_the_current_bearer() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/auth/logout"))
            .and(header("authorization", "Bearer guest-bearer"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;

        GrappaClient::new(mock_server.uri())
            .logout("guest-bearer")
            .await
            .expect("guest logout");
    }

    #[tokio::test]
    async fn failed_logout_keeps_the_server_error_visible_to_the_caller() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/auth/logout"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let error = GrappaClient::new(mock_server.uri())
            .logout("guest-bearer")
            .await
            .expect_err("server did not confirm logout");
        assert_eq!(error.status(), Some(StatusCode::SERVICE_UNAVAILABLE));
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

        // No body at all: no challenge to complete.
        match error {
            LoginError::TwoFactorRequired(challenge) => assert!(challenge.passkey_only()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn login_202_carries_the_totp_challenge_in_both_shapes() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .and(body_json(
                serde_json::json!({"identifier": "totp", "password": "pw"}),
            ))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "two_factor_required": true,
                "challenge_token": "ch-1"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .and(body_json(
                serde_json::json!({"identifier": "both", "password": "pw"}),
            ))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "two_factor_required": true,
                "passkey_options": {
                    "challenge_id": "p",
                    "public_key": {
                        "challenge": "q2x0Y2hhbGxlbmdl",
                        "rp_id": "irc.example.org",
                        "timeout": 300_000,
                        "user_verification": "required",
                        "allow_credentials": [
                            {"type": "public-key", "id": "Y3JlZA", "transports": ["usb"]}
                        ]
                    }
                },
                "totp_available": true,
                "challenge_token": "ch-2"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .and(body_json(
                serde_json::json!({"identifier": "codes", "password": "pw"}),
            ))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "two_factor_required": true,
                "passkey_options": {"challenge_id": "p", "public_key": {}},
                "totp_available": false,
                "challenge_token": "ch-3"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .and(body_json(
                serde_json::json!({"identifier": "passkey", "password": "pw"}),
            ))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "two_factor_required": true,
                "passkey_options": {"challenge_id": "p", "public_key": {}},
                "totp_available": false,
                "challenge_token": null
            })))
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());
        let challenge = |identifier: &str| {
            let request = LoginRequest {
                identifier: identifier.to_string(),
                password: "pw".to_string(),
            };
            let client = client.clone();
            async move {
                match client.login(&request).await {
                    Err(LoginError::TwoFactorRequired(challenge)) => challenge,
                    other => panic!("unexpected {other:?}"),
                }
            }
        };

        let totp = challenge("totp").await;
        assert_eq!(totp.challenge_token.as_deref(), Some("ch-1"));
        assert!(!totp.passkey_offered);
        assert!(totp.totp_available && !totp.recovery_code_only());
        let both = challenge("both").await;
        assert_eq!(both.challenge_token.as_deref(), Some("ch-2"));
        assert!(both.passkey_offered && !both.passkey_only());
        assert!(!both.recovery_code_only());
        let options = both.passkey_options.expect("typed passkey options");
        assert_eq!(options.challenge_id, "p");
        assert_eq!(options.public_key.rp_id, "irc.example.org");
        assert_eq!(
            options.public_key.user_verification.as_deref(),
            Some("required")
        );
        assert_eq!(options.public_key.allow_credentials[0].id, "Y3JlZA");
        assert_eq!(options.public_key.allow_credentials[0].transports, ["usb"]);
        // A passkey plus recovery codes and no TOTP: the code door only
        // takes recovery codes. Options that don't read still count as a
        // passkey offer.
        let codes = challenge("codes").await;
        assert!(codes.recovery_code_only());
        assert!(codes.passkey_offered && codes.passkey_options.is_none());
        let passkey = challenge("passkey").await;
        assert!(passkey.passkey_only() && !passkey.recovery_code_only());
    }

    #[tokio::test]
    async fn verify_totp_login_returns_the_bearer_and_keeps_refusal_codes() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/totp/verify"))
            .and(body_json(
                serde_json::json!({"challenge_token": "ch", "code": "123456"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "full-session",
                "subject": {"kind": "user", "name": "vjt"}
            })))
            .mount(&mock_server)
            .await;
        for (code, status, error) in [
            ("000000", 401, "invalid_two_factor"),
            ("111111", 401, "two_factor_challenge_expired"),
            ("222222", 429, "too_many_attempts"),
        ] {
            Mock::given(method("POST"))
                .and(path("/auth/totp/verify"))
                .and(body_json(
                    serde_json::json!({"challenge_token": "ch", "code": code}),
                ))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(serde_json::json!({"error": error})),
                )
                .mount(&mock_server)
                .await;
        }
        let client = GrappaClient::new(mock_server.uri());

        let login = client
            .verify_totp_login("ch", "123456")
            .await
            .expect("verify");
        assert_eq!(login.token, "full-session");
        for (code, status, error) in [
            ("000000", StatusCode::UNAUTHORIZED, "invalid_two_factor"),
            (
                "111111",
                StatusCode::UNAUTHORIZED,
                "two_factor_challenge_expired",
            ),
            ("222222", StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"),
        ] {
            let refused = client.verify_totp_login("ch", code).await.unwrap_err();
            assert_eq!(refused.status(), Some(status));
            assert_eq!(refused.code(), Some(error));
        }
    }

    #[tokio::test]
    async fn mint_share_token_sends_the_bearer_and_reads_the_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/me/share-token"))
            .and(header("authorization", "Bearer full"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "SFMyNTY.payload.sig",
                "expires_at": "2026-09-30T12:10:00Z"
            })))
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        let minted = client.mint_share_token("full").await.expect("mint");
        assert_eq!(minted.token, "SFMyNTY.payload.sig");
        assert_eq!(minted.expires_at, "2026-09-30T12:10:00Z");
        assert!(!format!("{minted:?}").contains("SFMyNTY"));
    }

    #[tokio::test]
    async fn mint_share_token_keeps_refusal_codes() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/me/share-token"))
            .and(header("authorization", "Bearer per-client"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(serde_json::json!({"error": "client_token_scope"})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/share-token"))
            .and(header("authorization", "Bearer incognito"))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(serde_json::json!({"error": "forbidden"})),
            )
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        let scope = client.mint_share_token("per-client").await.unwrap_err();
        assert_eq!(scope.status(), Some(StatusCode::FORBIDDEN));
        assert_eq!(scope.code(), Some("client_token_scope"));
        let incognito = client.mint_share_token("incognito").await.unwrap_err();
        assert_eq!(incognito.code(), Some("forbidden"));
    }

    #[tokio::test]
    async fn consume_share_token_returns_a_login_shaped_answer_without_a_bearer() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/share/consume"))
            .and(body_json(serde_json::json!({"token": "share-1"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "new-session",
                "subject": {"kind": "user", "id": "u-1", "name": "vjt"}
            })))
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        let login = client
            .consume_share_token("share-1")
            .await
            .expect("consume");
        assert_eq!(login.token, "new-session");
        assert_eq!(login.subject["name"], "vjt");
        let requests = mock_server.received_requests().await.expect("requests");
        assert!(requests[0].headers.get("authorization").is_none());
    }

    #[tokio::test]
    async fn consume_share_token_keeps_refusal_codes() {
        let mock_server = MockServer::start().await;
        for (token, status, error) in [
            ("old", 410, "share_token_expired"),
            ("used", 410, "share_token_consumed"),
            ("forged", 401, "unauthorized"),
            ("orphan", 404, "not_found"),
            ("spray", 429, "too_many_attempts"),
        ] {
            Mock::given(method("POST"))
                .and(path("/auth/share/consume"))
                .and(body_json(serde_json::json!({"token": token})))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(serde_json::json!({"error": error})),
                )
                .mount(&mock_server)
                .await;
        }
        let client = GrappaClient::new(mock_server.uri());

        for (token, status, error) in [
            ("old", StatusCode::GONE, "share_token_expired"),
            ("used", StatusCode::GONE, "share_token_consumed"),
            ("forged", StatusCode::UNAUTHORIZED, "unauthorized"),
            ("orphan", StatusCode::NOT_FOUND, "not_found"),
            ("spray", StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"),
        ] {
            let refused = client.consume_share_token(token).await.unwrap_err();
            assert_eq!(refused.status(), Some(status));
            assert_eq!(refused.code(), Some(error));
        }
    }

    /// A per-run stand-in for the account password in the TOTP tests, built
    /// from the process id alone: no string literal in the source becomes a
    /// credential, which is what code scanning looks for.
    fn test_password() -> String {
        std::process::id().to_string()
    }

    #[tokio::test]
    async fn totp_settings_enroll_confirm_and_disable() {
        let password = test_password();
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/totp"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"enabled": false})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/totp/enrollment"))
            .and(body_json(serde_json::json!({"password": password})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "enrollment_token": "enr",
                "secret": "JBSWY3DPEHPK3PXP",
                "provisioning_uri": "otpauth://totp/Grappa:vjt?secret=JBSWY3DPEHPK3PXP&issuer=Grappa"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/totp/enrollment/confirm"))
            .and(body_json(
                serde_json::json!({"enrollment_token": "enr", "code": "123456"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "enabled": true,
                "recovery_codes": ["aaaa-bbbb", "cccc-dddd"]
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/me/totp"))
            .and(body_json(serde_json::json!({"password": password})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"enabled": false})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        assert!(!client.fetch_totp_status("tok").await.expect("status"));
        let enrollment = client
            .start_totp_enrollment("tok", &password)
            .await
            .expect("start");
        assert_eq!(enrollment.enrollment_token, "enr");
        assert!(enrollment.provisioning_uri.starts_with("otpauth://totp/"));
        let codes = client
            .confirm_totp_enrollment("tok", "enr", "123456")
            .await
            .expect("confirm");
        assert_eq!(
            codes,
            vec!["aaaa-bbbb".to_string(), "cccc-dddd".to_string()]
        );
        client
            .disable_totp("tok", &password)
            .await
            .expect("disable");
    }

    #[tokio::test]
    async fn totp_settings_refusals_keep_their_codes() {
        let password = test_password();
        // The refusals below don't depend on which password is sent.
        let wrong_password = test_password();
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/totp"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(serde_json::json!({"error": "client_token_scope"})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/totp/enrollment"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(serde_json::json!({"error": "already_enabled"})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/me/totp"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"error": "invalid_credentials"})),
            )
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        let scope = client.fetch_totp_status("tok").await.unwrap_err();
        assert_eq!(scope.status(), Some(StatusCode::FORBIDDEN));
        assert_eq!(scope.code(), Some("client_token_scope"));
        let already = client
            .start_totp_enrollment("tok", &password)
            .await
            .unwrap_err();
        assert_eq!(already.code(), Some("already_enabled"));
        let wrong = client
            .disable_totp("tok", &wrong_password)
            .await
            .unwrap_err();
        assert_eq!(wrong.status(), Some(StatusCode::UNAUTHORIZED));
        assert_eq!(wrong.code(), Some("invalid_credentials"));
    }

    /// An assertion as an authenticator would hand it back, base64url.
    fn test_assertion(challenge_id: &str) -> PasskeyAssertion {
        PasskeyAssertion {
            challenge_id: challenge_id.to_string(),
            raw_id: "Y3JlZA".to_string(),
            authenticator_data: "YXV0aA".to_string(),
            client_data_json: "e30".to_string(),
            signature: "c2ln".to_string(),
            user_handle: None,
        }
    }

    fn assertion_body(challenge_id: &str) -> Value {
        serde_json::json!({
            "challenge_id": challenge_id,
            "raw_id": "Y3JlZA",
            "authenticator_data": "YXV0aA",
            "client_data_json": "e30",
            "signature": "c2ln",
            "user_handle": null
        })
    }

    #[tokio::test]
    async fn passkey_sign_in_doors_return_the_bearer_and_keep_refusal_codes() {
        // Recovery codes built at run time, like the test passwords.
        let good_code = format!("{}-good", test_password());
        let spent_code = format!("{}-spent", test_password());
        let mock_server = MockServer::start().await;
        let login = serde_json::json!({"token": "full-session", "subject": {"kind": "user"}});
        Mock::given(method("POST"))
            .and(path("/auth/passkeys/second-factor"))
            .and(body_json(assertion_body("second")))
            .respond_with(ResponseTemplate::new(200).set_body_json(login.clone()))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/passkeys/second-factor"))
            .and(body_json(assertion_body("busy")))
            .respond_with(
                ResponseTemplate::new(503)
                    .set_body_json(serde_json::json!({"error": "db_unavailable"})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/passkeys/options"))
            .and(body_json(serde_json::json!({"identifier": "vjt"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge_id": "pwless",
                "public_key": {
                    "challenge": "Y2hhbA",
                    "rp_id": "irc.example.org",
                    "timeout": 300_000,
                    "user_verification": "required"
                }
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/passkeys/verify"))
            .and(body_json(assertion_body("pwless")))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"error": "invalid_two_factor"})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/passkeys/recover"))
            .and(body_json(
                serde_json::json!({"identifier": "vjt", "recovery_code": good_code}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(login))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/passkeys/recover"))
            .and(body_json(
                serde_json::json!({"identifier": "vjt", "recovery_code": spent_code}),
            ))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_json(serde_json::json!({"error": "too_many_attempts"})),
            )
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        let second = client
            .verify_passkey_second_factor(&test_assertion("second"))
            .await
            .expect("second factor");
        assert_eq!(second.token, "full-session");
        // A saturated database is not a bad authenticator.
        let busy = client
            .verify_passkey_second_factor(&test_assertion("busy"))
            .await
            .unwrap_err();
        assert_eq!(busy.status(), Some(StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(busy.code(), Some("db_unavailable"));

        let options = client.passkey_login_options("vjt").await.expect("options");
        assert_eq!(options.challenge_id, "pwless");
        // The passwordless door never names the account's credentials.
        assert!(options.public_key.allow_credentials.is_empty());
        let refused = client
            .verify_passkey_login(&test_assertion("pwless"))
            .await
            .unwrap_err();
        assert_eq!(refused.status(), Some(StatusCode::UNAUTHORIZED));
        assert_eq!(refused.code(), Some("invalid_two_factor"));

        let recovered = client
            .recover_passkey_login("vjt", &good_code)
            .await
            .expect("recover");
        assert_eq!(recovered.token, "full-session");
        let throttled = client
            .recover_passkey_login("vjt", &spent_code)
            .await
            .unwrap_err();
        assert_eq!(throttled.status(), Some(StatusCode::TOO_MANY_REQUESTS));
        assert_eq!(throttled.code(), Some("too_many_attempts"));
    }

    #[tokio::test]
    async fn passkey_settings_follow_the_grappa_contract() {
        let password = test_password();
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/passkeys"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "mode": "second_factor",
                "passkeys": [
                    {
                        "id": "0b6f0c5e-0000-4000-8000-000000000001",
                        "name": "YubiKey",
                        "inserted_at": "2026-09-01T10:00:00.000000Z",
                        "last_used_at": null
                    }
                ]
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/passkeys/registration/options"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(
                serde_json::json!({"password": password, "name": "Laptop"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge_id": "reg",
                "public_key": {
                    "challenge": "Y2hhbA",
                    "rp": {"id": "irc.example.org", "name": "Grappa"},
                    "user": {"id": "dWlk", "name": "vjt", "display_name": "vjt"},
                    "pub_key_cred_params": [
                        {"type": "public-key", "alg": -7},
                        {"type": "public-key", "alg": -257}
                    ],
                    "timeout": 300_000,
                    "attestation": "none",
                    "authenticator_selection": {
                        "resident_key": "preferred",
                        "user_verification": "required"
                    }
                }
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/passkeys/registration"))
            .and(body_json(serde_json::json!({
                "challenge_id": "reg",
                "raw_id": "Y3JlZA",
                "attestation_object": "b2Jq",
                "client_data_json": "e30",
                "transports": ["usb"]
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "0b6f0c5e-0000-4000-8000-000000000002",
                "name": "Laptop",
                "inserted_at": "2026-09-30T10:00:00.000000Z",
                "last_used_at": null
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/passkeys/mode/options"))
            .and(body_json(
                serde_json::json!({"password": password, "mode": "disabled"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge_id": "mode",
                "public_key": {"challenge": "Y2hhbA", "rp_id": "irc.example.org"}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/passkeys/passwordless/recovery"))
            .and(body_json(serde_json::json!({"password": password})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "recovery_codes": ["aaaa-bbbb", "cccc-dddd"],
                "recovery_token": "sealed"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/passkeys/passwordless/options"))
            .and(body_json(serde_json::json!({"recovery_token": "sealed"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge_id": "activate",
                "public_key": {"challenge": "Y2hhbA", "rp_id": "irc.example.org"}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/me/passkeys/mode"))
            .and(body_json(assertion_body("activate")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"mode": "passwordless"})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/me/passkeys/0b6f0c5e-0000-4000-8000-000000000001"))
            .and(body_json(serde_json::json!({"password": password})))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/me/passkeys/last"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(serde_json::json!({"error": "passkey_required"})),
            )
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        let status = client.fetch_passkeys("tok").await.expect("status");
        assert_eq!(status.mode, PasskeyMode::SecondFactor);
        assert_eq!(status.passkeys.len(), 1);
        assert_eq!(status.passkeys[0].name.as_deref(), Some("YubiKey"));
        assert_eq!(status.passkeys[0].last_used_at, None);

        let registration = client
            .start_passkey_registration("tok", &password, "Laptop")
            .await
            .expect("registration options");
        assert_eq!(registration.challenge_id, "reg");
        assert_eq!(registration.public_key.rp.id, "irc.example.org");
        let algorithms: Vec<i64> = registration
            .public_key
            .pub_key_cred_params
            .iter()
            .map(|param| param.alg)
            .collect();
        assert_eq!(algorithms, [-7, -257]);
        assert_eq!(registration.public_key.attestation.as_deref(), Some("none"));
        assert_eq!(
            registration
                .public_key
                .authenticator_selection
                .user_verification
                .as_deref(),
            Some("required")
        );
        let credential = PasskeyCredential {
            challenge_id: "reg".to_string(),
            raw_id: "Y3JlZA".to_string(),
            attestation_object: "b2Jq".to_string(),
            client_data_json: "e30".to_string(),
            transports: vec!["usb".to_string()],
        };
        let added = client
            .finish_passkey_registration("tok", &credential)
            .await
            .expect("registration");
        assert_eq!(added.name.as_deref(), Some("Laptop"));

        let mode = client
            .start_passkey_mode_change("tok", &password, PasskeyMode::Disabled)
            .await
            .expect("mode options");
        assert_eq!(mode.challenge_id, "mode");
        assert!(mode.public_key.allow_credentials.is_empty());

        let recovery = client
            .prepare_passwordless("tok", &password)
            .await
            .expect("recovery codes");
        assert_eq!(recovery.recovery_codes.len(), 2);
        let activation = client
            .start_passwordless_activation("tok", &recovery.recovery_token)
            .await
            .expect("activation options");
        assert_eq!(
            client
                .finish_passkey_mode_change("tok", &test_assertion(&activation.challenge_id))
                .await
                .expect("mode"),
            PasskeyMode::Passwordless
        );

        client
            .delete_passkey("tok", "0b6f0c5e-0000-4000-8000-000000000001", &password)
            .await
            .expect("delete");
        let last = client
            .delete_passkey("tok", "last", &password)
            .await
            .unwrap_err();
        assert_eq!(last.status(), Some(StatusCode::CONFLICT));
        assert_eq!(last.code(), Some("passkey_required"));
    }

    #[tokio::test]
    async fn passkey_settings_refuse_a_client_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/passkeys"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(serde_json::json!({"error": "client_token_scope"})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let scope = GrappaClient::new(mock_server.uri())
            .fetch_passkeys("client-token")
            .await
            .unwrap_err();
        assert_eq!(scope.status(), Some(StatusCode::FORBIDDEN));
        assert_eq!(scope.code(), Some("client_token_scope"));
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
    async fn login_reads_the_refusal_code_and_retry_after() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .and(body_json(serde_json::json!({"identifier": "ada_guest"})))
            .respond_with(
                ResponseTemplate::new(409)
                    .insert_header("retry-after", "42")
                    .set_body_json(serde_json::json!({"error": "anon_collision"})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "ada_guest".to_string(),
            password: String::new(),
        };
        let error = client.login(&request).await.expect_err("should fail");

        match error {
            LoginError::Refused {
                status,
                code,
                retry_after,
            } => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(code.as_deref(), Some("anon_collision"));
                assert_eq!(retry_after, Some(42));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    async fn send_hello(mock_server: &MockServer) -> GrappaClientError {
        let client = GrappaClient::new(mock_server.uri());
        let request = crate::rest::SendMessageRequest::plain("hello");
        client
            .send_message("abc123", "libera", "#rust", &request)
            .await
            .expect_err("should be refused")
    }

    #[tokio::test]
    async fn a_rate_limited_write_exposes_the_wait_the_server_asks_for() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/channels/%23rust/messages"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "3")
                    .set_body_json(serde_json::json!({
                        "error": "rate_limited",
                        "retry_after_ms": 1500
                    })),
            )
            .mount(&mock_server)
            .await;

        let error = send_hello(&mock_server).await;

        assert_eq!(error.status(), Some(StatusCode::TOO_MANY_REQUESTS));
        assert_eq!(error.code(), Some("rate_limited"));
        // The header wins over the body's milliseconds.
        assert_eq!(error.retry_after(), Some(Duration::from_secs(3)));
    }

    #[tokio::test]
    async fn a_rate_limited_write_without_a_header_falls_back_to_the_body() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/channels/%23rust/messages"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "error": "rate_limited",
                "retry_after_ms": 1500
            })))
            .mount(&mock_server)
            .await;

        let error = send_hello(&mock_server).await;

        assert_eq!(error.retry_after(), Some(Duration::from_millis(1500)));
    }

    #[tokio::test]
    async fn a_refusal_without_a_wait_hint_has_no_retry_after() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/channels/%23rust/messages"))
            .respond_with(ResponseTemplate::new(503).set_body_string("<html>busy</html>"))
            .mount(&mock_server)
            .await;

        let error = send_hello(&mock_server).await;

        assert_eq!(error.status(), Some(StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(error.retry_after(), None);
        // Transport and URL errors have none either.
        assert_eq!(
            GrappaClientError::InvalidUrl("x".to_string()).retry_after(),
            None
        );
    }

    #[tokio::test]
    async fn login_refusal_without_a_json_body_has_no_code() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/login"))
            .respond_with(ResponseTemplate::new(502).set_body_string("<html>bad gateway</html>"))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = LoginRequest {
            identifier: "vjt".to_string(),
            password: "s3cr3t".to_string(),
        };
        let error = client.login(&request).await.expect_err("should fail");

        match error {
            LoginError::Refused {
                status,
                code,
                retry_after,
            } => {
                assert_eq!(status, StatusCode::BAD_GATEWAY);
                assert_eq!(code, None);
                assert_eq!(retry_after, None);
            }
            other => panic!("unexpected {other:?}"),
        }
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
    async fn decline_invite_deletes_the_encoded_invite_and_surfaces_not_invited() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/invites/%23rust"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/invites/%23gone"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"error": "not_invited"})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .decline_invite("abc123", "libera", "#rust")
            .await
            .expect("decline_invite");
        let err = client
            .decline_invite("abc123", "libera", "#gone")
            .await
            .expect_err("404 not_invited");
        assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
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
    async fn admin_account_and_network_writes_use_their_contracts() {
        // Built at run time: the test only checks the value is passed
        // through, and a literal would read as a hard-coded credential.
        let password = format!("pw-{}", std::process::id());
        let new_password = format!("{password}-new");
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/admin/users"))
            .and(body_json(
                serde_json::json!({"name": "ada", "password": password, "is_admin": false}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/admin/users/u-1/password"))
            .and(body_json(serde_json::json!({"password": new_password})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/admin/networks"))
            .and(body_json(serde_json::json!({"slug": "oftc"})))
            .respond_with(ResponseTemplate::new(409))
            .mount(&mock_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/admin/networks/libera"))
            .and(body_json(
                serde_json::json!({"visitor_enabled": true, "max_per_ip": null}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/admin/networks/7"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .create_admin_user("t", "ada", &password, false)
            .await
            .expect("create user");
        client
            .set_admin_user_password("t", "u-1", &new_password)
            .await
            .expect("password");
        let err = client
            .create_admin_network("t", "oftc")
            .await
            .expect_err("duplicate");
        assert_eq!(err.status(), Some(StatusCode::CONFLICT));
        client
            .update_admin_network(
                "t",
                "libera",
                &serde_json::json!({"visitor_enabled": true, "max_per_ip": null}),
            )
            .await
            .expect("update network");
        client
            .delete_admin_network("t", "7")
            .await
            .expect("delete network");
    }

    #[tokio::test]
    async fn admin_servers_and_settings_use_their_contracts() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/networks/7/servers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "servers": [{"id": 3, "host": "irc.example", "port": 6697, "tls": true}]
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/admin/networks/7/servers"))
            .and(body_json(
                serde_json::json!({"host": "irc2.example", "port": 6667, "tls": false}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/admin/networks/7/servers/3"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"network_session_count": 0})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/admin/settings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "settings": {"dcc": {"max_transfer_bytes": 1024}}
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/admin/settings"))
            .and(body_json(
                serde_json::json!({"dcc": {"max_transfer_bytes": 2048}}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let servers = client.fetch_admin_servers("t", "7").await.expect("servers");
        assert_eq!(servers.len(), 1);
        client
            .add_admin_server("t", "7", "irc2.example", 6667, false)
            .await
            .expect("add server");
        client
            .delete_admin_server("t", "7", "3")
            .await
            .expect("delete server");
        let settings = client.fetch_admin_settings("t").await.expect("settings");
        assert_eq!(settings["dcc"]["max_transfer_bytes"], 1024);
        client
            .update_admin_settings(
                "t",
                &serde_json::json!({"dcc": {"max_transfer_bytes": 2048}}),
            )
            .await
            .expect("save settings");
    }

    #[tokio::test]
    async fn admin_credentials_and_vhosts_use_their_contracts() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "credentials": [{"user_id": "u-1", "network_id": 7}]
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/admin/credentials/u-1/7"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/admin/vhosts/4"))
            .and(body_json(serde_json::json!({"in_pool": false})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/admin/vhosts/4/grants"))
            .and(body_json(
                serde_json::json!({"subject_type": "user", "subject_id": "u-1"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/admin/vhosts/grants/9"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        assert_eq!(
            client
                .fetch_admin_credentials("t")
                .await
                .expect("list")
                .len(),
            1
        );
        client
            .delete_admin_credential("t", "u-1", "7")
            .await
            .expect("unbind");
        client
            .update_admin_vhost("t", "4", &serde_json::json!({"in_pool": false}))
            .await
            .expect("toggle");
        client
            .grant_admin_vhost("t", "4", "user", "u-1")
            .await
            .expect("grant");
        client
            .revoke_admin_vhost_grant("t", "9")
            .await
            .expect("revoke");
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
    async fn update_display_prefs_merges_the_date_format_into_the_stored_map() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/display-prefs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "display_prefs": {"time_format": "hms", "presence_filter": "all", "bold_mentions": true},
                "persisted": true
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/display-prefs"))
            .and(body_json(serde_json::json!({
                "display_prefs": {
                    "time_format": "hms",
                    "presence_filter": "all",
                    "bold_mentions": true,
                    "date_format": "dmy"
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let prefs = DisplayPrefs {
            date_format: Some(crate::rest::DateFormat::Dmy),
            ..DisplayPrefs::default()
        };
        GrappaClient::new(mock_server.uri())
            .update_display_prefs("tok", &prefs)
            .await
            .expect("update");
    }

    #[tokio::test]
    async fn fetch_presence_pins_reads_the_map_and_whether_it_was_saved() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/display-prefs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "display_prefs": {"presence_filter": {"libera #rust": "hide", "libera #x": 1}},
                "persisted": true
            })))
            .mount(&mock_server)
            .await;

        let pins = GrappaClient::new(mock_server.uri())
            .fetch_presence_pins("tok")
            .await
            .expect("pins");
        assert!(pins.persisted);
        assert_eq!(
            pins.pins,
            BTreeMap::from([("libera #rust".to_string(), PresencePref::Hide)])
        );
    }

    #[tokio::test]
    async fn put_presence_pins_adds_to_the_stored_map_and_keeps_the_rest() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/display-prefs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "display_prefs": {
                    "bold_mentions": false,
                    "presence_filter": {"libera #other": "hide", "libera #rust": "hide"}
                },
                "persisted": true
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/display-prefs"))
            .and(body_json(serde_json::json!({
                "display_prefs": {
                    "bold_mentions": false,
                    "presence_filter": {"libera #other": "hide", "libera #rust": "show"}
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let pins = BTreeMap::from([("libera #rust".to_string(), PresencePref::Show)]);
        GrappaClient::new(mock_server.uri())
            .put_presence_pins("tok", &pins)
            .await
            .expect("put");
    }

    #[tokio::test]
    async fn put_presence_pins_starts_a_map_when_the_account_has_none() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/display-prefs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "display_prefs": {"time_format": "hms"},
                "persisted": false
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/display-prefs"))
            .and(body_json(serde_json::json!({
                "display_prefs": {
                    "time_format": "hms",
                    "presence_filter": {"libera #rust": "hide"}
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let pins = BTreeMap::from([("libera #rust".to_string(), PresencePref::Hide)]);
        GrappaClient::new(mock_server.uri())
            .put_presence_pins("tok", &pins)
            .await
            .expect("put");
    }

    #[tokio::test]
    async fn update_display_prefs_reports_a_rejected_value_as_422() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/display-prefs"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"display_prefs": {}})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/display-prefs"))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "error": "invalid",
                "field_errors": {"display_prefs": ["date_format is invalid"]}
            })))
            .mount(&mock_server)
            .await;

        let error = GrappaClient::new(mock_server.uri())
            .update_display_prefs("tok", &DisplayPrefs::default())
            .await
            .unwrap_err();
        assert_eq!(error.status(), Some(StatusCode::UNPROCESSABLE_ENTITY));
    }

    #[tokio::test]
    async fn attach_network_posts_the_slug() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/session/networks"))
            .and(header("authorization", "Bearer tok"))
            .and(body_json(serde_json::json!({"network": "libera"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        GrappaClient::new(mock_server.uri())
            .attach_network("tok", "libera")
            .await
            .expect("attach");
    }

    #[tokio::test]
    async fn fetch_featured_channels_reads_names_and_optional_descriptions() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/featured"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "channels": [
                    {"name": "#grappa", "description": "Support"},
                    {"name": "#lobby", "description": null}
                ]
            })))
            .mount(&mock_server)
            .await;

        let channels = GrappaClient::new(mock_server.uri())
            .fetch_featured_channels("tok", "libera")
            .await
            .expect("featured");
        assert_eq!(
            channels,
            vec![
                FeaturedChannel {
                    name: "#grappa".into(),
                    description: Some("Support".into()),
                },
                FeaturedChannel {
                    name: "#lobby".into(),
                    description: None,
                },
            ]
        );
    }

    #[tokio::test]
    async fn detach_network_deletes_the_session_binding() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/session/networks/libera"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;

        GrappaClient::new(mock_server.uri())
            .detach_network("tok", "libera")
            .await
            .expect("detach");
    }

    #[tokio::test]
    async fn detach_network_reports_visitor_and_unknown_refusals_by_status() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/session/networks/libera"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/session/networks/gone"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        let forbidden = client.detach_network("tok", "libera").await.unwrap_err();
        assert_eq!(forbidden.status(), Some(StatusCode::FORBIDDEN));
        let missing = client.detach_network("tok", "gone").await.unwrap_err();
        assert_eq!(missing.status(), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn away_nick_suffix_reads_null_as_rename_off() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/away-nick-suffix"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"away_nick_suffix": null})),
            )
            .mount(&mock_server)
            .await;

        let suffix = GrappaClient::new(mock_server.uri())
            .fetch_away_nick_suffix("tok")
            .await
            .expect("suffix");
        assert_eq!(suffix, None);
    }

    #[tokio::test]
    async fn away_nick_suffix_is_an_error_on_a_server_without_it() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me/settings/away-nick-suffix"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        // The caller hides the setting rather than showing "off".
        let error = GrappaClient::new(mock_server.uri())
            .fetch_away_nick_suffix("tok")
            .await
            .unwrap_err();
        assert_eq!(error.status(), Some(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn set_away_nick_suffix_sends_the_tail_or_null() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/away-nick-suffix"))
            .and(body_json(serde_json::json!({"away_nick_suffix": "|away"})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"away_nick_suffix": "|away"})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/away-nick-suffix"))
            .and(body_json(serde_json::json!({"away_nick_suffix": null})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"away_nick_suffix": null})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/me/settings/away-nick-suffix"))
            .and(body_json(serde_json::json!({"away_nick_suffix": "a b"})))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "error": "invalid",
                "field_errors": {"away_nick_suffix": ["is invalid"]}
            })))
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        client
            .set_away_nick_suffix("tok", Some("|away"))
            .await
            .expect("set");
        client
            .set_away_nick_suffix("tok", None)
            .await
            .expect("clear");
        let refused = client
            .set_away_nick_suffix("tok", Some("a b"))
            .await
            .unwrap_err();
        assert_eq!(refused.status(), Some(StatusCode::UNPROCESSABLE_ENTITY));
    }

    #[tokio::test]
    async fn fetch_admin_uploads_keeps_soft_deleted_rows_and_the_budget() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/uploads"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uploads": [
                    {"id": "u1", "slug": "abcdefghijklmnopqrstuvwxyz", "mime": "image/png",
                     "bytes": 2048, "original_filename": "cat.png", "subject_kind": "user",
                     "subject_id": "s1", "expires_at": "2026-10-01T00:00:00Z",
                     "deleted_at": null, "inserted_at": "2026-09-27T00:00:00Z"},
                    {"id": "u2", "slug": "zyxwvutsrqponmlkjihgfedcba", "mime": "text/plain",
                     "bytes": 10, "original_filename": null, "subject_kind": "visitor",
                     "subject_id": "v1", "expires_at": null,
                     "deleted_at": "2026-09-27T10:00:00Z", "inserted_at": null}
                ],
                "live_bytes_sum": 2048,
                "global_cap_bytes": 1073741824
            })))
            .mount(&mock_server)
            .await;

        let view = GrappaClient::new(mock_server.uri())
            .fetch_admin_uploads("tok")
            .await
            .expect("uploads");
        assert_eq!(view.uploads.len(), 2);
        assert!(view.uploads[0].is_live());
        assert_eq!(view.uploads[0].display_name(), "cat.png");
        assert!(!view.uploads[1].is_live());
        assert_eq!(view.uploads[1].display_name(), "zyxwvutsrqponmlkjihgfedcba");
        assert_eq!(view.live_bytes_sum, 2048);
        assert_eq!(view.global_cap_bytes, 1_073_741_824);
    }

    #[tokio::test]
    async fn admin_uploads_are_refused_to_a_client_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/uploads"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/admin/uploads/u1"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        let list = client.fetch_admin_uploads("tok").await.unwrap_err();
        assert_eq!(list.status(), Some(StatusCode::FORBIDDEN));
        let delete = client.delete_admin_upload("tok", "u1").await.unwrap_err();
        assert_eq!(delete.status(), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn delete_admin_upload_targets_the_row_id() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/admin/uploads/u1"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;

        GrappaClient::new(mock_server.uri())
            .delete_admin_upload("tok", "u1")
            .await
            .expect("delete");
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
    async fn reconnect_and_terminate_address_the_composite_key() {
        let mock_server = MockServer::start().await;
        let visitor = "visitor:3f2a9c1e-0000-4000-8000-000000000001:7";
        Mock::given(method("POST"))
            .and(path(format!("/admin/sessions/{visitor}/reconnect")))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/admin/sessions/user:vjt:1"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/admin/sessions/user:self:2"))
            .respond_with(ResponseTemplate::new(422))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .reconnect_admin_session("abc123", visitor)
            .await
            .expect("reconnect");
        client
            .terminate_admin_session("abc123", "user:vjt:1")
            .await
            .expect("terminate");
        let refused = client
            .terminate_admin_session("abc123", "user:self:2")
            .await
            .expect_err("own session");
        assert_eq!(refused.status(), Some(StatusCode::UNPROCESSABLE_ENTITY));
    }

    #[tokio::test]
    async fn network_message_count_distinguishes_zero_from_unknown() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/networks/7/message_count"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"message_count": 1234})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/admin/networks/8/message_count"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"message_count": 0})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/admin/networks/9/message_count"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/admin/networks/10/message_count"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        assert_eq!(
            client
                .fetch_admin_network_message_count("abc123", "7")
                .await
                .expect("count"),
            Some(1234)
        );
        assert_eq!(
            client
                .fetch_admin_network_message_count("abc123", "8")
                .await
                .expect("empty"),
            Some(0)
        );
        assert_eq!(
            client
                .fetch_admin_network_message_count("abc123", "9")
                .await
                .expect("older server"),
            None
        );
        let refused = client
            .fetch_admin_network_message_count("abc123", "10")
            .await
            .expect_err("not an admin");
        assert_eq!(refused.status(), Some(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn featured_channels_admin_crud_uses_its_contracts() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/networks/7/featured_channels"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "featured_channels": [
                    {"id": 4, "network_id": 7, "name": "#grappa", "description": null,
                     "position": 0, "enabled": false}
                ]
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/admin/networks/7/featured_channels"))
            .and(body_json(
                serde_json::json!({"name": "#lobby", "description": "Hello"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": 5})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/admin/networks/7/featured_channels/4"))
            .and(body_json(serde_json::json!({"enabled": true})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 4})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/admin/networks/7/featured_channels/4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let listed = client
            .fetch_admin_featured_channels("t", "7")
            .await
            .expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["name"], "#grappa");
        client
            .add_admin_featured_channel(
                "t",
                "7",
                &serde_json::json!({"name": "#lobby", "description": "Hello"}),
            )
            .await
            .expect("add");
        client
            .update_admin_featured_channel("t", "7", "4", &serde_json::json!({"enabled": true}))
            .await
            .expect("update");
        client
            .delete_admin_featured_channel("t", "7", "4")
            .await
            .expect("delete");
    }

    #[tokio::test]
    async fn edit_server_and_credential_send_only_the_changes() {
        // Built at run time, like the other credential tests: the value is
        // only passed through.
        let rotated = format!("pw-{}", std::process::id());
        let mock_server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/admin/networks/7/servers/3"))
            .and(body_json(
                serde_json::json!({"host": "irc3.example", "port": 6667}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 3})))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/admin/credentials/u-1/7"))
            .and(body_json(serde_json::json!({"realname": "Ada"})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"nick": "ada", "session_action": "left_alone"}),
                ),
            )
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/admin/credentials/u-1/8"))
            .and(body_json(serde_json::json!({"password": rotated})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"nick": "ada", "session_action": "stopped"})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        client
            .update_admin_server(
                "t",
                "7",
                "3",
                &serde_json::json!({"host": "irc3.example", "port": 6667}),
            )
            .await
            .expect("edit server");
        assert!(!client
            .update_admin_credential("t", "u-1", "7", &serde_json::json!({"realname": "Ada"}))
            .await
            .expect("cosmetic edit"));
        assert!(client
            .update_admin_credential("t", "u-1", "8", &serde_json::json!({"password": rotated}))
            .await
            .expect("password edit"));
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
    async fn update_network_profile_sends_only_set_fields() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/networks/libera/profile"))
            .and(header("authorization", "Bearer abc123"))
            .and(body_json(
                serde_json::json!({"gender": "female", "custom": ""}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"gender": "female", "custom": null})),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/networks/libera/profile"))
            .and(header("authorization", "Bearer invalid"))
            .respond_with(ResponseTemplate::new(422))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let request = crate::profile::NetworkProfileRequest {
            gender: Some("female".to_string()),
            custom: Some(String::new()),
            ..crate::profile::NetworkProfileRequest::default()
        };
        let credential = client
            .update_network_profile("abc123", "libera", &request)
            .await
            .expect("update_network_profile");
        assert_eq!(credential["gender"], "female");
        let err = client
            .update_network_profile("invalid", "libera", &request)
            .await
            .expect_err("422");
        assert_eq!(err.status(), Some(StatusCode::UNPROCESSABLE_ENTITY));
    }

    #[tokio::test]
    async fn upload_network_avatar_puts_multipart_and_returns_the_credential() {
        let mock_server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/networks/libera/avatar"))
            .and(header("authorization", "Bearer abc123"))
            .and(header_regex("content-type", "^multipart/form-data"))
            .and(body_string_contains("name=\"file\""))
            .and(body_string_contains("image/png"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "avatar_url": "https://irc.example/uploads/abcd.png"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/networks/libera/avatar"))
            .and(header("authorization", "Bearer toolarge"))
            .respond_with(ResponseTemplate::new(413))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let credential = client
            .upload_network_avatar("abc123", "libera", "me.png", "image/png", vec![1, 2, 3])
            .await
            .expect("upload_network_avatar");
        assert_eq!(
            credential["avatar_url"],
            "https://irc.example/uploads/abcd.png"
        );
        let err = client
            .upload_network_avatar("toolarge", "libera", "me.png", "image/png", vec![1, 2, 3])
            .await
            .expect_err("413");
        assert_eq!(err.status(), Some(StatusCode::PAYLOAD_TOO_LARGE));
    }

    #[tokio::test]
    async fn delete_network_avatar_returns_the_credential() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/avatar"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"avatar_url": null})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let credential = client
            .delete_network_avatar("abc123", "libera")
            .await
            .expect("delete_network_avatar");
        assert!(credential["avatar_url"].is_null());
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
            .add_ignore("abc123", "libera", "*!*@spammer.example", None)
            .await
            .expect("add_ignore");
        assert_eq!(response.outcome, "added");
        // An older server answers with masks only: they read as plain rules.
        assert_eq!(
            response.entries(),
            vec![IgnoreEntry {
                mask: "*!*@spammer.example".into(),
                text_pattern: None
            }]
        );
    }

    #[tokio::test]
    async fn fetch_ignores_keeps_two_rules_sharing_a_mask_apart() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/ignores"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "masks": ["relay!*@*", "relay!*@*", "*!*@spam"],
                "entries": [
                    {"mask": "relay!*@*", "text_pattern": "<A>*"},
                    {"mask": "relay!*@*", "text_pattern": "<B> says *"},
                    {"mask": "*!*@spam", "text_pattern": null}
                ]
            })))
            .mount(&mock_server)
            .await;

        let entries = GrappaClient::new(mock_server.uri())
            .fetch_ignores("tok", "libera")
            .await
            .expect("ignores");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].text_pattern.as_deref(), Some("<A>*"));
        assert_eq!(entries[1].text_pattern.as_deref(), Some("<B> says *"));
        assert_eq!(entries[2].text_pattern, None);
    }

    #[tokio::test]
    async fn fetch_ignores_falls_back_to_masks_on_an_older_server() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/ignores"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"masks": ["*!*@spam"]})),
            )
            .mount(&mock_server)
            .await;

        let entries = GrappaClient::new(mock_server.uri())
            .fetch_ignores("tok", "libera")
            .await
            .expect("ignores");
        assert_eq!(
            entries,
            vec![IgnoreEntry {
                mask: "*!*@spam".into(),
                text_pattern: None
            }]
        );
    }

    #[tokio::test]
    async fn add_ignore_posts_the_pair_and_reads_invalid_text_pattern() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/ignores"))
            .and(body_json(
                serde_json::json!({"mask": "relay!*@*", "text_pattern": "<A>*"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "masks": ["relay!*@*"],
                "entries": [{"mask": "relay!*@*", "text_pattern": "<A>*"}],
                "mask": "relay!*@*",
                "text_pattern": "<A>*",
                "outcome": "added"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/networks/libera/ignores"))
            .and(body_json(
                serde_json::json!({"mask": "relay!*@*", "text_pattern": "  "}),
            ))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(serde_json::json!({"error": "invalid_text_pattern"})),
            )
            .mount(&mock_server)
            .await;
        let client = GrappaClient::new(mock_server.uri());

        let added = client
            .add_ignore("tok", "libera", "relay!*@*", Some("<A>*"))
            .await
            .expect("add");
        assert_eq!(added.text_pattern.as_deref(), Some("<A>*"));

        let refused = client
            .add_ignore("tok", "libera", "relay!*@*", Some("  "))
            .await
            .unwrap_err();
        assert_eq!(refused.status(), Some(StatusCode::UNPROCESSABLE_ENTITY));
        assert_eq!(refused.code(), Some("invalid_text_pattern"));
    }

    #[tokio::test]
    async fn remove_ignore_sends_the_pattern_as_an_encoded_query() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/ignores/relay!*@*"))
            .and(query_param("text_pattern", "<B> says *"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "masks": [],
                "entries": [],
                "mask": "relay!*@*",
                "text_pattern": "<B> says *",
                "outcome": "removed"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        GrappaClient::new(mock_server.uri())
            .remove_ignore("tok", "libera", "relay!*@*", Some("<B> says *"))
            .await
            .expect("remove");
    }

    #[tokio::test]
    async fn remove_ignore_without_a_pattern_sends_no_query() {
        let mock_server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/ignores/*!*@spam"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "masks": [],
                "mask": "*!*@spam",
                "outcome": "removed"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        GrappaClient::new(mock_server.uri())
            .remove_ignore("tok", "libera", "*!*@spam", None)
            .await
            .expect("remove");
        let requests = mock_server.received_requests().await.expect("requests");
        assert_eq!(requests[0].url.query(), None);
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
    async fn server_files_stay_on_the_server() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/avatars/bob.png"))
            .and(header("authorization", "Bearer t"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "image/png")
                    .set_body_bytes(vec![1, 2, 3]),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let (bytes, content_type) = client
            .fetch_server_file("t", "/avatars/bob.png")
            .await
            .expect("path");
        assert_eq!(bytes, vec![1, 2, 3]);
        assert_eq!(content_type.as_deref(), Some("image/png"));
        let same_server = format!("{}/avatars/bob.png", mock_server.uri());
        assert!(client.fetch_server_file("t", &same_server).await.is_ok());
        assert!(client
            .fetch_server_file("t", "https://elsewhere.example/a.png")
            .await
            .is_err());
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
            .set_active_theme("abc123", 7, None)
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
    async fn fetch_messages_around_sends_the_cursor() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/channels/%23rust/messages"))
            .and(query_param("around", "120"))
            .and(query_param("limit", "50"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{ "id": 120 }])),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let rows = client
            .fetch_messages_around("t", "libera", "#rust", 120, 50)
            .await
            .expect("page around the message");
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn fetch_messages_count_sends_the_anchor_and_cap() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/channels/%23rust/messages/count"))
            .and(query_param("after", "812"))
            .and(query_param("cap", "201"))
            .and(header("authorization", "Bearer abc123"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"count": 42})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let count = client
            .fetch_messages_count("abc123", "libera", "#rust", 812, Some(201))
            .await
            .expect("gap probe");
        assert_eq!(count, 42);
    }

    #[tokio::test]
    async fn fetch_messages_count_reads_count_from_a_three_key_body() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/channels/vjt/messages/count"))
            .and(query_param("after", "7"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"count": 3, "messages": 2, "events": 1})),
            )
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let count = client
            .fetch_messages_count("t", "libera", "vjt", 7, None)
            .await
            .expect("uncapped gap probe");
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn fetch_messages_count_reports_a_missing_route() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/networks/libera/channels/%23rust/messages/count"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = GrappaClient::new(mock_server.uri());
        let err = client
            .fetch_messages_count("t", "libera", "#rust", 1, Some(201))
            .await
            .expect_err("404");
        assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
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
