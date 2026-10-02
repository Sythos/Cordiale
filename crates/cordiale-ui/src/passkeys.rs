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

//! Passkeys in the UI: Settings > Security (issue #147) and the status
//! keys of a passkey sign-in (issue #160). The page shows the mode and the
//! passkeys and deletes them with the password everywhere; adding one and
//! changing the mode need a ceremony, which only some platforms can run
//! (see `ceremony`). Like TOTP, a per-client token is refused with 403
//! `client_token_scope`.

use cordiale_core::client::GrappaClientError;
use cordiale_core::rest::PasskeyMode;

use crate::ceremony::CeremonyError;

/// The modes Settings can switch to directly; passwordless has its own
/// two-step door.
pub(crate) fn settable_mode(key: &str) -> Option<PasskeyMode> {
    match key {
        "second_factor" => Some(PasskeyMode::SecondFactor),
        "disabled" => Some(PasskeyMode::Disabled),
        _ => None,
    }
}

/// The mode as the page's `security-passkey-mode` key.
pub(crate) fn mode_key(mode: PasskeyMode) -> &'static str {
    match mode {
        PasskeyMode::Disabled => "disabled",
        PasskeyMode::SecondFactor => "second_factor",
        PasskeyMode::Passwordless => "passwordless",
    }
}

/// Status key for a refused passkey settings call. A 401 is a wrong
/// password (never a dead session), unless its code is `invalid_two_factor`:
/// that is how Grappa refuses a ceremony, and it can't say whether the
/// authenticator was wrong or the origin Cordiale asserted differs from the
/// server's (`refused`; see `cordiale_core::passkey_origin`). A 409 is the
/// last passkey a mode still needs, and a 503 a busy server, which must not
/// read as a bad request. `gone` (404) only asks for a fresh list.
pub(crate) fn settings_error_key(err: &GrappaClientError) -> &'static str {
    match (err.status().map(|status| status.as_u16()), err.code()) {
        (_, Some("client_token_scope")) | (Some(403), _) => "client-token",
        (_, Some("passkey_required")) | (Some(409), _) => "last-passkey",
        (Some(404), _) => "gone",
        (_, Some("db_unavailable")) | (Some(503), _) => "busy",
        (_, Some("invalid_two_factor")) => "refused",
        (Some(401), _) => "wrong-password",
        (Some(429), _) => "throttled",
        _ => "failed",
    }
}

/// Status key for a refused passkey sign-in call, on the connect screen.
/// Every failed assertion is Grappa's opaque 401 `invalid_two_factor`,
/// which is also what a wrong origin looks like (`passkey-refused`); 401 `invalid_credentials`
/// on the passwordless door is an account that isn't passwordless.
pub(crate) fn sign_in_error_key(err: &GrappaClientError) -> &'static str {
    match (err.status().map(|status| status.as_u16()), err.code()) {
        (_, Some("invalid_credentials")) => "passkey-no-account",
        (_, Some("invalid_two_factor")) | (Some(401), _) => "passkey-refused",
        (_, Some("too_many_attempts")) | (Some(429), _) => "too-many-attempts",
        (_, Some("db_unavailable")) | (Some(503), _) => "passkey-busy",
        (None, _) => "unreachable",
        _ => "passkey-failed",
    }
}

/// Status key for a ceremony that produced no answer, on the connect
/// screen and in Settings alike.
pub(crate) fn ceremony_error_key(err: &CeremonyError) -> &'static str {
    match err {
        CeremonyError::Cancelled => "passkey-cancelled",
        CeremonyError::Unsupported
        | CeremonyError::InvalidOptions(_)
        | CeremonyError::Failed(_) => "passkey-failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordiale_core::client::StatusCode;

    fn rejected(status: u16, code: Option<&str>) -> GrappaClientError {
        GrappaClientError::Rejected {
            status: StatusCode::from_u16(status).expect("status"),
            code: code.map(str::to_string),
            retry_after: None,
        }
    }

    #[test]
    fn modes_map_to_the_wire_spelling() {
        assert_eq!(mode_key(PasskeyMode::Disabled), "disabled");
        assert_eq!(mode_key(PasskeyMode::SecondFactor), "second_factor");
        assert_eq!(mode_key(PasskeyMode::Passwordless), "passwordless");
    }

    #[test]
    fn refusals_keep_scope_last_passkey_and_busy_apart() {
        assert_eq!(
            settings_error_key(&rejected(403, Some("client_token_scope"))),
            "client-token"
        );
        assert_eq!(
            settings_error_key(&rejected(409, Some("passkey_required"))),
            "last-passkey"
        );
        assert_eq!(
            settings_error_key(&rejected(404, Some("not_found"))),
            "gone"
        );
        assert_eq!(
            settings_error_key(&rejected(503, Some("db_unavailable"))),
            "busy"
        );
        assert_eq!(
            settings_error_key(&rejected(401, Some("invalid_credentials"))),
            "wrong-password"
        );
        assert_eq!(
            settings_error_key(&rejected(429, Some("too_many_attempts"))),
            "throttled"
        );
        assert_eq!(settings_error_key(&rejected(500, None)), "failed");
    }

    #[test]
    fn only_the_direct_modes_are_settable() {
        assert_eq!(
            settable_mode("second_factor"),
            Some(PasskeyMode::SecondFactor)
        );
        assert_eq!(settable_mode("disabled"), Some(PasskeyMode::Disabled));
        assert_eq!(settable_mode("passwordless"), None);
    }

    #[test]
    fn sign_in_refusals_keep_account_answer_and_throttle_apart() {
        assert_eq!(
            sign_in_error_key(&rejected(401, Some("invalid_credentials"))),
            "passkey-no-account"
        );
        assert_eq!(
            sign_in_error_key(&rejected(401, Some("invalid_two_factor"))),
            "passkey-refused"
        );
        assert_eq!(
            sign_in_error_key(&rejected(429, Some("too_many_attempts"))),
            "too-many-attempts"
        );
        assert_eq!(
            sign_in_error_key(&rejected(503, Some("db_unavailable"))),
            "passkey-busy"
        );
        assert_eq!(sign_in_error_key(&rejected(500, None)), "passkey-failed");
        assert_eq!(
            ceremony_error_key(&CeremonyError::Cancelled),
            "passkey-cancelled"
        );
        assert_eq!(
            ceremony_error_key(&CeremonyError::Failed("0x80090029".into())),
            "passkey-failed"
        );
    }

    #[test]
    fn a_refused_ceremony_is_not_a_wrong_password() {
        assert_eq!(
            settings_error_key(&rejected(401, Some("invalid_two_factor"))),
            "refused"
        );
        assert_eq!(
            settings_error_key(&rejected(401, Some("invalid_credentials"))),
            "wrong-password"
        );
    }
}
