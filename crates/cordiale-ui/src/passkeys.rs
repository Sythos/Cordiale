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

//! Settings > Security: the account's passkeys (issue #147). Cordiale
//! can't run a WebAuthn ceremony yet (see `docs/passkey-spike.md`), so the
//! page shows the mode and the passkeys and deletes them with the password;
//! adding one or changing the mode stays in Cicchetto. Like TOTP, a
//! per-client token is refused with 403 `client_token_scope`.

use cordiale_core::client::GrappaClientError;
use cordiale_core::rest::PasskeyMode;

/// The mode as the page's `security-passkey-mode` key.
pub(crate) fn mode_key(mode: PasskeyMode) -> &'static str {
    match mode {
        PasskeyMode::Disabled => "disabled",
        PasskeyMode::SecondFactor => "second_factor",
        PasskeyMode::Passwordless => "passwordless",
    }
}

/// Status key for a refused passkey settings call. A 401 is a wrong
/// password (never a dead session), a 409 the last passkey a mode still
/// needs, and a 503 a busy server, which must not read as a bad request.
/// `gone` (404) only asks for a fresh list.
pub(crate) fn settings_error_key(err: &GrappaClientError) -> &'static str {
    match (err.status().map(|status| status.as_u16()), err.code()) {
        (_, Some("client_token_scope")) | (Some(403), _) => "client-token",
        (_, Some("passkey_required")) | (Some(409), _) => "last-passkey",
        (Some(404), _) => "gone",
        (_, Some("db_unavailable")) | (Some(503), _) => "busy",
        (Some(401), _) => "wrong-password",
        (Some(429), _) => "throttled",
        _ => "failed",
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
}
