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

//! Settings > Security: the account's TOTP, as Cicchetto manages it
//! (issue #118). Enrolment re-authenticates with the password, shows the
//! secret as text and as a QR code for an authenticator app, arms it with a
//! first code and shows the recovery codes once; disabling asks for the
//! password again. A per-client token can't touch any of it (Grappa answers
//! 403 `client_token_scope`), which the page explains instead of offering a
//! setup that would fail. Passkeys stay out of scope.

use cordiale_core::client::GrappaClientError;
use qrcode::{Color, QrCode};

/// Modules of blank border around the code, as the QR spec asks.
const QUIET_ZONE: usize = 4;
/// Pixels per module, so the code scans comfortably from a screen.
const SCALE: usize = 6;

/// The `otpauth://` URI as an RGB bitmap (dark modules on white):
/// `(side in pixels, rgb bytes)`. `None` if the URI can't be encoded.
pub(crate) fn qr_rgb(uri: &str) -> Option<(u32, Vec<u8>)> {
    let code = QrCode::new(uri.as_bytes()).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let modules = width + 2 * QUIET_ZONE;
    let side = modules * SCALE;
    let mut rgb = vec![0xff_u8; side * side * 3];
    for (index, color) in colors.iter().enumerate() {
        if *color != Color::Dark {
            continue;
        }
        let (row, col) = (index / width + QUIET_ZONE, index % width + QUIET_ZONE);
        for y in row * SCALE..(row + 1) * SCALE {
            for x in col * SCALE..(col + 1) * SCALE {
                let at = (y * side + x) * 3;
                rgb[at..at + 3].fill(0);
            }
        }
    }
    Some((u32::try_from(side).ok()?, rgb))
}

/// Status key for a refused TOTP settings call. On these re-authenticating
/// doors a 401 is a wrong password, never a dead session.
pub(crate) fn settings_error_key(err: &GrappaClientError) -> &'static str {
    match (err.status().map(|status| status.as_u16()), err.code()) {
        (_, Some("client_token_scope")) | (Some(403), _) => "client-token",
        (_, Some("already_enabled")) | (Some(409), _) => "already-enabled",
        (_, Some("invalid_two_factor")) => "invalid-code",
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
    fn the_qr_code_is_a_square_bitmap_with_a_white_border() {
        let (side, rgb) =
            qr_rgb("otpauth://totp/Grappa:vjt?secret=JBSWY3DPEHPK3PXP&issuer=Grappa").expect("qr");
        let side = side as usize;
        assert_eq!(rgb.len(), side * side * 3);
        assert_eq!(side % SCALE, 0);
        // The quiet zone is white, and the finder pattern's corner is dark.
        assert!(rgb[..QUIET_ZONE * SCALE * 3]
            .iter()
            .all(|byte| *byte == 0xff));
        let corner = (QUIET_ZONE * SCALE * side + QUIET_ZONE * SCALE) * 3;
        assert_eq!(&rgb[corner..corner + 3], &[0, 0, 0]);
    }

    #[test]
    fn refusals_explain_the_scope_and_never_look_like_a_dead_session() {
        assert_eq!(
            settings_error_key(&rejected(403, Some("client_token_scope"))),
            "client-token"
        );
        assert_eq!(
            settings_error_key(&rejected(409, Some("already_enabled"))),
            "already-enabled"
        );
        assert_eq!(
            settings_error_key(&rejected(401, Some("invalid_two_factor"))),
            "invalid-code"
        );
        assert_eq!(
            settings_error_key(&rejected(401, Some("invalid_credentials"))),
            "wrong-password"
        );
        assert_eq!(settings_error_key(&rejected(429, None)), "throttled");
        assert_eq!(settings_error_key(&rejected(500, None)), "failed");
    }
}
