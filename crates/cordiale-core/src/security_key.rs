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

//! The decisions of a passkey ceremony on a USB security key spoken to
//! directly over CTAP2 (issue #161), kept apart from the device code so
//! they're tested on every platform: how the key verifies the user (Grappa
//! requires it), the PIN rules, the PIN protocol, the flags of the key's
//! answer, and what a CTAP2 status means for the user.
//!
//! The `clientDataJSON`, the `none` attestation and Grappa's wire bodies
//! are the ceremony seam's (`cordiale-ui`'s `ceremony.rs`), shared with
//! the other backends.

/// COSE id of ES256, the key type every FIDO2 security key can make and
/// the first one Grappa lists.
pub const ES256: i32 = -7;

/// Flags in `authenticatorData`: user present and user verified.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// `rpIdHash` (32 bytes), flags (1) and the signature counter (4): the
/// shortest `authenticatorData` there is.
const AUTH_DATA_MIN_LEN: usize = 37;

/// A security key's PIN. It never reaches a log: `Debug` hides it.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPin(String);

impl KeyPin {
    pub fn new(pin: String) -> Self {
        KeyPin(pin)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for KeyPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyPin(<redacted>)")
    }
}

/// Why a security key gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// No security key is plugged in.
    NoDevice,
    /// More than one security key is plugged in.
    SeveralDevices,
    /// The key has a PIN and the attempt carried none: ask for it and run
    /// the same request again (Grappa spends its options only on
    /// verification).
    PinRequired,
    /// Wrong PIN; `retries` is what the key says is left, when it says.
    PinInvalid { retries: Option<u32> },
    /// Too many wrong PINs in a row: the key wants to be unplugged first.
    PinAuthBlocked,
    /// The PIN is blocked for good: only a reset, which erases the key,
    /// helps.
    PinBlocked,
    /// The PIN is too short or too long.
    PinPolicy,
    /// The key supports a PIN but has none, so it can't verify the user as
    /// Grappa requires.
    PinNotSet,
    /// The key can't verify the user at all, or answered without doing it.
    NoUserVerification,
    /// None of the account's passkeys lives on this key.
    NotRegistered,
    /// Not touched in time, or refused on the key.
    Denied,
    /// No room left on the key for another passkey.
    KeyFull,
    /// Grappa asked for a key type the key can't make, or a discoverable
    /// credential the key can't keep.
    Unsupported,
    /// Anything else; the text is for the log.
    Failed(String),
}

impl KeyError {
    /// The key the UI shows this error with.
    pub fn key(&self) -> &'static str {
        match self {
            KeyError::NoDevice => "key-missing",
            KeyError::SeveralDevices => "key-several",
            KeyError::PinRequired => "",
            KeyError::PinInvalid { .. } => "key-pin-invalid",
            KeyError::PinAuthBlocked => "key-pin-auth-blocked",
            KeyError::PinBlocked => "key-pin-blocked",
            KeyError::PinPolicy => "key-pin-policy",
            KeyError::PinNotSet => "key-pin-not-set",
            KeyError::NoUserVerification => "key-no-uv",
            KeyError::NotRegistered => "key-not-registered",
            KeyError::Denied => "key-denied",
            KeyError::KeyFull => "key-full",
            KeyError::Unsupported => "key-unsupported",
            KeyError::Failed(_) => "key-failed",
        }
    }

    /// The PIN field should be shown (first ask, a wrong or refused PIN).
    pub fn asks_for_pin(&self) -> bool {
        matches!(
            self,
            KeyError::PinRequired | KeyError::PinInvalid { .. } | KeyError::PinPolicy
        )
    }

    /// The PIN attempts left, -1 when unknown.
    pub fn retries_left(&self) -> i32 {
        match self {
            KeyError::PinInvalid {
                retries: Some(left),
            } => i32::try_from(*left).unwrap_or(i32::MAX),
            _ => -1,
        }
    }
}

/// How a key gets Grappa the "user verified" flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserVerification {
    /// With its PIN, typed in Cordiale.
    Pin,
    /// On its own (a fingerprint), with no PIN set.
    BuiltIn,
}

/// Picks the verification from the key's `clientPin` and `uv` options,
/// each present and true, present and false, or absent. A PIN wins when
/// one is set: it works on every key, while a fingerprint may not be
/// enrolled.
pub fn user_verification(
    client_pin: Option<bool>,
    built_in_uv: Option<bool>,
) -> Result<UserVerification, KeyError> {
    match (client_pin, built_in_uv) {
        (Some(true), _) => Ok(UserVerification::Pin),
        (_, Some(true)) => Ok(UserVerification::BuiltIn),
        (Some(false), _) => Err(KeyError::PinNotSet),
        _ => Err(KeyError::NoUserVerification),
    }
}

/// CTAP2 PINs are at least 4 characters and at most 63 bytes of UTF-8;
/// checked before the key sees them, since a refused PIN may count as a
/// wrong one.
pub fn check_pin(pin: &str) -> Result<(), KeyError> {
    if pin.chars().count() < 4 || pin.len() > 63 {
        Err(KeyError::PinPolicy)
    } else {
        Ok(())
    }
}

/// The PIN to send with a ceremony: none for a key that verifies on its
/// own; for a PIN key, the typed one once it passes `check_pin`, or
/// `PinRequired` so the UI asks for it.
pub fn pin_to_send(
    verification: UserVerification,
    pin: Option<&KeyPin>,
) -> Result<Option<&str>, KeyError> {
    match (verification, pin) {
        (UserVerification::BuiltIn, _) => Ok(None),
        (UserVerification::Pin, None) => Err(KeyError::PinRequired),
        (UserVerification::Pin, Some(pin)) => {
            check_pin(pin.as_str())?;
            Ok(Some(pin.as_str()))
        }
    }
}

/// The PIN protocol to speak: 1, which CTAP 2.0 keys know, unless the key
/// lists only 2. A key that lists none is a CTAP 2.0 key.
pub fn pin_protocol(supported: &[u32]) -> u8 {
    if !supported.contains(&1) && supported.contains(&2) {
        2
    } else {
        1
    }
}

/// Grappa accepts an ES256 key, the one type every security key makes.
pub fn accepts_es256(algorithms: &[i32]) -> bool {
    algorithms.contains(&ES256)
}

/// Whether to ask the key for a discoverable credential: when Grappa
/// requires one, or prefers one and the key can keep it.
pub fn resident_key(required: bool, preferred: bool, key_can: bool) -> Result<bool, KeyError> {
    match (required, key_can) {
        (true, false) => Err(KeyError::Unsupported),
        (true, true) => Ok(true),
        (false, _) => Ok(preferred && key_can),
    }
}

/// The credential an assertion answered with. CTAP2 lets a key leave it
/// out when the allow list had exactly one entry.
pub fn answered_credential(returned: &[u8], allow: &[Vec<u8>]) -> Option<Vec<u8>> {
    if !returned.is_empty() {
        return Some(returned.to_vec());
    }
    match allow {
        [only] => Some(only.clone()),
        _ => None,
    }
}

/// Checks the flags of the key's `authenticatorData`: Grappa refuses an
/// answer without "user present" and "user verified", so catching it here
/// gives a clear message instead of an opaque 401.
pub fn check_user_verified(auth_data: &[u8]) -> Result<(), KeyError> {
    if auth_data.len() < AUTH_DATA_MIN_LEN {
        return Err(KeyError::Failed(format!(
            "authenticator data too short ({} bytes)",
            auth_data.len()
        )));
    }
    let flags = auth_data[32];
    if flags & (FLAG_UP | FLAG_UV) == FLAG_UP | FLAG_UV {
        Ok(())
    } else {
        Err(KeyError::NoUserVerification)
    }
}

/// The CTAP status byte in a backend's error text, written as
/// `... err = 0x31 CTAP2_ERR_PIN_INVALID ...`.
pub fn ctap_status(message: &str) -> Option<u8> {
    let (_, rest) = message.split_once("err = 0x")?;
    let hex: String = rest
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .take(2)
        .collect();
    u8::from_str_radix(&hex, 16).ok()
}

/// What a backend's error text means for the user: its CTAP status when it
/// carries one (CTAP 2.1 §8.2), otherwise a plain failure.
pub fn ctap_error(message: &str) -> KeyError {
    match ctap_status(message) {
        Some(0x31) => KeyError::PinInvalid { retries: None },
        Some(0x32) => KeyError::PinBlocked,
        Some(0x34) => KeyError::PinAuthBlocked,
        Some(0x35) => KeyError::PinNotSet,
        Some(0x36) => KeyError::PinRequired,
        Some(0x37) => KeyError::PinPolicy,
        Some(0x2e) => KeyError::NotRegistered,
        // Operation denied, keep-alive cancelled, user action timeout,
        // built-in verification blocked or failed.
        Some(0x27 | 0x2d | 0x2f | 0x3c | 0x3f) => KeyError::Denied,
        Some(0x28) => KeyError::KeyFull,
        Some(0x26 | 0x2b) => KeyError::Unsupported,
        _ => KeyError::Failed(message.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PIN of `len` digits, built rather than written out: tests keep
    /// credential-like values out of literals.
    fn digits(len: usize) -> String {
        (1..=len)
            .map(|n| char::from(b'0' + (n % 10) as u8))
            .collect()
    }

    fn auth_data(flags: u8, extra: usize) -> Vec<u8> {
        let mut data = vec![0x11; 32];
        data.push(flags);
        data.extend_from_slice(&[0, 0, 0, 7]);
        data.extend(std::iter::repeat_n(0x22, extra));
        data
    }

    #[test]
    fn a_set_pin_wins_over_built_in_verification() {
        assert_eq!(
            user_verification(Some(true), Some(true)),
            Ok(UserVerification::Pin)
        );
        assert_eq!(
            user_verification(Some(true), None),
            Ok(UserVerification::Pin)
        );
        assert_eq!(
            user_verification(Some(false), Some(true)),
            Ok(UserVerification::BuiltIn)
        );
        assert_eq!(
            user_verification(Some(false), None),
            Err(KeyError::PinNotSet)
        );
        assert_eq!(
            user_verification(None, Some(false)),
            Err(KeyError::NoUserVerification)
        );
    }

    #[test]
    fn pins_follow_the_ctap2_length_rules() {
        assert_eq!(check_pin(&digits(4)), Ok(()));
        assert_eq!(check_pin(&digits(3)), Err(KeyError::PinPolicy));
        assert_eq!(check_pin(&"é".repeat(4)), Ok(()));
        assert_eq!(check_pin(&"a".repeat(63)), Ok(()));
        assert_eq!(check_pin(&"a".repeat(64)), Err(KeyError::PinPolicy));
    }

    #[test]
    fn a_pin_key_asks_for_its_pin_and_checks_it_first() {
        let pin = KeyPin::new(digits(4));
        let short = KeyPin::new(digits(2));
        assert_eq!(pin_to_send(UserVerification::BuiltIn, Some(&pin)), Ok(None));
        assert_eq!(
            pin_to_send(UserVerification::Pin, None),
            Err(KeyError::PinRequired)
        );
        assert_eq!(
            pin_to_send(UserVerification::Pin, Some(&pin)),
            Ok(Some(digits(4).as_str()))
        );
        assert_eq!(
            pin_to_send(UserVerification::Pin, Some(&short)),
            Err(KeyError::PinPolicy)
        );
    }

    #[test]
    fn pin_protocol_two_only_when_one_is_missing() {
        assert_eq!(pin_protocol(&[]), 1);
        assert_eq!(pin_protocol(&[2, 1]), 1);
        assert_eq!(pin_protocol(&[2]), 2);
    }

    #[test]
    fn es256_is_required() {
        assert!(accepts_es256(&[-7, -257]));
        assert!(!accepts_es256(&[-257]));
    }

    #[test]
    fn discoverable_credentials_follow_grappa_and_the_key() {
        assert_eq!(resident_key(false, true, true), Ok(true));
        assert_eq!(resident_key(false, true, false), Ok(false));
        assert_eq!(resident_key(false, false, true), Ok(false));
        assert_eq!(resident_key(true, false, true), Ok(true));
        assert_eq!(resident_key(true, false, false), Err(KeyError::Unsupported));
    }

    #[test]
    fn a_left_out_credential_is_the_only_one_allowed() {
        let one = vec![vec![9, 9]];
        assert_eq!(answered_credential(&[1], &one), Some(vec![1]));
        assert_eq!(answered_credential(&[], &one), Some(vec![9, 9]));
        assert_eq!(answered_credential(&[], &[]), None);
        assert_eq!(answered_credential(&[], &[vec![1], vec![2]]), None);
    }

    #[test]
    fn answers_need_user_present_and_verified() {
        assert_eq!(check_user_verified(&auth_data(0x05, 0)), Ok(()));
        assert_eq!(check_user_verified(&auth_data(0x45, 10)), Ok(()));
        assert_eq!(
            check_user_verified(&auth_data(0x01, 0)),
            Err(KeyError::NoUserVerification)
        );
        assert_eq!(
            check_user_verified(&auth_data(0x04, 0)),
            Err(KeyError::NoUserVerification)
        );
        assert!(matches!(
            check_user_verified(&[0; 36]),
            Err(KeyError::Failed(_))
        ));
    }

    #[test]
    fn ctap_statuses_are_read_from_the_backend_text() {
        assert_eq!(
            ctap_status("response_status err = 0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid."),
            Some(0x31)
        );
        assert_eq!(ctap_status("response_status err = 0x5"), Some(0x05));
        assert_eq!(ctap_status("read err = 0xFE"), Some(0xfe));
        assert_eq!(ctap_status("FIDO device not found."), None);
    }

    #[test]
    fn ctap_statuses_map_to_what_the_user_can_do() {
        let error = |code: &str| ctap_error(&format!("response_status err = {code} X"));
        assert_eq!(error("0x31"), KeyError::PinInvalid { retries: None });
        assert_eq!(error("0x32"), KeyError::PinBlocked);
        assert_eq!(error("0x34"), KeyError::PinAuthBlocked);
        assert_eq!(error("0x35"), KeyError::PinNotSet);
        assert_eq!(error("0x36"), KeyError::PinRequired);
        assert_eq!(error("0x37"), KeyError::PinPolicy);
        assert_eq!(error("0x2E"), KeyError::NotRegistered);
        assert_eq!(error("0x2F"), KeyError::Denied);
        assert_eq!(error("0x27"), KeyError::Denied);
        assert_eq!(error("0x28"), KeyError::KeyFull);
        assert_eq!(error("0x26"), KeyError::Unsupported);
        assert!(matches!(error("0x02"), KeyError::Failed(_)));
        assert!(matches!(
            ctap_error("Nonce verification failed"),
            KeyError::Failed(_)
        ));
    }

    #[test]
    fn errors_have_ui_keys_and_the_pin_ones_reopen_the_pin_field() {
        assert_eq!(KeyError::NoDevice.key(), "key-missing");
        assert_eq!(KeyError::Failed("x".into()).key(), "key-failed");
        assert_eq!(KeyError::PinRequired.key(), "");
        assert!(KeyError::PinRequired.asks_for_pin());
        assert!(KeyError::PinInvalid { retries: Some(2) }.asks_for_pin());
        assert!(KeyError::PinPolicy.asks_for_pin());
        assert!(!KeyError::PinBlocked.asks_for_pin());
        assert!(!KeyError::Denied.asks_for_pin());
        assert_eq!(KeyError::PinInvalid { retries: Some(2) }.retries_left(), 2);
        assert_eq!(KeyError::PinInvalid { retries: None }.retries_left(), -1);
        assert_eq!(KeyError::Denied.retries_left(), -1);
    }

    #[test]
    fn a_pin_never_shows_in_debug_output() {
        let printed = format!("{:?}", Some(KeyPin::new(digits(6))));
        assert!(!printed.contains(&digits(6)));
        assert!(printed.contains("<redacted>"));
    }
}
