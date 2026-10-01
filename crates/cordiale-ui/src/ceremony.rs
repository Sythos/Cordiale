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

//! The WebAuthn ceremony behind a platform-neutral seam: `available`,
//! `get_assertion` and `make_credential` dispatch to the platform's
//! backend (`webauthn.dll` on Windows, issue #160; USB security keys over
//! CTAP2 on Linux and macOS with the `ctap-hid` cargo feature, issue #161);
//! elsewhere they answer `Unsupported`.
//!
//! Everything that doesn't touch an authenticator lives here as plain
//! functions, the same on every platform: the `clientDataJSON` Cordiale
//! builds itself (as a browser would), Grappa's options decoded to bytes,
//! and the authenticator's answer turned into Grappa's wire bodies
//! (base64url without padding). Grappa checks the origin string exactly,
//! the RP ID hash, user verification, and accepts attestation `none` only
//! (see `docs/passkey-spike.md`).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use cordiale_core::passkey_origin::rp_id as origin_rp_id;
use cordiale_core::rest::{
    PasskeyAssertion, PasskeyCreationOptions, PasskeyCredential, PasskeyOptions,
    PasskeyRequestOptions,
};

/// `clientDataJSON` types Grappa (Wax) accepts.
const GET: &str = "webauthn.get";
const CREATE: &str = "webauthn.create";

/// Grappa asks for five minutes; a missing or odd value stays in a range
/// the system dialog handles.
const DEFAULT_TIMEOUT_MS: u64 = 300_000;
const MIN_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 600_000;

/// The native window the system passkey dialog belongs to.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct ParentWindow(pub(crate) isize);

/// Why a ceremony didn't produce an answer. Nothing here reached Grappa.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum CeremonyError {
    /// This platform has no backend, or its system API is missing.
    Unsupported,
    /// Cancelled, timed out, or no authenticator had a passkey for this
    /// account: the system doesn't tell these apart reliably.
    Cancelled,
    /// Grappa's options can't be used (the field that failed).
    InvalidOptions(&'static str),
    /// Anything else the platform reported, for the log.
    Failed(String),
}

/// For the log.
impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CeremonyError::Unsupported => f.write_str("no passkey backend on this system"),
            CeremonyError::Cancelled => f.write_str("cancelled, timed out or no passkey"),
            CeremonyError::InvalidOptions(field) => write!(f, "unusable options: {field}"),
            CeremonyError::Failed(reason) => write!(f, "failed: {reason}"),
        }
    }
}

/// An assertion to ask an authenticator for, already decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct AssertionRequest {
    pub rp_id: String,
    /// The exact bytes whose hash the authenticator signs; the same bytes
    /// go to Grappa.
    pub client_data_json: Vec<u8>,
    /// Credential ids that may answer. Empty on the passwordless door: any
    /// discoverable credential for `rp_id` may.
    pub allow_credentials: Vec<Vec<u8>>,
    pub timeout_ms: u32,
}

/// An authenticator's assertion, raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct AssertionResponse {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// A credential to create, already decoded. User verification is always
/// required and attestation always `none`: Grappa accepts nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct CredentialRequest {
    pub rp_id: String,
    pub rp_name: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    /// COSE algorithm ids, in Grappa's order of preference.
    pub algorithms: Vec<i32>,
    pub client_data_json: Vec<u8>,
    pub timeout_ms: u32,
    /// `resident_key: "required"`.
    pub require_resident_key: bool,
    /// `resident_key: "preferred"`: discoverable when the authenticator can
    /// store it, which the passwordless door needs.
    pub prefer_resident_key: bool,
}

/// A newly created credential, raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct CredentialResponse {
    pub credential_id: Vec<u8>,
    /// The authenticator data, attested credential included. The
    /// attestation statement is dropped: see `none_attestation_object`.
    pub authenticator_data: Vec<u8>,
    /// How the authenticator was reached (`usb`, `internal`...), if known.
    pub transports: Vec<String>,
}

/// Whether this platform can run a ceremony at all.
#[cfg(windows)]
pub fn available() -> bool {
    crate::webauthn_windows::available()
}

#[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
pub fn available() -> bool {
    true
}

#[cfg(not(any(
    windows,
    all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos"))
)))]
pub fn available() -> bool {
    false
}

/// Asks an authenticator for an assertion. Blocks until the user answers
/// the system prompt: run it off the async runtime (`run_assertion`).
#[cfg(windows)]
pub fn get_assertion(
    request: &AssertionRequest,
    parent: Option<ParentWindow>,
) -> Result<AssertionResponse, CeremonyError> {
    crate::webauthn_windows::get_assertion(request, parent)
}

#[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
pub fn get_assertion(
    request: &AssertionRequest,
    _parent: Option<ParentWindow>,
) -> Result<AssertionResponse, CeremonyError> {
    crate::ceremony_ctap::get_assertion(request)
}

#[cfg(not(any(
    windows,
    all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos"))
)))]
pub fn get_assertion(
    _request: &AssertionRequest,
    _parent: Option<ParentWindow>,
) -> Result<AssertionResponse, CeremonyError> {
    Err(CeremonyError::Unsupported)
}

/// Asks an authenticator for a new credential. Blocks like
/// `get_assertion`.
#[cfg(windows)]
pub fn make_credential(
    request: &CredentialRequest,
    parent: Option<ParentWindow>,
) -> Result<CredentialResponse, CeremonyError> {
    crate::webauthn_windows::make_credential(request, parent)
}

#[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
pub fn make_credential(
    request: &CredentialRequest,
    _parent: Option<ParentWindow>,
) -> Result<CredentialResponse, CeremonyError> {
    crate::ceremony_ctap::make_credential(request)
}

#[cfg(not(any(
    windows,
    all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos"))
)))]
pub fn make_credential(
    _request: &CredentialRequest,
    _parent: Option<ParentWindow>,
) -> Result<CredentialResponse, CeremonyError> {
    Err(CeremonyError::Unsupported)
}

/// The window handle the system dialog should sit on. Call it on the UI
/// thread.
#[cfg(windows)]
pub fn parent_window(window: &slint::Window) -> Option<ParentWindow> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let handle = window.window_handle();
    let raw = handle.window_handle().ok()?.as_raw();
    let RawWindowHandle::Win32(win32) = raw else {
        return None;
    };
    Some(ParentWindow(win32.hwnd.get()))
}

#[cfg(not(windows))]
pub fn parent_window(_window: &slint::Window) -> Option<ParentWindow> {
    None
}

/// Runs the assertion Grappa's `options` ask for, off the async runtime,
/// and returns the body the passkey doors take. `origin` is Cordiale's
/// guess at Grappa's passkey origin (see `ceremony_origin`).
pub async fn run_assertion(
    options: &PasskeyOptions<PasskeyRequestOptions>,
    origin: &str,
    parent: Option<ParentWindow>,
) -> Result<PasskeyAssertion, CeremonyError> {
    let request = assertion_request(&options.public_key, origin)?;
    let challenge_id = options.challenge_id.clone();
    tokio::task::spawn_blocking(move || -> Result<PasskeyAssertion, CeremonyError> {
        let response = get_assertion(&request, parent)?;
        Ok(assertion_wire(challenge_id, &request, &response))
    })
    .await
    .map_err(|err| CeremonyError::Failed(err.to_string()))?
}

/// Runs the registration Grappa's `options` ask for, like `run_assertion`.
pub async fn run_registration(
    options: &PasskeyOptions<PasskeyCreationOptions>,
    origin: &str,
    parent: Option<ParentWindow>,
) -> Result<PasskeyCredential, CeremonyError> {
    let request = credential_request(&options.public_key, origin)?;
    let challenge_id = options.challenge_id.clone();
    tokio::task::spawn_blocking(move || -> Result<PasskeyCredential, CeremonyError> {
        let response = make_credential(&request, parent)?;
        Ok(credential_wire(challenge_id, &request, &response))
    })
    .await
    .map_err(|err| CeremonyError::Failed(err.to_string()))?
}

/// The origin to claim for a ceremony on `rp_id`. Grappa's RP ID is its
/// origin's host, so a guess with another host can't be right; the likely
/// origin is then plain HTTPS on the RP ID.
pub fn ceremony_origin(guess: &str, rp_id: &str) -> String {
    if origin_rp_id(guess) == rp_id {
        guess.to_string()
    } else {
        format!("https://{rp_id}")
    }
}

/// The `clientDataJSON` a browser would build: `type`, the challenge as
/// base64url without padding, and the exact origin. Wax reads only these
/// (plus an optional `tokenBinding`) and hashes the raw bytes.
pub fn client_data_json(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":false}}",
        json_string(kind),
        json_string(&URL_SAFE_NO_PAD.encode(challenge)),
        json_string(origin)
    )
    .into_bytes()
}

/// Decodes the options of an assertion (sign-in or mode change).
pub fn assertion_request(
    options: &PasskeyRequestOptions,
    origin: &str,
) -> Result<AssertionRequest, CeremonyError> {
    if options.rp_id.is_empty() {
        return Err(CeremonyError::InvalidOptions("rp_id"));
    }
    let challenge = decode(&options.challenge, "challenge")?;
    let allow_credentials = options
        .allow_credentials
        .iter()
        .filter(|credential| credential.kind == "public-key")
        .map(|credential| decode(&credential.id, "allow_credentials"))
        .collect::<Result<Vec<_>, _>>()?;
    let origin = ceremony_origin(origin, &options.rp_id);
    Ok(AssertionRequest {
        rp_id: options.rp_id.clone(),
        client_data_json: client_data_json(GET, &challenge, &origin),
        allow_credentials,
        timeout_ms: timeout_ms(options.timeout),
    })
}

/// Decodes the options of a registration.
pub fn credential_request(
    options: &PasskeyCreationOptions,
    origin: &str,
) -> Result<CredentialRequest, CeremonyError> {
    if options.rp.id.is_empty() {
        return Err(CeremonyError::InvalidOptions("rp.id"));
    }
    let challenge = decode(&options.challenge, "challenge")?;
    let user_id = decode(&options.user.id, "user.id")?;
    let algorithms: Vec<i32> = options
        .pub_key_cred_params
        .iter()
        .filter(|parameter| parameter.kind == "public-key")
        .filter_map(|parameter| i32::try_from(parameter.alg).ok())
        .collect();
    if algorithms.is_empty() {
        return Err(CeremonyError::InvalidOptions("pub_key_cred_params"));
    }
    let resident_key = options.authenticator_selection.resident_key.as_deref();
    let origin = ceremony_origin(origin, &options.rp.id);
    Ok(CredentialRequest {
        rp_id: options.rp.id.clone(),
        rp_name: options.rp.name.clone(),
        user_id,
        user_name: options.user.name.clone(),
        user_display_name: options.user.display_name.clone(),
        algorithms,
        client_data_json: client_data_json(CREATE, &challenge, &origin),
        timeout_ms: timeout_ms(options.timeout),
        require_resident_key: resident_key == Some("required"),
        prefer_resident_key: resident_key == Some("preferred"),
    })
}

/// The body `POST /auth/passkeys/*` and `POST /me/passkeys/mode` take.
pub fn assertion_wire(
    challenge_id: String,
    request: &AssertionRequest,
    response: &AssertionResponse,
) -> PasskeyAssertion {
    PasskeyAssertion {
        challenge_id,
        raw_id: URL_SAFE_NO_PAD.encode(&response.credential_id),
        authenticator_data: URL_SAFE_NO_PAD.encode(&response.authenticator_data),
        client_data_json: URL_SAFE_NO_PAD.encode(&request.client_data_json),
        signature: URL_SAFE_NO_PAD.encode(&response.signature),
        user_handle: response
            .user_handle
            .as_ref()
            .map(|handle| URL_SAFE_NO_PAD.encode(handle)),
    }
}

/// The body `POST /me/passkeys/registration` takes, with the attestation
/// rebuilt in the `none` format whatever the authenticator sent.
pub fn credential_wire(
    challenge_id: String,
    request: &CredentialRequest,
    response: &CredentialResponse,
) -> PasskeyCredential {
    PasskeyCredential {
        challenge_id,
        raw_id: URL_SAFE_NO_PAD.encode(&response.credential_id),
        attestation_object: URL_SAFE_NO_PAD
            .encode(none_attestation_object(&response.authenticator_data)),
        client_data_json: URL_SAFE_NO_PAD.encode(&request.client_data_json),
        transports: response.transports.clone(),
    }
}

/// `{"fmt": "none", "attStmt": {}, "authData": <bytes>}` in canonical
/// CBOR. Grappa asks for attestation `none` and refuses a device's own
/// statement (`packed` with a certificate, `tpm`...), which is what a
/// browser strips too; the signed-over authenticator data stays as is.
pub fn none_attestation_object(authenticator_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(authenticator_data.len() + 32);
    // A map of three entries.
    out.push(0xa3);
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, "none");
    cbor_text(&mut out, "attStmt");
    // An empty map.
    out.push(0xa0);
    cbor_text(&mut out, "authData");
    cbor_head(&mut out, 2, authenticator_data.len());
    out.extend_from_slice(authenticator_data);
    out
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}

/// A CBOR item head: major type and length, in the shortest form.
fn cbor_head(out: &mut Vec<u8>, major: u8, length: usize) {
    let major = major << 5;
    if length < 24 {
        out.push(major | length as u8);
    } else if length <= 0xff {
        out.push(major | 24);
        out.push(length as u8);
    } else if length <= 0xffff {
        out.push(major | 25);
        out.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        out.push(major | 26);
        out.extend_from_slice(&(length as u32).to_be_bytes());
    }
}

fn json_string(text: &str) -> String {
    serde_json::Value::from(text).to_string()
}

fn decode(value: &str, field: &'static str) -> Result<Vec<u8>, CeremonyError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CeremonyError::InvalidOptions(field))
}

fn timeout_ms(timeout: Option<u64>) -> u32 {
    let milliseconds = timeout
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
    u32::try_from(milliseconds).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn request_options(value: Value) -> PasskeyRequestOptions {
        serde_json::from_value(value).expect("request options")
    }

    fn creation_options() -> PasskeyCreationOptions {
        serde_json::from_value(json!({
            "challenge": "AAECAw",
            "rp": {"id": "irc.example.org", "name": "Grappa"},
            "user": {"id": "dXNlci0x", "name": "alice", "display_name": "alice"},
            "pub_key_cred_params": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257}
            ],
            "timeout": 300000,
            "attestation": "none",
            "authenticator_selection": {"resident_key": "preferred", "user_verification": "required"}
        }))
        .expect("creation options")
    }

    #[test]
    fn client_data_carries_type_challenge_and_exact_origin() {
        let raw = client_data_json(GET, &[0xfb, 0xff, 0x01], "https://irc.example.org");
        let parsed: Value = serde_json::from_slice(&raw).expect("json");
        assert_eq!(parsed["type"], "webauthn.get");
        // base64url, no padding: `-` and `_`, never `+`, `/` or `=`.
        assert_eq!(parsed["challenge"], "-_8B");
        assert_eq!(parsed["origin"], "https://irc.example.org");
        let create = client_data_json(CREATE, b"x", "http://localhost:5173");
        let parsed: Value = serde_json::from_slice(&create).expect("json");
        assert_eq!(parsed["type"], "webauthn.create");
        assert_eq!(parsed["origin"], "http://localhost:5173");
    }

    #[test]
    fn the_origin_guess_stands_only_when_its_host_is_the_rp_id() {
        assert_eq!(
            ceremony_origin("https://irc.example.org", "irc.example.org"),
            "https://irc.example.org"
        );
        assert_eq!(
            ceremony_origin("http://irc.example.org:4000", "irc.example.org"),
            "http://irc.example.org:4000"
        );
        assert_eq!(
            ceremony_origin("https://10.0.0.5:4443", "irc.example.org"),
            "https://irc.example.org"
        );
    }

    #[test]
    fn a_passwordless_request_has_no_allow_list() {
        let request = assertion_request(
            &request_options(json!({
                "challenge": "AAECAw",
                "rp_id": "irc.example.org",
                "timeout": 300000,
                "user_verification": "required"
            })),
            "https://irc.example.org",
        )
        .expect("request");
        assert!(request.allow_credentials.is_empty());
        assert_eq!(request.rp_id, "irc.example.org");
        assert_eq!(request.timeout_ms, 300_000);
        let client_data: Value = serde_json::from_slice(&request.client_data_json).expect("json");
        assert_eq!(client_data["challenge"], "AAECAw");
        assert_eq!(client_data["origin"], "https://irc.example.org");
    }

    #[test]
    fn a_second_factor_request_decodes_its_allow_list() {
        let request = assertion_request(
            &request_options(json!({
                "challenge": "AAECAw",
                "rp_id": "irc.example.org",
                "allow_credentials": [
                    {"type": "public-key", "id": "AQID", "transports": ["usb"]},
                    {"type": "public-key", "id": "BAUG"}
                ]
            })),
            "https://irc.example.org",
        )
        .expect("request");
        assert_eq!(
            request.allow_credentials,
            vec![vec![1, 2, 3], vec![4, 5, 6]]
        );
        // No timeout sent: Grappa's own five minutes.
        assert_eq!(request.timeout_ms, 300_000);
    }

    #[test]
    fn unusable_options_are_refused_before_any_prompt() {
        let bad_challenge = request_options(json!({"challenge": "a+b/", "rp_id": "x.org"}));
        assert_eq!(
            assertion_request(&bad_challenge, "https://x.org"),
            Err(CeremonyError::InvalidOptions("challenge"))
        );
        let no_rp = request_options(json!({"challenge": "AAEC", "rp_id": ""}));
        assert_eq!(
            assertion_request(&no_rp, "https://x.org"),
            Err(CeremonyError::InvalidOptions("rp_id"))
        );
        let mut options = creation_options();
        options.pub_key_cred_params.clear();
        assert_eq!(
            credential_request(&options, "https://irc.example.org"),
            Err(CeremonyError::InvalidOptions("pub_key_cred_params"))
        );
    }

    #[test]
    fn creation_options_map_to_a_credential_request() {
        let request =
            credential_request(&creation_options(), "https://irc.example.org").expect("request");
        assert_eq!(request.rp_id, "irc.example.org");
        assert_eq!(request.rp_name, "Grappa");
        assert_eq!(request.user_id, b"user-1".to_vec());
        assert_eq!(request.user_name, "alice");
        assert_eq!(request.algorithms, vec![-7, -257]);
        assert!(request.prefer_resident_key && !request.require_resident_key);
        let client_data: Value = serde_json::from_slice(&request.client_data_json).expect("json");
        assert_eq!(client_data["type"], "webauthn.create");
    }

    #[test]
    fn the_none_attestation_object_is_canonical_cbor() {
        let header = [
            0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x67, b'a', b't', b't',
            b'S', b't', b'm', b't', 0xa0, 0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a',
        ];
        let short = none_attestation_object(&[7; 5]);
        assert_eq!(short[..header.len()], header);
        assert_eq!(short[header.len()..], [0x45, 7, 7, 7, 7, 7]);

        let medium = none_attestation_object(&[1; 200]);
        assert_eq!(medium[header.len()..header.len() + 2], [0x58, 200]);
        assert_eq!(medium.len(), header.len() + 2 + 200);

        let long = none_attestation_object(&[2; 300]);
        assert_eq!(long[header.len()..header.len() + 3], [0x59, 0x01, 0x2c]);
        assert_eq!(long.len(), header.len() + 3 + 300);
    }

    #[test]
    fn the_assertion_body_is_base64url_with_a_null_user_handle() {
        let request = AssertionRequest {
            rp_id: "irc.example.org".into(),
            client_data_json: b"{}".to_vec(),
            allow_credentials: Vec::new(),
            timeout_ms: 300_000,
        };
        let response = AssertionResponse {
            credential_id: vec![0xfb, 0xff],
            authenticator_data: vec![1, 2, 3],
            signature: vec![4, 5],
            user_handle: None,
        };
        let body =
            serde_json::to_value(assertion_wire("c1".into(), &request, &response)).expect("json");
        assert_eq!(body["challenge_id"], "c1");
        assert_eq!(body["raw_id"], "-_8");
        assert_eq!(body["authenticator_data"], "AQID");
        assert_eq!(body["client_data_json"], "e30");
        assert_eq!(body["signature"], "BAU");
        assert_eq!(body["user_handle"], Value::Null);

        let with_handle = AssertionResponse {
            user_handle: Some(b"user-1".to_vec()),
            ..response
        };
        let body = serde_json::to_value(assertion_wire("c1".into(), &request, &with_handle))
            .expect("json");
        assert_eq!(body["user_handle"], "dXNlci0x");
    }

    #[test]
    fn the_credential_body_rebuilds_the_attestation_as_none() {
        let request =
            credential_request(&creation_options(), "https://irc.example.org").expect("request");
        let response = CredentialResponse {
            credential_id: vec![9, 9],
            authenticator_data: vec![1, 2, 3],
            transports: vec!["internal".into()],
        };
        let body = credential_wire("c2".into(), &request, &response);
        assert_eq!(body.challenge_id, "c2");
        assert_eq!(body.raw_id, "CQk");
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&body.attestation_object)
                .expect("base64url"),
            none_attestation_object(&[1, 2, 3])
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&body.client_data_json)
                .expect("base64url"),
            request.client_data_json
        );
        assert_eq!(body.transports, vec!["internal".to_string()]);
    }

    #[cfg(not(any(
        windows,
        all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos"))
    )))]
    #[test]
    fn without_a_backend_every_ceremony_is_unsupported() {
        assert!(!available());
        let request = assertion_request(
            &request_options(json!({"challenge": "AAEC", "rp_id": "x.org"})),
            "https://x.org",
        )
        .expect("request");
        assert_eq!(
            get_assertion(&request, None),
            Err(CeremonyError::Unsupported)
        );
        let request =
            credential_request(&creation_options(), "https://irc.example.org").expect("request");
        assert_eq!(
            make_credential(&request, None),
            Err(CeremonyError::Unsupported)
        );
    }
}
