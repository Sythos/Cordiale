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

//! The ceremony backend for Linux and macOS (issue #161): USB security
//! keys spoken to directly over CTAP2/HID with `ctap-hid-fido2`, behind the
//! `ctap-hid` cargo feature. Neither system has a WebAuthn API a program
//! like Cordiale can use, so this reaches physical keys only: no synced
//! passkeys, no phone.
//!
//! The crate hashes the `challenge` it's given, so it gets the seam's
//! `clientDataJSON` bytes and the key signs their SHA-256, as for a
//! browser. Grappa requires user verification: a key with a PIN gets it
//! from Cordiale's own prompt (`key_prompt`), which also says when to touch
//! the key and offers a retry, since there's no system dialog doing that.
//! The decisions are in `cordiale_core::security_key`, with its tests.

use std::fmt::Display;
use std::panic::{catch_unwind, AssertUnwindSafe};

use cordiale_core::persistence;
use cordiale_core::security_key::{
    accepts_es256, answered_credential, check_user_verified, ctap_error, pin_protocol, pin_to_send,
    resident_key, user_verification, KeyError, KeyPin, UserVerification,
};
use ctap_hid_fido2::fidokey::{
    CredentialSupportedKeyType, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{get_fidokey_devices, FidoKeyHid, LibCfg};

use crate::ceremony::{
    AssertionRequest, AssertionResponse, CeremonyError, CredentialRequest, CredentialResponse,
};
use crate::key_prompt::{self, Reply};

/// The one security key plugged in, and what it can do.
struct Key {
    device: FidoKeyHid,
    verification: UserVerification,
    /// It can keep a discoverable credential, which passwordless sign-in
    /// needs.
    resident_keys: bool,
}

pub(crate) fn get_assertion(
    request: &AssertionRequest,
) -> Result<AssertionResponse, CeremonyError> {
    with_prompts(|pin| assertion(request, pin))
}

pub(crate) fn make_credential(
    request: &CredentialRequest,
) -> Result<CredentialResponse, CeremonyError> {
    with_prompts(|pin| creation(request, pin))
}

/// Runs `attempt` until the key answers, asking in between for the PIN or
/// whether to try again. Cancel, or five minutes without an answer, ends
/// the ceremony as cancelled. The PIN typed once is kept for a retry.
fn with_prompts<T>(
    mut attempt: impl FnMut(Option<&KeyPin>) -> Result<T, KeyError>,
) -> Result<T, CeremonyError> {
    let _overlay = key_prompt::Overlay;
    let mut pin: Option<KeyPin> = None;
    loop {
        let err = match guarded(|| attempt(pin.as_ref())) {
            Ok(answer) => return Ok(answer),
            Err(err) => err,
        };
        persistence::log_line(&format!("security key: {err:?}"));
        let step = if err.asks_for_pin() { "pin" } else { "error" };
        match key_prompt::ask(step, err.key(), err.retries_left()) {
            Reply::Pin(typed) => pin = Some(KeyPin::new(typed)),
            Reply::Retry => {}
            Reply::Cancel => return Err(CeremonyError::Cancelled),
        }
    }
}

/// The crate panics instead of failing in a few places (the HID layer
/// failing to start, a truncated answer from the key): report those as a
/// failed attempt instead of losing the ceremony thread.
fn guarded<T>(run: impl FnOnce() -> Result<T, KeyError>) -> Result<T, KeyError> {
    catch_unwind(AssertUnwindSafe(run)).unwrap_or_else(|_| {
        Err(KeyError::Failed(
            "the security key backend stopped unexpectedly".to_string(),
        ))
    })
}

fn assertion(
    request: &AssertionRequest,
    pin: Option<&KeyPin>,
) -> Result<AssertionResponse, KeyError> {
    let key = open()?;
    let pin = pin_to_send(key.verification, pin)?;
    let mut builder = GetAssertionArgsBuilder::new(&request.rp_id, &request.client_data_json);
    for id in &request.allow_credentials {
        builder = builder.add_credential_id(id);
    }
    if let Some(pin) = pin {
        builder = builder.pin(pin);
    }
    key_prompt::touching();
    // With an empty allow list and several passkeys for this server on the
    // key, the first one answers: there's no account picker.
    let answer = key
        .device
        .get_assertion_with_args(&builder.build())
        .map_err(|err| device_error(&key.device, err))?
        .into_iter()
        .next()
        .ok_or_else(|| KeyError::Failed("the key sent no assertion".to_string()))?;
    check_user_verified(&answer.auth_data)?;
    let credential_id = answered_credential(&answer.credential_id, &request.allow_credentials)
        .ok_or_else(|| KeyError::Failed("the key didn't say which passkey".to_string()))?;
    Ok(AssertionResponse {
        credential_id,
        authenticator_data: answer.auth_data,
        signature: answer.signature,
        user_handle: (!answer.user.id.is_empty()).then_some(answer.user.id),
    })
}

fn creation(
    request: &CredentialRequest,
    pin: Option<&KeyPin>,
) -> Result<CredentialResponse, KeyError> {
    // The crate makes ES256 (or EdDSA) keys; Grappa lists ES256 first.
    if !accepts_es256(&request.algorithms) {
        return Err(KeyError::Unsupported);
    }
    let key = open()?;
    let resident = resident_key(
        request.require_resident_key,
        request.prefer_resident_key,
        key.resident_keys,
    )?;
    let pin = pin_to_send(key.verification, pin)?;
    let user = PublicKeyCredentialUserEntity::new(
        Some(request.user_id.as_slice()),
        Some(request.user_name.as_str()),
        Some(request.user_display_name.as_str()),
    );
    let mut builder = MakeCredentialArgsBuilder::new(&request.rp_id, &request.client_data_json)
        .key_type(CredentialSupportedKeyType::Ecdsa256)
        .user_entity(&user);
    if resident {
        builder = builder.resident_key();
    }
    if let Some(pin) = pin {
        builder = builder.pin(pin);
    }
    key_prompt::touching();
    let answer = key
        .device
        .make_credential_with_args(&builder.build())
        .map_err(|err| device_error(&key.device, err))?;
    check_user_verified(&answer.auth_data)?;
    if answer.credential_descriptor.id.is_empty() {
        return Err(KeyError::Failed(
            "the key sent no credential id".to_string(),
        ));
    }
    // The key's own attestation statement is dropped: the seam rebuilds
    // the object in the `none` format around this authenticator data.
    Ok(CredentialResponse {
        credential_id: answer.credential_descriptor.id,
        authenticator_data: answer.auth_data,
        transports: vec!["usb".to_string()],
    })
}

/// Opens the security key, which must be the only one plugged in, and
/// reads how it verifies the user.
fn open() -> Result<Key, KeyError> {
    let mut devices = get_fidokey_devices();
    let device = match devices.len() {
        0 => return Err(KeyError::NoDevice),
        1 => devices.remove(0),
        _ => return Err(KeyError::SeveralDevices),
    };
    let mut config = LibCfg::init();
    // Otherwise the crate prints "touch the sensor" on stdout; the prompt
    // says it instead.
    config.enable_keep_alive_msg = false;
    let mut key = FidoKeyHid::new(&[device.param], &config)
        .map_err(|err| KeyError::Failed(err.to_string()))?;
    let info = key.get_info().map_err(|err| ctap_error(&err.to_string()))?;
    let option = |name: &str| {
        info.options
            .iter()
            .find(|(entry, _)| entry == name)
            .map(|(_, value)| *value)
    };
    let verification = user_verification(option("clientPin"), option("uv"))?;
    let resident_keys = option("rk") == Some(true);
    key.pin_protocol_version = pin_protocol(&info.pin_uv_auth_protocols);
    Ok(Key {
        device: key,
        verification,
        resident_keys,
    })
}

/// A failed CTAP command, with the retries left after a wrong PIN.
fn device_error(device: &FidoKeyHid, err: impl Display) -> KeyError {
    match ctap_error(&err.to_string()) {
        KeyError::PinInvalid { .. } => KeyError::PinInvalid {
            retries: device
                .get_pin_retries()
                .ok()
                .and_then(|left| u32::try_from(left).ok()),
        },
        other => other,
    }
}
