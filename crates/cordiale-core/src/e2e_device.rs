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

//! Device certificate and device list checks for the E2E wire v2 (phase 2a).
//!
//! A remote device becomes usable only after [`accept_peer_device`] checks
//! its certificate. The Ed25519 check comes from `vodozemac` (Apache-2.0,
//! maintained by the Matrix project, pure Rust), the library chosen for the
//! Olm engine of the next phase. This module holds public values only.
//!
//! The versioned certificate and the signed device list are candidate
//! formats: see [`VersionedDeviceCertificate`].
//!
//! Not in this phase: the Olm account and sessions, their storage and the
//! link to the client events.

use serde::{Deserialize, Serialize};
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

use crate::e2e_wire::{
    check_list_devices, decide_list, decode_key, decode_signature, device_certificate_signed_text,
    device_id_signed_text, did_from_key_text, parse_device_certificate_signed_text,
    signed_list_signed_text, ListDecision, WireError, MAX_VERSION,
};

/// Why a certificate or a device list is rejected. The text never holds key
/// material.
#[derive(Debug, PartialEq, Eq)]
pub enum E2eError {
    Wire(WireError),
    /// The certificate signature is wrong.
    BadSignature,
    /// The signing key is not in the approved device list.
    UnknownSigner,
    /// The `did` does not belong to the key of the certificate.
    DeviceMismatch,
    /// The list has a lower version, or the same version with other keys.
    StaleList,
    /// A peer shows a master key other than the one stored. The stored key
    /// stays until the user acts.
    MasterChanged,
    /// The list holds a device key that an earlier list removed.
    RevokedDevice,
}

impl From<WireError> for E2eError {
    fn from(err: WireError) -> Self {
        E2eError::Wire(err)
    }
}

/// The public identity block of one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    pub did: String,
    pub curve25519: String,
    /// The Ed25519 key that signs the certificate; the `did` comes from it.
    pub master_ed25519: String,
    pub signature: String,
}

/// A remote device whose certificate passed every check. Only
/// [`accept_peer_device`] builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDevice {
    did: String,
    curve25519: String,
    ed25519: String,
}

impl PeerDevice {
    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn curve25519(&self) -> &str {
        &self.curve25519
    }

    pub fn ed25519(&self) -> &str {
        &self.ed25519
    }
}

/// Checks the certificate of a remote device against the approved list keys.
///
/// Rejects a bad key or signature text, a `did` that is not derived from the
/// signing key, a signer that is not in `approved_keys` and a wrong
/// signature.
pub fn accept_peer_device(
    cert: &DeviceCertificate,
    approved_keys: &[String],
) -> Result<PeerDevice, E2eError> {
    decode_key(&cert.curve25519)?;
    let master_raw = decode_key(&cert.master_ed25519)?;
    let signature_raw = decode_signature(&cert.signature)?;
    if did_from_key_text(&cert.master_ed25519)? != cert.did {
        return Err(E2eError::DeviceMismatch);
    }
    if !approved_keys.contains(&cert.master_ed25519) {
        return Err(E2eError::UnknownSigner);
    }
    let master =
        Ed25519PublicKey::from_slice(&master_raw).map_err(|_| E2eError::Wire(WireError::BadKey))?;
    let signature = Ed25519Signature::from_slice(&signature_raw)
        .map_err(|_| E2eError::Wire(WireError::BadSignature))?;
    let text = device_id_signed_text(&cert.curve25519, &cert.master_ed25519);
    master
        .verify(text.as_bytes(), &signature)
        .map_err(|_| E2eError::BadSignature)?;
    Ok(PeerDevice {
        did: cert.did.clone(),
        curve25519: cert.curve25519.clone(),
        ed25519: cert.master_ed25519.clone(),
    })
}

/// Decodes the key and signature text, then checks the signature. Callers
/// build `signed` only from input that already passed the canonical checks.
fn verify_signature(signer_ed25519: &str, signature: &str, signed: &[u8]) -> Result<(), E2eError> {
    let signer_raw = decode_key(signer_ed25519)?;
    let signature_raw = decode_signature(signature)?;
    let signer =
        Ed25519PublicKey::from_slice(&signer_raw).map_err(|_| E2eError::Wire(WireError::BadKey))?;
    let signature = Ed25519Signature::from_slice(&signature_raw)
        .map_err(|_| E2eError::Wire(WireError::BadSignature))?;
    signer
        .verify(signed, &signature)
        .map_err(|_| E2eError::BadSignature)
}

/// The MD-3 certificate candidate: the master key signs
/// `irc-e2e:v2:dev:<N>:<E>` for one device key. This is the current
/// candidate of the coordinated protocol change, not a final ruling. Only the
/// builder and parser in `e2e_wire` know the text form, so a later change
/// stays in that one place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedDeviceCertificate {
    /// N: the version of the first signed list that holds the device.
    pub first_list_version: u32,
    /// E: the full Ed25519 key of the device.
    pub device_ed25519: String,
    /// The Ed25519 key of the master that signed the certificate.
    pub master_ed25519: String,
    pub signature: String,
}

/// Builds a certificate. `sign` receives the exact bytes to sign and returns
/// the signature text. The input is checked before `sign` runs, and the
/// signature text is checked after.
pub fn build_device_certificate(
    first_list_version: u32,
    device_ed25519: &str,
    master_ed25519: &str,
    sign: impl FnOnce(&[u8]) -> String,
) -> Result<VersionedDeviceCertificate, E2eError> {
    let text = device_certificate_signed_text(first_list_version, device_ed25519)?;
    decode_key(master_ed25519)?;
    let signature = sign(&text);
    decode_signature(&signature)?;
    Ok(VersionedDeviceCertificate {
        first_list_version,
        device_ed25519: device_ed25519.to_string(),
        master_ed25519: master_ed25519.to_string(),
        signature,
    })
}

/// Checks a certificate from signed bytes, as a verifier gets them. The bytes
/// must parse to canonical text before any signature check. The signer must
/// be in `approved_keys`. Returns `(N, E)`.
pub fn verify_device_certificate_bytes(
    signed: &[u8],
    master_ed25519: &str,
    signature: &str,
    approved_keys: &[String],
) -> Result<(u32, String), E2eError> {
    let (version, device) = parse_device_certificate_signed_text(signed)?;
    decode_key(master_ed25519)?;
    decode_signature(signature)?;
    if !approved_keys.iter().any(|key| key == master_ed25519) {
        return Err(E2eError::UnknownSigner);
    }
    verify_signature(master_ed25519, signature, signed)?;
    Ok((version, device))
}

/// Checks a certificate: rebuilds its signed text from the fields, then
/// checks the signature with [`verify_device_certificate_bytes`].
pub fn verify_device_certificate(
    cert: &VersionedDeviceCertificate,
    approved_keys: &[String],
) -> Result<(), E2eError> {
    let signed = device_certificate_signed_text(cert.first_list_version, &cert.device_ed25519)?;
    verify_device_certificate_bytes(
        &signed,
        &cert.master_ed25519,
        &cert.signature,
        approved_keys,
    )
    .map(|_| ())
}

/// Builds the signed text of a device list and signs it with `sign`. The keys
/// are sorted by `e2e_wire`: the caller does not need to order them.
pub fn build_signed_list_signature(
    list_version: u32,
    device_keys: &[String],
    sign: impl FnOnce(&[u8]) -> String,
) -> Result<String, E2eError> {
    let text = signed_list_signed_text(list_version, device_keys)?;
    let signature = sign(&text);
    decode_signature(&signature)?;
    Ok(signature)
}

/// Checks the signature of a device list against the master key. The list is
/// checked and sorted before the signature check.
pub fn verify_signed_list(
    list_version: u32,
    device_keys: &[String],
    master_ed25519: &str,
    signature: &str,
) -> Result<(), E2eError> {
    let text = signed_list_signed_text(list_version, device_keys)?;
    verify_signature(master_ed25519, signature, &text)
}

/// The newest device list that passed its checks, for one remote user.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListState {
    stored: Option<(u32, Vec<String>)>,
}

impl ListState {
    /// Applies the version rule. A lower version, or the same version with
    /// other keys, is `StaleList`. A version out of 1 to 2^31 - 1 is
    /// `BadVersion`. Returns what changed.
    pub fn apply(&mut self, version: u32, keys: &[String]) -> Result<ListDecision, E2eError> {
        if !(1..=MAX_VERSION).contains(&version) {
            return Err(WireError::BadVersion.into());
        }
        check_list_devices(keys)?;
        let decision = decide_list(
            self.stored.as_ref().map(|(v, k)| (*v, k.as_slice())),
            version,
            keys,
        );
        match decision {
            ListDecision::Replace => self.stored = Some((version, keys.to_vec())),
            ListDecision::NoOp => {}
            ListDecision::Ignore => return Err(E2eError::StaleList),
        }
        Ok(decision)
    }

    pub fn keys(&self) -> &[String] {
        match &self.stored {
            Some((_, keys)) => keys.as_slice(),
            None => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vodozemac::olm::Account;

    /// A certificate signed by a fresh account, as a device builds its own.
    fn new_certificate() -> DeviceCertificate {
        let account = Account::new();
        let keys = account.identity_keys();
        let curve25519 = keys.curve25519.to_base64();
        let master_ed25519 = keys.ed25519.to_base64();
        let text = device_id_signed_text(&curve25519, &master_ed25519);
        DeviceCertificate {
            did: did_from_key_text(&master_ed25519).unwrap(),
            signature: account.sign(text.as_bytes()).to_base64(),
            curve25519,
            master_ed25519,
        }
    }

    #[test]
    fn certificate_of_a_new_device_is_accepted() {
        let cert = new_certificate();
        let peer = accept_peer_device(&cert, std::slice::from_ref(&cert.master_ed25519)).unwrap();
        assert_eq!(peer.did(), cert.did);
        assert_eq!(peer.curve25519(), cert.curve25519);
        assert_eq!(peer.ed25519(), cert.master_ed25519);
    }

    #[test]
    fn certificate_with_a_bad_signature_is_rejected() {
        let mut cert = new_certificate();
        let keys = vec![cert.master_ed25519.clone()];
        cert.signature = new_certificate().signature;
        assert_eq!(
            accept_peer_device(&cert, &keys),
            Err(E2eError::BadSignature)
        );
    }

    #[test]
    fn certificate_with_a_swapped_device_key_is_rejected() {
        let mut cert = new_certificate();
        let keys = vec![cert.master_ed25519.clone()];
        cert.curve25519 = new_certificate().curve25519;
        assert_eq!(
            accept_peer_device(&cert, &keys),
            Err(E2eError::BadSignature)
        );
    }

    #[test]
    fn certificate_with_a_wrong_did_is_rejected() {
        let mut cert = new_certificate();
        let keys = vec![cert.master_ed25519.clone()];
        cert.did = new_certificate().did;
        assert_eq!(
            accept_peer_device(&cert, &keys),
            Err(E2eError::DeviceMismatch)
        );
    }

    #[test]
    fn certificate_from_an_unknown_signer_is_rejected() {
        let cert = new_certificate();
        let other = new_certificate();
        assert_eq!(
            accept_peer_device(&cert, &[other.master_ed25519]),
            Err(E2eError::UnknownSigner)
        );
    }

    #[test]
    fn certificate_with_bad_key_text_is_rejected() {
        let mut cert = new_certificate();
        let keys = vec![cert.master_ed25519.clone()];
        cert.curve25519 = "short".to_string();
        assert_eq!(
            accept_peer_device(&cert, &keys),
            Err(E2eError::Wire(WireError::BadKey))
        );
    }

    fn sign_with(account: &Account) -> impl Fn(&[u8]) -> String + '_ {
        move |bytes| account.sign(bytes).to_base64()
    }

    #[test]
    fn versioned_certificate_signs_the_candidate_bytes() {
        let master = Account::new();
        let master_key = master.identity_keys().ed25519.to_base64();
        let device_key = Account::new().identity_keys().ed25519.to_base64();
        let mut signed = Vec::new();
        let cert = build_device_certificate(4, &device_key, &master_key, |bytes| {
            signed = bytes.to_vec();
            master.sign(bytes).to_base64()
        })
        .unwrap();
        assert_eq!(
            signed,
            format!("irc-e2e:v2:dev:4:{device_key}").into_bytes()
        );
        assert_eq!(cert.first_list_version, 4);
        let approved = vec![master_key.clone()];
        assert_eq!(verify_device_certificate(&cert, &approved), Ok(()));
        assert_eq!(
            verify_device_certificate_bytes(&signed, &master_key, &cert.signature, &approved),
            Ok((4, device_key))
        );
    }

    #[test]
    fn versioned_certificate_rejects_a_changed_field() {
        let master = Account::new();
        let master_key = master.identity_keys().ed25519.to_base64();
        let device_key = Account::new().identity_keys().ed25519.to_base64();
        let approved = vec![master_key.clone()];
        let cert =
            build_device_certificate(4, &device_key, &master_key, sign_with(&master)).unwrap();
        let mut other_version = cert.clone();
        other_version.first_list_version = 5;
        assert_eq!(
            verify_device_certificate(&other_version, &approved),
            Err(E2eError::BadSignature)
        );
        let mut other_device = cert.clone();
        other_device.device_ed25519 = Account::new().identity_keys().ed25519.to_base64();
        assert_eq!(
            verify_device_certificate(&other_device, &approved),
            Err(E2eError::BadSignature)
        );
        assert_eq!(
            verify_device_certificate(&cert, &[new_certificate().master_ed25519]),
            Err(E2eError::UnknownSigner)
        );
    }

    #[test]
    fn versioned_certificate_checks_input_before_the_signature() {
        let master = Account::new();
        let master_key = master.identity_keys().ed25519.to_base64();
        let device_key = Account::new().identity_keys().ed25519.to_base64();
        let approved = vec![master_key.clone()];
        let never = |_: &[u8]| -> String { panic!("sign must not run") };
        assert_eq!(
            build_device_certificate(0, &device_key, &master_key, never),
            Err(E2eError::Wire(WireError::BadVersion))
        );
        assert_eq!(
            build_device_certificate(1, "short", &master_key, never),
            Err(E2eError::Wire(WireError::BadKey))
        );
        assert_eq!(
            build_device_certificate(1, &device_key, "short", never),
            Err(E2eError::Wire(WireError::BadKey))
        );
        let signature = master.sign(b"x").to_base64();
        // A non-canonical version never reaches the signature check.
        let text = format!("irc-e2e:v2:dev:01:{device_key}");
        assert_eq!(
            verify_device_certificate_bytes(text.as_bytes(), &master_key, &signature, &approved),
            Err(E2eError::Wire(WireError::BadVersion))
        );
        let bad_signature = format!("{signature}=");
        let good = format!("irc-e2e:v2:dev:1:{device_key}");
        assert_eq!(
            verify_device_certificate_bytes(
                good.as_bytes(),
                &master_key,
                &bad_signature,
                &approved
            ),
            Err(E2eError::Wire(WireError::BadSignature))
        );
    }

    #[test]
    fn signed_list_signature_covers_the_sorted_full_keys() {
        let master = Account::new();
        let master_key = master.identity_keys().ed25519.to_base64();
        let keys: Vec<String> = (0..3)
            .map(|_| Account::new().identity_keys().ed25519.to_base64())
            .collect();
        let signature = build_signed_list_signature(7, &keys, sign_with(&master)).unwrap();
        let mut reversed = keys.clone();
        reversed.reverse();
        assert_eq!(
            verify_signed_list(7, &reversed, &master_key, &signature),
            Ok(())
        );
        assert_eq!(
            verify_signed_list(8, &keys, &master_key, &signature),
            Err(E2eError::BadSignature)
        );
        assert_eq!(
            verify_signed_list(7, &keys[..2], &master_key, &signature),
            Err(E2eError::BadSignature)
        );
        assert_eq!(
            verify_signed_list(7, &[], &master_key, &signature),
            Err(E2eError::Wire(WireError::BadDeviceCount))
        );
        assert_eq!(
            verify_signed_list(7, &keys, &master_key, "short"),
            Err(E2eError::Wire(WireError::BadSignature))
        );
    }

    #[test]
    fn list_versions_follow_the_wire_rule() {
        let keys: Vec<String> = (0..2).map(|_| new_certificate().master_ed25519).collect();
        let mut list = ListState::default();
        assert_eq!(list.apply(2, &keys), Ok(ListDecision::Replace));
        assert_eq!(list.apply(2, &keys), Ok(ListDecision::NoOp));
        assert_eq!(list.apply(1, &keys), Err(E2eError::StaleList));
        assert_eq!(list.apply(2, &keys[..1]), Err(E2eError::StaleList));
        assert_eq!(list.apply(3, &keys[..1]), Ok(ListDecision::Replace));
        assert_eq!(list.keys(), &keys[..1]);
        assert_eq!(
            list.apply(4, &[]),
            Err(E2eError::Wire(WireError::BadDeviceCount))
        );
    }

    #[test]
    fn list_version_out_of_range_is_rejected() {
        let keys = vec![new_certificate().master_ed25519];
        let bad = Err(E2eError::Wire(WireError::BadVersion));
        let mut list = ListState::default();
        assert_eq!(list.apply(0, &keys), bad);
        assert_eq!(list.apply(MAX_VERSION + 1, &keys), bad);
        assert_eq!(list.apply(u32::MAX, &keys), bad);
        assert!(list.keys().is_empty());
        assert_eq!(list.apply(1, &keys), Ok(ListDecision::Replace));
        assert_eq!(list.apply(u32::MAX, &keys), bad);
        assert_eq!(list.apply(2, &keys), Ok(ListDecision::Replace));
        assert_eq!(list.apply(MAX_VERSION, &keys), Ok(ListDecision::Replace));
    }
}
