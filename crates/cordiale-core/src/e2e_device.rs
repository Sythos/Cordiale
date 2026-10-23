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
//! Not in this phase: the Olm account and sessions, their storage, the
//! signature over the signed device list (its signed text is not in
//! `e2e_wire` yet) and the link to the client events.

use serde::{Deserialize, Serialize};
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

use crate::e2e_wire::{
    check_list_devices, decide_list, decode_key, decode_signature, device_id_signed_text,
    did_from_key_text, ListDecision, WireError, MAX_VERSION,
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

/// The newest device list that passed its checks, for one remote user.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
