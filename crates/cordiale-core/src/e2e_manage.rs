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

//! Peer side of E2E device management: list versions, revoked keys and the
//! master key of one remote user.
//!
//! [`PeerDirectory`] checks the master signature before any state changes. It
//! never replaces the master key by itself, and a revoked key stays revoked.
//!
//! Not in this slice: the signing side of the own account (revoke and reset),
//! the storage in the encrypted store, the adapter for the route names and
//! error tokens of protocol 49 and the device screens.

use crate::e2e_device::{
    accept_peer_device, verify_signed_list, DeviceCertificate, E2eError, ListState, PeerDevice,
};
use crate::e2e_wire::{decode_key, ListDecision, WireError};

/// Why a management action is rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum ManageError {
    E2e(E2eError),
    /// The signed list comes from a master key that is not the stored one.
    MasterChanged,
    /// The key was revoked and stays revoked.
    RevokedKey,
    /// The master key has no SAS confirmation yet.
    Unverified,
}

impl From<E2eError> for ManageError {
    fn from(err: E2eError) -> Self {
        ManageError::E2e(err)
    }
}

impl From<WireError> for ManageError {
    fn from(err: WireError) -> Self {
        ManageError::E2e(err.into())
    }
}

/// A device list with the master signature over its signed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedList {
    pub version: u32,
    pub keys: Vec<String>,
    pub signature: String,
}

/// The device state kept for one remote user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDirectory {
    master_ed25519: String,
    verified: bool,
    list: ListState,
    revoked: Vec<String>,
}

impl PeerDirectory {
    /// A directory for a master key not yet verified with SAS.
    pub fn new(master_ed25519: &str) -> Result<Self, ManageError> {
        decode_key(master_ed25519)?;
        Ok(Self {
            master_ed25519: master_ed25519.to_string(),
            verified: false,
            list: ListState::default(),
            revoked: Vec::new(),
        })
    }

    pub fn master_ed25519(&self) -> &str {
        &self.master_ed25519
    }

    pub fn is_verified(&self) -> bool {
        self.verified
    }

    pub fn keys(&self) -> &[String] {
        self.list.keys()
    }

    pub fn revoked(&self) -> &[String] {
        &self.revoked
    }

    /// The user confirmed the SAS for the stored master key.
    pub fn confirm_sas(&mut self) {
        self.verified = true;
    }

    /// Applies a signed list. A list of another master, a bad signature, a
    /// stale version and a revoked key leave the state as it is. A higher
    /// version moves the keys that it drops to the revoked set.
    pub fn apply_list(
        &mut self,
        master_ed25519: &str,
        list: &SignedList,
    ) -> Result<ListDecision, ManageError> {
        if master_ed25519 != self.master_ed25519 {
            return Err(ManageError::MasterChanged);
        }
        verify_signed_list(list.version, &list.keys, master_ed25519, &list.signature)?;
        let mut next = self.list.clone();
        let decision = next.apply(list.version, &list.keys)?;
        if decision == ListDecision::Replace {
            if list.keys.iter().any(|key| self.revoked.contains(key)) {
                return Err(ManageError::RevokedKey);
            }
            for key in self.list.keys() {
                if !list.keys.contains(key) && !self.revoked.contains(key) {
                    self.revoked.push(key.clone());
                }
            }
            self.list = next;
        }
        Ok(decision)
    }

    /// Replaces the master key after an explicit user action, for example
    /// when the peer reset the identity. The old list is dropped, so every
    /// device must appear in a new list. The revoked set stays. The new master
    /// needs a new SAS confirmation.
    pub fn accept_new_master(&mut self, master_ed25519: &str) -> Result<(), ManageError> {
        decode_key(master_ed25519)?;
        self.master_ed25519 = master_ed25519.to_string();
        self.verified = false;
        self.list = ListState::default();
        Ok(())
    }

    /// Checks the certificate of a remote device. Needs a verified master and
    /// a key that is in the list and not revoked.
    pub fn accept_device(&self, cert: &DeviceCertificate) -> Result<PeerDevice, ManageError> {
        if !self.verified {
            return Err(ManageError::Unverified);
        }
        if self.revoked.contains(&cert.master_ed25519) {
            return Err(ManageError::RevokedKey);
        }
        Ok(accept_peer_device(cert, self.list.keys())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_device::build_signed_list_signature;
    use crate::e2e_wire::{device_id_signed_text, did_from_key_text};
    use vodozemac::olm::Account;

    fn key_of(account: &Account) -> String {
        account.identity_keys().ed25519.to_base64()
    }

    fn sign_list(master: &Account, version: u32, keys: &[String]) -> SignedList {
        let signature =
            build_signed_list_signature(version, keys, |text| master.sign(text).to_base64())
                .unwrap();
        SignedList {
            version,
            keys: keys.to_vec(),
            signature,
        }
    }

    fn certificate(device: &Account) -> DeviceCertificate {
        let curve25519 = device.identity_keys().curve25519.to_base64();
        let ed25519 = key_of(device);
        let text = device_id_signed_text(&curve25519, &ed25519);
        DeviceCertificate {
            did: did_from_key_text(&ed25519).unwrap(),
            curve25519,
            master_ed25519: ed25519,
            signature: device.sign(text.as_bytes()).to_base64(),
        }
    }

    /// A master, three devices and a directory that holds the first list.
    fn setup() -> (Account, Vec<Account>, Vec<String>, PeerDirectory) {
        let master = Account::new();
        let devices: Vec<Account> = (0..3).map(|_| Account::new()).collect();
        let keys: Vec<String> = devices.iter().map(key_of).collect();
        let mut peer = PeerDirectory::new(&key_of(&master)).unwrap();
        let first = sign_list(&master, 1, &keys);
        peer.apply_list(&key_of(&master), &first).unwrap();
        (master, devices, keys, peer)
    }

    #[test]
    fn valid_revoke_keeps_the_dropped_key_revoked() {
        let (master, _, keys, mut peer) = setup();
        let second = sign_list(&master, 2, &keys[..2]);
        assert_eq!(
            peer.apply_list(&key_of(&master), &second),
            Ok(ListDecision::Replace)
        );
        assert_eq!(peer.keys(), &keys[..2]);
        assert_eq!(peer.revoked(), &keys[2..]);
    }

    #[test]
    fn list_with_a_foreign_signer_changes_nothing() {
        let (master, _, keys, mut peer) = setup();
        let forged = sign_list(&Account::new(), 2, &keys[..2]);
        assert_eq!(
            peer.apply_list(&key_of(&master), &forged),
            Err(ManageError::E2e(E2eError::BadSignature))
        );
        assert_eq!(peer.keys(), keys.as_slice());
        assert!(peer.revoked().is_empty());
    }

    #[test]
    fn stale_and_equal_versions_follow_the_rule() {
        let (master, _, keys, mut peer) = setup();
        let master_key = key_of(&master);
        let second = sign_list(&master, 2, &keys[..2]);
        peer.apply_list(&master_key, &second).unwrap();
        assert_eq!(
            peer.apply_list(&master_key, &second),
            Ok(ListDecision::NoOp)
        );
        let lower = sign_list(&master, 1, &keys[..2]);
        assert_eq!(
            peer.apply_list(&master_key, &lower),
            Err(ManageError::E2e(E2eError::StaleList))
        );
        let other = sign_list(&master, 2, &keys[..1]);
        assert_eq!(
            peer.apply_list(&master_key, &other),
            Err(ManageError::E2e(E2eError::StaleList))
        );
        assert_eq!(peer.keys(), &keys[..2]);
        assert_eq!(peer.revoked(), &keys[2..]);
    }

    #[test]
    fn revoked_key_cannot_come_back() {
        let (master, _, keys, mut peer) = setup();
        let master_key = key_of(&master);
        peer.apply_list(&master_key, &sign_list(&master, 2, &keys[..2]))
            .unwrap();
        let back = sign_list(&master, 3, &keys);
        assert_eq!(
            peer.apply_list(&master_key, &back),
            Err(ManageError::RevokedKey)
        );
        assert_eq!(peer.keys(), &keys[..2]);
    }

    #[test]
    fn device_needs_sas_and_a_key_that_is_not_revoked() {
        let (master, devices, keys, mut peer) = setup();
        let cert = certificate(&devices[2]);
        assert_eq!(peer.accept_device(&cert), Err(ManageError::Unverified));
        peer.confirm_sas();
        assert!(peer.accept_device(&cert).is_ok());
        peer.apply_list(&key_of(&master), &sign_list(&master, 2, &keys[..2]))
            .unwrap();
        assert_eq!(peer.accept_device(&cert), Err(ManageError::RevokedKey));
    }

    #[test]
    fn new_master_needs_an_explicit_step_and_a_new_sas() {
        let (master, devices, keys, mut peer) = setup();
        peer.confirm_sas();
        let new_master = Account::new();
        let new_key = key_of(&new_master);
        // Reset: a new master and a version 1 list with one device.
        let reset = sign_list(&new_master, 1, &keys[..1]);
        assert_eq!(
            peer.apply_list(&new_key, &reset),
            Err(ManageError::MasterChanged)
        );
        assert_eq!(peer.master_ed25519(), key_of(&master));
        assert!(peer.is_verified());
        peer.accept_new_master(&new_key).unwrap();
        assert!(!peer.is_verified());
        assert!(peer.keys().is_empty());
        assert_eq!(peer.apply_list(&new_key, &reset), Ok(ListDecision::Replace));
        // The other devices are not in the new list: they pair again.
        let cert = certificate(&devices[1]);
        peer.confirm_sas();
        assert_eq!(
            peer.accept_device(&cert),
            Err(ManageError::E2e(E2eError::UnknownSigner))
        );
        assert!(peer.accept_device(&certificate(&devices[0])).is_ok());
    }
}
