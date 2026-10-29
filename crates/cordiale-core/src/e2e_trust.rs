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

//! Peer trust and retained revocation for the E2E wire v2 (phase 2b).
//!
//! Trust binds to the network, the nick and the master key, never to the nick
//! or the `did` alone. [`PeerTrust`] checks the master signature of a device
//! list before it accepts the list, applies the version rule of
//! [`ListState`], and keeps every key that a list removed. The state is public
//! values only and serializes to JSON, so a restart keeps the revocations.
//!
//! The signed texts follow the current candidate of the coordinated protocol
//! change. They live in `e2e_wire`, so a later ruling changes that file only.
//!
//! Not in this phase: the check of a first message from a new device, the
//! replay guard, the Olm sessions for each device, the disk file for this
//! state and the link to the client and session events.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::e2e_device::{verify_signed_list, E2eError, ListState};
use crate::e2e_list_migration::has_legacy_order;
use crate::e2e_wire::{decode_key, did_from_key_text, ListDecision};

/// What a master key means for a peer that may be known already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterStatus {
    /// First time: the peer is stored with this master, not verified.
    New,
    /// The master equals the stored one.
    Same,
    /// The master differs from the stored one. Warn the user. The stored
    /// master stays.
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PeerRecord {
    master: String,
    sas_verified: bool,
    list: ListState,
    /// Device Ed25519 key to its Curve25519 key, for devices seen so far.
    curves: BTreeMap<String, String>,
    revoked: BTreeSet<String>,
    revoked_curves: BTreeSet<String>,
    /// True after a list from this master verified only in the old raw byte
    /// order. The list was refused. A valid list clears the mark.
    #[serde(default)]
    needs_new_list: bool,
    /// Device Ed25519 key to the version N of its certificate, for devices
    /// that a first message certified and no stored list holds yet.
    #[serde(default)]
    certified: BTreeMap<String, u32>,
}

impl PeerRecord {
    fn new(master: &str) -> Self {
        PeerRecord {
            master: master.to_string(),
            sas_verified: false,
            list: ListState::default(),
            curves: BTreeMap::new(),
            revoked: BTreeSet::new(),
            revoked_curves: BTreeSet::new(),
            needs_new_list: false,
            certified: BTreeMap::new(),
        }
    }

    fn is_revoked(&self, ed25519: &str, curve25519: Option<&str>) -> bool {
        self.revoked.contains(ed25519)
            || curve25519.is_some_and(|curve| self.revoked_curves.contains(curve))
    }
}

/// The peers of one local account, by network and nick.
///
/// The caller passes the nick in one fixed case form for each network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerTrust {
    peers: BTreeMap<String, PeerRecord>,
}

fn peer_key(network: &str, nick: &str) -> String {
    format!("{network}\u{0}{nick}")
}

impl PeerTrust {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// Compares a master key with the stored one. A new master for a known
    /// peer is `Changed` and replaces nothing.
    pub fn observe_master(
        &mut self,
        network: &str,
        nick: &str,
        master: &str,
    ) -> Result<MasterStatus, E2eError> {
        decode_key(master)?;
        let key = peer_key(network, nick);
        match self.peers.get(&key) {
            None => {
                self.peers.insert(key, PeerRecord::new(master));
                Ok(MasterStatus::New)
            }
            Some(record) if record.master == master => Ok(MasterStatus::Same),
            Some(_) => Ok(MasterStatus::Changed),
        }
    }

    /// The stored master of a peer.
    pub fn master(&self, network: &str, nick: &str) -> Option<&str> {
        self.peers
            .get(&peer_key(network, nick))
            .map(|record| record.master.as_str())
    }

    /// True when the user verified the stored master by SAS.
    pub fn is_sas_verified(&self, network: &str, nick: &str) -> bool {
        self.peers
            .get(&peer_key(network, nick))
            .is_some_and(|record| record.sas_verified)
    }

    /// Records a SAS check of `master`. It fails with `MasterChanged` when
    /// `master` is not the stored one.
    pub fn mark_sas_verified(
        &mut self,
        network: &str,
        nick: &str,
        master: &str,
    ) -> Result<(), E2eError> {
        match self.peers.get_mut(&peer_key(network, nick)) {
            Some(record) if record.master == master => {
                record.sas_verified = true;
                Ok(())
            }
            _ => Err(E2eError::MasterChanged),
        }
    }

    /// Replaces the master of a peer. Call it only after an explicit user
    /// action. The list, the devices and the revocations of the old master
    /// go away with it, and the new master starts unverified.
    pub fn replace_master_by_user(
        &mut self,
        network: &str,
        nick: &str,
        master: &str,
    ) -> Result<(), E2eError> {
        decode_key(master)?;
        self.peers
            .insert(peer_key(network, nick), PeerRecord::new(master));
        Ok(())
    }

    /// Checks and applies a signed device list.
    ///
    /// The master signature is checked first. A list from a master other than
    /// the stored one is `MasterChanged`. A list that holds a revoked key is
    /// `RevokedDevice`. Then the version rule runs. A device that a higher
    /// list removes is revoked, with its curve key when known. A refused list
    /// changes nothing.
    pub fn accept_list(
        &mut self,
        network: &str,
        nick: &str,
        master: &str,
        version: u32,
        keys: &[String],
        signature: &str,
    ) -> Result<ListDecision, E2eError> {
        let key = peer_key(network, nick);
        if let Err(err) = verify_signed_list(version, keys, master, signature) {
            // A list that verifies only in the old raw byte order is refused.
            // The stored state stays. The peer is marked, and no device is
            // revoked.
            if has_legacy_order(version, keys, master, signature) {
                if let Some(record) = self.peers.get_mut(&key).filter(|r| r.master == master) {
                    record.needs_new_list = true;
                }
                return Err(E2eError::LegacyListOrder);
            }
            return Err(err);
        }
        let mut record = match self.peers.get(&key) {
            Some(record) if record.master != master => return Err(E2eError::MasterChanged),
            Some(record) => record.clone(),
            None => PeerRecord::new(master),
        };
        for device in keys {
            let curve = record.curves.get(device).map(String::as_str);
            if record.is_revoked(device, curve) {
                return Err(E2eError::RevokedDevice);
            }
        }
        let previous = record.list.keys().to_vec();
        let decision = record.list.apply(version, keys)?;
        record.needs_new_list = false;
        if decision == ListDecision::Replace {
            // A certificate is the word of the master that list N held the
            // device. A list at N or newer that lacks it drops the device.
            let passed = record
                .certified
                .iter()
                .filter(|(device, n)| **n <= version && !keys.contains(*device))
                .map(|(device, _)| device.clone());
            let dropped: Vec<String> = previous
                .iter()
                .filter(|device| !keys.contains(device))
                .cloned()
                .chain(passed)
                .collect();
            for device in dropped {
                if let Some(curve) = record.curves.get(&device) {
                    record.revoked_curves.insert(curve.clone());
                }
                record.revoked.insert(device);
            }
            record.certified.retain(|_, n| *n > version);
        }
        self.peers.insert(key, record);
        Ok(decision)
    }

    /// Revokes one device of an account at once, with its curve key when
    /// known. Use it for the own account, where the user revokes a device
    /// without a list from a peer. A missing record is made with `master`.
    pub fn revoke_device(
        &mut self,
        network: &str,
        nick: &str,
        master: &str,
        ed25519: &str,
    ) -> Result<(), E2eError> {
        decode_key(master)?;
        decode_key(ed25519)?;
        let record = self
            .peers
            .entry(peer_key(network, nick))
            .or_insert_with(|| PeerRecord::new(master));
        if let Some(curve) = record.curves.get(ed25519) {
            record.revoked_curves.insert(curve.clone());
        }
        record.revoked.insert(ed25519.to_string());
        Ok(())
    }

    /// Records the Curve25519 key of a device of a known peer, so a later
    /// revocation covers it. When the device is already revoked, its curve key
    /// is revoked too. Returns false for an unknown peer.
    pub fn record_curve(
        &mut self,
        network: &str,
        nick: &str,
        ed25519: &str,
        curve25519: &str,
    ) -> Result<bool, E2eError> {
        decode_key(ed25519)?;
        decode_key(curve25519)?;
        Ok(match self.peers.get_mut(&peer_key(network, nick)) {
            Some(record) => {
                record
                    .curves
                    .insert(ed25519.to_string(), curve25519.to_string());
                if record.revoked.contains(ed25519) {
                    record.revoked_curves.insert(curve25519.to_string());
                }
                true
            }
            None => false,
        })
    }

    /// Records that a certificate of the master named the device at the list
    /// version `n`, when no stored list holds the device. A later list that
    /// reaches `n` without the device revokes it. Returns false for an
    /// unknown peer.
    pub fn record_certified(&mut self, network: &str, nick: &str, ed25519: &str, n: u32) -> bool {
        match self.peers.get_mut(&peer_key(network, nick)) {
            Some(record) => {
                record.certified.insert(ed25519.to_string(), n);
                true
            }
            None => false,
        }
    }

    /// The version of the stored list of a peer, or 0 when none is stored.
    pub fn list_version(&self, network: &str, nick: &str) -> u32 {
        self.peers
            .get(&peer_key(network, nick))
            .map_or(0, |record| record.list.version())
    }

    /// True when the last list of the peer verified only in the old raw byte
    /// order. The user needs a new list from the peer.
    pub fn needs_new_list(&self, network: &str, nick: &str) -> bool {
        self.peers
            .get(&peer_key(network, nick))
            .is_some_and(|record| record.needs_new_list)
    }

    /// The Ed25519 keys of the devices in the local list of a peer.
    pub fn listed_devices(&self, network: &str, nick: &str) -> &[String] {
        match self.peers.get(&peer_key(network, nick)) {
            Some(record) => record.list.keys(),
            None => &[],
        }
    }

    /// True when the key was revoked, or its curve key was.
    pub fn is_revoked(
        &self,
        network: &str,
        nick: &str,
        ed25519: &str,
        curve25519: Option<&str>,
    ) -> bool {
        self.peers
            .get(&peer_key(network, nick))
            .is_some_and(|record| record.is_revoked(ed25519, curve25519))
    }

    /// True when a revoked device key of the peer has this `did`. Use it when
    /// only the `did` of a sender is known, for example after a restart.
    pub fn is_did_revoked(&self, network: &str, nick: &str, did: &str) -> bool {
        self.peers
            .get(&peer_key(network, nick))
            .is_some_and(|record| {
                record
                    .revoked
                    .iter()
                    .any(|key| did_from_key_text(key).is_ok_and(|revoked| revoked == did))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_device::build_signed_list_signature;
    use vodozemac::olm::Account;

    const NET: &str = "net";
    const NICK: &str = "alice";

    fn key_of(account: &Account) -> String {
        account.identity_keys().ed25519.to_base64()
    }

    fn new_keys(count: usize) -> Vec<String> {
        (0..count).map(|_| key_of(&Account::new())).collect()
    }

    /// Four device keys whose raw byte order differs from the text order.
    fn keys_in_two_orders() -> Vec<String> {
        use crate::e2e_wire::{legacy_raw_order_list_signed_text, signed_list_signed_text};
        loop {
            let keys = new_keys(4);
            if signed_list_signed_text(1, &keys).unwrap()
                != legacy_raw_order_list_signed_text(1, &keys).unwrap()
            {
                return keys;
            }
        }
    }

    fn old_order_signature(master: &Account, version: u32, keys: &[String]) -> String {
        let text = crate::e2e_wire::legacy_raw_order_list_signed_text(version, keys).unwrap();
        master.sign(&text).to_base64()
    }

    fn accept(
        trust: &mut PeerTrust,
        master: &Account,
        version: u32,
        keys: &[String],
    ) -> Result<ListDecision, E2eError> {
        let signature =
            build_signed_list_signature(version, keys, |bytes| master.sign(bytes).to_base64())
                .unwrap();
        trust.accept_list(NET, NICK, &key_of(master), version, keys, &signature)
    }

    #[test]
    fn list_versions_follow_the_rule() {
        let master = Account::new();
        let keys = new_keys(2);
        let mut trust = PeerTrust::default();
        assert_eq!(
            accept(&mut trust, &master, 2, &keys),
            Ok(ListDecision::Replace)
        );
        assert_eq!(
            accept(&mut trust, &master, 2, &keys),
            Ok(ListDecision::NoOp)
        );
        assert_eq!(
            accept(&mut trust, &master, 1, &keys),
            Err(E2eError::StaleList)
        );
        assert_eq!(
            accept(&mut trust, &master, 2, &keys[..1]),
            Err(E2eError::StaleList)
        );
        assert_eq!(
            accept(&mut trust, &master, 3, &keys[..1]),
            Ok(ListDecision::Replace)
        );
        assert_eq!(trust.listed_devices(NET, NICK), &keys[..1]);
    }

    #[test]
    fn list_with_a_bad_signature_changes_nothing() {
        let master = Account::new();
        let keys = new_keys(1);
        let mut trust = PeerTrust::default();
        let other =
            build_signed_list_signature(1, &keys, |bytes| Account::new().sign(bytes).to_base64())
                .unwrap();
        assert_eq!(
            trust.accept_list(NET, NICK, &key_of(&master), 1, &keys, &other),
            Err(E2eError::BadSignature)
        );
        assert_eq!(trust.master(NET, NICK), None);
        assert!(trust.listed_devices(NET, NICK).is_empty());
    }

    #[test]
    fn peer_list_in_the_old_order_is_refused_and_marks_the_peer() {
        let master = Account::new();
        let master_key = key_of(&master);
        let keys = keys_in_two_orders();
        let first = keys[..2].to_vec();
        let mut trust = PeerTrust::default();
        accept(&mut trust, &master, 1, &first).unwrap();
        let before = trust.clone();
        let old = old_order_signature(&master, 2, &keys);
        assert_eq!(
            trust.accept_list(NET, NICK, &master_key, 2, &keys, &old),
            Err(E2eError::LegacyListOrder)
        );
        // The last good list stays and no device is revoked.
        assert_eq!(trust.listed_devices(NET, NICK), first.as_slice());
        assert!(first.iter().all(|k| !trust.is_revoked(NET, NICK, k, None)));
        assert!(trust.needs_new_list(NET, NICK));
        let mut unmarked = trust.clone();
        let record = unmarked.peers.get_mut(&peer_key(NET, NICK)).unwrap();
        record.needs_new_list = false;
        assert_eq!(unmarked, before);
        // The mark survives a restart and a valid list clears it.
        let mut restored = PeerTrust::from_json(&trust.to_json().unwrap()).unwrap();
        assert!(restored.needs_new_list(NET, NICK));
        assert_eq!(
            accept(&mut restored, &master, 2, &keys),
            Ok(ListDecision::Replace)
        );
        assert!(!restored.needs_new_list(NET, NICK));
    }

    #[test]
    fn unknown_peer_with_an_old_order_list_gets_no_record() {
        let master = Account::new();
        let keys = keys_in_two_orders();
        let old = old_order_signature(&master, 1, &keys);
        let mut trust = PeerTrust::default();
        assert_eq!(
            trust.accept_list(NET, NICK, &key_of(&master), 1, &keys, &old),
            Err(E2eError::LegacyListOrder)
        );
        assert_eq!(trust, PeerTrust::default());
    }

    #[test]
    fn removed_device_stays_revoked_after_a_restart() {
        let master = Account::new();
        let keys = new_keys(2);
        let mut trust = PeerTrust::default();
        accept(&mut trust, &master, 1, &keys).unwrap();
        accept(&mut trust, &master, 2, &keys[..1]).unwrap();
        assert!(trust.is_revoked(NET, NICK, &keys[1], None));
        let mut restored = PeerTrust::from_json(&trust.to_json().unwrap()).unwrap();
        assert!(restored.is_revoked(NET, NICK, &keys[1], None));
        assert_eq!(
            accept(&mut restored, &master, 3, &keys),
            Err(E2eError::RevokedDevice)
        );
        assert_eq!(restored.listed_devices(NET, NICK), &keys[..1]);
    }

    #[test]
    fn a_revoked_device_is_found_by_its_did_after_a_restart() {
        let master = Account::new();
        let keys = new_keys(2);
        let mut trust = PeerTrust::default();
        accept(&mut trust, &master, 1, &keys).unwrap();
        accept(&mut trust, &master, 2, &keys[..1]).unwrap();
        let restored = PeerTrust::from_json(&trust.to_json().unwrap()).unwrap();
        let revoked = did_from_key_text(&keys[1]).unwrap();
        let kept = did_from_key_text(&keys[0]).unwrap();
        assert!(restored.is_did_revoked(NET, NICK, &revoked));
        assert!(!restored.is_did_revoked(NET, NICK, &kept));
        assert!(!restored.is_did_revoked(NET, "other", &revoked));
    }

    #[test]
    fn revoked_device_keeps_its_curve_key_revoked() {
        let master = Account::new();
        let device = Account::new();
        let device_key = key_of(&device);
        let curve = device.identity_keys().curve25519.to_base64();
        let mut trust = PeerTrust::default();
        assert_eq!(
            trust.record_curve(NET, NICK, &device_key, &curve),
            Ok(false)
        );
        accept(
            &mut trust,
            &master,
            1,
            &[device_key.clone(), key_of(&Account::new())],
        )
        .unwrap();
        assert_eq!(trust.record_curve(NET, NICK, &device_key, &curve), Ok(true));
        accept(&mut trust, &master, 2, &new_keys(1)).unwrap();
        assert!(trust.is_revoked(NET, NICK, "unrelated", Some(&curve)));
        let restored = PeerTrust::from_json(&trust.to_json().unwrap()).unwrap();
        assert!(restored.is_revoked(NET, NICK, "unrelated", Some(&curve)));
    }

    #[test]
    fn curve_learned_after_removal_is_revoked() {
        let master = Account::new();
        let device = Account::new();
        let device_key = key_of(&device);
        let curve = device.identity_keys().curve25519.to_base64();
        let mut trust = PeerTrust::default();
        accept(
            &mut trust,
            &master,
            1,
            &[device_key.clone(), key_of(&Account::new())],
        )
        .unwrap();
        accept(&mut trust, &master, 2, &new_keys(1)).unwrap();
        assert!(!trust.is_revoked(NET, NICK, "unrelated", Some(&curve)));
        assert_eq!(trust.record_curve(NET, NICK, &device_key, &curve), Ok(true));
        assert!(trust.is_revoked(NET, NICK, "unrelated", Some(&curve)));
        let restored = PeerTrust::from_json(&trust.to_json().unwrap()).unwrap();
        assert!(restored.is_revoked(NET, NICK, "unrelated", Some(&curve)));
    }

    #[test]
    fn changed_master_warns_and_never_replaces_the_stored_one() {
        let master = Account::new();
        let master_key = key_of(&master);
        let other = Account::new();
        let mut trust = PeerTrust::default();
        assert_eq!(
            trust.observe_master(NET, NICK, &master_key),
            Ok(MasterStatus::New)
        );
        assert_eq!(
            trust.observe_master(NET, NICK, &master_key),
            Ok(MasterStatus::Same)
        );
        trust.mark_sas_verified(NET, NICK, &master_key).unwrap();
        assert_eq!(
            trust.observe_master(NET, NICK, &key_of(&other)),
            Ok(MasterStatus::Changed)
        );
        assert_eq!(
            accept(&mut trust, &other, 1, &new_keys(1)),
            Err(E2eError::MasterChanged)
        );
        assert_eq!(
            trust.mark_sas_verified(NET, NICK, &key_of(&other)),
            Err(E2eError::MasterChanged)
        );
        assert_eq!(trust.master(NET, NICK), Some(master_key.as_str()));
        assert!(trust.is_sas_verified(NET, NICK));
        trust
            .replace_master_by_user(NET, NICK, &key_of(&other))
            .unwrap();
        assert_eq!(trust.master(NET, NICK), Some(key_of(&other).as_str()));
        assert!(!trust.is_sas_verified(NET, NICK));
    }

    #[test]
    fn trust_binds_to_network_and_nick() {
        let master_key = key_of(&Account::new());
        let mut trust = PeerTrust::default();
        trust.observe_master(NET, NICK, &master_key).unwrap();
        trust.mark_sas_verified(NET, NICK, &master_key).unwrap();
        assert!(trust.is_sas_verified(NET, NICK));
        assert!(!trust.is_sas_verified("other-net", NICK));
        assert!(!trust.is_sas_verified(NET, "bob"));
        assert_eq!(trust.master("other-net", NICK), None);
    }
}
