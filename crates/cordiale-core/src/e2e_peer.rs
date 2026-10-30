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

//! Use of a remote device and its replay state for the E2E wire v2.
//!
//! A remote device reaches the engine by one of two doors. Both check the
//! master key, the id block of the device, the `did`, the revocations and the
//! signed list.
//!
//! - [`verify_peer_device`] is the door of a KEYS answer. The device must be in
//!   the verified signed list, and a server list can only narrow it.
//! - [`verify_certified_device`] is the door of a first message (`pkmsg`). The
//!   message has no list. The master signs a certificate for the device with
//!   the list version N. The device passes when the stored list holds it, or
//!   when the stored list is older than N.
//!
//! The `fb` recipient binding is not checked here. It is a field of the inner
//! message of a first message, so the engine checks it after the decryption.
//!
//! Trust, Olm sessions and replay state use the real identity of the peer:
//! the network, the nick and the `did`. The label of a query window is never
//! part of a key, so the plain and locked entries of one peer share one
//! record and one session.
//!
//! The replay rule follows the seen-session check of the irc-olm engine (PR 4);
//! the window size is a choice of this client. A first message is refused when its msgid
//! was seen for the same device. A new session is refused when its session id
//! was seen. The state keeps the newest [`REPLAY_WINDOW`] ids for each device
//! and each kind. It is public values only and serializes to JSON for the
//! sealed store.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::e2e_device::{
    verify_device_certificate, verify_signature, E2eError, PeerDevice, VersionedDeviceCertificate,
};
use crate::e2e_trust::{MasterStatus, PeerTrust};
use crate::e2e_wire::{decode_key, device_id_signed_text, did_from_key_text, ListDecision};

/// The number of ids that the replay state keeps for each device.
pub const REPLAY_WINDOW: usize = 256;

/// The key of the state of one remote device: network, nick and `did`. It
/// is also the id of the Olm session with the device.
pub fn peer_device_key(network: &str, nick: &str, did: &str) -> String {
    format!("{network}\u{0}{nick}\u{0}{did}")
}

/// What a remote device presents in a KEYS answer.
#[derive(Debug, Clone)]
pub struct PeerBundle<'a> {
    /// The master key of the peer.
    pub master: &'a str,
    pub list_version: u32,
    pub list_keys: &'a [String],
    pub list_signature: &'a str,
    /// The Ed25519 key of the device. Its `did` comes from it.
    pub device_ed25519: &'a str,
    pub curve25519: &'a str,
    /// The signature of the device key over its id text: the curve key and
    /// the master key.
    pub id_signature: &'a str,
}

/// What the first message of a device presents: the id block, the master and
/// the certificate of the master for the device.
#[derive(Debug, Clone)]
pub struct CertifiedBundle<'a> {
    pub master: &'a str,
    /// N: the list version in the certificate.
    pub certificate_version: u32,
    pub certificate_signature: &'a str,
    pub device_ed25519: &'a str,
    pub curve25519: &'a str,
    pub id_signature: &'a str,
}

/// Applies the signed list of a KEYS answer without a device. A newer list
/// from the known master is kept, so its revocations stay. A first list of an
/// unknown master is not kept: only a verified device pins a master.
pub fn apply_peer_list(
    trust: &mut PeerTrust,
    network: &str,
    nick: &str,
    master: &str,
    list_version: u32,
    list_keys: &[String],
    list_signature: &str,
) -> Result<ListDecision, E2eError> {
    let mut next = trust.clone();
    let status = next.observe_master(network, nick, master)?;
    if status == MasterStatus::Changed {
        return Err(E2eError::MasterChanged);
    }
    let decision = next.accept_list(
        network,
        nick,
        master,
        list_version,
        list_keys,
        list_signature,
    )?;
    if status == MasterStatus::Same && decision == ListDecision::Replace {
        *trust = next;
    }
    Ok(decision)
}

/// Checks a device of a KEYS answer. `server_keys` is the list that the
/// server reports, when it reports one.
///
/// A newer signed list from the known master is kept even when the device is
/// refused, so its revocations stay. Nothing else changes unless every check
/// passes.
pub fn verify_peer_device(
    trust: &mut PeerTrust,
    network: &str,
    nick: &str,
    server_keys: Option<&[String]>,
    bundle: &PeerBundle<'_>,
) -> Result<PeerDevice, E2eError> {
    let mut next = trust.clone();
    let status = next.observe_master(network, nick, bundle.master)?;
    if status == MasterStatus::Changed {
        return Err(E2eError::MasterChanged);
    }
    let decision = next.accept_list(
        network,
        nick,
        bundle.master,
        bundle.list_version,
        bundle.list_keys,
        bundle.list_signature,
    )?;
    match check_listed_device(&next, network, nick, server_keys, bundle) {
        Ok(did) => {
            next.record_curve(network, nick, bundle.device_ed25519, bundle.curve25519)?;
            *trust = next;
            Ok(PeerDevice::new(
                did,
                bundle.curve25519.to_string(),
                bundle.device_ed25519.to_string(),
            ))
        }
        Err(err) => {
            if status == MasterStatus::Same && decision == ListDecision::Replace {
                *trust = next;
            }
            Err(err)
        }
    }
}

/// The checks of one device against a trust state that already holds the
/// list of the bundle. It changes no state. Returns the `did`.
fn check_listed_device(
    next: &PeerTrust,
    network: &str,
    nick: &str,
    server_keys: Option<&[String]>,
    bundle: &PeerBundle<'_>,
) -> Result<String, E2eError> {
    let device = bundle.device_ed25519;
    let did = did_from_key_text(device)?;
    if next.is_revoked(network, nick, device, Some(bundle.curve25519)) {
        return Err(E2eError::RevokedDevice);
    }
    let listed = bundle.list_keys.iter().any(|key| key == device);
    let on_server = server_keys.is_none_or(|keys| keys.iter().any(|key| key == device));
    if !listed || !on_server {
        return Err(E2eError::NotListed);
    }
    check_id_block(
        bundle.master,
        device,
        bundle.curve25519,
        bundle.id_signature,
    )?;
    Ok(did)
}

/// Checks the signature of the device over its curve key and its master.
fn check_id_block(
    master: &str,
    device: &str,
    curve25519: &str,
    id_signature: &str,
) -> Result<(), E2eError> {
    decode_key(curve25519)?;
    let text = device_id_signed_text(curve25519, master);
    verify_signature(device, id_signature, text.as_bytes())
}

/// Checks the device of a first message. The caller compares the `did` of the
/// device with the `from` field of the frame.
///
/// The trust state changes only when every check passes. A device that the
/// stored list does not hold is recorded with its N: a later list that reaches
/// N without the device revokes it.
pub fn verify_certified_device(
    trust: &mut PeerTrust,
    network: &str,
    nick: &str,
    bundle: &CertifiedBundle<'_>,
) -> Result<PeerDevice, E2eError> {
    let mut next = trust.clone();
    if next.observe_master(network, nick, bundle.master)? == MasterStatus::Changed {
        return Err(E2eError::MasterChanged);
    }
    let device = bundle.device_ed25519;
    let did = did_from_key_text(device)?;
    check_id_block(
        bundle.master,
        device,
        bundle.curve25519,
        bundle.id_signature,
    )?;
    let certificate = VersionedDeviceCertificate {
        first_list_version: bundle.certificate_version,
        device_ed25519: device.to_string(),
        master_ed25519: bundle.master.to_string(),
        signature: bundle.certificate_signature.to_string(),
    };
    verify_device_certificate(&certificate, &[bundle.master.to_string()])?;
    if next.is_revoked(network, nick, device, Some(bundle.curve25519)) {
        return Err(E2eError::RevokedDevice);
    }
    let listed = next
        .listed_devices(network, nick)
        .iter()
        .any(|key| key == device);
    if !listed {
        // The stored list is the word of the master on its devices from its
        // version on: a device it does not hold is not a device of the master.
        if bundle.certificate_version <= next.list_version(network, nick) {
            return Err(E2eError::NotListed);
        }
        next.record_certified(network, nick, device, bundle.certificate_version);
    }
    next.record_curve(network, nick, device, bundle.curve25519)?;
    *trust = next;
    Ok(PeerDevice::new(
        did,
        bundle.curve25519.to_string(),
        device.to_string(),
    ))
}

/// The first-message and new-session ids that Cordiale already accepted, for
/// each remote device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayState {
    first_messages: BTreeMap<String, Vec<String>>,
    sessions: BTreeMap<String, Vec<String>>,
}

impl ReplayState {
    /// Accepts the first message of a device once. A second message with the
    /// same msgid is `Replay`.
    pub fn accept_first_message(
        &mut self,
        network: &str,
        nick: &str,
        did: &str,
        msgid: &str,
    ) -> Result<(), E2eError> {
        record(&mut self.first_messages, network, nick, did, msgid)
    }

    /// Accepts a new session of a device once. A second session with the
    /// same session id is `Replay`.
    pub fn accept_new_session(
        &mut self,
        network: &str,
        nick: &str,
        did: &str,
        session_id: &str,
    ) -> Result<(), E2eError> {
        record(&mut self.sessions, network, nick, did, session_id)
    }
}

fn record(
    map: &mut BTreeMap<String, Vec<String>>,
    network: &str,
    nick: &str,
    did: &str,
    id: &str,
) -> Result<(), E2eError> {
    let seen = map.entry(peer_device_key(network, nick, did)).or_default();
    if seen.iter().any(|known| known == id) {
        return Err(E2eError::Replay);
    }
    seen.push(id.to_string());
    if seen.len() > REPLAY_WINDOW {
        seen.remove(0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_device::{build_device_certificate, build_signed_list_signature};
    use crate::e2e_wire::WireError;
    use vodozemac::olm::Account;

    const NET: &str = "net";
    const NICK: &str = "alice";
    const MAP_NICKS: [&str; 3] = ["constructor", "__proto__", "toString"];

    struct Peer {
        master: Account,
        device: Account,
        keys: Vec<String>,
        signature: String,
    }

    struct Fields {
        master: String,
        version: u32,
        keys: Vec<String>,
        signature: String,
        device: String,
        curve: String,
        id_signature: String,
        server: Option<Vec<String>>,
    }

    fn ed(account: &Account) -> String {
        account.identity_keys().ed25519.to_base64()
    }

    fn curve(account: &Account) -> String {
        account.identity_keys().curve25519.to_base64()
    }

    fn certify(master: &Account, n: u32, device: &Account) -> VersionedDeviceCertificate {
        build_device_certificate(n, &ed(device), &ed(master), |text| {
            master.sign(text).to_base64()
        })
        .unwrap()
    }

    fn sign_list(master: &Account, version: u32, keys: &[String]) -> String {
        build_signed_list_signature(version, keys, |text| master.sign(text).to_base64()).unwrap()
    }

    fn peer() -> Peer {
        let master = Account::new();
        let device = Account::new();
        let keys = vec![ed(&device)];
        let signature = sign_list(&master, 1, &keys);
        Peer {
            master,
            device,
            keys,
            signature,
        }
    }

    fn did_of(account: &Account) -> String {
        did_from_key_text(&ed(account)).unwrap()
    }

    /// The signature of `device` over its id text under `master`.
    fn id_signature(device: &Account, master: &Account) -> String {
        let text = device_id_signed_text(&curve(device), &ed(master));
        device.sign(text).to_base64()
    }

    /// Runs the check on a good KEYS device; `tweak` breaks one field first.
    fn check(
        trust: &mut PeerTrust,
        nick: &str,
        peer: &Peer,
        tweak: impl FnOnce(&mut Fields),
    ) -> Result<PeerDevice, E2eError> {
        let mut fields = Fields {
            master: ed(&peer.master),
            version: 1,
            keys: peer.keys.clone(),
            signature: peer.signature.clone(),
            device: ed(&peer.device),
            curve: curve(&peer.device),
            id_signature: id_signature(&peer.device, &peer.master),
            server: None,
        };
        tweak(&mut fields);
        let bundle = PeerBundle {
            master: &fields.master,
            list_version: fields.version,
            list_keys: &fields.keys,
            list_signature: &fields.signature,
            device_ed25519: &fields.device,
            curve25519: &fields.curve,
            id_signature: &fields.id_signature,
        };
        verify_peer_device(trust, NET, nick, fields.server.as_deref(), &bundle)
    }

    /// Runs the check on a good first message of `peer` with the certificate
    /// version `n`; `tweak` breaks one field first.
    fn check_certified(
        trust: &mut PeerTrust,
        nick: &str,
        peer: &Peer,
        n: u32,
        tweak: impl FnOnce(&mut CertifiedFields),
    ) -> Result<PeerDevice, E2eError> {
        let mut fields = CertifiedFields {
            master: ed(&peer.master),
            version: n,
            signature: certify(&peer.master, n, &peer.device).signature,
            device: ed(&peer.device),
            curve: curve(&peer.device),
            id_signature: id_signature(&peer.device, &peer.master),
        };
        tweak(&mut fields);
        let bundle = CertifiedBundle {
            master: &fields.master,
            certificate_version: fields.version,
            certificate_signature: &fields.signature,
            device_ed25519: &fields.device,
            curve25519: &fields.curve,
            id_signature: &fields.id_signature,
        };
        verify_certified_device(trust, NET, nick, &bundle)
    }

    struct CertifiedFields {
        master: String,
        version: u32,
        signature: String,
        device: String,
        curve: String,
        id_signature: String,
    }

    #[test]
    fn good_bundle_passes() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        let device = check(&mut trust, NICK, &peer, |_| {}).unwrap();
        assert_eq!(device.did(), did_of(&peer.device));
        assert_eq!(device.ed25519(), ed(&peer.device));
        assert_eq!(device.curve25519(), curve(&peer.device));
        assert_eq!(trust.listed_devices(NET, NICK), peer.keys.as_slice());
    }

    #[test]
    fn bad_signature_is_refused_and_changes_nothing() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        let other = sign_list(&Account::new(), 1, &peer.keys);
        let result = check(&mut trust, NICK, &peer, |f| f.signature = other);
        assert_eq!(result.unwrap_err(), E2eError::BadSignature);
        assert_eq!(trust, PeerTrust::default());
    }

    #[test]
    fn older_list_version_is_refused() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        let keys = vec![ed(&peer.device), ed(&Account::new())];
        let signature = sign_list(&peer.master, 2, &keys);
        check(&mut trust, NICK, &peer, |f| {
            f.version = 2;
            f.keys = keys;
            f.signature = signature;
        })
        .unwrap();
        let result = check(&mut trust, NICK, &peer, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::StaleList);
    }

    #[test]
    fn unknown_master_is_refused() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer, |_| {}).unwrap();
        let stranger = Account::new();
        let result = check(&mut trust, NICK, &peer, |f| {
            f.master = ed(&stranger);
            f.signature = sign_list(&stranger, 1, &f.keys);
        });
        assert_eq!(result.unwrap_err(), E2eError::MasterChanged);
    }

    #[test]
    fn wrong_id_signature_is_refused() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        // Another key signed the id text.
        let other = id_signature(&Account::new(), &peer.master);
        let result = check(&mut trust, NICK, &peer, |f| f.id_signature = other);
        assert_eq!(result.unwrap_err(), E2eError::BadSignature);
        // The device signed the id text for another master.
        let other_master = id_signature(&peer.device, &Account::new());
        let result = check(&mut trust, NICK, &peer, |f| f.id_signature = other_master);
        assert_eq!(result.unwrap_err(), E2eError::BadSignature);
    }

    #[test]
    fn bad_device_key_text_is_refused() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        let result = check(&mut trust, NICK, &peer, |f| f.device = "x".into());
        assert_eq!(result.unwrap_err(), E2eError::Wire(WireError::BadKey));
    }

    #[test]
    fn bad_curve_text_is_refused() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        let result = check(&mut trust, NICK, &peer, |f| f.curve = "x".into());
        assert_eq!(result.unwrap_err(), E2eError::Wire(WireError::BadKey));
    }

    #[test]
    fn device_outside_the_verified_list_is_refused() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        let extra = Account::new();
        let result = check(&mut trust, NICK, &peer, |f| {
            f.device = ed(&extra);
            f.id_signature = id_signature(&extra, &peer.master);
        });
        assert_eq!(result.unwrap_err(), E2eError::NotListed);
        // A server list never adds a device. It can remove one.
        let result = check(&mut trust, NICK, &peer, |f| {
            f.server = Some(vec![ed(&extra)]);
        });
        assert_eq!(result.unwrap_err(), E2eError::NotListed);
    }

    #[test]
    fn revoked_device_is_refused() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer, |_| {}).unwrap();
        // List 2 removes the first device and holds another one.
        let keep = Account::new();
        let keys = vec![ed(&keep)];
        let signature = sign_list(&peer.master, 2, &keys);
        let (new_keys, new_signature) = (keys.clone(), signature.clone());
        let listed = keys.clone();
        let kept = Peer {
            master: Account::from_pickle(peer.master.pickle()),
            device: keep,
            keys,
            signature,
        };
        check(&mut trust, NICK, &kept, |f| f.version = 2).unwrap();
        assert!(trust.is_revoked(NET, NICK, &ed(&peer.device), None));
        // The removed device is refused with the new list and with the old.
        let result = check(&mut trust, NICK, &peer, |f| {
            f.version = 2;
            f.keys = new_keys;
            f.signature = new_signature;
        });
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
        // The old list holds a revoked key: the revocation check comes first.
        let result = check(&mut trust, NICK, &peer, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
        assert_eq!(trust.listed_devices(NET, NICK), listed.as_slice());
        assert!(trust.is_revoked(NET, NICK, &ed(&peer.device), None));
    }

    #[test]
    fn refused_device_keeps_the_newer_list_and_its_revocations() {
        let master = Account::new();
        let (a, b) = (Account::new(), Account::new());
        let both = vec![ed(&a), ed(&b)];
        let only_b = vec![ed(&b)];
        let peer_a = Peer {
            master: Account::from_pickle(master.pickle()),
            keys: both.clone(),
            signature: sign_list(&master, 1, &both),
            device: a,
        };
        let peer_b = Peer {
            master: Account::from_pickle(master.pickle()),
            keys: both.clone(),
            signature: sign_list(&master, 1, &both),
            device: b,
        };
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer_b, |_| {}).unwrap();
        // Device A presents list 2 without A. A is refused, list 2 stays.
        let signature = sign_list(&master, 2, &only_b);
        let result = check(&mut trust, NICK, &peer_a, |f| {
            f.version = 2;
            f.keys = only_b.clone();
            f.signature = signature;
        });
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
        assert!(trust.is_revoked(NET, NICK, &ed(&peer_a.device), None));
        assert_eq!(trust.listed_devices(NET, NICK), only_b.as_slice());
        // A cannot go back to list 1.
        let result = check(&mut trust, NICK, &peer_a, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
    }

    #[test]
    fn a_first_message_passes_with_a_certificate_and_no_stored_list() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        let device = check_certified(&mut trust, NICK, &peer, 1, |_| {}).unwrap();
        assert_eq!(device.did(), did_of(&peer.device));
        assert_eq!(device.curve25519(), curve(&peer.device));
        assert_eq!(trust.master(NET, NICK), Some(ed(&peer.master).as_str()));
        assert_eq!(trust.list_version(NET, NICK), 0);
        // A device that the list holds needs no newer certificate.
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer, |_| {}).unwrap();
        check_certified(&mut trust, NICK, &peer, 1, |_| {}).unwrap();
    }

    #[test]
    fn a_certificate_with_a_wrong_signature_or_n_is_refused() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        // The signature covers N = 1. The field says 2.
        let result = check_certified(&mut trust, NICK, &peer, 1, |f| f.version = 2);
        assert_eq!(result.unwrap_err(), E2eError::BadSignature);
        // Another key signed the certificate.
        let stranger = certify(&Account::new(), 1, &peer.device).signature;
        let result = check_certified(&mut trust, NICK, &peer, 1, |f| f.signature = stranger);
        assert_eq!(result.unwrap_err(), E2eError::BadSignature);
        // N out of range.
        let result = check_certified(&mut trust, NICK, &peer, 1, |f| f.version = 0);
        assert!(result.is_err());
        // A refusal leaves the trust state empty.
        assert_eq!(trust, PeerTrust::default());
    }

    #[test]
    fn a_first_message_with_another_master_or_id_is_refused() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        check_certified(&mut trust, NICK, &peer, 1, |_| {}).unwrap();
        let stranger = Account::new();
        let result = check_certified(&mut trust, NICK, &peer, 1, |f| {
            f.master = ed(&stranger);
            f.signature = certify(&stranger, 1, &peer.device).signature;
            f.id_signature = id_signature(&peer.device, &stranger);
        });
        assert_eq!(result.unwrap_err(), E2eError::MasterChanged);
        let other = id_signature(&Account::new(), &peer.master);
        let result = check_certified(&mut trust, "bob", &peer, 1, |f| f.id_signature = other);
        assert_eq!(result.unwrap_err(), E2eError::BadSignature);
        let result = check_certified(&mut trust, "bob", &peer, 1, |f| f.curve = "x".into());
        assert_eq!(result.unwrap_err(), E2eError::Wire(WireError::BadKey));
    }

    #[test]
    fn a_certificate_is_stale_once_the_stored_list_reaches_its_n() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer, |_| {}).unwrap();
        // List 2 holds another device only.
        let keep = Account::new();
        let keys = vec![ed(&keep)];
        let signature = sign_list(&peer.master, 2, &keys);
        let kept = Peer {
            master: Account::from_pickle(peer.master.pickle()),
            device: keep,
            keys,
            signature,
        };
        check(&mut trust, NICK, &kept, |f| f.version = 2).unwrap();
        // A new device certified at N = 2 is not in list 2: stale. At N = 3
        // the stored list is older than N and the device passes.
        let newcomer = Peer {
            master: Account::from_pickle(peer.master.pickle()),
            device: Account::new(),
            keys: Vec::new(),
            signature: String::new(),
        };
        let result = check_certified(&mut trust, NICK, &newcomer, 2, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::NotListed);
        check_certified(&mut trust, NICK, &newcomer, 3, |_| {}).unwrap();
        // The first device was revoked by list 2, whatever its certificate.
        let result = check_certified(&mut trust, NICK, &peer, 1, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
    }

    #[test]
    fn a_list_that_reaches_n_without_a_certified_device_revokes_it() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        let newcomer = Account::new();
        let keys = vec![ed(&peer.device)];
        trust.observe_master(NET, NICK, &ed(&peer.master)).unwrap();
        trust
            .accept_list(NET, NICK, &ed(&peer.master), 1, &keys, &peer.signature)
            .unwrap();
        let certified = Peer {
            master: Account::from_pickle(peer.master.pickle()),
            device: newcomer,
            keys: Vec::new(),
            signature: String::new(),
        };
        check_certified(&mut trust, NICK, &certified, 3, |_| {}).unwrap();
        let curve_key = curve(&certified.device);
        assert!(!trust.is_revoked(NET, NICK, &ed(&certified.device), Some(&curve_key)));
        // List 2 is below N: the certified device stays.
        let list_2 = sign_list(&peer.master, 2, &keys);
        trust
            .accept_list(NET, NICK, &ed(&peer.master), 2, &keys, &list_2)
            .unwrap();
        assert!(!trust.is_revoked(NET, NICK, &ed(&certified.device), Some(&curve_key)));
        // List 3 reaches N and lacks the device: it is revoked, with its curve.
        let list_3 = sign_list(&peer.master, 3, &keys);
        trust
            .accept_list(NET, NICK, &ed(&peer.master), 3, &keys, &list_3)
            .unwrap();
        assert!(trust.is_revoked(NET, NICK, &ed(&certified.device), Some(&curve_key)));
        let result = check_certified(&mut trust, NICK, &certified, 3, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
    }

    #[test]
    fn trust_revocation_and_replay_state_are_the_same_after_a_restart() {
        let peer = peer();
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer, |_| {}).unwrap();
        let keep = Account::new();
        let keys = vec![ed(&keep)];
        let kept = Peer {
            master: Account::from_pickle(peer.master.pickle()),
            signature: sign_list(&peer.master, 2, &keys),
            keys,
            device: keep,
        };
        check(&mut trust, NICK, &kept, |f| f.version = 2).unwrap();
        let mut replay = ReplayState::default();
        replay.accept_first_message(NET, NICK, "d1", "m1").unwrap();
        replay.accept_new_session(NET, NICK, "d1", "s1").unwrap();
        // The sealed store keeps the state as JSON.
        let mut trust_again = PeerTrust::from_json(&trust.to_json().unwrap()).unwrap();
        let mut replay_again: ReplayState =
            serde_json::from_str(&serde_json::to_string(&replay).unwrap()).unwrap();
        assert_eq!(trust_again, trust);
        assert_eq!(replay_again, replay);
        assert!(trust_again.is_revoked(NET, NICK, &ed(&peer.device), None));
        let result = check(&mut trust_again, NICK, &peer, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
        check(&mut trust_again, NICK, &kept, |f| f.version = 2).unwrap();
        assert_eq!(
            replay_again.accept_first_message(NET, NICK, "d1", "m1"),
            Err(E2eError::Replay)
        );
        assert_eq!(
            replay_again.accept_new_session(NET, NICK, "d1", "s1"),
            Err(E2eError::Replay)
        );
    }

    #[test]
    fn replayed_first_message_and_session_are_refused() {
        let mut replay = ReplayState::default();
        replay.accept_first_message(NET, NICK, "d1", "m1").unwrap();
        assert_eq!(
            replay.accept_first_message(NET, NICK, "d1", "m1"),
            Err(E2eError::Replay)
        );
        replay.accept_first_message(NET, NICK, "d2", "m1").unwrap();
        replay.accept_new_session(NET, NICK, "d1", "s1").unwrap();
        assert_eq!(
            replay.accept_new_session(NET, NICK, "d1", "s1"),
            Err(E2eError::Replay)
        );
    }

    #[test]
    fn replay_window_is_bounded() {
        let mut replay = ReplayState::default();
        for index in 0..=REPLAY_WINDOW {
            replay
                .accept_first_message(NET, NICK, "did", &format!("m{index}"))
                .unwrap();
        }
        let seen = &replay.first_messages[&peer_device_key(NET, NICK, "did")];
        assert_eq!(seen.len(), REPLAY_WINDOW);
        let last = format!("m{REPLAY_WINDOW}");
        assert_eq!(
            replay.accept_first_message(NET, NICK, "did", &last),
            Err(E2eError::Replay)
        );
    }

    #[test]
    fn nicks_that_name_object_members_are_plain_keys() {
        let mut trust = PeerTrust::default();
        let mut replay = ReplayState::default();
        for nick in MAP_NICKS {
            let peer = peer();
            check(&mut trust, nick, &peer, |_| {}).unwrap();
            assert_eq!(trust.listed_devices(NET, nick), peer.keys.as_slice());
            assert!(trust.master(NET, nick).is_some());
            replay.accept_first_message(NET, nick, "did", "m").unwrap();
            assert_eq!(
                replay.accept_first_message(NET, nick, "did", "m"),
                Err(E2eError::Replay)
            );
        }
        // No other nick sees the record of these nicks.
        assert!(trust.master(NET, "valueOf").is_none());
        assert!(trust.listed_devices(NET, "valueOf").is_empty());
        replay
            .accept_first_message(NET, "valueOf", "did", "m")
            .unwrap();
    }

    #[test]
    fn device_key_does_not_depend_on_a_query_label() {
        assert_ne!(
            peer_device_key(NET, NICK, "d1"),
            peer_device_key(NET, NICK, "d2")
        );
        assert_eq!(
            peer_device_key(NET, NICK, "d1"),
            peer_device_key(NET, NICK, "d1")
        );
    }
}
