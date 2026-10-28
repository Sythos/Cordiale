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
//! [`verify_peer_device`] is the one door to a remote device. It checks the
//! signed list, the master key, the certificate with its N, the `did`, the
//! curve key and the `fb` recipient binding. A device that is not in the
//! verified signed list never passes. A server list can only narrow the
//! verified list.
//!
//! Trust, Olm sessions and replay state use the real identity of the peer:
//! the network, the nick and the `did`. The label of a query window is never
//! part of a key, so the plain and locked entries of one peer share one
//! record and one session.
//!
//! The replay rule is a candidate. A first message is refused when its msgid
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
use crate::e2e_wire::{bundle_key_signed_text, did_from_key_text, recipient_binding, ListDecision};

/// The number of ids that the replay state keeps for each device.
pub const REPLAY_WINDOW: usize = 256;

/// The key of the state of one remote device: network, nick and `did`. It
/// is also the id of the Olm session with the device.
pub fn peer_device_key(network: &str, nick: &str, did: &str) -> String {
    format!("{network}\u{0}{nick}\u{0}{did}")
}

/// What a remote device presents before Cordiale uses it.
#[derive(Debug, Clone)]
pub struct PeerBundle<'a> {
    /// The master key of the peer.
    pub master: &'a str,
    pub list_version: u32,
    pub list_keys: &'a [String],
    pub list_signature: &'a str,
    /// The certificate of the device, signed by the master.
    pub certificate: &'a VersionedDeviceCertificate,
    pub did: &'a str,
    pub curve25519: &'a str,
    /// The signature of the device key over its curve key.
    pub curve_signature: &'a str,
    /// The recipient binding that the device claims.
    pub fb: &'a str,
}

/// Checks a remote device. `own_ed25519` is the device key of this client.
/// `server_keys` is the list that the server reports, when it reports one.
///
/// A newer signed list from the known master is kept even when the device is
/// refused, so its revocations stay. Nothing else changes unless every check
/// passes.
pub fn verify_peer_device(
    trust: &mut PeerTrust,
    network: &str,
    nick: &str,
    own_ed25519: &str,
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
    match check_device(&next, network, nick, own_ed25519, server_keys, bundle) {
        Ok(()) => {
            let device = bundle.certificate.device_ed25519.as_str();
            next.record_curve(network, nick, device, bundle.curve25519)?;
            *trust = next;
            Ok(PeerDevice::new(
                bundle.did.to_string(),
                bundle.curve25519.to_string(),
                device.to_string(),
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
/// list of the bundle. It changes no state.
fn check_device(
    next: &PeerTrust,
    network: &str,
    nick: &str,
    own_ed25519: &str,
    server_keys: Option<&[String]>,
    bundle: &PeerBundle<'_>,
) -> Result<(), E2eError> {
    let cert = bundle.certificate;
    if cert.master_ed25519 != bundle.master {
        return Err(E2eError::UnknownSigner);
    }
    verify_device_certificate(cert, &[bundle.master.to_string()])?;
    if cert.first_list_version > bundle.list_version {
        return Err(E2eError::BadCertificateVersion);
    }
    let device = cert.device_ed25519.as_str();
    if did_from_key_text(device)? != bundle.did {
        return Err(E2eError::DeviceMismatch);
    }
    if next.is_revoked(network, nick, device, Some(bundle.curve25519)) {
        return Err(E2eError::RevokedDevice);
    }
    let listed = bundle.list_keys.iter().any(|key| key == device);
    let on_server = server_keys.is_none_or(|keys| keys.iter().any(|key| key == device));
    if !listed || !on_server {
        return Err(E2eError::NotListed);
    }
    let curve_text = bundle_key_signed_text(bundle.curve25519)?;
    verify_signature(device, bundle.curve_signature, &curve_text)?;
    if bundle.fb != recipient_binding(device, own_ed25519) {
        return Err(E2eError::RecipientMismatch);
    }
    Ok(())
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
        certificate: VersionedDeviceCertificate,
        keys: Vec<String>,
        signature: String,
    }

    struct Fields {
        master: String,
        version: u32,
        keys: Vec<String>,
        signature: String,
        certificate: VersionedDeviceCertificate,
        did: String,
        curve: String,
        curve_signature: String,
        fb: String,
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
        let certificate = certify(&master, 1, &device);
        let keys = vec![ed(&device)];
        let signature = sign_list(&master, 1, &keys);
        Peer {
            master,
            device,
            certificate,
            keys,
            signature,
        }
    }

    fn did_of(account: &Account) -> String {
        did_from_key_text(&ed(account)).unwrap()
    }

    fn curve_signature(device: &Account) -> String {
        let text = bundle_key_signed_text(&curve(device)).unwrap();
        device.sign(&text).to_base64()
    }

    fn own_key() -> String {
        ed(&Account::new())
    }

    /// Runs the check on a good bundle; `tweak` breaks one field first.
    fn check(
        trust: &mut PeerTrust,
        nick: &str,
        peer: &Peer,
        own: &str,
        tweak: impl FnOnce(&mut Fields),
    ) -> Result<PeerDevice, E2eError> {
        let mut fields = Fields {
            master: ed(&peer.master),
            version: 1,
            keys: peer.keys.clone(),
            signature: peer.signature.clone(),
            certificate: peer.certificate.clone(),
            did: did_of(&peer.device),
            curve: curve(&peer.device),
            curve_signature: curve_signature(&peer.device),
            fb: recipient_binding(&ed(&peer.device), own),
            server: None,
        };
        tweak(&mut fields);
        let bundle = PeerBundle {
            master: &fields.master,
            list_version: fields.version,
            list_keys: &fields.keys,
            list_signature: &fields.signature,
            certificate: &fields.certificate,
            did: &fields.did,
            curve25519: &fields.curve,
            curve_signature: &fields.curve_signature,
            fb: &fields.fb,
        };
        verify_peer_device(trust, NET, nick, own, fields.server.as_deref(), &bundle)
    }

    #[test]
    fn good_bundle_passes() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        let device = check(&mut trust, NICK, &peer, &own, |_| {}).unwrap();
        assert_eq!(device.did(), did_of(&peer.device));
        assert_eq!(device.ed25519(), ed(&peer.device));
        assert_eq!(trust.listed_devices(NET, NICK), peer.keys.as_slice());
    }

    #[test]
    fn bad_signature_is_refused_and_changes_nothing() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        let other = sign_list(&Account::new(), 1, &peer.keys);
        let result = check(&mut trust, NICK, &peer, &own, |f| f.signature = other);
        assert_eq!(result.unwrap_err(), E2eError::BadSignature);
        assert_eq!(trust, PeerTrust::default());
    }

    #[test]
    fn older_list_version_is_refused() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        let keys = vec![ed(&peer.device), ed(&Account::new())];
        let signature = sign_list(&peer.master, 2, &keys);
        check(&mut trust, NICK, &peer, &own, |f| {
            f.version = 2;
            f.keys = keys;
            f.signature = signature;
        })
        .unwrap();
        let result = check(&mut trust, NICK, &peer, &own, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::StaleList);
    }

    #[test]
    fn unknown_master_is_refused() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer, &own, |_| {}).unwrap();
        let stranger = Account::new();
        let result = check(&mut trust, NICK, &peer, &own, |f| {
            f.master = ed(&stranger);
            f.signature = sign_list(&stranger, 1, &f.keys);
            f.certificate = certify(&stranger, 1, &peer.device);
        });
        assert_eq!(result.unwrap_err(), E2eError::MasterChanged);
        // A certificate that another key signed does not pass either.
        let result = check(&mut trust, "bob", &peer, &own, |f| {
            f.certificate = certify(&Account::new(), 1, &peer.device);
        });
        assert_eq!(result.unwrap_err(), E2eError::UnknownSigner);
    }

    #[test]
    fn certificate_with_another_n_is_refused() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        // The signature covers N = 1. The field says 2.
        let result = check(&mut trust, NICK, &peer, &own, |f| {
            f.certificate.first_list_version = 2;
        });
        assert_eq!(result.unwrap_err(), E2eError::BadSignature);
        // A signed N above the list version is refused.
        let result = check(&mut trust, NICK, &peer, &own, |f| {
            f.certificate = certify(&peer.master, 3, &peer.device);
        });
        assert_eq!(result.unwrap_err(), E2eError::BadCertificateVersion);
    }

    #[test]
    fn wrong_did_is_refused() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        let other = did_of(&Account::new());
        let result = check(&mut trust, NICK, &peer, &own, |f| f.did = other);
        assert_eq!(result.unwrap_err(), E2eError::DeviceMismatch);
    }

    #[test]
    fn wrong_fb_is_refused() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        let wrong = recipient_binding(&ed(&peer.device), &own_key());
        let result = check(&mut trust, NICK, &peer, &own, |f| f.fb = wrong);
        assert_eq!(result.unwrap_err(), E2eError::RecipientMismatch);
    }

    #[test]
    fn wrong_curve_signature_is_refused() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        let other = curve_signature(&Account::new());
        let result = check(&mut trust, NICK, &peer, &own, |f| f.curve_signature = other);
        assert_eq!(result.unwrap_err(), E2eError::BadSignature);
    }

    #[test]
    fn bad_curve_text_is_refused() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        let result = check(&mut trust, NICK, &peer, &own, |f| f.curve = "x".into());
        assert_eq!(result.unwrap_err(), E2eError::Wire(WireError::BadKey));
    }

    #[test]
    fn device_outside_the_verified_list_is_refused() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        let extra = Account::new();
        let result = check(&mut trust, NICK, &peer, &own, |f| {
            f.certificate = certify(&peer.master, 1, &extra);
            f.did = did_of(&extra);
        });
        assert_eq!(result.unwrap_err(), E2eError::NotListed);
        // A server list never adds a device. It can remove one.
        let result = check(&mut trust, NICK, &peer, &own, |f| {
            f.server = Some(vec![ed(&extra)]);
        });
        assert_eq!(result.unwrap_err(), E2eError::NotListed);
    }

    #[test]
    fn revoked_device_is_refused() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer, &own, |_| {}).unwrap();
        // List 2 removes the first device and holds another one.
        let keep = Account::new();
        let keys = vec![ed(&keep)];
        let signature = sign_list(&peer.master, 2, &keys);
        let certificate = certify(&peer.master, 2, &keep);
        let (new_keys, new_signature) = (keys.clone(), signature.clone());
        let listed = keys.clone();
        let kept = Peer {
            master: Account::from_pickle(peer.master.pickle()),
            device: keep,
            certificate,
            keys,
            signature,
        };
        check(&mut trust, NICK, &kept, &own, |f| f.version = 2).unwrap();
        assert!(trust.is_revoked(NET, NICK, &ed(&peer.device), None));
        // The removed device is refused with the new list and with the old.
        let result = check(&mut trust, NICK, &peer, &own, |f| {
            f.version = 2;
            f.keys = new_keys;
            f.signature = new_signature;
        });
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
        // The old list holds a revoked key: the revocation check comes first.
        let result = check(&mut trust, NICK, &peer, &own, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
        assert_eq!(trust.listed_devices(NET, NICK), listed.as_slice());
        assert!(trust.is_revoked(NET, NICK, &ed(&peer.device), None));
    }

    #[test]
    fn refused_device_keeps_the_newer_list_and_its_revocations() {
        let own = own_key();
        let master = Account::new();
        let (a, b) = (Account::new(), Account::new());
        let both = vec![ed(&a), ed(&b)];
        let only_b = vec![ed(&b)];
        let peer_a = Peer {
            master: Account::from_pickle(master.pickle()),
            certificate: certify(&master, 1, &a),
            keys: both.clone(),
            signature: sign_list(&master, 1, &both),
            device: a,
        };
        let peer_b = Peer {
            master: Account::from_pickle(master.pickle()),
            certificate: certify(&master, 1, &b),
            keys: both.clone(),
            signature: sign_list(&master, 1, &both),
            device: b,
        };
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer_b, &own, |_| {}).unwrap();
        // Device A presents list 2 without A. A is refused, list 2 stays.
        let signature = sign_list(&master, 2, &only_b);
        let result = check(&mut trust, NICK, &peer_a, &own, |f| {
            f.version = 2;
            f.keys = only_b.clone();
            f.signature = signature;
        });
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
        assert!(trust.is_revoked(NET, NICK, &ed(&peer_a.device), None));
        assert_eq!(trust.listed_devices(NET, NICK), only_b.as_slice());
        // A cannot go back to list 1.
        let result = check(&mut trust, NICK, &peer_a, &own, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
    }

    #[test]
    fn trust_revocation_and_replay_state_are_the_same_after_a_restart() {
        let (peer, own) = (peer(), own_key());
        let mut trust = PeerTrust::default();
        check(&mut trust, NICK, &peer, &own, |_| {}).unwrap();
        let keep = Account::new();
        let keys = vec![ed(&keep)];
        let kept = Peer {
            master: Account::from_pickle(peer.master.pickle()),
            certificate: certify(&peer.master, 2, &keep),
            signature: sign_list(&peer.master, 2, &keys),
            keys,
            device: keep,
        };
        check(&mut trust, NICK, &kept, &own, |f| f.version = 2).unwrap();
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
        let result = check(&mut trust_again, NICK, &peer, &own, |_| {});
        assert_eq!(result.unwrap_err(), E2eError::RevokedDevice);
        check(&mut trust_again, NICK, &kept, &own, |f| f.version = 2).unwrap();
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
        let own = own_key();
        let mut trust = PeerTrust::default();
        let mut replay = ReplayState::default();
        for nick in MAP_NICKS {
            let peer = peer();
            check(&mut trust, nick, &peer, &own, |_| {}).unwrap();
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
