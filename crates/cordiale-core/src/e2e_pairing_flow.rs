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

//! The X1 pairing flow between two devices of one user.
//!
//! The creator is a device that holds the master key. It opens a rendezvous
//! and shows the pairing link. The joiner is the new device. It reads the
//! link and joins. The two sides then do these steps:
//!
//! 1. The joiner opens an ECIES channel to the key of the link and posts the
//!    initial message. The creator opens its side of the channel.
//! 2. Both devices show the two-digit check code of the channel. The user
//!    types the code on each device. A wrong code ends the pairing.
//! 3. The joiner posts its public device keys, sealed, after its confirmation.
//! 4. The creator, after its own confirmation and the keys of the joiner,
//!    signs the certificate, puts the new signed list and posts the grant.
//!    Nothing is signed or published before both confirmations.
//! 5. The joiner checks the grant, saves list and certificate, and runs the
//!    provision of its bundle. The creator closes the rendezvous.
//!
//! The channel is `vodozemac::ecies` with the info text [`PAIRING_INFO`]. The
//! message shapes, the info text and the digit mode are a **candidate**: the
//! final contract of the relay is not in this repository. A change of the
//! contract touches this module only.
//!
//! The channel secret lives in memory only. The sealed store holds a small
//! record (role, rendezvous id, start time) in its pairing slot, so a restart
//! knows that a rendezvous is open and closes it. The slot is empty after
//! success, cancel, timeout, failure and restart.
//!
//! No `Debug` output holds a link, a key or a payload.

use std::fmt;

use serde::{Deserialize, Serialize};
use vodozemac::ecies::{
    DigitMode, Ecies, EstablishedEcies, InboundCreationResult, InitialMessage, Message,
    OutboundCreationResult,
};
use vodozemac::olm::Account;
use vodozemac::Curve25519PublicKey;
use zeroize::Zeroize;

use crate::client::GrappaClient;
use crate::e2e_device::{
    build_device_certificate, build_signed_list_signature, verify_device_certificate,
    verify_signed_list, VersionedDeviceCertificate,
};
use crate::e2e_identity_routes::ListRequest;
use crate::e2e_manage::SignedList;
use crate::e2e_pairing::{
    take_pairing_link, ClosedReason, PairingCallError, PairingError, PairingLink, PairingPush,
    PairingRole, RelayMessage, Rendezvous,
};
use crate::e2e_provision::{provision_device, ProvisionError};
use crate::e2e_refusal::E2eRouteError;
use crate::e2e_state::E2eStateStore;
use crate::e2e_wire::{
    check_list_devices, decode_key, pairing_message_fits, MAX_VERSION, PAIRING_LIFETIME_SECS,
    PAIRING_MESSAGE_MAX_BYTES,
};

/// The info text of the ECIES channel. Candidate value.
pub const PAIRING_INFO: &str = "irc-e2e:v2:pair";

/// Version of the record in the pairing slot of the sealed store.
const RECORD_VERSION: u8 = 1;

/// Bytes of the tag that the channel adds to a plaintext.
const CHANNEL_OVERHEAD: usize = 16;

/// Why a pairing ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// The user cancelled.
    Cancelled,
    /// The 300-second lifetime ran out.
    Timeout,
    /// The relay closed the rendezvous.
    Closed(ClosedReason),
    /// The user typed a code that is not the check code.
    WrongCode,
    /// A message did not open with the channel.
    BadChannel,
    /// A message had a wrong shape or an unexpected type.
    BadMessage,
    /// A call, the store or the provision failed.
    Failed,
}

/// Why a step of the flow is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowError {
    /// The link is not valid for this rendezvous.
    Link(PairingError),
    /// The pairing has ended or is done.
    NotActive,
    /// The rendezvous gave the other role.
    WrongRole,
    /// The channel is not open yet, so there is no code.
    NoChannel,
    /// The typed code is not the check code. The pairing ends.
    WrongCode,
    /// The creator has not both confirmations.
    NotConfirmed,
    /// A payload is over a limit of the relay. Nothing was sent.
    TooLarge,
    BadChannel,
    BadMessage,
    /// The grant does not verify, or it is for another device.
    BadGrant,
    /// The list has four devices already, or its version is at the top.
    ListFull,
    /// The creator has no master key or no own list.
    NoIdentity,
    /// The sealed store failed.
    Store,
}

/// The public keys of the new device. They are not secret, but no `Debug`
/// output shows them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinerDevice {
    pub ed25519: String,
    pub curve25519: String,
}

impl fmt::Debug for JoinerDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JoinerDevice(..)")
    }
}

impl JoinerDevice {
    /// The device of this store. A store with no identity gets one, as the
    /// provision does on a first start.
    pub fn from_store(store: &mut E2eStateStore) -> Result<Self, FlowError> {
        let account = match store.olm_identity().map_err(|_| FlowError::Store)? {
            Some(account) => account,
            None => {
                let account = Account::new();
                store.set_account(&account).map_err(|_| FlowError::Store)?;
                account
            }
        };
        let keys = account.identity_keys();
        Ok(Self {
            ed25519: keys.ed25519.to_base64(),
            curve25519: keys.curve25519.to_base64(),
        })
    }
}

/// What the creator hands to the joiner: the master key, the certificate for
/// the new device and the new signed list.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub master: String,
    pub certificate: VersionedDeviceCertificate,
    pub list: SignedList,
}

impl fmt::Debug for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Grant(..)")
    }
}

/// The plaintext messages of the channel.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
enum Wire {
    Hello,
    Confirm { ed25519: String, curve25519: String },
    Grant(Grant),
}

/// A sealed message with the totals of the relay before it. The client call
/// checks the limits again with these totals.
pub struct Outgoing {
    payload: String,
    count: usize,
    total_bytes: usize,
}

impl fmt::Debug for Outgoing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outgoing")
            .field("count", &self.count)
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

impl Outgoing {
    pub fn payload(&self) -> &str {
        &self.payload
    }
}

/// What the session read from the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowEvent {
    /// The channel is open and the check code is known.
    CodeReady,
    /// The creator took the public keys of the joiner.
    PeerConfirmed,
    /// The joiner took the grant. The caller must verify and apply it.
    Granted(Grant),
}

/// What the user sees of a pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingStatus {
    /// The creator waits for the joiner.
    Waiting,
    /// Both sides show this code. The user types it to confirm.
    Code(String),
    /// This side confirmed and waits for the other side.
    AwaitingPeer,
    Done,
    Ended(EndReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The creator has no initial message yet.
    Open,
    /// The channel is open.
    Keyed,
    Done,
    Ended(EndReason),
}

/// One pairing, as seen by one device. Pure state: no call is made here.
pub struct PairingSession {
    role: PairingRole,
    rendezvous_id: String,
    started_at: i64,
    stage: Stage,
    waiting: Option<Ecies>,
    channel: Option<EstablishedEcies>,
    own_device: Option<JoinerDevice>,
    peer_device: Option<JoinerDevice>,
    code: Option<u8>,
    own_confirmed: bool,
    last_seq: u64,
    relay_count: usize,
    relay_bytes: usize,
}

impl fmt::Debug for PairingSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingSession")
            .field("role", &self.role)
            .field("stage", &self.stage)
            .field("last_seq", &self.last_seq)
            .finish_non_exhaustive()
    }
}

fn code_of(channel: &EstablishedEcies) -> u8 {
    channel.check_code().to_digit(DigitMode::NoLeadingZero)
}

impl PairingSession {
    fn new(role: PairingRole, rendezvous_id: &str, now: i64) -> Self {
        Self {
            role,
            rendezvous_id: rendezvous_id.to_string(),
            started_at: now,
            stage: Stage::Open,
            waiting: None,
            channel: None,
            own_device: None,
            peer_device: None,
            code: None,
            own_confirmed: false,
            last_seq: 0,
            relay_count: 0,
            relay_bytes: 0,
        }
    }

    /// The creator side: makes the ephemeral key and the pairing link.
    pub fn create(rendezvous: &Rendezvous, now: i64) -> Result<(Self, PairingLink), FlowError> {
        if rendezvous.role != PairingRole::Creator {
            return Err(FlowError::WrongRole);
        }
        let ecies = Ecies::with_info(PAIRING_INFO);
        let link = PairingLink::new(&rendezvous.id, &ecies.public_key().to_base64())
            .map_err(FlowError::Link)?;
        let mut session = Self::new(PairingRole::Creator, &rendezvous.id, now);
        session.waiting = Some(ecies);
        Ok((session, link))
    }

    /// The joiner side: opens the channel to the key of the link. Gives the
    /// session and the initial message to post.
    pub fn join(
        link: &PairingLink,
        rendezvous: &Rendezvous,
        device: JoinerDevice,
        now: i64,
    ) -> Result<(Self, Outgoing), FlowError> {
        if rendezvous.role != PairingRole::Joiner {
            return Err(FlowError::WrongRole);
        }
        if link.rendezvous_id() != rendezvous.id {
            return Err(FlowError::Link(PairingError::BadId));
        }
        let their = Curve25519PublicKey::from_base64(link.ephemeral_key())
            .map_err(|_| FlowError::Link(PairingError::BadLink))?;
        let hello = serde_json::to_vec(&Wire::Hello).map_err(|_| FlowError::BadMessage)?;
        let OutboundCreationResult { ecies, message } = Ecies::with_info(PAIRING_INFO)
            .establish_outbound_channel(their, &hello)
            .map_err(|_| FlowError::BadChannel)?;
        let payload = message.encode();
        if !pairing_message_fits(0, 0, payload.len()) {
            return Err(FlowError::TooLarge);
        }
        let mut session = Self::new(PairingRole::Joiner, &rendezvous.id, now);
        session.code = Some(code_of(&ecies));
        session.channel = Some(ecies);
        session.own_device = Some(device);
        session.stage = Stage::Keyed;
        session.relay_count = 1;
        session.relay_bytes = payload.len();
        let outgoing = Outgoing {
            payload,
            count: 0,
            total_bytes: 0,
        };
        Ok((session, outgoing))
    }

    pub fn role(&self) -> PairingRole {
        self.role
    }

    pub fn rendezvous_id(&self) -> &str {
        &self.rendezvous_id
    }

    /// The last relay sequence that the session took in.
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// True while the session can still take a step.
    pub fn is_active(&self) -> bool {
        matches!(self.stage, Stage::Open | Stage::Keyed)
    }

    pub fn status(&self) -> PairingStatus {
        match self.stage {
            Stage::Open => PairingStatus::Waiting,
            Stage::Keyed => match (self.code, self.own_confirmed) {
                (Some(code), false) => PairingStatus::Code(format!("{code:02}")),
                _ => PairingStatus::AwaitingPeer,
            },
            Stage::Done => PairingStatus::Done,
            Stage::Ended(reason) => PairingStatus::Ended(reason),
        }
    }

    fn fail(&mut self, reason: EndReason, error: FlowError) -> FlowError {
        self.end(reason);
        error
    }

    /// Ends the session and drops the secrets of the channel.
    pub fn end(&mut self, reason: EndReason) {
        if self.is_active() {
            self.stage = Stage::Ended(reason);
        }
        self.waiting = None;
        self.channel = None;
    }

    /// The user cancelled.
    pub fn cancel(&mut self) {
        self.end(EndReason::Cancelled);
    }

    /// Ends the session when its lifetime is over. True when it ended now.
    pub fn expire(&mut self, now: i64) -> bool {
        let lifetime = i64::try_from(PAIRING_LIFETIME_SECS).unwrap_or(i64::MAX);
        if self.is_active() && now.saturating_sub(self.started_at) >= lifetime {
            self.end(EndReason::Timeout);
            return true;
        }
        false
    }

    /// The relay closed the rendezvous. A finished session ignores it.
    pub fn on_closed(&mut self, reason: ClosedReason) {
        self.end(EndReason::Closed(reason));
    }

    /// Takes in the messages of the relay. A message at or below the last
    /// sequence is skipped, so a repeat or a catch-up is safe. The order of
    /// the list does not matter. A message of this side is skipped.
    pub fn accept(&mut self, messages: &[RelayMessage]) -> Result<Vec<FlowEvent>, FlowError> {
        if !self.is_active() {
            return Err(FlowError::NotActive);
        }
        let mut sorted: Vec<&RelayMessage> = messages.iter().collect();
        sorted.sort_by_key(|message| message.seq);
        let mut events = Vec::new();
        for message in sorted {
            if message.seq <= self.last_seq {
                continue;
            }
            self.last_seq = message.seq;
            if message.from == self.role {
                continue;
            }
            if message.payload.len() > PAIRING_MESSAGE_MAX_BYTES {
                return Err(self.fail(EndReason::BadMessage, FlowError::BadMessage));
            }
            self.relay_count += 1;
            self.relay_bytes = self.relay_bytes.saturating_add(message.payload.len());
            if let Some(event) = self.take_in(&message.payload)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    fn take_in(&mut self, payload: &str) -> Result<Option<FlowEvent>, FlowError> {
        match self.stage {
            Stage::Open => self.take_hello(payload),
            Stage::Keyed => self.take_sealed(payload),
            Stage::Done | Stage::Ended(_) => Ok(None),
        }
    }

    /// The creator reads the initial message and opens its side.
    fn take_hello(&mut self, payload: &str) -> Result<Option<FlowEvent>, FlowError> {
        let Some(ecies) = self.waiting.take() else {
            return Err(self.fail(EndReason::BadChannel, FlowError::BadChannel));
        };
        let Ok(initial) = InitialMessage::decode(payload) else {
            return Err(self.fail(EndReason::BadChannel, FlowError::BadChannel));
        };
        let InboundCreationResult { ecies, message } =
            match ecies.establish_inbound_channel(&initial) {
                Ok(result) => result,
                Err(_) => return Err(self.fail(EndReason::BadChannel, FlowError::BadChannel)),
            };
        if !matches!(serde_json::from_slice::<Wire>(&message), Ok(Wire::Hello)) {
            return Err(self.fail(EndReason::BadChannel, FlowError::BadChannel));
        }
        self.code = Some(code_of(&ecies));
        self.channel = Some(ecies);
        self.stage = Stage::Keyed;
        Ok(Some(FlowEvent::CodeReady))
    }

    /// Opens one sealed message and reads it for the role of this side.
    fn take_sealed(&mut self, payload: &str) -> Result<Option<FlowEvent>, FlowError> {
        let Ok(message) = Message::decode(payload) else {
            return Err(self.fail(EndReason::BadMessage, FlowError::BadMessage));
        };
        let Some(channel) = self.channel.as_mut() else {
            return Err(self.fail(EndReason::BadChannel, FlowError::BadChannel));
        };
        let opened = channel.decrypt(&message);
        let Ok(mut plain) = opened else {
            return Err(self.fail(EndReason::BadChannel, FlowError::BadChannel));
        };
        let wire = serde_json::from_slice::<Wire>(&plain);
        plain.zeroize();
        match (self.role, wire) {
            (
                PairingRole::Creator,
                Ok(Wire::Confirm {
                    ed25519,
                    curve25519,
                }),
            ) => {
                let keys_ok = decode_key(&ed25519).is_ok() && decode_key(&curve25519).is_ok();
                if !keys_ok || self.peer_device.is_some() {
                    return Err(self.fail(EndReason::BadMessage, FlowError::BadMessage));
                }
                self.peer_device = Some(JoinerDevice {
                    ed25519,
                    curve25519,
                });
                Ok(Some(FlowEvent::PeerConfirmed))
            }
            (PairingRole::Joiner, Ok(Wire::Grant(grant))) => Ok(Some(FlowEvent::Granted(grant))),
            _ => Err(self.fail(EndReason::BadMessage, FlowError::BadMessage)),
        }
    }

    /// The user typed the code of this device. A code that is not the check
    /// code ends the pairing. The joiner gets its sealed keys to post; the
    /// creator gets nothing to post.
    pub fn confirm(&mut self, typed: &str) -> Result<Option<Outgoing>, FlowError> {
        if !self.is_active() {
            return Err(FlowError::NotActive);
        }
        let code = self.code.ok_or(FlowError::NoChannel)?;
        if typed.trim().parse::<u8>().ok() != Some(code) {
            return Err(self.fail(EndReason::WrongCode, FlowError::WrongCode));
        }
        if self.own_confirmed {
            return Ok(None);
        }
        self.own_confirmed = true;
        match (self.role, self.own_device.clone()) {
            (PairingRole::Joiner, Some(device)) => {
                let wire = Wire::Confirm {
                    ed25519: device.ed25519,
                    curve25519: device.curve25519,
                };
                self.seal(&wire).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// The keys of the joiner, once both devices confirmed. This is the only
    /// way to the signing step of the creator.
    pub fn confirmed_device(&self) -> Option<&JoinerDevice> {
        if self.role == PairingRole::Creator && self.stage == Stage::Keyed && self.own_confirmed {
            self.peer_device.as_ref()
        } else {
            None
        }
    }

    /// Seals the grant for the joiner. Refused until both devices confirmed.
    /// The session is done when the grant is sealed.
    pub fn seal_grant(&mut self, grant: &Grant) -> Result<Outgoing, FlowError> {
        if self.confirmed_device().is_none() {
            return Err(FlowError::NotConfirmed);
        }
        let outgoing = self.seal(&Wire::Grant(grant.clone()))?;
        self.finish();
        Ok(outgoing)
    }

    /// Marks the pairing as done and drops the secrets of the channel.
    pub fn finish(&mut self) {
        if self.is_active() {
            self.stage = Stage::Done;
        }
        self.waiting = None;
        self.channel = None;
    }

    /// Seals one message. The size is checked before the channel is used, so
    /// a refused message does not move the counter of the channel.
    fn seal(&mut self, wire: &Wire) -> Result<Outgoing, FlowError> {
        let mut plain = serde_json::to_vec(wire).map_err(|_| FlowError::BadMessage)?;
        let bound = (plain.len() + CHANNEL_OVERHEAD).div_ceil(3) * 4 + 4;
        if !pairing_message_fits(self.relay_count, self.relay_bytes, bound) {
            plain.zeroize();
            return Err(FlowError::TooLarge);
        }
        let Some(channel) = self.channel.as_mut() else {
            plain.zeroize();
            return Err(FlowError::NoChannel);
        };
        let payload = channel.encrypt(&plain).encode();
        plain.zeroize();
        let outgoing = Outgoing {
            count: self.relay_count,
            total_bytes: self.relay_bytes,
            payload,
        };
        self.relay_count += 1;
        self.relay_bytes = self.relay_bytes.saturating_add(outgoing.payload.len());
        Ok(outgoing)
    }
}

/// Makes the grant: the new list with the new device, signed by the master,
/// and the certificate of the device for the version of that list.
pub fn build_grant(
    master: &Account,
    current: &SignedList,
    device_ed25519: &str,
) -> Result<Grant, FlowError> {
    decode_key(device_ed25519).map_err(|_| FlowError::BadMessage)?;
    let master_key = master.identity_keys().ed25519.to_base64();
    verify_signed_list(
        current.version,
        &current.keys,
        &master_key,
        &current.signature,
    )
    .map_err(|_| FlowError::NoIdentity)?;
    let version = current
        .version
        .checked_add(1)
        .filter(|version| *version <= MAX_VERSION)
        .ok_or(FlowError::ListFull)?;
    let mut keys = current.keys.clone();
    if !keys.iter().any(|key| key == device_ed25519) {
        keys.push(device_ed25519.to_string());
    }
    check_list_devices(&keys).map_err(|_| FlowError::ListFull)?;
    let signature =
        build_signed_list_signature(version, &keys, |text| master.sign(text).to_base64())
            .map_err(|_| FlowError::BadGrant)?;
    keys.sort();
    let certificate = build_device_certificate(version, device_ed25519, &master_key, |text| {
        master.sign(text).to_base64()
    })
    .map_err(|_| FlowError::BadGrant)?;
    Ok(Grant {
        master: master_key,
        certificate,
        list: SignedList {
            version,
            keys,
            signature,
        },
    })
}

/// The joiner checks a grant and saves the list and the certificate. The
/// list must verify under the master of the grant and hold the own key. The
/// certificate must be for the own key and for the version of the list. A
/// device that holds a master key of its own refuses the grant of another.
pub fn apply_grant(
    store: &mut E2eStateStore,
    own_ed25519: &str,
    grant: &Grant,
) -> Result<(), FlowError> {
    let list = &grant.list;
    verify_signed_list(list.version, &list.keys, &grant.master, &list.signature)
        .map_err(|_| FlowError::BadGrant)?;
    check_list_devices(&list.keys).map_err(|_| FlowError::BadGrant)?;
    let certificate = &grant.certificate;
    let ok = list.keys.iter().any(|key| key == own_ed25519)
        && certificate.device_ed25519 == own_ed25519
        && certificate.master_ed25519 == grant.master
        && certificate.first_list_version == list.version;
    if !ok {
        return Err(FlowError::BadGrant);
    }
    verify_device_certificate(certificate, std::slice::from_ref(&grant.master))
        .map_err(|_| FlowError::BadGrant)?;
    if let Some(own_master) = store.master_key().map_err(|_| FlowError::Store)? {
        if own_master.identity_keys().ed25519.to_base64() != grant.master {
            return Err(FlowError::BadGrant);
        }
    }
    store.set_signed_list(list).map_err(|_| FlowError::Store)?;
    store
        .set_device_certificate(certificate)
        .map_err(|_| FlowError::Store)
}

/// The record in the pairing slot of the sealed store. It holds no key.
#[derive(Serialize, Deserialize)]
struct PendingRecord {
    v: u8,
    creator: bool,
    rendezvous_id: String,
    started_at: i64,
}

/// A rendezvous that was open when the app stopped.
#[derive(Clone, PartialEq, Eq)]
pub struct StalePairing {
    pub role: PairingRole,
    rendezvous_id: String,
}

impl fmt::Debug for StalePairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StalePairing")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl StalePairing {
    pub fn rendezvous_id(&self) -> &str {
        &self.rendezvous_id
    }
}

/// Saves the record of an open pairing in the pairing slot.
pub fn save_pending(store: &mut E2eStateStore, session: &PairingSession) -> Result<(), FlowError> {
    let record = PendingRecord {
        v: RECORD_VERSION,
        creator: session.role == PairingRole::Creator,
        rendezvous_id: session.rendezvous_id.clone(),
        started_at: session.started_at,
    };
    let text = serde_json::to_string(&record).map_err(|_| FlowError::Store)?;
    store
        .set_pending_pairing(&text)
        .map_err(|_| FlowError::Store)
}

/// Empties the pairing slot.
pub fn clear_pending(store: &mut E2eStateStore) -> Result<(), FlowError> {
    store.clear_pending_pairing().map_err(|_| FlowError::Store)
}

/// Run once when the store opens. The channel secret is in memory only, so
/// any record in the slot is stale: the slot is emptied. The record that was
/// there, when it reads, is returned so the caller can close the rendezvous.
pub fn take_stale_pairing(store: &mut E2eStateStore) -> Result<Option<StalePairing>, FlowError> {
    let stale = store.pending_pairing().map(|text| {
        serde_json::from_str::<PendingRecord>(text)
            .ok()
            .filter(|record| record.v == RECORD_VERSION)
            .map(|record| StalePairing {
                role: if record.creator {
                    PairingRole::Creator
                } else {
                    PairingRole::Joiner
                },
                rendezvous_id: record.rendezvous_id,
            })
    });
    match stale {
        None => Ok(None),
        Some(record) => {
            clear_pending(store)?;
            Ok(record)
        }
    }
}

/// Failure of a driver step. No value holds a key, a link or a payload.
#[derive(Debug)]
pub enum DriveError {
    Flow(FlowError),
    Call(Box<PairingCallError>),
    Route(Box<E2eRouteError>),
    Provision(Box<ProvisionError>),
}

impl From<FlowError> for DriveError {
    fn from(err: FlowError) -> Self {
        Self::Flow(err)
    }
}

impl From<PairingCallError> for DriveError {
    fn from(err: PairingCallError) -> Self {
        Self::Call(Box::new(err))
    }
}

impl From<E2eRouteError> for DriveError {
    fn from(err: E2eRouteError) -> Self {
        Self::Route(Box::new(err))
    }
}

impl From<ProvisionError> for DriveError {
    fn from(err: ProvisionError) -> Self {
        Self::Provision(Box::new(err))
    }
}

/// What a driver step needs to call the server.
#[derive(Clone, Copy)]
pub struct PairingContext<'a> {
    pub client: &'a GrappaClient,
    pub token: &'a str,
    pub protocol: Option<u32>,
    /// The network whose list and devices the pairing changes.
    pub network_id: &'a str,
}

impl fmt::Debug for PairingContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingContext")
            .field("network_id", &self.network_id)
            .finish_non_exhaustive()
    }
}

async fn post(
    ctx: &PairingContext<'_>,
    session: &PairingSession,
    outgoing: &Outgoing,
) -> Result<(), DriveError> {
    ctx.client
        .post_pairing_message(
            ctx.token,
            &session.rendezvous_id,
            &outgoing.payload,
            outgoing.count,
            outgoing.total_bytes,
            ctx.protocol,
        )
        .await?;
    Ok(())
}

/// Closes the rendezvous when asked, ignoring a failure, and empties the
/// pairing slot. The slot is emptied also when the close fails.
async fn cleanup(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &PairingSession,
    close: bool,
) {
    if close {
        let _ = ctx
            .client
            .close_pairing(ctx.token, &session.rendezvous_id, ctx.protocol)
            .await;
    }
    let _ = clear_pending(store);
}

/// Ends the session after a failed step and cleans up.
async fn abort(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
    error: DriveError,
) -> DriveError {
    session.end(EndReason::Failed);
    cleanup(ctx, store, session, true).await;
    error
}

/// The creator opens a rendezvous and gets the pairing link.
pub async fn start_creator(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    now: i64,
) -> Result<(PairingSession, PairingLink), DriveError> {
    let rendezvous = ctx.client.create_pairing(ctx.token, ctx.protocol).await?;
    let (session, link) = PairingSession::create(&rendezvous, now)?;
    if let Err(error) = save_pending(store, &session) {
        let _ = ctx
            .client
            .close_pairing(ctx.token, &session.rendezvous_id, ctx.protocol)
            .await;
        return Err(error.into());
    }
    Ok((session, link))
}

/// The joiner reads the link, joins and posts the initial message. `text`
/// holds the link and is cleared at once, also when the link is bad.
pub async fn start_joiner(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    text: &mut String,
    now: i64,
) -> Result<PairingSession, DriveError> {
    let link = take_pairing_link(text).map_err(FlowError::Link)?;
    let device = JoinerDevice::from_store(store)?;
    let rendezvous = ctx
        .client
        .join_pairing(ctx.token, link.rendezvous_id(), ctx.protocol)
        .await?;
    let (mut session, hello) = PairingSession::join(&link, &rendezvous, device, now)?;
    if let Err(error) = save_pending(store, &session) {
        session.end(EndReason::Failed);
        cleanup(ctx, store, &session, true).await;
        return Err(error.into());
    }
    if let Err(error) = post(ctx, &session, &hello).await {
        return Err(abort(ctx, store, &mut session, error).await);
    }
    Ok(session)
}

/// Fetches the messages after the last sequence (the catch-up) and takes
/// them in. Call it for every `e2e_pairing_message` event and after a
/// reconnect. A failure ends the pairing and cleans up.
pub async fn pump(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
) -> Result<(), DriveError> {
    if !session.is_active() {
        return Err(FlowError::NotActive.into());
    }
    let result = pump_inner(ctx, store, session).await;
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(abort(ctx, store, session, error).await),
    }
}

async fn pump_inner(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
) -> Result<(), DriveError> {
    let messages = ctx
        .client
        .fetch_pairing_messages(
            ctx.token,
            &session.rendezvous_id,
            session.last_seq,
            ctx.protocol,
        )
        .await?;
    for event in session.accept(&messages)? {
        match event {
            FlowEvent::CodeReady => {}
            FlowEvent::PeerConfirmed => {
                if session.confirmed_device().is_some() {
                    finish_creator(ctx, store, session).await?;
                }
            }
            FlowEvent::Granted(grant) => finish_joiner(ctx, store, session, &grant).await?,
        }
    }
    Ok(())
}

/// The user typed the code on this device. A wrong code ends the pairing.
pub async fn confirm(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
    typed: &str,
) -> Result<(), DriveError> {
    let outgoing = match session.confirm(typed) {
        Ok(outgoing) => outgoing,
        Err(FlowError::WrongCode) => {
            cleanup(ctx, store, session, true).await;
            return Err(FlowError::WrongCode.into());
        }
        Err(error) => return Err(error.into()),
    };
    let result = confirm_inner(ctx, store, session, outgoing).await;
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(abort(ctx, store, session, error).await),
    }
}

async fn confirm_inner(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
    outgoing: Option<Outgoing>,
) -> Result<(), DriveError> {
    if let Some(outgoing) = outgoing {
        post(ctx, session, &outgoing).await?;
    }
    if session.confirmed_device().is_some() {
        finish_creator(ctx, store, session).await?;
    }
    Ok(())
}

/// The creator signs and publishes. It is reached only through
/// `confirmed_device`, so both devices confirmed. The list goes to the
/// server before the grant goes to the joiner.
async fn finish_creator(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
) -> Result<(), DriveError> {
    let device = session
        .confirmed_device()
        .cloned()
        .ok_or(FlowError::NotConfirmed)?;
    let master = store
        .master_key()
        .map_err(|_| FlowError::Store)?
        .ok_or(FlowError::NoIdentity)?;
    let current = store.signed_list().ok_or(FlowError::NoIdentity)?;
    let grant = build_grant(&master, &current, &device.ed25519)?;
    let request = ListRequest::new(&grant.master, &grant.list)
        .map_err(|err| DriveError::from(E2eRouteError::Wire(err)))?;
    ctx.client
        .put_e2e_list(ctx.token, ctx.network_id, ctx.protocol, &request)
        .await?;
    store
        .set_signed_list(&grant.list)
        .map_err(|_| FlowError::Store)?;
    let outgoing = session.seal_grant(&grant)?;
    post(ctx, session, &outgoing).await?;
    // The joiner closes the rendezvous after it took the grant, so the grant
    // is still there to fetch.
    cleanup(ctx, store, session, false).await;
    Ok(())
}

/// The joiner checks the grant, saves it and runs the provision, which
/// registers the device and uploads its public bundle.
async fn finish_joiner(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
    grant: &Grant,
) -> Result<(), DriveError> {
    let own = JoinerDevice::from_store(store)?;
    apply_grant(store, &own.ed25519, grant)?;
    provision_device(ctx.client, ctx.token, ctx.network_id, ctx.protocol, store).await?;
    session.finish();
    cleanup(ctx, store, session, true).await;
    Ok(())
}

/// Handles a pairing event of the user topic. An event for another
/// rendezvous is stale and changes nothing.
pub async fn on_push(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
    push: &PairingPush,
) -> Result<(), DriveError> {
    match push {
        PairingPush::Message { rendezvous_id, .. } if *rendezvous_id == session.rendezvous_id => {
            pump(ctx, store, session).await
        }
        PairingPush::Closed {
            rendezvous_id,
            reason,
        } if *rendezvous_id == session.rendezvous_id => {
            session.on_closed(*reason);
            cleanup(ctx, store, session, false).await;
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The user cancelled. The rendezvous is closed and the slot is emptied.
pub async fn cancel(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
) {
    session.cancel();
    cleanup(ctx, store, session, true).await;
}

/// Ends a pairing whose lifetime is over. True when it ended now.
pub async fn tick(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
    now: i64,
) -> bool {
    if session.expire(now) {
        cleanup(ctx, store, session, true).await;
        return true;
    }
    false
}

/// Closes the rendezvous that a restart found open. A failure is ignored:
/// the relay drops a rendezvous after its lifetime.
pub async fn close_stale(ctx: &PairingContext<'_>, stale: &StalePairing) {
    let _ = ctx
        .client
        .close_pairing(ctx.token, stale.rendezvous_id(), ctx.protocol)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_store::{E2eKeyProvider, E2eStoreError};
    use crate::e2e_wire::{did_from_key_text, PAIRING_MAX_MESSAGES, PAIRING_TOTAL_MAX_BYTES};
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const ID: &str = "AbCdEfGhIjKlMnOpQrStUv";
    const PROTOCOL: Option<u32> = Some(50);
    const CREATOR_TOKEN: &str = "creator-token";
    const JOINER_TOKEN: &str = "joiner-token";

    struct TestKey([u8; 32]);

    impl E2eKeyProvider for TestKey {
        fn load_or_create_key(&self) -> Result<[u8; 32], E2eStoreError> {
            Ok(self.0)
        }
    }

    /// A random key for one test; no key is written in the source.
    fn fresh_key() -> TestKey {
        TestKey(Account::new().identity_keys().curve25519.to_bytes())
    }

    fn scratch_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "cordiale-e2e-pairing-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn open_store(dir: &std::path::Path, name: &str) -> E2eStateStore {
        E2eStateStore::open(dir.join(name), &fresh_key()).expect("open")
    }

    fn rendezvous(role: PairingRole) -> Rendezvous {
        Rendezvous {
            id: ID.to_string(),
            role,
            expires_at: "later".to_string(),
        }
    }

    fn device() -> JoinerDevice {
        let account = Account::new();
        let keys = account.identity_keys();
        JoinerDevice {
            ed25519: keys.ed25519.to_base64(),
            curve25519: keys.curve25519.to_base64(),
        }
    }

    fn relay(seq: u64, from: PairingRole, outgoing: &Outgoing) -> RelayMessage {
        RelayMessage {
            seq,
            from,
            payload: outgoing.payload.clone(),
        }
    }

    /// Two sessions with the channel open: the creator has read the hello.
    fn open_pair() -> (PairingSession, PairingSession, JoinerDevice) {
        let (mut creator, link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), 100).expect("create");
        let new_device = device();
        let (joiner, hello) = PairingSession::join(
            &link,
            &rendezvous(PairingRole::Joiner),
            new_device.clone(),
            100,
        )
        .expect("join");
        let events = creator
            .accept(&[relay(1, PairingRole::Joiner, &hello)])
            .expect("hello");
        assert_eq!(events, vec![FlowEvent::CodeReady]);
        (creator, joiner, new_device)
    }

    fn code_text(session: &PairingSession) -> String {
        match session.status() {
            PairingStatus::Code(code) => code,
            other => panic!("no code: {other:?}"),
        }
    }

    // ---- pure session ----

    #[test]
    fn both_sides_show_the_same_two_digit_code() {
        let (creator, joiner, _) = open_pair();
        let code = code_text(&creator);
        assert_eq!(code.len(), 2);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(code, code_text(&joiner));
    }

    #[test]
    fn success_needs_both_confirmations_before_the_signing_step() {
        let (mut creator, mut joiner, new_device) = open_pair();
        let code = code_text(&creator);
        // The joiner confirms first and sends its keys.
        let keys = joiner.confirm(&code).expect("joiner").expect("keys");
        let events = creator
            .accept(&[relay(2, PairingRole::Joiner, &keys)])
            .expect("keys");
        assert_eq!(events, vec![FlowEvent::PeerConfirmed]);
        // The creator has not confirmed: the signing step stays closed.
        assert!(creator.confirmed_device().is_none());
        let master = Account::new();
        let list = signed_list_of(&master, 1, &[device().ed25519]);
        let grant = build_grant(&master, &list, &new_device.ed25519).expect("grant");
        assert_eq!(
            creator.seal_grant(&grant).unwrap_err(),
            FlowError::NotConfirmed
        );
        assert!(creator.confirm(&code).expect("creator").is_none());
        assert_eq!(creator.confirmed_device(), Some(&new_device));
        let sealed = creator.seal_grant(&grant).expect("sealed");
        assert_eq!(creator.status(), PairingStatus::Done);
        let events = joiner
            .accept(&[relay(3, PairingRole::Creator, &sealed)])
            .expect("grant");
        assert_eq!(events, vec![FlowEvent::Granted(grant)]);
    }

    #[test]
    fn the_creator_without_the_keys_of_the_joiner_cannot_sign() {
        let (mut creator, _joiner, _) = open_pair();
        let code = code_text(&creator);
        creator.confirm(&code).expect("creator");
        assert!(creator.confirmed_device().is_none());
    }

    #[test]
    fn a_bad_code_ends_the_pairing_and_drops_the_channel() {
        let (mut creator, _joiner, _) = open_pair();
        let code = code_text(&creator);
        let wrong = format!("{:02}", (code.parse::<u8>().unwrap() + 1) % 100);
        assert_eq!(creator.confirm(&wrong).unwrap_err(), FlowError::WrongCode);
        assert_eq!(creator.status(), PairingStatus::Ended(EndReason::WrongCode));
        assert!(creator.channel.is_none());
        assert_eq!(creator.confirm(&code).unwrap_err(), FlowError::NotActive);
        let (mut other, _, _) = open_pair();
        assert_eq!(other.confirm("x1").unwrap_err(), FlowError::WrongCode);
    }

    #[test]
    fn confirm_before_the_channel_has_no_code() {
        let (mut creator, _link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), 0).expect("create");
        assert_eq!(creator.status(), PairingStatus::Waiting);
        assert_eq!(creator.confirm("10").unwrap_err(), FlowError::NoChannel);
    }

    #[test]
    fn cancel_and_close_end_the_pairing() {
        let (mut creator, mut joiner, _) = open_pair();
        creator.cancel();
        assert_eq!(creator.status(), PairingStatus::Ended(EndReason::Cancelled));
        joiner.on_closed(ClosedReason::Closed);
        assert_eq!(
            joiner.status(),
            PairingStatus::Ended(EndReason::Closed(ClosedReason::Closed))
        );
        // A later event does not change the end reason.
        joiner.on_closed(ClosedReason::Expired);
        assert_eq!(
            joiner.status(),
            PairingStatus::Ended(EndReason::Closed(ClosedReason::Closed))
        );
    }

    #[test]
    fn the_pairing_times_out_after_the_lifetime() {
        let (mut creator, _link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), 1_000).expect("create");
        let lifetime = i64::try_from(PAIRING_LIFETIME_SECS).unwrap();
        assert!(!creator.expire(1_000 + lifetime - 1));
        assert!(creator.is_active());
        assert!(creator.expire(1_000 + lifetime));
        assert_eq!(creator.status(), PairingStatus::Ended(EndReason::Timeout));
        assert!(!creator.expire(1_000 + 2 * lifetime));
    }

    #[test]
    fn a_repeat_and_a_catch_up_are_safe() {
        let (mut creator, mut joiner, _) = open_pair();
        let code = code_text(&creator);
        let keys = joiner.confirm(&code).unwrap().unwrap();
        let message = relay(2, PairingRole::Joiner, &keys);
        // The same message twice, with an own message of the creator and
        // the hello again: only the new message counts.
        let own = RelayMessage {
            seq: 3,
            from: PairingRole::Creator,
            payload: "ignored".to_string(),
        };
        let hello_again = RelayMessage {
            seq: 1,
            from: PairingRole::Joiner,
            payload: "ignored".to_string(),
        };
        let events = creator
            .accept(&[own, message.clone(), hello_again, message])
            .expect("accept");
        assert_eq!(events, vec![FlowEvent::PeerConfirmed]);
        assert_eq!(creator.last_seq(), 3);
    }

    #[test]
    fn a_message_that_does_not_open_ends_the_pairing() {
        let (mut creator, _joiner, _) = open_pair();
        let junk = RelayMessage {
            seq: 2,
            from: PairingRole::Joiner,
            payload: "AAAA".to_string(),
        };
        assert_eq!(creator.accept(&[junk]).unwrap_err(), FlowError::BadChannel);
        assert_eq!(
            creator.status(),
            PairingStatus::Ended(EndReason::BadChannel)
        );
        // A hello that does not open (a wrong key) also ends it.
        let (mut waiting, _link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), 0).unwrap();
        let junk = RelayMessage {
            seq: 1,
            from: PairingRole::Joiner,
            payload: "AAAA|AAAA".to_string(),
        };
        assert!(waiting.accept(&[junk]).is_err());
        assert!(!waiting.is_active());
    }

    #[test]
    fn a_hello_for_another_key_does_not_open() {
        let (_creator, link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), 0).unwrap();
        let (_other, other_link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), 0).unwrap();
        let (_joiner, hello) =
            PairingSession::join(&other_link, &rendezvous(PairingRole::Joiner), device(), 0)
                .unwrap();
        let (mut creator, _) =
            PairingSession::create(&rendezvous(PairingRole::Creator), 0).unwrap();
        let _ = link;
        assert!(creator
            .accept(&[relay(1, PairingRole::Joiner, &hello)])
            .is_err());
    }

    #[test]
    fn a_link_for_another_rendezvous_is_refused() {
        let (_creator, link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), 0).unwrap();
        let mut other = rendezvous(PairingRole::Joiner);
        other.id = "ZyXwVuTsRqPoNmLkJiHgFe".to_string();
        assert_eq!(
            PairingSession::join(&link, &other, device(), 0).unwrap_err(),
            FlowError::Link(PairingError::BadId)
        );
        assert_eq!(
            PairingSession::join(&link, &rendezvous(PairingRole::Creator), device(), 0)
                .unwrap_err(),
            FlowError::WrongRole
        );
    }

    #[test]
    fn a_payload_over_a_limit_is_refused_before_it_is_sealed() {
        let (_creator, mut joiner, _) = open_pair();
        let code = code_text(&joiner);
        joiner.relay_count = PAIRING_MAX_MESSAGES;
        assert_eq!(joiner.confirm(&code).unwrap_err(), FlowError::TooLarge);
        let (_creator, mut joiner, _) = open_pair();
        let code = code_text(&joiner);
        joiner.relay_bytes = PAIRING_TOTAL_MAX_BYTES - 10;
        assert_eq!(joiner.confirm(&code).unwrap_err(), FlowError::TooLarge);
    }

    #[test]
    fn a_message_over_the_size_limit_from_the_relay_ends_the_pairing() {
        let (mut creator, _joiner, _) = open_pair();
        let big = RelayMessage {
            seq: 2,
            from: PairingRole::Joiner,
            payload: "A".repeat(PAIRING_MESSAGE_MAX_BYTES + 1),
        };
        assert_eq!(creator.accept(&[big]).unwrap_err(), FlowError::BadMessage);
        assert!(!creator.is_active());
    }

    #[test]
    fn debug_output_holds_no_link_key_or_payload() {
        let (creator, joiner, new_device) = open_pair();
        let master = Account::new();
        let list = signed_list_of(&master, 1, &[device().ed25519]);
        let grant = build_grant(&master, &list, &new_device.ed25519).unwrap();
        let outgoing = Outgoing {
            payload: "SECRET-PAYLOAD".to_string(),
            count: 1,
            total_bytes: 2,
        };
        let stale = StalePairing {
            role: PairingRole::Creator,
            rendezvous_id: ID.to_string(),
        };
        let client = GrappaClient::new("http://localhost");
        let ctx = PairingContext {
            client: &client,
            token: "TOKEN-VALUE",
            protocol: PROTOCOL,
            network_id: "libera",
        };
        let text = format!(
            "{creator:?} {joiner:?} {new_device:?} {grant:?} {outgoing:?} {stale:?} {ctx:?}"
        );
        // The message names the value, never prints it.
        for (label, value) in [
            ("payload", "SECRET-PAYLOAD"),
            ("token", "TOKEN-VALUE"),
            ("rendezvous", ID),
            ("device ed25519", new_device.ed25519.as_str()),
            ("device curve25519", new_device.curve25519.as_str()),
            ("master", grant.master.as_str()),
            ("list signature", grant.list.signature.as_str()),
        ] {
            assert!(!text.contains(value), "{label}");
        }
    }

    // ---- grant ----

    fn signed_list_of(master: &Account, version: u32, keys: &[String]) -> SignedList {
        let signature =
            build_signed_list_signature(version, keys, |text| master.sign(text).to_base64())
                .unwrap();
        let mut sorted = keys.to_vec();
        sorted.sort();
        SignedList {
            version,
            keys: sorted,
            signature,
        }
    }

    #[test]
    fn the_grant_adds_the_device_and_signs_a_certificate_for_the_new_version() {
        let master = Account::new();
        let first = device().ed25519;
        let current = signed_list_of(&master, 1, std::slice::from_ref(&first));
        let new_device = device();
        let grant = build_grant(&master, &current, &new_device.ed25519).unwrap();
        assert_eq!(grant.list.version, 2);
        assert!(grant.list.keys.contains(&first));
        assert!(grant.list.keys.contains(&new_device.ed25519));
        let master_key = master.identity_keys().ed25519.to_base64();
        verify_signed_list(2, &grant.list.keys, &master_key, &grant.list.signature).unwrap();
        assert_eq!(grant.certificate.first_list_version, 2);
        verify_device_certificate(&grant.certificate, &[master_key]).unwrap();
    }

    #[test]
    fn a_full_list_or_a_forged_list_gives_no_grant() {
        let master = Account::new();
        let keys: Vec<String> = (0..4).map(|_| device().ed25519).collect();
        let full = signed_list_of(&master, 1, &keys);
        assert_eq!(
            build_grant(&master, &full, &device().ed25519).unwrap_err(),
            FlowError::ListFull
        );
        let other = Account::new();
        let forged = signed_list_of(&other, 1, &keys[..1]);
        assert_eq!(
            build_grant(&master, &forged, &device().ed25519).unwrap_err(),
            FlowError::NoIdentity
        );
    }

    #[test]
    fn the_joiner_refuses_a_grant_for_another_device() {
        let dir = scratch_dir("grant");
        let mut store = open_store(&dir, "joiner.bin");
        let own = JoinerDevice::from_store(&mut store).unwrap();
        let master = Account::new();
        let list = signed_list_of(&master, 1, &[device().ed25519]);
        let other = device();
        let grant = build_grant(&master, &list, &other.ed25519).unwrap();
        assert_eq!(
            apply_grant(&mut store, &own.ed25519, &grant).unwrap_err(),
            FlowError::BadGrant
        );
        assert!(store.signed_list().is_none());
        assert!(store.device_certificate().is_none());
        let good = build_grant(&master, &list, &own.ed25519).unwrap();
        apply_grant(&mut store, &own.ed25519, &good).unwrap();
        assert_eq!(store.signed_list(), Some(good.list.clone()));
        assert_eq!(store.device_certificate(), Some(good.certificate.clone()));
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- pairing slot ----

    #[test]
    fn the_slot_holds_a_record_without_keys_and_a_restart_empties_it() {
        let dir = scratch_dir("slot");
        let provider = fresh_key();
        let path = dir.join("state.bin");
        {
            let mut store = E2eStateStore::open(path.clone(), &provider).unwrap();
            let (session, link) =
                PairingSession::create(&rendezvous(PairingRole::Creator), 5).unwrap();
            save_pending(&mut store, &session).unwrap();
            let text = store.pending_pairing().unwrap().to_string();
            assert!(!text.contains(link.ephemeral_key()));
            assert!(text.contains(ID));
        }
        // A restart: the record is stale, it is returned once and emptied.
        let mut store = E2eStateStore::open(path.clone(), &provider).unwrap();
        let stale = take_stale_pairing(&mut store).unwrap().expect("stale");
        assert_eq!(stale.role, PairingRole::Creator);
        assert_eq!(stale.rendezvous_id(), ID);
        assert!(store.pending_pairing().is_none());
        assert!(take_stale_pairing(&mut store).unwrap().is_none());
        drop(store);
        let store = E2eStateStore::open(path, &provider).unwrap();
        assert!(store.pending_pairing().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_record_is_emptied_too() {
        let dir = scratch_dir("stale");
        let mut store = open_store(&dir, "state.bin");
        store.set_pending_pairing("not json").unwrap();
        assert!(take_stale_pairing(&mut store).unwrap().is_none());
        assert!(store.pending_pairing().is_none());
        store
            .set_pending_pairing(r#"{"v":9,"creator":true,"rendezvous_id":"x","started_at":1}"#)
            .unwrap();
        assert!(take_stale_pairing(&mut store).unwrap().is_none());
        assert!(store.pending_pairing().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- fake server: relay and network routes ----

    #[derive(Default)]
    struct Fake {
        joined: bool,
        closed: bool,
        messages: Vec<Value>,
        list: Option<Value>,
        devices: Vec<Value>,
        keys: HashMap<String, (usize, bool)>,
        list_puts: usize,
        key_posts: usize,
        pairing_calls: usize,
    }

    type Shared = Arc<Mutex<Fake>>;

    fn body_of(request: &Request) -> Value {
        serde_json::from_slice(&request.body).expect("json body")
    }

    fn is_joiner(request: &Request) -> bool {
        request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains(JOINER_TOKEN))
    }

    fn did_of_path(request: &Request) -> String {
        request
            .url
            .path()
            .split('/')
            .nth(5)
            .unwrap_or_default()
            .to_string()
    }

    async fn fake_server(state: &Shared) -> MockServer {
        let server = MockServer::start().await;
        let rendezvous_json =
            |role: &str| json!({"rendezvous": {"id": ID, "role": role, "expires_at": "later"}});

        let s = Arc::clone(state);
        Mock::given(method("POST"))
            .and(path("/e2e/pairings"))
            .respond_with(move |_: &Request| {
                s.lock().unwrap().pairing_calls += 1;
                ResponseTemplate::new(201).set_body_json(rendezvous_json("creator"))
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("POST"))
            .and(path(format!("/e2e/pairings/{ID}/join")))
            .respond_with(move |_: &Request| {
                let mut state = s.lock().unwrap();
                state.pairing_calls += 1;
                state.joined = true;
                ResponseTemplate::new(200).set_body_json(rendezvous_json("joiner"))
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("POST"))
            .and(path(format!("/e2e/pairings/{ID}/messages")))
            .respond_with(move |request: &Request| {
                let mut state = s.lock().unwrap();
                state.pairing_calls += 1;
                let from = if is_joiner(request) {
                    "joiner"
                } else {
                    "creator"
                };
                let message = json!({
                    "seq": state.messages.len() + 1,
                    "from": from,
                    "payload": body_of(request)["payload"].clone(),
                });
                state.messages.push(message.clone());
                ResponseTemplate::new(201).set_body_json(json!({"message": message}))
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("GET"))
            .and(path(format!("/e2e/pairings/{ID}/messages")))
            .respond_with(move |request: &Request| {
                let mut state = s.lock().unwrap();
                state.pairing_calls += 1;
                let after = request
                    .url
                    .query_pairs()
                    .find(|(name, _)| name == "after")
                    .and_then(|(_, value)| value.parse::<u64>().ok())
                    .unwrap_or(0);
                let messages: Vec<Value> = state
                    .messages
                    .iter()
                    .filter(|message| message["seq"].as_u64() > Some(after))
                    .cloned()
                    .collect();
                ResponseTemplate::new(200).set_body_json(json!({"messages": messages}))
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("DELETE"))
            .and(path(format!("/e2e/pairings/{ID}")))
            .respond_with(move |_: &Request| {
                let mut state = s.lock().unwrap();
                state.pairing_calls += 1;
                state.closed = true;
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("GET"))
            .and(path("/networks/libera/e2e/list"))
            .respond_with(move |_: &Request| match &s.lock().unwrap().list {
                Some(list) => ResponseTemplate::new(200).set_body_json(list),
                None => ResponseTemplate::new(404).set_body_json(json!({"error": "not_found"})),
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("PUT"))
            .and(path("/networks/libera/e2e/list"))
            .respond_with(move |request: &Request| {
                let body = body_of(request);
                let mut state = s.lock().unwrap();
                state.list_puts += 1;
                state.list = Some(body.clone());
                ResponseTemplate::new(200).set_body_json(body)
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("GET"))
            .and(path("/networks/libera/e2e/devices"))
            .respond_with(move |_: &Request| {
                let devices = s.lock().unwrap().devices.clone();
                ResponseTemplate::new(200).set_body_json(json!({"devices": devices}))
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("POST"))
            .and(path("/networks/libera/e2e/devices"))
            .respond_with(move |request: &Request| {
                let mut record = body_of(request);
                let ed25519 = record["ed25519"].clone();
                record["did"] = json!(did_from_key_text(ed25519.as_str().expect("key")).unwrap());
                let mut state = s.lock().unwrap();
                state.devices.retain(|device| device["ed25519"] != ed25519);
                state.devices.push(record.clone());
                ResponseTemplate::new(200).set_body_json(record)
            })
            .mount(&server)
            .await;

        let keys_path = r"^/networks/libera/e2e/devices/[A-Za-z0-9_-]{11}/keys$";
        let s = Arc::clone(state);
        Mock::given(method("GET"))
            .and(path_regex(keys_path))
            .respond_with(move |request: &Request| {
                let state = s.lock().unwrap();
                let (count, fallback) = state
                    .keys
                    .get(&did_of_path(request))
                    .copied()
                    .unwrap_or((0, false));
                ResponseTemplate::new(200)
                    .set_body_json(json!({"one_time_keys": count, "fallback": fallback}))
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("POST"))
            .and(path_regex(keys_path))
            .respond_with(move |request: &Request| {
                let body = body_of(request);
                let mut state = s.lock().unwrap();
                state.key_posts += 1;
                let entry = state.keys.entry(did_of_path(request)).or_default();
                entry.0 += body["one_time_keys"].as_array().map_or(0, Vec::len);
                entry.1 |= body.get("fallback").is_some();
                let (count, fallback) = *entry;
                ResponseTemplate::new(200)
                    .set_body_json(json!({"one_time_keys": count, "fallback": fallback}))
            })
            .mount(&server)
            .await;
        server
    }

    /// A server, a provisioned creator and a joiner that has an identity but
    /// no master. Both use the same server and the same account.
    struct World {
        server: MockServer,
        state: Shared,
        client: GrappaClient,
        dir: PathBuf,
        creator_store: E2eStateStore,
        joiner_store: E2eStateStore,
    }

    async fn world(name: &str) -> World {
        let dir = scratch_dir(name);
        let state = Shared::default();
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());
        let mut creator_store = open_store(&dir, "creator.bin");
        provision_device(
            &client,
            CREATOR_TOKEN,
            "libera",
            Some(49),
            &mut creator_store,
        )
        .await
        .expect("provision the creator");
        let mut joiner_store = open_store(&dir, "joiner.bin");
        JoinerDevice::from_store(&mut joiner_store).expect("identity");
        World {
            server,
            state,
            client,
            dir,
            creator_store,
            joiner_store,
        }
    }

    fn ctx<'a>(client: &'a GrappaClient, token: &'a str) -> PairingContext<'a> {
        PairingContext {
            client,
            token,
            protocol: PROTOCOL,
            network_id: "libera",
        }
    }

    #[tokio::test]
    async fn a_new_device_pairs_and_a_peer_can_ask_for_its_keys() {
        let mut w = world("success").await;
        let creator_ctx = ctx(&w.client, CREATOR_TOKEN);
        let joiner_ctx = ctx(&w.client, JOINER_TOKEN);
        assert_eq!(w.state.lock().unwrap().list_puts, 1);

        let (mut creator, link) = start_creator(&creator_ctx, &mut w.creator_store, 100)
            .await
            .expect("start creator");
        assert!(w.creator_store.pending_pairing().is_some());
        let mut text = link.url("grappa.example");
        let mut joiner = start_joiner(&joiner_ctx, &mut w.joiner_store, &mut text, 100)
            .await
            .expect("start joiner");
        assert!(text.is_empty(), "the link buffer is cleared");
        assert!(w.joiner_store.pending_pairing().is_some());

        pump(&creator_ctx, &mut w.creator_store, &mut creator)
            .await
            .expect("hello");
        let code = code_text(&creator);
        assert_eq!(code, code_text(&joiner));

        // The joiner confirms; the creator has not: nothing is published.
        confirm(&joiner_ctx, &mut w.joiner_store, &mut joiner, &code)
            .await
            .expect("joiner confirms");
        pump(&creator_ctx, &mut w.creator_store, &mut creator)
            .await
            .expect("keys");
        assert_eq!(w.state.lock().unwrap().list_puts, 1);
        assert_eq!(creator.status(), PairingStatus::Code(code.clone()));

        // The creator confirms: the list is signed and published, once.
        confirm(&creator_ctx, &mut w.creator_store, &mut creator, &code)
            .await
            .expect("creator confirms");
        assert_eq!(w.state.lock().unwrap().list_puts, 2);
        assert_eq!(creator.status(), PairingStatus::Done);
        assert!(w.creator_store.pending_pairing().is_none());

        pump(&joiner_ctx, &mut w.joiner_store, &mut joiner)
            .await
            .expect("grant");
        assert_eq!(joiner.status(), PairingStatus::Done);
        assert!(w.joiner_store.pending_pairing().is_none());

        let new_key = w
            .joiner_store
            .olm_identity()
            .unwrap()
            .unwrap()
            .identity_keys()
            .ed25519
            .to_base64();
        let new_did = did_from_key_text(&new_key).unwrap();
        let fake = w.state.lock().unwrap();
        assert!(fake.closed);
        let list = fake.list.as_ref().unwrap();
        assert_eq!(list["ver"], json!(2));
        assert!(list["devices"]
            .as_array()
            .unwrap()
            .contains(&json!(new_key)));
        // The new device is registered and holds a public bundle that a
        // peer can claim keys from.
        assert!(fake.devices.iter().any(|d| d["did"] == json!(new_did)));
        let (one_time, fallback) = fake.keys[&new_did];
        assert!(one_time > 0 && fallback);
        drop(fake);
        assert!(w.joiner_store.device_certificate().is_some());
        let _ = (&w.server, &w.dir);
        let _ = fs::remove_dir_all(&w.dir);
    }

    #[tokio::test]
    async fn the_joiner_confirming_alone_never_publishes_a_list() {
        let mut w = world("alone").await;
        let creator_ctx = ctx(&w.client, CREATOR_TOKEN);
        let joiner_ctx = ctx(&w.client, JOINER_TOKEN);
        let (mut creator, link) = start_creator(&creator_ctx, &mut w.creator_store, 0)
            .await
            .unwrap();
        let mut text = link.code();
        let mut joiner = start_joiner(&joiner_ctx, &mut w.joiner_store, &mut text, 0)
            .await
            .unwrap();
        pump(&creator_ctx, &mut w.creator_store, &mut creator)
            .await
            .unwrap();
        let code = code_text(&joiner);
        confirm(&joiner_ctx, &mut w.joiner_store, &mut joiner, &code)
            .await
            .unwrap();
        pump(&creator_ctx, &mut w.creator_store, &mut creator)
            .await
            .unwrap();
        assert_eq!(w.state.lock().unwrap().list_puts, 1);
        assert!(creator.is_active());
        let _ = fs::remove_dir_all(&w.dir);
    }

    #[tokio::test]
    async fn cancel_closes_the_rendezvous_and_empties_the_slot() {
        let mut w = world("cancel").await;
        let creator_ctx = ctx(&w.client, CREATOR_TOKEN);
        let (mut creator, _link) = start_creator(&creator_ctx, &mut w.creator_store, 0)
            .await
            .unwrap();
        cancel(&creator_ctx, &mut w.creator_store, &mut creator).await;
        assert_eq!(creator.status(), PairingStatus::Ended(EndReason::Cancelled));
        assert!(w.state.lock().unwrap().closed);
        assert!(w.creator_store.pending_pairing().is_none());
        let _ = fs::remove_dir_all(&w.dir);
    }

    #[tokio::test]
    async fn a_bad_code_closes_the_rendezvous_and_a_retry_starts_clean() {
        let mut w = world("badcode").await;
        let creator_ctx = ctx(&w.client, CREATOR_TOKEN);
        let joiner_ctx = ctx(&w.client, JOINER_TOKEN);
        let (mut creator, link) = start_creator(&creator_ctx, &mut w.creator_store, 0)
            .await
            .unwrap();
        let mut text = link.code();
        let mut joiner = start_joiner(&joiner_ctx, &mut w.joiner_store, &mut text, 0)
            .await
            .unwrap();
        pump(&creator_ctx, &mut w.creator_store, &mut creator)
            .await
            .unwrap();
        let code: u8 = code_text(&creator).parse().unwrap();
        let wrong = format!("{:02}", (code + 1) % 100);
        let result = confirm(&joiner_ctx, &mut w.joiner_store, &mut joiner, &wrong).await;
        assert!(matches!(
            result,
            Err(DriveError::Flow(FlowError::WrongCode))
        ));
        assert!(w.joiner_store.pending_pairing().is_none());
        assert!(w.state.lock().unwrap().closed);
        assert_eq!(w.state.lock().unwrap().list_puts, 1);

        // Retry: a new pairing starts with a new session and a new slot.
        let (retry, _link) = start_creator(&creator_ctx, &mut w.creator_store, 10)
            .await
            .unwrap();
        assert!(retry.is_active());
        assert!(w.creator_store.pending_pairing().is_some());
        let _ = fs::remove_dir_all(&w.dir);
    }

    #[tokio::test]
    async fn timeout_closes_the_rendezvous_and_empties_the_slot() {
        let mut w = world("timeout").await;
        let creator_ctx = ctx(&w.client, CREATOR_TOKEN);
        let (mut creator, _link) = start_creator(&creator_ctx, &mut w.creator_store, 0)
            .await
            .unwrap();
        assert!(!tick(&creator_ctx, &mut w.creator_store, &mut creator, 10).await);
        assert!(w.creator_store.pending_pairing().is_some());
        let late = i64::try_from(PAIRING_LIFETIME_SECS).unwrap();
        assert!(tick(&creator_ctx, &mut w.creator_store, &mut creator, late).await);
        assert_eq!(creator.status(), PairingStatus::Ended(EndReason::Timeout));
        assert!(w.creator_store.pending_pairing().is_none());
        assert!(w.state.lock().unwrap().closed);
        let _ = fs::remove_dir_all(&w.dir);
    }

    #[tokio::test]
    async fn events_for_another_rendezvous_are_stale_and_a_close_event_ends_the_pairing() {
        let mut w = world("events").await;
        let creator_ctx = ctx(&w.client, CREATOR_TOKEN);
        let (mut creator, _link) = start_creator(&creator_ctx, &mut w.creator_store, 0)
            .await
            .unwrap();
        let calls = w.state.lock().unwrap().pairing_calls;
        let stale = PairingPush::Message {
            rendezvous_id: "ZyXwVuTsRqPoNmLkJiHgFe".to_string(),
            seq: 1,
            from: PairingRole::Joiner,
        };
        on_push(&creator_ctx, &mut w.creator_store, &mut creator, &stale)
            .await
            .unwrap();
        assert_eq!(w.state.lock().unwrap().pairing_calls, calls);
        assert!(creator.is_active());
        let closed = PairingPush::Closed {
            rendezvous_id: ID.to_string(),
            reason: ClosedReason::Replaced,
        };
        on_push(&creator_ctx, &mut w.creator_store, &mut creator, &closed)
            .await
            .unwrap();
        assert_eq!(
            creator.status(),
            PairingStatus::Ended(EndReason::Closed(ClosedReason::Replaced))
        );
        assert!(w.creator_store.pending_pairing().is_none());
        let _ = fs::remove_dir_all(&w.dir);
    }

    #[tokio::test]
    async fn a_restart_closes_the_open_rendezvous_and_leaves_no_state() {
        let mut w = world("restart").await;
        let creator_ctx = ctx(&w.client, CREATOR_TOKEN);
        let (_creator, _link) = start_creator(&creator_ctx, &mut w.creator_store, 0)
            .await
            .unwrap();
        // The app stops here: the session is gone, the slot still holds the
        // record. The next start reads it, closes the rendezvous, empties it.
        let stale = take_stale_pairing(&mut w.creator_store)
            .unwrap()
            .expect("stale");
        close_stale(&creator_ctx, &stale).await;
        assert!(w.state.lock().unwrap().closed);
        assert!(w.creator_store.pending_pairing().is_none());
        let _ = fs::remove_dir_all(&w.dir);
    }

    #[tokio::test]
    async fn a_server_below_protocol_48_gets_no_pairing_request() {
        let w = world("old").await;
        let old = PairingContext {
            client: &w.client,
            token: CREATOR_TOKEN,
            protocol: Some(47),
            network_id: "libera",
        };
        let mut store = open_store(&w.dir, "old.bin");
        let before = w.state.lock().unwrap().pairing_calls;
        let result = start_creator(&old, &mut store, 0).await;
        assert!(
            matches!(&result, Err(DriveError::Call(error)) if matches!(**error, PairingCallError::Unavailable))
        );
        assert_eq!(w.state.lock().unwrap().pairing_calls, before);
        assert!(store.pending_pairing().is_none());
        let _ = fs::remove_dir_all(&w.dir);
    }

    #[tokio::test]
    async fn a_payload_over_the_limit_is_refused_before_the_call() {
        let w = world("limit").await;
        let before = w.state.lock().unwrap().pairing_calls;
        let big = "A".repeat(PAIRING_MESSAGE_MAX_BYTES + 1);
        let result = w
            .client
            .post_pairing_message(CREATOR_TOKEN, ID, &big, 0, 0, PROTOCOL)
            .await;
        assert!(matches!(result, Err(PairingCallError::TooLarge)));
        let result = w
            .client
            .post_pairing_message(CREATOR_TOKEN, ID, "A", PAIRING_MAX_MESSAGES, 0, PROTOCOL)
            .await;
        assert!(matches!(result, Err(PairingCallError::TooLarge)));
        assert_eq!(w.state.lock().unwrap().pairing_calls, before);
        let _ = fs::remove_dir_all(&w.dir);
    }

    #[tokio::test]
    async fn the_paired_device_provisions_again_without_a_master() {
        let mut w = world("again").await;
        let creator_ctx = ctx(&w.client, CREATOR_TOKEN);
        let joiner_ctx = ctx(&w.client, JOINER_TOKEN);
        let (mut creator, link) = start_creator(&creator_ctx, &mut w.creator_store, 0)
            .await
            .unwrap();
        let mut text = link.code();
        let mut joiner = start_joiner(&joiner_ctx, &mut w.joiner_store, &mut text, 0)
            .await
            .unwrap();
        pump(&creator_ctx, &mut w.creator_store, &mut creator)
            .await
            .unwrap();
        let code = code_text(&creator);
        confirm(&joiner_ctx, &mut w.joiner_store, &mut joiner, &code)
            .await
            .unwrap();
        confirm(&creator_ctx, &mut w.creator_store, &mut creator, &code)
            .await
            .unwrap();
        // The creator reads the keys of the joiner now, and signs.
        pump(&creator_ctx, &mut w.creator_store, &mut creator)
            .await
            .unwrap();
        pump(&joiner_ctx, &mut w.joiner_store, &mut joiner)
            .await
            .unwrap();
        // A later start runs the provision again: it needs no pairing.
        let again = provision_device(
            &w.client,
            JOINER_TOKEN,
            "libera",
            Some(49),
            &mut w.joiner_store,
        )
        .await
        .expect("provision again");
        assert!(!again.device_registered && !again.list_published);
        assert!(w.joiner_store.master_key().unwrap().is_none());
        let _ = fs::remove_dir_all(&w.dir);
    }
}
