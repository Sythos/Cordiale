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
//! The creator is the holder: a device that holds the master key. It opens a
//! rendezvous and shows the pairing link. The joiner is the new device. It
//! reads the link and joins. The two sides then do these steps:
//!
//! 1. The joiner opens an ECIES channel to the key of the link and posts the
//!    initial message `hello`. The relay refuses a `|` in a payload, so this
//!    first payload travels as base64url of its UTF-8, unpadded.
//! 2. The joiner shows the two-digit check code. The user types it on the
//!    holder. A wrong code ends the pairing. The holder then sends `offer`
//!    with its network and master key.
//! 3. The user confirms on the joiner. The joiner posts `join` with its public
//!    device keys and its own signature over the id text (S1).
//! 4. The holder checks the signature, signs the new list and the certificate,
//!    puts the list and posts `signed`. Nothing is signed or published before
//!    both confirmations.
//! 5. The joiner checks `signed`, saves list and certificate, provisions its
//!    bundle and posts `done`. The holder closes the rendezvous.
//!
//! The messages are compact JSON with `"v":1` and a `"t"` kind. The shapes,
//! the info text `irc-e2e:v2:pair` and the digit mode `AllowLeadingZero` are
//! the final text of section 4g of the Grappa client protocol, and match
//! `pairingMessages.ts` of Cicchetto. This device pairs one network for each
//! pairing. An `offer` that names more networks is read for that network only,
//! and the others go in `skipped`. A change of the contract touches this
//! module only.
//!
//! The channel secret lives in memory only. The sealed store holds a small
//! record (role, rendezvous id, start time) in its pairing slot, so a restart
//! knows that a rendezvous is open and closes it. The slot is empty after
//! success, cancel, timeout, failure and restart.
//!
//! No `Debug` output holds a link, a key or a payload.

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
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
    verify_signature, verify_signed_list, VersionedDeviceCertificate,
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
    check_list_devices, decode_key, decode_signature, device_id_signed_text, pairing_message_fits,
    MAX_VERSION, PAIRING_LIFETIME_SECS, PAIRING_MESSAGE_MAX_BYTES,
};

/// The info text of the ECIES channel. Final value: section 4g of the Grappa
/// client protocol.
pub const PAIRING_INFO: &str = "irc-e2e:v2:pair";

/// The `v` of every plaintext message of the channel.
const WIRE_VERSION: u8 = 1;

/// The reasons that a network can be left out of a pairing.
const REFUSAL_REASONS: [&str; 4] = ["full", "paired", "list-changed", "failed"];

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
    /// The step needs a confirmation or a message that is not there yet.
    NotConfirmed,
    /// A payload is over a limit of the relay. Nothing was sent.
    TooLarge,
    BadChannel,
    BadMessage,
    /// The signed answer does not verify, or it is for another device.
    BadGrant,
    /// The list has four devices already, or its version is at the top.
    ListFull,
    /// The creator has no master key or no own list.
    NoIdentity,
    /// The offer of the holder does not name the network of this pairing.
    NotOffered,
    /// The holder refused the device, or its answer holds no certificate.
    Refused,
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

/// What the holder hands to the joiner in `signed`: the master key (from the
/// offer), the certificate for the new device and the new signed list.
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

#[derive(Serialize, Deserialize)]
struct WireNetwork {
    network: String,
    master: String,
}

#[derive(Serialize, Deserialize)]
struct WireId {
    curve25519: String,
    ed25519: String,
    sig: String,
}

#[derive(Serialize, Deserialize)]
struct WireJoined {
    network: String,
    id: WireId,
}

#[derive(Serialize, Deserialize)]
struct WireReason {
    network: String,
    reason: String,
}

#[derive(Serialize, Deserialize)]
struct WireList {
    ver: u32,
    devices: Vec<String>,
    sig: String,
}

#[derive(Serialize, Deserialize)]
struct WireSigned {
    network: String,
    cert: String,
    list: WireList,
}

/// The plaintext messages of the channel, as section 4g of the Grappa client
/// protocol lists them. An unknown extra field is ignored; a missing or
/// ill-typed field, an unknown `t` and a `v` other than 1 are refused.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
enum Wire {
    Hello {
        v: u8,
    },
    Offer {
        v: u8,
        networks: Vec<WireNetwork>,
        full: Vec<String>,
    },
    Join {
        v: u8,
        devices: Vec<WireJoined>,
        skipped: Vec<WireReason>,
    },
    Signed {
        v: u8,
        devices: Vec<WireSigned>,
        refused: Vec<WireReason>,
    },
    Done {
        v: u8,
        paired: Vec<String>,
    },
}

fn reasons_ok(list: &[WireReason]) -> bool {
    list.iter()
        .all(|item| !item.network.is_empty() && REFUSAL_REASONS.contains(&item.reason.as_str()))
}

impl Wire {
    /// The message when its version, keys, signatures and reasons are valid.
    fn checked(self) -> Option<Self> {
        let (v, ok) = match &self {
            Wire::Hello { v } => (*v, true),
            Wire::Offer { v, networks, full } => (
                *v,
                networks
                    .iter()
                    .all(|item| !item.network.is_empty() && decode_key(&item.master).is_ok())
                    && full.iter().all(|network| !network.is_empty()),
            ),
            Wire::Join {
                v,
                devices,
                skipped,
            } => (
                *v,
                devices.iter().all(|item| {
                    !item.network.is_empty()
                        && decode_key(&item.id.ed25519).is_ok()
                        && decode_key(&item.id.curve25519).is_ok()
                        && decode_signature(&item.id.sig).is_ok()
                }) && reasons_ok(skipped),
            ),
            Wire::Signed {
                v,
                devices,
                refused,
            } => (
                *v,
                devices.iter().all(|item| {
                    !item.network.is_empty()
                        && decode_signature(&item.cert).is_ok()
                        && decode_signature(&item.list.sig).is_ok()
                        && item.list.devices.iter().all(|key| decode_key(key).is_ok())
                }) && reasons_ok(refused),
            ),
            Wire::Done { v, paired } => (*v, paired.iter().all(|network| !network.is_empty())),
        };
        (v == WIRE_VERSION && ok).then_some(self)
    }
}

/// Reads the bytes of an opened message, or `None` for anything off-shape.
fn read_wire(bytes: &[u8]) -> Option<Wire> {
    serde_json::from_slice::<Wire>(bytes).ok()?.checked()
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
    /// The joiner took the offer of the holder and knows the master key.
    Offered,
    /// The holder took the public keys of the joiner. The caller must check
    /// the signature of the id block and then answer with `signed`.
    Joined,
    /// The joiner took the signed answer. The caller must verify and apply it.
    Signed(Grant),
    /// The holder took `done`: the joiner is paired.
    Paired,
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
    /// The slug of the network that this pairing changes.
    network: String,
    started_at: i64,
    stage: Stage,
    waiting: Option<Ecies>,
    channel: Option<EstablishedEcies>,
    own_device: Option<JoinerDevice>,
    peer_device: Option<JoinerDevice>,
    /// The signature of the id block of the joiner, as the holder read it.
    peer_id_sig: Option<String>,
    /// The master key: the own one for the holder, the offered one for the
    /// joiner.
    master: Option<String>,
    /// The joiner: networks of the offer that this device leaves out.
    skipped: Vec<WireReason>,
    offer_sent: bool,
    join_sent: bool,
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
    channel.check_code().to_digit(DigitMode::AllowLeadingZero)
}

impl PairingSession {
    fn new(role: PairingRole, rendezvous_id: &str, network: &str, now: i64) -> Self {
        Self {
            role,
            rendezvous_id: rendezvous_id.to_string(),
            network: network.to_string(),
            started_at: now,
            stage: Stage::Open,
            waiting: None,
            channel: None,
            own_device: None,
            peer_device: None,
            peer_id_sig: None,
            master: None,
            skipped: Vec::new(),
            offer_sent: false,
            join_sent: false,
            code: None,
            own_confirmed: false,
            last_seq: 0,
            relay_count: 0,
            relay_bytes: 0,
        }
    }

    /// The creator side: makes the ephemeral key and the pairing link.
    pub fn create(
        rendezvous: &Rendezvous,
        network: &str,
        now: i64,
    ) -> Result<(Self, PairingLink), FlowError> {
        if rendezvous.role != PairingRole::Creator {
            return Err(FlowError::WrongRole);
        }
        let ecies = Ecies::with_info(PAIRING_INFO);
        let link = PairingLink::new(&rendezvous.id, &ecies.public_key().to_base64())
            .map_err(FlowError::Link)?;
        let mut session = Self::new(PairingRole::Creator, &rendezvous.id, network, now);
        session.waiting = Some(ecies);
        Ok((session, link))
    }

    /// The joiner side: opens the channel to the key of the link. Gives the
    /// session and the initial message to post. The initial message travels
    /// as base64url, because the relay refuses the `|` of its encoding.
    pub fn join(
        link: &PairingLink,
        rendezvous: &Rendezvous,
        network: &str,
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
        let hello = serde_json::to_vec(&Wire::Hello { v: WIRE_VERSION })
            .map_err(|_| FlowError::BadMessage)?;
        let OutboundCreationResult { ecies, message } = Ecies::with_info(PAIRING_INFO)
            .establish_outbound_channel(their, &hello)
            .map_err(|_| FlowError::BadChannel)?;
        let payload = URL_SAFE_NO_PAD.encode(message.encode().as_bytes());
        if !pairing_message_fits(0, 0, payload.len()) {
            return Err(FlowError::TooLarge);
        }
        let mut session = Self::new(PairingRole::Joiner, &rendezvous.id, network, now);
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

    /// The holder sets its own master key, which the offer carries.
    pub fn set_master(&mut self, master: &str) -> Result<(), FlowError> {
        decode_key(master).map_err(|_| FlowError::NoIdentity)?;
        self.master = Some(master.to_string());
        Ok(())
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
        let encoded = URL_SAFE_NO_PAD
            .decode(payload)
            .ok()
            .and_then(|raw| String::from_utf8(raw).ok());
        let Some(Ok(initial)) = encoded.as_deref().map(InitialMessage::decode) else {
            return Err(self.fail(EndReason::BadChannel, FlowError::BadChannel));
        };
        let InboundCreationResult { ecies, message } =
            match ecies.establish_inbound_channel(&initial) {
                Ok(result) => result,
                Err(_) => return Err(self.fail(EndReason::BadChannel, FlowError::BadChannel)),
            };
        if !matches!(read_wire(&message), Some(Wire::Hello { .. })) {
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
        let wire = read_wire(&plain);
        plain.zeroize();
        match (self.role, wire) {
            (PairingRole::Joiner, Some(Wire::Offer { networks, .. })) => self.take_offer(networks),
            (PairingRole::Creator, Some(Wire::Join { devices, .. })) => self.take_join(devices),
            (PairingRole::Joiner, Some(Wire::Signed { devices, .. })) => self.take_signed(devices),
            (PairingRole::Creator, Some(Wire::Done { paired, .. })) => {
                if self.offer_sent && paired.contains(&self.network) {
                    Ok(Some(FlowEvent::Paired))
                } else {
                    Err(self.fail(EndReason::Failed, FlowError::BadMessage))
                }
            }
            _ => Err(self.fail(EndReason::BadMessage, FlowError::BadMessage)),
        }
    }

    /// The joiner keeps the master key offered for its network. The other
    /// offered networks go in `skipped`.
    fn take_offer(&mut self, networks: Vec<WireNetwork>) -> Result<Option<FlowEvent>, FlowError> {
        if self.master.is_some() {
            return Err(self.fail(EndReason::BadMessage, FlowError::BadMessage));
        }
        let mut master = None;
        let mut skipped = Vec::new();
        for item in networks {
            if item.network == self.network {
                master = Some(item.master);
            } else {
                skipped.push(WireReason {
                    network: item.network,
                    reason: "failed".to_string(),
                });
            }
        }
        let Some(master) = master else {
            return Err(self.fail(EndReason::Failed, FlowError::NotOffered));
        };
        self.master = Some(master);
        self.skipped = skipped;
        Ok(Some(FlowEvent::Offered))
    }

    /// The holder keeps the device keys and the signature of the joiner. The
    /// signature is checked in `peer_id_signature_valid`.
    fn take_join(&mut self, devices: Vec<WireJoined>) -> Result<Option<FlowEvent>, FlowError> {
        let entry = devices
            .into_iter()
            .find(|item| item.network == self.network);
        let Some(entry) = entry else {
            return Err(self.fail(EndReason::Failed, FlowError::Refused));
        };
        if !self.offer_sent || self.peer_device.is_some() {
            return Err(self.fail(EndReason::BadMessage, FlowError::BadMessage));
        }
        self.peer_device = Some(JoinerDevice {
            ed25519: entry.id.ed25519,
            curve25519: entry.id.curve25519,
        });
        self.peer_id_sig = Some(entry.id.sig);
        Ok(Some(FlowEvent::Joined))
    }

    /// The joiner builds the grant from the answer of the holder.
    fn take_signed(&mut self, devices: Vec<WireSigned>) -> Result<Option<FlowEvent>, FlowError> {
        let entry = devices
            .into_iter()
            .find(|item| item.network == self.network);
        let (Some(entry), Some(master), Some(own)) =
            (entry, self.master.clone(), self.own_device.clone())
        else {
            return Err(self.fail(EndReason::Failed, FlowError::Refused));
        };
        let grant = Grant {
            certificate: VersionedDeviceCertificate {
                first_list_version: entry.list.ver,
                device_ed25519: own.ed25519,
                master_ed25519: master.clone(),
                signature: entry.cert,
            },
            list: SignedList {
                version: entry.list.ver,
                keys: entry.list.devices,
                signature: entry.list.sig,
            },
            master,
        };
        Ok(Some(FlowEvent::Signed(grant)))
    }

    /// The user typed the code of this device. A code that is not the check
    /// code ends the pairing. The holder gets its sealed `offer` to post. The
    /// joiner gets nothing here: its `join` follows with `seal_join`, when the
    /// offer is there.
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
        if self.role == PairingRole::Joiner {
            self.own_confirmed = true;
            return Ok(None);
        }
        let master = self.master.clone().ok_or(FlowError::NoIdentity)?;
        let network = self.network.clone();
        let outgoing = self.seal(&Wire::Offer {
            v: WIRE_VERSION,
            networks: vec![WireNetwork { network, master }],
            full: Vec::new(),
        })?;
        self.own_confirmed = true;
        self.offer_sent = true;
        Ok(Some(outgoing))
    }

    /// True when the joiner confirmed, holds the offer and sent no `join`.
    pub fn join_ready(&self) -> bool {
        self.role == PairingRole::Joiner
            && self.stage == Stage::Keyed
            && self.own_confirmed
            && self.master.is_some()
            && !self.join_sent
    }

    /// Seals `join` for the joiner. `id_signature` is the signature of the
    /// own device over the id text for the offered master key (S1).
    pub fn seal_join(&mut self, id_signature: &str) -> Result<Outgoing, FlowError> {
        if !self.join_ready() {
            return Err(FlowError::NotConfirmed);
        }
        let device = self.own_device.clone().ok_or(FlowError::NoIdentity)?;
        let wire = Wire::Join {
            v: WIRE_VERSION,
            devices: vec![WireJoined {
                network: self.network.clone(),
                id: WireId {
                    curve25519: device.curve25519,
                    ed25519: device.ed25519,
                    sig: id_signature.to_string(),
                },
            }],
            skipped: std::mem::take(&mut self.skipped),
        };
        let outgoing = self.seal(&wire)?;
        self.join_sent = true;
        Ok(outgoing)
    }

    /// The keys of the joiner, once the holder confirmed and sent its offer.
    /// This is the only way to the signing step of the holder.
    pub fn confirmed_device(&self) -> Option<&JoinerDevice> {
        if self.role == PairingRole::Creator
            && self.stage == Stage::Keyed
            && self.own_confirmed
            && self.offer_sent
        {
            self.peer_device.as_ref()
        } else {
            None
        }
    }

    /// True when the joiner signed its id block for the master of the holder.
    pub fn peer_id_signature_valid(&self) -> bool {
        match (&self.peer_device, &self.peer_id_sig, &self.master) {
            (Some(device), Some(signature), Some(master)) => verify_signature(
                &device.ed25519,
                signature,
                device_id_signed_text(&device.curve25519, master).as_bytes(),
            )
            .is_ok(),
            _ => false,
        }
    }

    /// Seals `signed` for the joiner. Refused until both sides confirmed. The
    /// pairing stays open until the joiner answers `done`.
    pub fn seal_signed(&mut self, grant: &Grant) -> Result<Outgoing, FlowError> {
        if self.confirmed_device().is_none() {
            return Err(FlowError::NotConfirmed);
        }
        let wire = Wire::Signed {
            v: WIRE_VERSION,
            devices: vec![WireSigned {
                network: self.network.clone(),
                cert: grant.certificate.signature.clone(),
                list: WireList {
                    ver: grant.list.version,
                    devices: grant.list.keys.clone(),
                    sig: grant.list.signature.clone(),
                },
            }],
            refused: Vec::new(),
        };
        self.seal(&wire)
    }

    /// Seals `signed` with a refusal for the network. The pairing ends as
    /// failed on this side.
    pub fn seal_refusal(&mut self, reason: &str) -> Result<Outgoing, FlowError> {
        if self.confirmed_device().is_none() || !REFUSAL_REASONS.contains(&reason) {
            return Err(FlowError::NotConfirmed);
        }
        let wire = Wire::Signed {
            v: WIRE_VERSION,
            devices: Vec::new(),
            refused: vec![WireReason {
                network: self.network.clone(),
                reason: reason.to_string(),
            }],
        };
        let outgoing = self.seal(&wire)?;
        self.end(EndReason::Failed);
        Ok(outgoing)
    }

    /// Seals `done` for the holder, after the joiner kept the answer.
    pub fn seal_done(&mut self) -> Result<Outgoing, FlowError> {
        if self.role != PairingRole::Joiner || !self.join_sent {
            return Err(FlowError::NotConfirmed);
        }
        let wire = Wire::Done {
            v: WIRE_VERSION,
            paired: vec![self.network.clone()],
        };
        self.seal(&wire)
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
    let (session, link) = PairingSession::create(&rendezvous, ctx.network_id, now)?;
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
    let (mut session, hello) =
        PairingSession::join(&link, &rendezvous, ctx.network_id, device, now)?;
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
            FlowEvent::Offered => send_join_if_ready(ctx, store, session).await?,
            FlowEvent::Joined => finish_creator(ctx, store, session).await?,
            FlowEvent::Signed(grant) => finish_joiner(ctx, store, session, &grant).await?,
            FlowEvent::Paired => {
                // The holder closes the rendezvous after `done`.
                session.finish();
                cleanup(ctx, store, session, true).await;
            }
        }
    }
    Ok(())
}

/// The holder takes its master key, which the offer carries. A joiner has
/// nothing to prepare.
fn prepare_holder(store: &E2eStateStore, session: &mut PairingSession) -> Result<(), FlowError> {
    if session.role != PairingRole::Creator || session.master.is_some() {
        return Ok(());
    }
    let master = store
        .master_key()
        .map_err(|_| FlowError::Store)?
        .ok_or(FlowError::NoIdentity)?;
    session.set_master(&master.identity_keys().ed25519.to_base64())
}

/// The user typed the code on this device. A wrong code ends the pairing.
pub async fn confirm(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
    typed: &str,
) -> Result<(), DriveError> {
    prepare_holder(store, session)?;
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
    send_join_if_ready(ctx, store, session).await
}

/// The joiner posts `join` when it confirmed and holds the offer. The id
/// block carries the signature of this device over the id text for the
/// offered master key (S1).
async fn send_join_if_ready(
    ctx: &PairingContext<'_>,
    store: &E2eStateStore,
    session: &mut PairingSession,
) -> Result<(), DriveError> {
    if !session.join_ready() {
        return Ok(());
    }
    let account = store
        .olm_identity()
        .map_err(|_| FlowError::Store)?
        .ok_or(FlowError::NoIdentity)?;
    let master = session.master.clone().ok_or(FlowError::NotConfirmed)?;
    let curve25519 = account.identity_keys().curve25519.to_base64();
    let signature = account
        .sign(device_id_signed_text(&curve25519, &master).as_bytes())
        .to_base64();
    let outgoing = session.seal_join(&signature)?;
    post(ctx, session, &outgoing).await
}

/// The holder answers a refusal and ends. The joiner closes the rendezvous.
async fn refuse(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
    reason: &str,
) -> Result<(), DriveError> {
    let outgoing = session.seal_refusal(reason)?;
    post(ctx, session, &outgoing).await?;
    cleanup(ctx, store, session, false).await;
    Ok(())
}

/// The holder signs and publishes. It is reached only after the `join`
/// message, so both sides confirmed. The list goes to the server before
/// `signed` goes to the joiner. A bad id signature, a device that is listed
/// already and a full list get a refusal.
async fn finish_creator(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
) -> Result<(), DriveError> {
    let device = session
        .confirmed_device()
        .cloned()
        .ok_or(FlowError::NotConfirmed)?;
    if !session.peer_id_signature_valid() {
        return refuse(ctx, store, session, "failed").await;
    }
    let master = store
        .master_key()
        .map_err(|_| FlowError::Store)?
        .ok_or(FlowError::NoIdentity)?;
    let current = store.signed_list().ok_or(FlowError::NoIdentity)?;
    if current.keys.contains(&device.ed25519) {
        return refuse(ctx, store, session, "paired").await;
    }
    let grant = match build_grant(&master, &current, &device.ed25519) {
        Ok(grant) => grant,
        Err(FlowError::ListFull) => return refuse(ctx, store, session, "full").await,
        Err(error) => return Err(error.into()),
    };
    let request = ListRequest::new(&grant.master, &grant.list)
        .map_err(|err| DriveError::from(E2eRouteError::Wire(err)))?;
    ctx.client
        .put_e2e_list(ctx.token, ctx.network_id, ctx.protocol, &request)
        .await?;
    store
        .set_signed_list(&grant.list)
        .map_err(|_| FlowError::Store)?;
    let outgoing = session.seal_signed(&grant)?;
    post(ctx, session, &outgoing).await
}

/// The joiner checks the answer, saves it and runs the provision, which
/// registers the device and uploads its public bundle. Then it posts `done`.
/// The holder closes the rendezvous.
async fn finish_joiner(
    ctx: &PairingContext<'_>,
    store: &mut E2eStateStore,
    session: &mut PairingSession,
    grant: &Grant,
) -> Result<(), DriveError> {
    let own = JoinerDevice::from_store(store)?;
    apply_grant(store, &own.ed25519, grant)?;
    provision_device(ctx.client, ctx.token, ctx.network_id, ctx.protocol, store).await?;
    let outgoing = session.seal_done()?;
    post(ctx, session, &outgoing).await?;
    session.finish();
    cleanup(ctx, store, session, false).await;
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
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const ID: &str = "AbCdEfGhIjKlMnOpQrStUv";
    const NET: &str = "azzurra";

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

    fn key_of(account: &Account) -> String {
        account.identity_keys().ed25519.to_base64()
    }

    fn device_of(account: &Account) -> JoinerDevice {
        let keys = account.identity_keys();
        JoinerDevice {
            ed25519: keys.ed25519.to_base64(),
            curve25519: keys.curve25519.to_base64(),
        }
    }

    fn id_signature(account: &Account, master: &str) -> String {
        let curve = account.identity_keys().curve25519.to_base64();
        account
            .sign(device_id_signed_text(&curve, master).as_bytes())
            .to_base64()
    }

    fn signed_list_of(master: &Account, version: u32, keys: &[String]) -> SignedList {
        let signature =
            build_signed_list_signature(version, keys, |text| master.sign(text).to_base64())
                .expect("list signature");
        SignedList {
            version,
            keys: keys.to_vec(),
            signature,
        }
    }

    fn relay(seq: u64, from: PairingRole, outgoing: &Outgoing) -> RelayMessage {
        RelayMessage {
            seq,
            from,
            payload: outgoing.payload.clone(),
        }
    }

    struct Pair {
        creator: PairingSession,
        joiner: PairingSession,
        master: Account,
        account: Account,
    }

    /// Two sessions with the channel open: the holder has read the hello and
    /// knows its master key.
    fn open_pair() -> Pair {
        let master = Account::new();
        let account = Account::new();
        let (mut creator, link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), NET, 100).expect("create");
        creator.set_master(&key_of(&master)).expect("master");
        let (joiner, hello) = PairingSession::join(
            &link,
            &rendezvous(PairingRole::Joiner),
            NET,
            device_of(&account),
            100,
        )
        .expect("join");
        let events = creator
            .accept(&[relay(1, PairingRole::Joiner, &hello)])
            .expect("hello");
        assert_eq!(events, vec![FlowEvent::CodeReady]);
        Pair {
            creator,
            joiner,
            master,
            account,
        }
    }

    fn code_text(session: &PairingSession) -> String {
        match session.status() {
            PairingStatus::Code(code) => code,
            other => panic!("no code: {other:?}"),
        }
    }

    /// Runs the steps up to the `join` message that the holder has read.
    fn joined_pair() -> Pair {
        let mut pair = open_pair();
        let code = code_text(&pair.creator);
        let offer = pair.creator.confirm(&code).expect("code").expect("offer");
        let events = pair
            .joiner
            .accept(&[relay(2, PairingRole::Creator, &offer)])
            .expect("offer");
        assert_eq!(events, vec![FlowEvent::Offered]);
        assert!(pair.joiner.confirm(&code).expect("confirm").is_none());
        assert!(pair.joiner.join_ready());
        let signature = id_signature(&pair.account, &key_of(&pair.master));
        let join = pair.joiner.seal_join(&signature).expect("join message");
        let events = pair
            .creator
            .accept(&[relay(3, PairingRole::Joiner, &join)])
            .expect("join");
        assert_eq!(events, vec![FlowEvent::Joined]);
        pair
    }

    // ---- wire messages ----

    fn key() -> String {
        key_of(&Account::new())
    }

    fn signature() -> String {
        Account::new().sign(b"x").to_base64()
    }

    #[test]
    fn the_five_messages_of_section_4g_read() {
        let hello = json!({"v": 1, "t": "hello"});
        let offer = json!({"v": 1, "t": "offer", "networks": [{"network": NET, "master": key()}], "full": []});
        let join = json!({"v": 1, "t": "join", "devices": [{"network": NET, "id": {
            "curve25519": key(), "ed25519": key(), "sig": signature()}}], "skipped": []});
        let signed = json!({"v": 1, "t": "signed", "devices": [{"network": NET, "cert": signature(),
            "list": {"ver": 2, "devices": [key()], "sig": signature()}}], "refused": []});
        let done = json!({"v": 1, "t": "done", "paired": [NET]});
        for value in [hello, offer, join, signed, done] {
            let bytes = serde_json::to_vec(&value).expect("json");
            assert!(read_wire(&bytes).is_some(), "{value}");
        }
    }

    /// The fixture file with its two placeholders filled in.
    fn pairing_fixture() -> serde_json::Value {
        let text = include_str!("../tests/fixtures/e2e/pairing_v1.json")
            .replace("$KEY", "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo")
            .replace("$SIG", &"A".repeat(86));
        serde_json::from_str(&text).expect("fixture file is JSON")
    }

    #[test]
    fn the_fixture_messages_read_and_the_invalid_ones_do_not() {
        let all = pairing_fixture();
        for case in all["valid"].as_array().expect("valid") {
            let bytes = serde_json::to_vec(&case["message"]).expect("json");
            assert!(read_wire(&bytes).is_some(), "{}", case["case"]);
        }
        for case in all["invalid"].as_array().expect("invalid") {
            let bytes = serde_json::to_vec(&case["message"]).expect("json");
            assert!(read_wire(&bytes).is_none(), "{}", case["case"]);
        }
    }

    #[test]
    fn an_unknown_extra_field_is_ignored() {
        let bytes = br#"{"v":1,"t":"done","paired":["azzurra"],"extra":true}"#;
        assert!(read_wire(bytes).is_some());
    }

    #[test]
    fn malformed_messages_are_refused() {
        let cases = [
            json!({"v": 2, "t": "hello"}),
            json!({"t": "hello"}),
            json!({"v": 1, "t": "unknown"}),
            json!({"v": 1}),
            json!({"v": 1, "t": "done"}),
            json!({"v": 1, "t": "done", "paired": [""]}),
            json!({"v": 1, "t": "done", "paired": "azzurra"}),
            json!({"v": 1, "t": "offer", "networks": [{"network": NET, "master": "short"}], "full": []}),
            json!({"v": 1, "t": "join", "devices": [], "skipped": [{"network": NET, "reason": "other"}]}),
            json!({"v": 1, "t": "signed", "devices": [{"network": NET, "cert": "short",
                "list": {"ver": 2, "devices": [], "sig": signature()}}], "refused": []}),
        ];
        for value in cases {
            let bytes = serde_json::to_vec(&value).expect("json");
            assert!(read_wire(&bytes).is_none(), "{value}");
        }
        assert!(read_wire(b"not json").is_none());
    }

    // ---- pure session ----

    #[test]
    fn both_sides_show_the_same_two_digit_code() {
        let pair = open_pair();
        let code = code_text(&pair.creator);
        assert_eq!(code.len(), 2);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(code, code_text(&pair.joiner));
    }

    #[test]
    fn the_initial_message_is_base64url_without_a_bar() {
        let account = Account::new();
        let (_creator, link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), NET, 100).expect("create");
        let (_joiner, hello) = PairingSession::join(
            &link,
            &rendezvous(PairingRole::Joiner),
            NET,
            device_of(&account),
            100,
        )
        .expect("join");
        let payload = hello.payload();
        assert!(!payload.contains('|'));
        assert!(payload
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let raw = URL_SAFE_NO_PAD.decode(payload).expect("base64url");
        let text = String::from_utf8(raw).expect("utf-8");
        assert!(text.contains('|'));
    }

    #[test]
    fn a_plain_encoding_of_the_initial_message_is_refused() {
        let (mut creator, link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), NET, 100).expect("create");
        let their = Curve25519PublicKey::from_base64(link.ephemeral_key()).expect("key");
        let hello = serde_json::to_vec(&Wire::Hello { v: 1 }).expect("hello");
        let OutboundCreationResult { message, .. } = Ecies::with_info(PAIRING_INFO)
            .establish_outbound_channel(their, &hello)
            .expect("outbound");
        let plain = RelayMessage {
            seq: 1,
            from: PairingRole::Joiner,
            payload: message.encode(),
        };
        assert_eq!(creator.accept(&[plain]).unwrap_err(), FlowError::BadChannel);
        assert_eq!(
            creator.status(),
            PairingStatus::Ended(EndReason::BadChannel)
        );
    }

    #[test]
    fn the_whole_pairing_runs_in_the_order_of_section_4g() {
        let mut pair = joined_pair();
        assert!(pair.creator.peer_id_signature_valid());
        let device = pair.creator.confirmed_device().cloned().expect("device");
        assert_eq!(device, device_of(&pair.account));
        let own = Account::new();
        let list = signed_list_of(&pair.master, 1, &[key_of(&own)]);
        let grant = build_grant(&pair.master, &list, &device.ed25519).expect("grant");
        let signed = pair.creator.seal_signed(&grant).expect("signed");
        let events = pair
            .joiner
            .accept(&[relay(4, PairingRole::Creator, &signed)])
            .expect("signed");
        assert_eq!(events, vec![FlowEvent::Signed(grant)]);
        let done = pair.joiner.seal_done().expect("done");
        pair.joiner.finish();
        assert_eq!(pair.joiner.status(), PairingStatus::Done);
        let events = pair
            .creator
            .accept(&[relay(5, PairingRole::Joiner, &done)])
            .expect("done");
        assert_eq!(events, vec![FlowEvent::Paired]);
    }

    #[test]
    fn the_holder_without_a_master_key_sends_no_offer() {
        let account = Account::new();
        let (mut creator, link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), NET, 100).expect("create");
        let (_joiner, hello) = PairingSession::join(
            &link,
            &rendezvous(PairingRole::Joiner),
            NET,
            device_of(&account),
            100,
        )
        .expect("join");
        creator
            .accept(&[relay(1, PairingRole::Joiner, &hello)])
            .expect("hello");
        let code = code_text(&creator);
        assert_eq!(creator.confirm(&code).unwrap_err(), FlowError::NoIdentity);
        assert!(creator.confirmed_device().is_none());
    }

    #[test]
    fn a_bad_code_ends_the_pairing_and_drops_the_channel() {
        let mut pair = open_pair();
        let code = code_text(&pair.creator);
        let wrong = format!("{:02}", (code.parse::<u8>().unwrap() + 1) % 100);
        assert_eq!(
            pair.creator.confirm(&wrong).unwrap_err(),
            FlowError::WrongCode
        );
        assert_eq!(
            pair.creator.status(),
            PairingStatus::Ended(EndReason::WrongCode)
        );
        assert!(pair.creator.channel.is_none());
        assert_eq!(
            pair.creator.confirm(&code).unwrap_err(),
            FlowError::NotActive
        );
    }

    #[test]
    fn the_joiner_sends_no_join_before_the_offer() {
        let mut pair = open_pair();
        let code = code_text(&pair.joiner);
        assert!(pair.joiner.confirm(&code).expect("confirm").is_none());
        assert!(!pair.joiner.join_ready());
        assert_eq!(
            pair.joiner.seal_join("sig").unwrap_err(),
            FlowError::NotConfirmed
        );
    }

    #[test]
    fn the_joiner_sends_no_join_before_its_own_confirmation() {
        let mut pair = open_pair();
        let code = code_text(&pair.creator);
        let offer = pair.creator.confirm(&code).expect("code").expect("offer");
        pair.joiner
            .accept(&[relay(2, PairingRole::Creator, &offer)])
            .expect("offer");
        assert!(!pair.joiner.join_ready());
        assert_eq!(
            pair.joiner.seal_join("sig").unwrap_err(),
            FlowError::NotConfirmed
        );
    }

    #[test]
    fn an_id_signature_for_another_master_is_not_valid() {
        let mut pair = open_pair();
        let code = code_text(&pair.creator);
        let offer = pair.creator.confirm(&code).expect("code").expect("offer");
        pair.joiner
            .accept(&[relay(2, PairingRole::Creator, &offer)])
            .expect("offer");
        pair.joiner.confirm(&code).expect("confirm");
        let signature = id_signature(&pair.account, &key());
        let join = pair.joiner.seal_join(&signature).expect("join message");
        pair.creator
            .accept(&[relay(3, PairingRole::Joiner, &join)])
            .expect("join");
        assert!(!pair.creator.peer_id_signature_valid());
    }

    #[test]
    fn a_refusal_ends_both_sides() {
        let mut pair = joined_pair();
        let refusal = pair.creator.seal_refusal("full").expect("refusal");
        assert_eq!(
            pair.creator.status(),
            PairingStatus::Ended(EndReason::Failed)
        );
        assert_eq!(
            pair.joiner
                .accept(&[relay(4, PairingRole::Creator, &refusal)])
                .unwrap_err(),
            FlowError::Refused
        );
        assert_eq!(
            pair.joiner.status(),
            PairingStatus::Ended(EndReason::Failed)
        );
    }

    #[test]
    fn a_refusal_needs_a_known_reason_and_the_join() {
        let mut pair = open_pair();
        assert_eq!(
            pair.creator.seal_refusal("failed").unwrap_err(),
            FlowError::NotConfirmed
        );
        let mut joined = joined_pair();
        assert_eq!(
            joined.creator.seal_refusal("other").unwrap_err(),
            FlowError::NotConfirmed
        );
    }

    #[test]
    fn signed_cannot_be_sealed_before_the_join() {
        let mut pair = open_pair();
        let code = code_text(&pair.creator);
        pair.creator.confirm(&code).expect("code");
        let list = signed_list_of(&pair.master, 1, &[key()]);
        let grant = build_grant(&pair.master, &list, &key()).expect("grant");
        assert_eq!(
            pair.creator.seal_signed(&grant).unwrap_err(),
            FlowError::NotConfirmed
        );
    }

    #[test]
    fn an_offer_without_the_network_ends_the_joiner() {
        let master = Account::new();
        let account = Account::new();
        let (mut other, link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), "other-net", 100)
                .expect("create");
        other.set_master(&key_of(&master)).expect("master");
        let (mut joiner, hello) = PairingSession::join(
            &link,
            &rendezvous(PairingRole::Joiner),
            NET,
            device_of(&account),
            100,
        )
        .expect("join");
        other
            .accept(&[relay(1, PairingRole::Joiner, &hello)])
            .expect("hello");
        let code = code_text(&other);
        let offer = other.confirm(&code).expect("code").expect("offer");
        assert_eq!(
            joiner
                .accept(&[relay(2, PairingRole::Creator, &offer)])
                .unwrap_err(),
            FlowError::NotOffered
        );
        assert_eq!(joiner.status(), PairingStatus::Ended(EndReason::Failed));
    }

    #[test]
    fn a_done_message_before_the_offer_ends_the_holder() {
        let mut pair = open_pair();
        let code = code_text(&pair.creator);
        pair.joiner.confirm(&code).expect("confirm");
        // The joiner sends `done` before any offer: the holder refuses it.
        pair.joiner.join_sent = true;
        let done = pair.joiner.seal_done().expect("done");
        assert_eq!(
            pair.creator
                .accept(&[relay(2, PairingRole::Joiner, &done)])
                .unwrap_err(),
            FlowError::BadMessage
        );
        assert_eq!(
            pair.creator.status(),
            PairingStatus::Ended(EndReason::Failed)
        );
    }

    #[test]
    fn a_repeated_or_stale_message_gives_no_second_event() {
        let mut pair = open_pair();
        let code = code_text(&pair.creator);
        let offer = pair.creator.confirm(&code).expect("code").expect("offer");
        let message = relay(2, PairingRole::Creator, &offer);
        let first = pair
            .joiner
            .accept(std::slice::from_ref(&message))
            .expect("offer");
        assert_eq!(first, vec![FlowEvent::Offered]);
        let again = pair.joiner.accept(&[message]).expect("repeat");
        assert!(again.is_empty());
        assert_eq!(pair.joiner.last_seq(), 2);
    }

    #[test]
    fn a_message_of_the_own_side_is_skipped() {
        let mut pair = open_pair();
        let code = code_text(&pair.creator);
        let offer = pair.creator.confirm(&code).expect("code").expect("offer");
        let own = relay(2, PairingRole::Creator, &offer);
        assert!(pair.creator.accept(&[own]).expect("own").is_empty());
    }

    #[test]
    fn an_oversize_payload_ends_the_pairing() {
        let mut pair = open_pair();
        let big = RelayMessage {
            seq: 2,
            from: PairingRole::Creator,
            payload: "A".repeat(PAIRING_MESSAGE_MAX_BYTES + 1),
        };
        assert_eq!(
            pair.joiner.accept(&[big]).unwrap_err(),
            FlowError::BadMessage
        );
    }

    #[test]
    fn a_session_expires_after_its_lifetime() {
        let mut pair = open_pair();
        assert!(!pair.creator.expire(100));
        let lifetime = i64::try_from(PAIRING_LIFETIME_SECS).expect("lifetime");
        assert!(pair.creator.expire(100 + lifetime));
        assert_eq!(
            pair.creator.status(),
            PairingStatus::Ended(EndReason::Timeout)
        );
    }

    #[test]
    fn a_session_with_the_wrong_role_is_refused() {
        assert_eq!(
            PairingSession::create(&rendezvous(PairingRole::Joiner), NET, 1).unwrap_err(),
            FlowError::WrongRole
        );
    }

    // ---- list and certificate ----

    #[test]
    fn a_grant_adds_the_device_and_applies() {
        let master = Account::new();
        let holder = Account::new();
        let joiner = Account::new();
        let list = signed_list_of(&master, 1, &[key_of(&holder)]);
        let grant = build_grant(&master, &list, &key_of(&joiner)).expect("grant");
        assert_eq!(grant.list.version, 2);
        assert_eq!(grant.list.keys.len(), 2);
        let dir = scratch_dir("apply");
        let mut store = open_store(&dir, "joiner.bin");
        apply_grant(&mut store, &key_of(&joiner), &grant).expect("apply");
        assert_eq!(store.signed_list().map(|list| list.version), Some(2));
    }

    #[test]
    fn a_grant_for_another_device_is_refused() {
        let master = Account::new();
        let list = signed_list_of(&master, 1, &[key()]);
        let grant = build_grant(&master, &list, &key()).expect("grant");
        let dir = scratch_dir("other-device");
        let mut store = open_store(&dir, "joiner.bin");
        assert_eq!(
            apply_grant(&mut store, &key(), &grant).unwrap_err(),
            FlowError::BadGrant
        );
        assert!(store.signed_list().is_none());
    }

    #[test]
    fn a_grant_with_a_bad_list_signature_is_refused() {
        let master = Account::new();
        let joiner = Account::new();
        let list = signed_list_of(&master, 1, &[key()]);
        let mut grant = build_grant(&master, &list, &key_of(&joiner)).expect("grant");
        grant.list.signature = signature();
        let dir = scratch_dir("bad-list");
        let mut store = open_store(&dir, "joiner.bin");
        assert_eq!(
            apply_grant(&mut store, &key_of(&joiner), &grant).unwrap_err(),
            FlowError::BadGrant
        );
    }

    #[test]
    fn a_grant_with_a_certificate_of_another_master_is_refused() {
        let master = Account::new();
        let joiner = Account::new();
        let list = signed_list_of(&master, 1, &[key()]);
        let mut grant = build_grant(&master, &list, &key_of(&joiner)).expect("grant");
        grant.certificate.signature = signature();
        let dir = scratch_dir("bad-cert");
        let mut store = open_store(&dir, "joiner.bin");
        assert_eq!(
            apply_grant(&mut store, &key_of(&joiner), &grant).unwrap_err(),
            FlowError::BadGrant
        );
    }

    #[test]
    fn a_full_list_gives_no_grant() {
        let master = Account::new();
        let keys: Vec<String> = (0..4).map(|_| key()).collect();
        let list = signed_list_of(&master, 1, &keys);
        assert_eq!(
            build_grant(&master, &list, &key()).unwrap_err(),
            FlowError::ListFull
        );
    }

    #[test]
    fn a_list_signed_by_another_master_gives_no_grant() {
        let master = Account::new();
        let list = signed_list_of(&Account::new(), 1, &[key()]);
        assert_eq!(
            build_grant(&master, &list, &key()).unwrap_err(),
            FlowError::NoIdentity
        );
    }

    // ---- pairing slot ----

    #[test]
    fn a_restart_finds_the_open_rendezvous_once() {
        let dir = scratch_dir("stale");
        let mut store = open_store(&dir, "state.bin");
        let (session, _link) =
            PairingSession::create(&rendezvous(PairingRole::Creator), NET, 100).expect("create");
        save_pending(&mut store, &session).expect("save");
        let stale = take_stale_pairing(&mut store)
            .expect("take")
            .expect("record");
        assert_eq!(stale.rendezvous_id(), ID);
        assert_eq!(stale.role, PairingRole::Creator);
        assert!(take_stale_pairing(&mut store).expect("again").is_none());
    }
}
