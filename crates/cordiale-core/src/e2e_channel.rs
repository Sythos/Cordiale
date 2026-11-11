// MIT License
//
// Copyright (c) 2026 Sythos ([https://www.sythos.net/](https://www.sythos.net/))
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

//! Group keys for end-to-end encrypted channels (protocol 62 and higher).
//!
//! The model follows the Grappa channel contract: one Megolm group session
//! for each sending device, not one key for the whole channel.
//!
//! - A device encrypts its channel messages with its own outbound group
//!   session. The payload is `{"v":3,"ch":…,"sid":…,"i":…,"body":…}`.
//! - The device gives the key of its session to every member in one pairwise
//!   Olm message: `{"t":"gkey","ch":…,"sid":…,"key":…}`. The key never goes
//!   to the server and never into a channel line.
//! - The key is exported at the current message index. A member who joins
//!   later gets the key from that index on and cannot read earlier messages.
//! - A member who leaves or is removed makes the own session invalid on
//!   every remaining device. The device makes a new session and gives its key
//!   to the remaining members only. The old session is deleted.
//! - The sender is the device that gave the key through Olm. A message is
//!   opened only with the session of a member device, so the sender is a
//!   verified device identity and never a nickname.
//! - A membership event carries a sequence number. A number that is not
//!   higher than the last one is ignored, so duplicate and out-of-order
//!   events are safe.
//!
//! This module is pure state: no network, no UI. The state is a part of the
//! sealed E2E state file (`e2e_state.rs`) and is separate from the Olm
//! sessions of the private queries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle,
    MegolmMessage, SessionConfig, SessionKey,
};
use zeroize::Zeroize;

/// Version of the channel payload.
pub const PAYLOAD_VERSION: u8 = 3;
/// Message indices that a device remembers for each inbound session.
pub const SEEN_WINDOW: usize = 1024;
/// Inbound sessions kept for each sending device: the current one and the
/// one before it, so a message in flight at a rotation still opens.
const SESSIONS_PER_DEVICE: usize = 2;
/// Longest accepted channel payload text.
const MAX_PAYLOAD_LEN: usize = 32 * 1024;
/// Key shares that wait for the membership of their sender, for each channel.
const MAX_PENDING_SHARES: usize = 16;
/// Longest key share text that waits.
const MAX_SHARE_LEN: usize = 1024;

/// Why a channel operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// The text is not a valid payload or key share.
    BadFormat,
    /// The channel in the text is not the channel of the window.
    WrongChannel,
    /// Cordiale has no session for the sender and session id.
    UnknownSession,
    /// The sender device is not a member of the channel.
    NotMember,
    /// The ciphertext, the signature or the message index is not valid.
    BadCiphertext,
    /// The message index was accepted before.
    Replay,
    /// The channel has no valid key to send with.
    NoKey,
    /// The own device is not a member of the channel.
    NotAuthorized,
}

/// What the UI shows for a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStatus {
    /// The channel does not use E2E. Plain channels stay as they are.
    Plain,
    /// The channel is E2E and the own device has no valid key to send with.
    NoKey,
    /// The channel is E2E and the own device can send.
    Encrypted,
}

/// What happens to a message that the user sends in an E2E channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPlan {
    /// Seal the message with the own group session.
    Encrypt,
    /// Keep the message. Cordiale has no key. Nothing goes out.
    Pending,
    /// Send the clear text. Only after an explicit user choice.
    Plain,
}

/// The result of a membership event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipOutcome {
    /// The sequence number is not new. The event is ignored.
    Stale,
    /// The member set did not change.
    Unchanged,
    /// The member set changed. `removed` is true when a member left: the own
    /// session is then invalid and the next send makes a new one.
    Changed { removed: bool },
}

/// An opened message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub sender_did: String,
    pub session_id: String,
    pub index: u32,
    pub text: String,
}

/// Normalized id of a channel on a network. `channel` is already folded.
pub fn channel_id(network: &str, channel: &str) -> String {
    format!("{network}\u{0}{channel}")
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Inbound {
    /// JSON of the pickle of the inbound group session.
    pickle: String,
    /// Order of arrival, to drop the oldest session of a device.
    order: u64,
    /// Message indices accepted.
    seen: VecDeque<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ChannelState {
    /// Authorized devices (`did`).
    members: BTreeSet<String>,
    /// Sequence number of the last membership event applied.
    membership_seq: u64,
    /// True while the own session is invalid.
    needs_rotation: bool,
    /// JSON of the pickle of the own outbound group session.
    outbound: Option<String>,
    /// Members that got the key of the own current session.
    shared_to: BTreeSet<String>,
    /// Inbound sessions by `did`, then session id.
    inbound: BTreeMap<String, BTreeMap<String, Inbound>>,
    /// Counter for `Inbound::order`.
    counter: u64,
    /// Key shares of devices that were not members yet: `(did, text)`. The
    /// first Olm message of a new peer can come before the membership event.
    /// A share waits here and is read when its sender becomes a member.
    #[serde(default)]
    pending: Vec<(String, String)>,
}

impl ChannelState {
    fn wipe(&mut self) {
        if let Some(text) = self.outbound.as_mut() {
            text.zeroize();
        }
        self.outbound = None;
        self.shared_to.clear();
    }

    fn wipe_all(&mut self) {
        self.wipe();
        for (_, text) in self.pending.iter_mut() {
            text.zeroize();
        }
        self.pending.clear();
        for sessions in self.inbound.values_mut() {
            for entry in sessions.values_mut() {
                entry.pickle.zeroize();
            }
        }
        self.inbound.clear();
    }
}

/// The channel sessions of this device. The pickle texts are overwritten on
/// drop.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelKeyring {
    channels: BTreeMap<String, ChannelState>,
}

impl Drop for ChannelKeyring {
    fn drop(&mut self) {
        for state in self.channels.values_mut() {
            state.wipe_all();
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Payload {
    v: u8,
    ch: String,
    sid: String,
    i: u32,
    body: String,
}

#[derive(Serialize, Deserialize)]
struct KeyShare {
    t: String,
    ch: String,
    sid: String,
    key: String,
}

/// Reads a key share for `channel`: the session id and the inbound session.
fn parse_share(channel: &str, text: &str) -> Result<(String, InboundGroupSession), ChannelError> {
    let share: KeyShare = serde_json::from_str(text).map_err(|_| ChannelError::BadFormat)?;
    if share.t != "gkey" {
        return Err(ChannelError::BadFormat);
    }
    if share.ch != channel {
        return Err(ChannelError::WrongChannel);
    }
    let key = SessionKey::from_base64(&share.key).map_err(|_| ChannelError::BadFormat)?;
    let session = InboundGroupSession::new(&key, SessionConfig::default());
    if session.session_id() != share.sid {
        return Err(ChannelError::BadFormat);
    }
    Ok((share.sid, session))
}

fn load_outbound(text: &str) -> Option<GroupSession> {
    let pickle: GroupSessionPickle = serde_json::from_str(text).ok()?;
    Some(GroupSession::from_pickle(pickle))
}

fn dump_outbound(session: &GroupSession) -> Option<String> {
    serde_json::to_string(&session.pickle()).ok()
}

impl ChannelKeyring {
    /// A keyring without channels.
    pub fn new() -> Self {
        Self::default()
    }

    /// What the UI shows. `e2e` is true when the channel was set to E2E.
    pub fn status(&self, network: &str, channel: &str, e2e: bool) -> ChannelStatus {
        if !e2e {
            return ChannelStatus::Plain;
        }
        match self.channels.get(&channel_id(network, channel)) {
            Some(state) if state.outbound.is_some() && !state.needs_rotation => {
                ChannelStatus::Encrypted
            }
            _ => ChannelStatus::NoKey,
        }
    }

    /// Chooses the route of a send in an E2E channel. Without a key the
    /// result is `Pending`. `Plain` needs `allow_plain`, the explicit
    /// choice of the user for this message.
    pub fn plan_send(&self, network: &str, channel: &str, allow_plain: bool) -> SendPlan {
        match self.status(network, channel, true) {
            ChannelStatus::Encrypted => SendPlan::Encrypt,
            _ if allow_plain => SendPlan::Plain,
            _ => SendPlan::Pending,
        }
    }

    /// The members known for the channel.
    pub fn members(&self, network: &str, channel: &str) -> Vec<String> {
        self.channels
            .get(&channel_id(network, channel))
            .map(|state| state.members.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The sequence number of the last membership event applied to the
    /// channel, or 0 when the channel has no state. The value is saved with
    /// the keyring, so it survives a restart.
    pub fn membership_seq(&self, network: &str, channel: &str) -> u64 {
        self.channels
            .get(&channel_id(network, channel))
            .map_or(0, |state| state.membership_seq)
    }

    /// Applies a membership event. `members` is the full set of authorized
    /// devices after the event. A number that is not above the last one is
    /// ignored. A member that left invalidates the own session and deletes
    /// the sessions of that member.
    pub fn apply_membership(
        &mut self,
        network: &str,
        channel: &str,
        seq: u64,
        members: BTreeSet<String>,
    ) -> MembershipOutcome {
        let state = self
            .channels
            .entry(channel_id(network, channel))
            .or_default();
        if seq <= state.membership_seq {
            return MembershipOutcome::Stale;
        }
        state.membership_seq = seq;
        if state.members == members {
            return MembershipOutcome::Unchanged;
        }
        let gone: Vec<String> = state.members.difference(&members).cloned().collect();
        let removed = !gone.is_empty();
        for did in &gone {
            if let Some(sessions) = state.inbound.remove(did) {
                for mut entry in sessions.into_values() {
                    entry.pickle.zeroize();
                }
            }
        }
        state.members = members;
        if removed {
            state.wipe();
            state.needs_rotation = true;
        }
        // A key share that waited for its sender is read now. A share of a
        // device that is not a member yet keeps waiting.
        for (did, mut text) in std::mem::take(&mut state.pending) {
            if state.members.contains(&did) {
                if let Ok((sid, session)) = parse_share(channel, &text) {
                    let _ = Self::insert_session(state, &did, sid, &session);
                }
                text.zeroize();
            } else {
                state.pending.push((did, text));
            }
        }
        MembershipOutcome::Changed { removed }
    }

    /// Removes revoked devices from every channel of `network`. A revoked
    /// device is a removed member: its inbound sessions and waiting key
    /// shares are deleted. When it was a member or held the key of the own
    /// session, the own session becomes invalid and the next send makes a
    /// new one for the remaining members only. The sequence number of the
    /// membership does not change. Returns true when a channel changed.
    pub fn revoke_devices(&mut self, network: &str, dids: &BTreeSet<String>) -> bool {
        let prefix = channel_id(network, "");
        let mut changed = false;
        for (key, state) in self.channels.iter_mut() {
            if !key.starts_with(&prefix) {
                continue;
            }
            let mut rotate = false;
            for did in dids {
                rotate |= state.members.remove(did);
                rotate |= state.shared_to.contains(did);
                if let Some(sessions) = state.inbound.remove(did) {
                    for mut entry in sessions.into_values() {
                        entry.pickle.zeroize();
                    }
                    changed = true;
                }
            }
            for (did, mut text) in std::mem::take(&mut state.pending) {
                if dids.contains(&did) {
                    text.zeroize();
                    changed = true;
                } else {
                    state.pending.push((did, text));
                }
            }
            if rotate {
                state.wipe();
                state.needs_rotation = true;
                changed = true;
            }
        }
        changed
    }

    /// Makes sure the own device can send: it makes a new outbound session
    /// when there is none or when a member left. Returns the members that
    /// still need the key of the current session. The own device must be a
    /// member.
    pub fn prepare_outbound(
        &mut self,
        network: &str,
        channel: &str,
        own_did: &str,
    ) -> Result<Vec<String>, ChannelError> {
        let state = self
            .channels
            .get_mut(&channel_id(network, channel))
            .ok_or(ChannelError::NotAuthorized)?;
        if !state.members.contains(own_did) {
            return Err(ChannelError::NotAuthorized);
        }
        if state.outbound.is_none() || state.needs_rotation {
            Self::start_session(state)?;
        }
        Ok(Self::missing_shares(state, own_did))
    }

    /// Replaces the own session on purpose (periodic rotation). The old
    /// session is deleted. Returns the members that need the new key.
    pub fn rotate(
        &mut self,
        network: &str,
        channel: &str,
        own_did: &str,
    ) -> Result<Vec<String>, ChannelError> {
        let state = self
            .channels
            .get_mut(&channel_id(network, channel))
            .ok_or(ChannelError::NotAuthorized)?;
        if !state.members.contains(own_did) {
            return Err(ChannelError::NotAuthorized);
        }
        Self::start_session(state)?;
        Ok(Self::missing_shares(state, own_did))
    }

    fn start_session(state: &mut ChannelState) -> Result<(), ChannelError> {
        let session = GroupSession::new(SessionConfig::default());
        let text = dump_outbound(&session).ok_or(ChannelError::BadFormat)?;
        state.wipe();
        state.outbound = Some(text);
        state.needs_rotation = false;
        Ok(())
    }

    fn missing_shares(state: &ChannelState, own_did: &str) -> Vec<String> {
        state
            .members
            .iter()
            .filter(|did| did.as_str() != own_did && !state.shared_to.contains(*did))
            .cloned()
            .collect()
    }

    /// True when a member still lacks the key of the current own session.
    /// A send then moves the ratchet before that member has the key.
    pub fn has_missing_shares(&self, network: &str, channel: &str, own_did: &str) -> bool {
        self.channels
            .get(&channel_id(network, channel))
            .is_some_and(|state| !Self::missing_shares(state, own_did).is_empty())
    }

    /// The text of the key share for the current own session. The caller
    /// sends it to one member through the Olm path only. The key is
    /// exported at the current message index.
    pub fn key_share(&self, network: &str, channel: &str) -> Result<String, ChannelError> {
        let state = self
            .channels
            .get(&channel_id(network, channel))
            .ok_or(ChannelError::NoKey)?;
        if state.needs_rotation {
            return Err(ChannelError::NoKey);
        }
        let session = state
            .outbound
            .as_deref()
            .and_then(load_outbound)
            .ok_or(ChannelError::NoKey)?;
        let share = KeyShare {
            t: "gkey".to_string(),
            ch: channel.to_string(),
            sid: session.session_id(),
            key: session.session_key().to_base64(),
        };
        serde_json::to_string(&share).map_err(|_| ChannelError::BadFormat)
    }

    /// Records that the key of the current session reached `did`. A send
    /// that failed is not recorded, so the next call asks again.
    pub fn mark_shared(&mut self, network: &str, channel: &str, did: &str) {
        if let Some(state) = self.channels.get_mut(&channel_id(network, channel)) {
            if state.members.contains(did) {
                state.shared_to.insert(did.to_string());
            }
        }
    }

    /// Accepts a key share that came through Olm from `sender_did`. The
    /// sender must be a member; a share of a device that is not a member yet
    /// waits (bounded) until a membership event adds it. Returns the session
    /// id.
    pub fn accept_key(
        &mut self,
        network: &str,
        channel: &str,
        sender_did: &str,
        text: &str,
    ) -> Result<String, ChannelError> {
        let (sid, session) = parse_share(channel, text)?;
        let state = self
            .channels
            .entry(channel_id(network, channel))
            .or_default();
        if !state.members.contains(sender_did) {
            if text.len() <= MAX_SHARE_LEN {
                if state.pending.len() >= MAX_PENDING_SHARES {
                    let (_, mut old) = state.pending.remove(0);
                    old.zeroize();
                }
                state
                    .pending
                    .push((sender_did.to_string(), text.to_string()));
            }
            return Err(ChannelError::NotMember);
        }
        Self::insert_session(state, sender_did, sid, &session)
    }

    /// Stores the inbound session of a member device.
    fn insert_session(
        state: &mut ChannelState,
        sender_did: &str,
        sid: String,
        session: &InboundGroupSession,
    ) -> Result<String, ChannelError> {
        let sessions = state.inbound.entry(sender_did.to_string()).or_default();
        if sessions.contains_key(&sid) {
            // A repeated share keeps the first one: it never moves the
            // readable range back.
            return Ok(sid);
        }
        let pickle =
            serde_json::to_string(&session.pickle()).map_err(|_| ChannelError::BadFormat)?;
        state.counter += 1;
        sessions.insert(
            sid.clone(),
            Inbound {
                pickle,
                order: state.counter,
                seen: VecDeque::new(),
            },
        );
        while sessions.len() > SESSIONS_PER_DEVICE {
            let oldest = sessions
                .iter()
                .min_by_key(|(_, entry)| entry.order)
                .map(|(sid, _)| sid.clone());
            match oldest.and_then(|sid| sessions.remove(&sid)) {
                Some(mut entry) => entry.pickle.zeroize(),
                None => break,
            }
        }
        Ok(sid)
    }

    /// Encrypts `text` for the channel with the own session. The result is
    /// the compact JSON payload of a channel message.
    pub fn encrypt(
        &mut self,
        network: &str,
        channel: &str,
        own_did: &str,
        text: &str,
    ) -> Result<String, ChannelError> {
        let state = self
            .channels
            .get_mut(&channel_id(network, channel))
            .ok_or(ChannelError::NoKey)?;
        if !state.members.contains(own_did) {
            return Err(ChannelError::NotAuthorized);
        }
        if state.needs_rotation {
            return Err(ChannelError::NoKey);
        }
        let mut session = state
            .outbound
            .as_deref()
            .and_then(load_outbound)
            .ok_or(ChannelError::NoKey)?;
        let message = session.encrypt(text.as_bytes());
        let payload = Payload {
            v: PAYLOAD_VERSION,
            ch: channel.to_string(),
            sid: session.session_id(),
            i: message.message_index(),
            body: message.to_base64(),
        };
        // The ratchet moved: keep it, or the next message repeats the index.
        let pickle = dump_outbound(&session).ok_or(ChannelError::BadFormat)?;
        if let Some(old) = state.outbound.as_mut() {
            old.zeroize();
        }
        state.outbound = Some(pickle);
        serde_json::to_string(&payload).map_err(|_| ChannelError::BadFormat)
    }

    /// Opens a channel payload that `sender_did` sent. The sender must be a
    /// member and must have given the key of the session. The message index
    /// is stored only after the message opened.
    pub fn decrypt(
        &mut self,
        network: &str,
        channel: &str,
        sender_did: &str,
        wire: &str,
    ) -> Result<Opened, ChannelError> {
        if wire.len() > MAX_PAYLOAD_LEN {
            return Err(ChannelError::BadFormat);
        }
        let payload: Payload = serde_json::from_str(wire).map_err(|_| ChannelError::BadFormat)?;
        if payload.v != PAYLOAD_VERSION {
            return Err(ChannelError::BadFormat);
        }
        if payload.ch != channel {
            return Err(ChannelError::WrongChannel);
        }
        let state = self
            .channels
            .get_mut(&channel_id(network, channel))
            .ok_or(ChannelError::UnknownSession)?;
        if !state.members.contains(sender_did) {
            return Err(ChannelError::NotMember);
        }
        let entry = state
            .inbound
            .get_mut(sender_did)
            .and_then(|sessions| sessions.get_mut(&payload.sid))
            .ok_or(ChannelError::UnknownSession)?;
        let message =
            MegolmMessage::from_base64(&payload.body).map_err(|_| ChannelError::BadFormat)?;
        if message.message_index() != payload.i {
            return Err(ChannelError::BadCiphertext);
        }
        if entry.seen.contains(&payload.i) {
            return Err(ChannelError::Replay);
        }
        let pickle: InboundGroupSessionPickle =
            serde_json::from_str(&entry.pickle).map_err(|_| ChannelError::BadFormat)?;
        let mut session = InboundGroupSession::from_pickle(pickle);
        let opened = session
            .decrypt(&message)
            .map_err(|_| ChannelError::BadCiphertext)?;
        let text = String::from_utf8(opened.plaintext).map_err(|_| ChannelError::BadCiphertext)?;
        entry.seen.push_back(opened.message_index);
        while entry.seen.len() > SEEN_WINDOW {
            entry.seen.pop_front();
        }
        Ok(Opened {
            sender_did: sender_did.to_string(),
            session_id: payload.sid,
            index: opened.message_index,
            text,
        })
    }

    /// Forgets all sessions of a channel, for example after the own device
    /// leaves it.
    pub fn forget(&mut self, network: &str, channel: &str) {
        if let Some(mut state) = self.channels.remove(&channel_id(network, channel)) {
            state.wipe_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "net";
    const CH: &str = "#room";

    struct Dev {
        did: String,
        ring: ChannelKeyring,
    }

    fn dev(did: &str) -> Dev {
        Dev {
            did: did.to_string(),
            ring: ChannelKeyring::new(),
        }
    }

    fn set(dids: &[&str]) -> BTreeSet<String> {
        dids.iter().map(|d| d.to_string()).collect()
    }

    /// Every device in `devs` sees the same membership event.
    fn membership(devs: &mut [&mut Dev], seq: u64, members: &[&str]) {
        for d in devs.iter_mut() {
            d.ring.apply_membership(NET, CH, seq, set(members));
        }
    }

    /// `from` prepares its session and gives its key to each device of
    /// `to` that it needs to, as the runtime does through Olm.
    fn share(from: &mut Dev, to: &mut [&mut Dev]) {
        let needed = from.ring.prepare_outbound(NET, CH, &from.did).unwrap();
        for did in needed {
            let text = from.ring.key_share(NET, CH).unwrap();
            if let Some(target) = to.iter_mut().find(|d| d.did == did) {
                target.ring.accept_key(NET, CH, &from.did, &text).unwrap();
            }
            from.ring.mark_shared(NET, CH, &did);
        }
    }

    fn send(d: &mut Dev, text: &str) -> String {
        d.ring.encrypt(NET, CH, &d.did, text).unwrap()
    }

    #[test]
    fn authorized_devices_open_messages() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a, &mut b], 1, &["a", "b"]);
        share(&mut a, &mut [&mut b]);
        share(&mut b, &mut [&mut a]);
        let wire = send(&mut a, "hello");
        let opened = b.ring.decrypt(NET, CH, "a", &wire).unwrap();
        assert_eq!(opened.text, "hello");
        assert_eq!(opened.sender_did, "a");
        assert_eq!(opened.index, 0);
        let wire = send(&mut b, "back");
        assert_eq!(a.ring.decrypt(NET, CH, "b", &wire).unwrap().text, "back");
    }

    #[test]
    fn payload_has_the_wire_shape() {
        let mut a = dev("a");
        membership(&mut [&mut a], 1, &["a"]);
        a.ring.prepare_outbound(NET, CH, "a").unwrap();
        let wire = send(&mut a, "x");
        let value: serde_json::Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(value["v"], 3);
        assert_eq!(value["ch"], CH);
        assert!(value["sid"].is_string());
        assert_eq!(value["i"], 0);
        assert!(value["body"].is_string());
        let share: serde_json::Value =
            serde_json::from_str(&a.ring.key_share(NET, CH).unwrap()).unwrap();
        assert_eq!(share["t"], "gkey");
        assert_eq!(share["ch"], CH);
    }

    #[test]
    fn new_member_cannot_open_earlier_messages() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a, &mut b], 1, &["a", "b"]);
        share(&mut a, &mut [&mut b]);
        let old = send(&mut a, "before");
        let mut c = dev("c");
        membership(&mut [&mut a, &mut b, &mut c], 2, &["a", "b", "c"]);
        // The old message index is behind the key that c gets.
        share(&mut a, &mut [&mut b, &mut c]);
        assert_eq!(
            c.ring.decrypt(NET, CH, "a", &old),
            Err(ChannelError::BadCiphertext)
        );
        let new = send(&mut a, "after");
        assert_eq!(c.ring.decrypt(NET, CH, "a", &new).unwrap().text, "after");
        assert_eq!(b.ring.decrypt(NET, CH, "a", &old).unwrap().text, "before");
    }

    #[test]
    fn removed_member_cannot_open_after_rotation() {
        let (mut a, mut b, mut c) = (dev("a"), dev("b"), dev("c"));
        membership(&mut [&mut a, &mut b, &mut c], 1, &["a", "b", "c"]);
        share(&mut a, &mut [&mut b, &mut c]);
        send(&mut a, "ok");
        membership(&mut [&mut a, &mut b], 2, &["a", "b"]);
        // The session is invalid until the new one exists.
        assert_eq!(a.ring.status(NET, CH, true), ChannelStatus::NoKey);
        assert_eq!(
            a.ring.encrypt(NET, CH, "a", "late"),
            Err(ChannelError::NoKey)
        );
        let needed = a.ring.prepare_outbound(NET, CH, "a").unwrap();
        assert_eq!(needed, vec!["b".to_string()]);
        share(&mut a, &mut [&mut b, &mut c]);
        let wire = send(&mut a, "secret");
        assert_eq!(b.ring.decrypt(NET, CH, "a", &wire).unwrap().text, "secret");
        // c holds the old key only: it has no session for the new id.
        assert_eq!(
            c.ring.decrypt(NET, CH, "a", &wire),
            Err(ChannelError::UnknownSession)
        );
    }

    #[test]
    fn removed_member_sessions_are_deleted() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a, &mut b], 1, &["a", "b"]);
        share(&mut a, &mut [&mut b]);
        share(&mut b, &mut [&mut a]);
        let wire = send(&mut b, "x");
        membership(&mut [&mut a], 2, &["a"]);
        assert_eq!(
            a.ring.decrypt(NET, CH, "b", &wire),
            Err(ChannelError::NotMember)
        );
    }

    #[test]
    fn duplicate_and_out_of_order_membership_events_are_ignored() {
        let mut ring = ChannelKeyring::new();
        assert_eq!(
            ring.apply_membership(NET, CH, 5, set(&["a", "b"])),
            MembershipOutcome::Changed { removed: false }
        );
        assert_eq!(
            ring.apply_membership(NET, CH, 5, set(&["a"])),
            MembershipOutcome::Stale
        );
        assert_eq!(
            ring.apply_membership(NET, CH, 4, set(&["a"])),
            MembershipOutcome::Stale
        );
        assert_eq!(
            ring.apply_membership(NET, CH, 6, set(&["a", "b"])),
            MembershipOutcome::Unchanged
        );
        assert_eq!(
            ring.members(NET, CH),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn key_share_from_non_member_or_wrong_channel_is_refused() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a, &mut b], 1, &["a", "b"]);
        a.ring.prepare_outbound(NET, CH, "a").unwrap();
        let text = a.ring.key_share(NET, CH).unwrap();
        assert_eq!(
            b.ring.accept_key(NET, CH, "x", &text),
            Err(ChannelError::NotMember)
        );
        assert_eq!(
            b.ring.accept_key(NET, "#other", "a", &text),
            Err(ChannelError::WrongChannel)
        );
        assert_eq!(
            b.ring.accept_key(NET, CH, "a", "not json"),
            Err(ChannelError::BadFormat)
        );
        // A session id that does not match the key is refused.
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["sid"] = serde_json::Value::String("other".to_string());
        assert_eq!(
            b.ring.accept_key(NET, CH, "a", &value.to_string()),
            Err(ChannelError::BadFormat)
        );
    }

    #[test]
    fn a_key_share_before_the_membership_event_is_read_when_the_sender_joins() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        // a knows both devices. b has not seen the membership event yet.
        membership(&mut [&mut a], 1, &["a", "b"]);
        a.ring.prepare_outbound(NET, CH, "a").unwrap();
        let text = a.ring.key_share(NET, CH).unwrap();
        assert_eq!(
            b.ring.accept_key(NET, CH, "a", &text),
            Err(ChannelError::NotMember)
        );
        let wire = send(&mut a, "late");
        assert_eq!(
            b.ring.decrypt(NET, CH, "a", &wire),
            Err(ChannelError::NotMember)
        );
        // The event comes: the waiting key share is read now.
        membership(&mut [&mut b], 1, &["a", "b"]);
        assert_eq!(b.ring.decrypt(NET, CH, "a", &wire).unwrap().text, "late");
    }

    #[test]
    fn a_waiting_key_share_is_not_used_while_its_sender_is_not_a_member() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a], 1, &["a", "b"]);
        a.ring.prepare_outbound(NET, CH, "a").unwrap();
        let text = a.ring.key_share(NET, CH).unwrap();
        assert!(b.ring.accept_key(NET, CH, "a", &text).is_err());
        // The member set arrives without "a": the share stays unused.
        membership(&mut [&mut b], 1, &["b", "x"]);
        let wire = send(&mut a, "x");
        assert_eq!(
            b.ring.decrypt(NET, CH, "a", &wire),
            Err(ChannelError::NotMember)
        );
    }

    #[test]
    fn the_waiting_list_is_bounded() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a], 1, &["a", "b"]);
        a.ring.prepare_outbound(NET, CH, "a").unwrap();
        let text = a.ring.key_share(NET, CH).unwrap();
        for i in 0..(MAX_PENDING_SHARES * 2) {
            let _ = b.ring.accept_key(NET, CH, &format!("d{i}"), &text);
        }
        let state = b.ring.channels.get(&channel_id(NET, CH)).unwrap();
        assert_eq!(state.pending.len(), MAX_PENDING_SHARES);
    }

    #[test]
    fn invalid_messages_are_rejected() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a, &mut b], 1, &["a", "b"]);
        share(&mut a, &mut [&mut b]);
        let wire = send(&mut a, "hi");
        // Repeated message.
        assert!(b.ring.decrypt(NET, CH, "a", &wire).is_ok());
        assert_eq!(
            b.ring.decrypt(NET, CH, "a", &wire),
            Err(ChannelError::Replay)
        );
        let wire2 = send(&mut a, "again");
        // Wrong channel.
        assert_eq!(
            b.ring.decrypt(NET, "#other", "a", &wire2),
            Err(ChannelError::WrongChannel)
        );
        // The sender is another device: it has no session of that id.
        assert_eq!(
            b.ring.decrypt(NET, CH, "b", &wire2),
            Err(ChannelError::UnknownSession)
        );
        assert_eq!(
            b.ring.decrypt(NET, CH, "x", &wire2),
            Err(ChannelError::NotMember)
        );
        // A forged body fails.
        let mut value: serde_json::Value = serde_json::from_str(&wire2).unwrap();
        let body = value["body"].as_str().unwrap().to_string();
        let mut flipped = body.into_bytes();
        let last = flipped.len() - 2;
        flipped[last] = if flipped[last] == b'A' { b'B' } else { b'A' };
        value["body"] = serde_json::Value::String(String::from_utf8(flipped).unwrap());
        assert_eq!(
            b.ring.decrypt(NET, CH, "a", &value.to_string()),
            Err(ChannelError::BadCiphertext)
        );
        // A wrong index is refused.
        let mut value: serde_json::Value = serde_json::from_str(&wire2).unwrap();
        value["i"] = serde_json::Value::from(9);
        assert_eq!(
            b.ring.decrypt(NET, CH, "a", &value.to_string()),
            Err(ChannelError::BadCiphertext)
        );
        // Not a payload.
        assert_eq!(
            b.ring.decrypt(NET, CH, "a", "plain text"),
            Err(ChannelError::BadFormat)
        );
        // None of the failures used up the real message.
        assert!(b.ring.decrypt(NET, CH, "a", &wire2).is_ok());
    }

    #[test]
    fn other_device_of_the_same_user_gets_the_key() {
        let (mut a1, mut a2, mut b) = (dev("a1"), dev("a2"), dev("b"));
        membership(&mut [&mut a1, &mut a2, &mut b], 1, &["a1", "a2", "b"]);
        share(&mut b, &mut [&mut a1, &mut a2]);
        let wire = send(&mut b, "from b");
        assert_eq!(a1.ring.decrypt(NET, CH, "b", &wire).unwrap().text, "from b");
        assert_eq!(a2.ring.decrypt(NET, CH, "b", &wire).unwrap().text, "from b");
    }

    #[test]
    fn a_member_without_the_key_counts_as_missing_share() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a, &mut b], 1, &["a", "b"]);
        a.ring.prepare_outbound(NET, CH, "a").unwrap();
        assert!(a.ring.has_missing_shares(NET, CH, "a"));
        a.ring.mark_shared(NET, CH, "b");
        assert!(!a.ring.has_missing_shares(NET, CH, "a"));
    }

    #[test]
    fn send_without_key_is_pending_until_user_choice() {
        let ring = ChannelKeyring::new();
        assert_eq!(ring.status(NET, CH, false), ChannelStatus::Plain);
        assert_eq!(ring.status(NET, CH, true), ChannelStatus::NoKey);
        assert_eq!(ring.plan_send(NET, CH, false), SendPlan::Pending);
        assert_eq!(ring.plan_send(NET, CH, true), SendPlan::Plain);
        let mut a = dev("a");
        membership(&mut [&mut a], 1, &["a"]);
        assert_eq!(a.ring.encrypt(NET, CH, "a", "x"), Err(ChannelError::NoKey));
        a.ring.prepare_outbound(NET, CH, "a").unwrap();
        assert_eq!(a.ring.plan_send(NET, CH, false), SendPlan::Encrypt);
        assert_eq!(a.ring.status(NET, CH, true), ChannelStatus::Encrypted);
    }

    #[test]
    fn state_survives_a_reconnect_through_serde() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a, &mut b], 1, &["a", "b"]);
        share(&mut a, &mut [&mut b]);
        let wire = send(&mut a, "kept");
        b.ring.decrypt(NET, CH, "a", &wire).unwrap();
        let mut restored_b: ChannelKeyring =
            serde_json::from_str(&serde_json::to_string(&b.ring).unwrap()).unwrap();
        let mut restored_a: ChannelKeyring =
            serde_json::from_str(&serde_json::to_string(&a.ring).unwrap()).unwrap();
        // The replay window survives.
        assert_eq!(
            restored_b.decrypt(NET, CH, "a", &wire),
            Err(ChannelError::Replay)
        );
        // The sender ratchet survives: the next index is new.
        let next = restored_a.encrypt(NET, CH, "a", "next").unwrap();
        let opened = restored_b.decrypt(NET, CH, "a", &next).unwrap();
        assert_eq!(opened.text, "next");
        assert_eq!(opened.index, 1);
    }

    #[test]
    fn rotation_replaces_the_session_and_keeps_old_messages_readable() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a, &mut b], 1, &["a", "b"]);
        share(&mut a, &mut [&mut b]);
        let first = send(&mut a, "one");
        a.ring.rotate(NET, CH, "a").unwrap();
        share(&mut a, &mut [&mut b]);
        let second = send(&mut a, "two");
        assert_eq!(b.ring.decrypt(NET, CH, "a", &second).unwrap().text, "two");
        assert_eq!(b.ring.decrypt(NET, CH, "a", &first).unwrap().text, "one");
        assert_eq!(
            a.ring.rotate(NET, CH, "z"),
            Err(ChannelError::NotAuthorized)
        );
    }

    #[test]
    fn a_revoked_device_is_a_removed_member() {
        let (mut a, mut b, mut c) = (dev("a"), dev("b"), dev("c"));
        membership(&mut [&mut a, &mut b, &mut c], 1, &["a", "b", "c"]);
        share(&mut a, &mut [&mut b, &mut c]);
        share(&mut c, &mut [&mut a]);
        assert_eq!(a.ring.status(NET, CH, true), ChannelStatus::Encrypted);
        let from_c = send(&mut c, "before");
        // The list of c drops its device: the own session of a is invalid.
        let revoked: BTreeSet<String> = set(&["c"]);
        assert!(a.ring.revoke_devices(NET, &revoked));
        assert_eq!(a.ring.status(NET, CH, true), ChannelStatus::NoKey);
        assert_eq!(a.ring.encrypt(NET, CH, "a", "x"), Err(ChannelError::NoKey));
        assert_eq!(
            a.ring.members(NET, CH),
            vec!["a".to_string(), "b".to_string()]
        );
        // The sessions of c are gone, and c is no sender any more.
        assert_eq!(
            a.ring.decrypt(NET, CH, "c", &from_c),
            Err(ChannelError::NotMember)
        );
        // The new session goes to b only, and c cannot read it.
        let needed = a.ring.prepare_outbound(NET, CH, "a").unwrap();
        assert_eq!(needed, vec!["b".to_string()]);
        share(&mut a, &mut [&mut b, &mut c]);
        let wire = send(&mut a, "after");
        assert_eq!(b.ring.decrypt(NET, CH, "a", &wire).unwrap().text, "after");
        assert_eq!(
            c.ring.decrypt(NET, CH, "a", &wire),
            Err(ChannelError::UnknownSession)
        );
        // A second call changes nothing, and the membership order stays.
        assert!(!a.ring.revoke_devices(NET, &revoked));
        assert_eq!(
            a.ring.apply_membership(NET, CH, 1, set(&["a", "b", "c"])),
            MembershipOutcome::Stale
        );
    }

    #[test]
    fn a_revocation_on_another_network_changes_nothing() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a, &mut b], 1, &["a", "b"]);
        share(&mut a, &mut [&mut b]);
        assert!(!a.ring.revoke_devices("other", &set(&["b"])));
        assert_eq!(a.ring.status(NET, CH, true), ChannelStatus::Encrypted);
    }

    #[test]
    fn a_revocation_deletes_a_waiting_key_share() {
        let (mut a, mut b) = (dev("a"), dev("b"));
        membership(&mut [&mut a], 1, &["a", "b"]);
        a.ring.prepare_outbound(NET, CH, "a").unwrap();
        let text = a.ring.key_share(NET, CH).unwrap();
        assert!(b.ring.accept_key(NET, CH, "a", &text).is_err());
        assert!(b.ring.revoke_devices(NET, &set(&["a"])));
        // The membership event comes later: the deleted share is not read.
        membership(&mut [&mut b], 1, &["a", "b"]);
        let wire = send(&mut a, "x");
        assert_eq!(
            b.ring.decrypt(NET, CH, "a", &wire),
            Err(ChannelError::UnknownSession)
        );
    }

    #[test]
    fn forget_removes_sessions() {
        let mut a = dev("a");
        membership(&mut [&mut a], 1, &["a"]);
        a.ring.prepare_outbound(NET, CH, "a").unwrap();
        a.ring.forget(NET, CH);
        assert_eq!(a.ring.status(NET, CH, true), ChannelStatus::NoKey);
    }
}
