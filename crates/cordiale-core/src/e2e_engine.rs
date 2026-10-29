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

//! The E2E engine of one device on one network: the receive and send paths.
//!
//! The engine joins the checks of [`crate::e2e_peer`], the Olm sessions of
//! [`crate::e2e_state`], the sealed history of [`crate::e2e_store`] and the
//! calls of [`crate::client`]. It has no path that sends clear text: a send
//! is an Olm message in a `pkmsg` or `msg` request, or an error.
//!
//! Receive: [`E2eEngine::handle_row`] reads one inbox row. [`E2eEngine::drain`]
//! reads the inbox pages and acknowledges each item after local processing,
//! also an item that cannot be decrypted. It never acknowledges an item whose
//! write to the history or the state failed. A repeated item gives one row:
//! the id of the item is part of the id of the history row.
//!
//! Send: [`E2eEngine::send_text`] encrypts, sends with the `from` and `to`
//! device ids and registers the `msgid` of the 202 answer in the
//! [`SendBook`]. A 202 is an acceptance, never a delivery.
//!
//! Own copies (S1): a row with `own` set is a copy of a message that another
//! device of the same account sent. It is opened like any other row. Its
//! plaintext is a [`CopyBody`] that names the peer, and the text goes to the
//! conversation of that peer as an own row.
//!
//! The label of the locked query ([`locked_label`]) is for display only. A
//! peer is pinned on its `did`; the nick is a routing hint.
//!
//! The JSON of the KEYS, `pkmsg` and `msg` payloads in [`KeysPayload`] and
//! [`MessagePayload`] is a candidate: the fields are not read from the text of
//! the protocol. A change stays in those two types.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vodozemac::olm::{Account, Message, OlmMessage, PreKeyMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

use crate::client::{GrappaClient, GrappaClientError};
use crate::e2e_device::{E2eError, PeerDevice, VersionedDeviceCertificate};
use crate::e2e_device_routes::{ClaimRequest, InboxAckRequest, InboxRow, InboxVerb};
use crate::e2e_pacing::{
    KeyReqPacer, KeyReqRefusal, MonotonicClock, SendBook, SendDropped, SendKey, SendResponse,
    SendStatus,
};
use crate::e2e_peer::{verify_peer_device, PeerBundle, ReplayState};
use crate::e2e_refusal::E2eRouteError;
use crate::e2e_state::E2eStateStore;
use crate::e2e_store::{E2eHistoryStore, E2eMessage, E2eStoreError, KeyringKeyProvider};
use crate::e2e_trust::PeerTrust;
use crate::e2e_wire::{
    did_from_key_text, parse_payload, recipient_binding, WireError, INBOX_PAGE_MAX, WILDCARD,
};
use crate::isupport::CaseMapping;
use crate::persistence::data_dir;
use crate::rest::{E2eSendPriority, E2eSendRequest, E2eSendVerb, QUERY_LOCK_LABEL};

/// Version number in the payloads that the engine writes.
const PAYLOAD_VERSION: u32 = 2;

/// How long a fragmented KEYS answer may stay in reassembly. The server owns
/// the real value; this is the value of the pacer until it is confirmed.
const KEYS_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// `sender_device` of own rows; this history is local to one device.
pub const OWN_DEVICE: &str = "own";

/// The display label of the locked query of `nick`. Use it for a window
/// name only: never as a nick, an API value or a wire field.
pub fn locked_label(nick: &str) -> String {
    format!("{QUERY_LOCK_LABEL}{nick}")
}

/// Where a send of a query window goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendRoute {
    /// The normal query `<user>`: the existing plain path.
    Plain { nick: String },
    /// The locked query `🔒<user>`: the E2E path only.
    Encrypted { nick: String },
}

impl SendRoute {
    /// The peer nick without the display label.
    pub fn nick(&self) -> &str {
        match self {
            SendRoute::Plain { nick } | SendRoute::Encrypted { nick } => nick,
        }
    }
}

/// Chooses the route from the name of the selected query window.
pub fn route_for_window(window_name: &str) -> SendRoute {
    match window_name.strip_prefix(QUERY_LOCK_LABEL) {
        Some(nick) => SendRoute::Encrypted {
            nick: nick.to_string(),
        },
        None => SendRoute::Plain {
            nick: window_name.to_string(),
        },
    }
}

/// The id of the E2E conversation of one peer in the sealed history. The
/// label of the locked query is not part of it.
pub fn conversation_id(network: &str, nick: &str) -> String {
    format!("{network}\u{0}{nick}")
}

/// The part of a file name for `network`: only letters, digits, `-` and `_`.
/// Any other slug has no engine files, so it has no engine.
fn file_part(network: &str) -> Option<&str> {
    (!network.is_empty()
        && network.len() <= 64
        && network
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
    .then_some(network)
}

/// Why an engine call failed.
#[derive(Debug)]
pub enum EngineError {
    /// The peer has no verified device or no key to open a session. Ask for
    /// keys with [`E2eEngine::request_keys`]. Nothing was sent.
    NotReady,
    /// The encryption failed. Nothing was sent.
    EncryptionFailed,
    Wire(WireError),
    Device(E2eError),
    Store(E2eStoreError),
    Route(E2eRouteError),
    Client(GrappaClientError),
    /// The send door did not accept the request.
    Rejected(SendResponse),
    /// A KEYREQ is not allowed now.
    Paced(KeyReqRefusal),
}

impl From<WireError> for EngineError {
    fn from(err: WireError) -> Self {
        EngineError::Wire(err)
    }
}

impl From<E2eError> for EngineError {
    fn from(err: E2eError) -> Self {
        EngineError::Device(err)
    }
}

impl From<E2eStoreError> for EngineError {
    fn from(err: E2eStoreError) -> Self {
        EngineError::Store(err)
    }
}

impl From<E2eRouteError> for EngineError {
    fn from(err: E2eRouteError) -> Self {
        EngineError::Route(err)
    }
}

impl From<GrappaClientError> for EngineError {
    fn from(err: GrappaClientError) -> Self {
        EngineError::Client(err)
    }
}

/// The payload of a KEYS row or of a claim answer: everything that
/// [`verify_peer_device`] needs, and one one-time key when the server gave
/// one. Candidate format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysPayload {
    pub v: u32,
    pub master: String,
    pub list_version: u32,
    pub list_keys: Vec<String>,
    pub list_signature: String,
    pub cert_version: u32,
    pub cert_signature: String,
    pub ed25519: String,
    pub did: String,
    pub curve25519: String,
    pub curve_signature: String,
    pub fb: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_time_key: Option<String>,
}

impl KeysPayload {
    pub fn parse(text: &str) -> Result<Self, WireError> {
        let value = parse_payload(text)?;
        serde_json::from_value(value).map_err(|_| WireError::BadPayload)
    }
}

/// The payload of a `pkmsg` or `msg` request: the `fb` binding and the Olm
/// message as base64. Candidate format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    pub v: u32,
    pub fb: String,
    pub ct: String,
}

impl MessagePayload {
    pub fn parse(text: &str) -> Result<Self, WireError> {
        let value = parse_payload(text)?;
        serde_json::from_value(value).map_err(|_| WireError::BadPayload)
    }

    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// The plaintext of a copy from another device of the same account: the peer
/// of the conversation and the text. Candidate format, like the payloads
/// above. The sender of copies is a later slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyBody {
    pub peer: String,
    pub text: String,
}

impl CopyBody {
    /// Reads the plaintext of a copy. A peer that is not a plain nick is
    /// refused: the label of the locked query is never a peer.
    pub fn parse(plain: &str) -> Option<Self> {
        let body: Self = serde_json::from_str(plain).ok()?;
        valid_peer(&body.peer).then_some(body)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

fn valid_peer(peer: &str) -> bool {
    !peer.is_empty()
        && peer.chars().count() <= 64
        && !peer.contains(QUERY_LOCK_LABEL)
        && !peer.chars().any(|ch| ch.is_whitespace() || ch.is_control())
}

/// What [`E2eEngine::handle_row`] did with one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowOutcome {
    /// The text is in the history, marked as encrypted.
    Stored,
    /// The row was seen before. No second row is written.
    Duplicate,
    /// A KEYS row gave a verified device.
    KeysRead,
    /// The row cannot be read: bad payload, no verified device, no session or
    /// a failed decryption. The caller acknowledges it.
    Undecryptable,
    /// A row that is not stored: a NACK.
    Ignored,
    /// The write to the history or the state failed. Do not acknowledge the
    /// row: it stays in the inbox for the next drain.
    StoreFailed,
}

impl RowOutcome {
    /// True when the caller acknowledges the row.
    pub fn acknowledge(self) -> bool {
        self != RowOutcome::StoreFailed
    }
}

/// What a send gave. The send is accepted; it is not delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentText {
    /// The `msgid` of the 202 answer, when the body had one.
    pub msgid: Option<String>,
    /// The key of the send in the [`SendBook`], when the answer had a `msgid`.
    pub key: Option<SendKey>,
}

#[derive(Debug, Clone)]
struct PeerEntry {
    nick: String,
    device: PeerDevice,
    /// A one-time key from a KEYS answer, used once to open the session.
    one_time_key: Option<String>,
}

/// The decrypted text and the state to save after the history write.
struct Decrypted {
    text: String,
    identity: Option<Account>,
    session: Session,
    replay: Option<ReplayState>,
}

pub struct E2eEngine {
    network: String,
    own_did: String,
    own_ed25519: String,
    state: E2eStateStore,
    history: E2eHistoryStore,
    /// Inbox ids that were processed in this run.
    seen: HashSet<u64>,
    /// Verified remote devices, by `did`.
    peers: HashMap<String, PeerEntry>,
    book: SendBook,
    keyreq: KeyReqPacer,
    clock: MonotonicClock,
    /// Devices that a newer signed list revoked. Their rows are not read.
    revoked_dids: HashSet<String>,
    /// Nicks that sent a message the engine could not read for lack of keys.
    keys_wanted: Vec<String>,
    /// Peers whose conversation got a new row since the last call of
    /// [`E2eEngine::take_changed_peers`].
    changed_peers: Vec<String>,
    local_sends: u64,
}

impl E2eEngine {
    /// Opens the engine for the Olm identity of `state`. A state without an
    /// identity is `NotReady`: the provisioning creates it first. The engine
    /// keeps the public device key only.
    pub fn new(
        network: &str,
        state: E2eStateStore,
        history: E2eHistoryStore,
    ) -> Result<Self, EngineError> {
        let own_ed25519 = state.device_key()?.ok_or(EngineError::NotReady)?;
        let own_did = did_from_key_text(&own_ed25519)?;
        Ok(Self {
            network: network.to_string(),
            own_did,
            own_ed25519,
            state,
            history,
            seen: HashSet::new(),
            peers: HashMap::new(),
            book: SendBook::new(),
            keyreq: KeyReqPacer::new(KEYS_REASSEMBLY_TIMEOUT),
            clock: MonotonicClock::new(),
            revoked_dids: HashSet::new(),
            keys_wanted: Vec::new(),
            changed_peers: Vec::new(),
            local_sends: 0,
        })
    }

    /// Opens the engine of `network` from the sealed files in the data
    /// folder. A network without a state file, or without an Olm identity in
    /// it, is `NotReady`: the provisioning makes the identity first, and this
    /// call never makes a key or a file of its own.
    pub fn open_for_network(network: &str) -> Result<Self, EngineError> {
        let part = file_part(network).ok_or(EngineError::NotReady)?;
        let dir = data_dir().ok_or(EngineError::Store(E2eStoreError::NoDataDir))?;
        let state_path = dir.join(format!("e2e_state_{part}.bin"));
        if !state_path.exists() {
            return Err(EngineError::NotReady);
        }
        let state = E2eStateStore::open(state_path, &KeyringKeyProvider)?;
        let history = E2eHistoryStore::open(
            dir.join(format!("e2e_history_{part}.bin")),
            &KeyringKeyProvider,
        )?;
        Self::new(network, state, history)
    }

    /// The nicks that have a conversation in the sealed history of this
    /// network.
    pub fn history_peers(&self) -> Vec<String> {
        let prefix = conversation_id(&self.network, "");
        let mut peers: Vec<String> = self
            .history
            .conversation_ids()
            .iter()
            .filter_map(|id| id.strip_prefix(&prefix).map(str::to_string))
            .collect();
        peers.sort();
        peers
    }

    /// The nicks whose conversation changed since the last call. The list is
    /// cleared.
    pub fn take_changed_peers(&mut self) -> Vec<String> {
        std::mem::take(&mut self.changed_peers)
    }

    fn note_changed(&mut self, nick: &str) {
        if !self.changed_peers.iter().any(|known| known == nick) {
            self.changed_peers.push(nick.to_string());
        }
    }

    pub fn own_did(&self) -> &str {
        &self.own_did
    }

    pub fn history(&self) -> &E2eHistoryStore {
        &self.history
    }

    /// True when the peer has a verified device and a way to start or keep an
    /// Olm session. The caller opens the locked query only then.
    pub fn is_ready(&self, nick: &str) -> bool {
        let trust = self.state.trust();
        self.peers
            .values()
            .any(|entry| entry.nick == nick && self.entry_ready(entry, &trust))
    }

    /// The nicks that have a verified device ready to send to, in order. A
    /// device of the own account counts under the own nick.
    pub fn ready_peers(&self) -> Vec<String> {
        let trust = self.state.trust();
        let mut nicks: Vec<String> = self
            .peers
            .values()
            .filter(|entry| self.entry_ready(entry, &trust))
            .map(|entry| entry.nick.clone())
            .collect();
        nicks.sort();
        nicks.dedup();
        nicks
    }

    /// True when the persisted trust revokes the device of `entry`.
    fn entry_revoked(&self, entry: &PeerEntry, trust: &PeerTrust) -> bool {
        trust.is_revoked(
            &self.network,
            &entry.nick,
            entry.device.ed25519(),
            Some(entry.device.curve25519()),
        )
    }

    /// True when the device is not revoked and has a session or a one-time
    /// key to open one.
    fn entry_ready(&self, entry: &PeerEntry, trust: &PeerTrust) -> bool {
        !self.entry_revoked(entry, trust)
            && (entry.one_time_key.is_some()
                || self
                    .state
                    .peer_session(&self.network, &entry.nick, entry.device.did())
                    .ok()
                    .flatten()
                    .is_some())
    }

    /// The status of a send. A 202 gives `Accepted`, never a delivered state.
    pub fn send_status(&self, key: &SendKey) -> Option<SendStatus> {
        self.book.status(key)
    }

    /// Applies an `e2e_send_dropped` event to the send book.
    pub fn apply_send_dropped(&mut self, payload: &Value) -> Option<SendDropped> {
        self.book.apply_payload(payload)
    }

    /// The nicks for which a KEYREQ is useful. The list is cleared.
    pub fn take_keys_wanted(&mut self) -> Vec<String> {
        std::mem::take(&mut self.keys_wanted)
    }

    /// Reads a KEYS text into the engine: a KEYS row or a claim answer. The
    /// device must pass [`verify_peer_device`]. The trust state is saved also
    /// when the device is refused, because a newer list stays.
    pub fn accept_keys(&mut self, nick: &str, keys: &str) -> Result<String, EngineError> {
        let payload = KeysPayload::parse(keys)?;
        let certificate = VersionedDeviceCertificate {
            first_list_version: payload.cert_version,
            device_ed25519: payload.ed25519.clone(),
            master_ed25519: payload.master.clone(),
            signature: payload.cert_signature.clone(),
        };
        let bundle = PeerBundle {
            master: &payload.master,
            list_version: payload.list_version,
            list_keys: &payload.list_keys,
            list_signature: &payload.list_signature,
            certificate: &certificate,
            did: &payload.did,
            curve25519: &payload.curve25519,
            curve_signature: &payload.curve_signature,
            fb: &payload.fb,
        };
        let mut trust = self.state.trust();
        let result = verify_peer_device(
            &mut trust,
            &self.network,
            nick,
            &self.own_ed25519,
            None,
            &bundle,
        );
        self.state.set_trust(&trust)?;
        // A newer list stays even when the device is refused: drop every
        // cached device that the trust state now revokes.
        let revoked: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, entry)| self.entry_revoked(entry, &trust))
            .map(|(did, _)| did.clone())
            .collect();
        for did in revoked {
            self.peers.remove(&did);
            self.revoked_dids.insert(did);
        }
        let device = result?;
        let did = device.did().to_string();
        self.revoked_dids.remove(&did);
        self.peers.insert(
            did.clone(),
            PeerEntry {
                nick: nick.to_string(),
                device,
                one_time_key: payload.one_time_key.clone(),
            },
        );
        Ok(did)
    }

    /// Reads one inbox row. It never sends and never acknowledges: the
    /// caller acknowledges when [`RowOutcome::acknowledge`] is true.
    pub fn handle_row(&mut self, row: &InboxRow, now: i64) -> RowOutcome {
        if self.seen.contains(&row.id) {
            return RowOutcome::Duplicate;
        }
        let outcome = match row.verb {
            InboxVerb::Keys => match self.accept_keys(&row.from, &row.payload) {
                Ok(_) => RowOutcome::KeysRead,
                Err(EngineError::Store(_)) => RowOutcome::StoreFailed,
                Err(_) => RowOutcome::Undecryptable,
            },
            InboxVerb::Nack => RowOutcome::Ignored,
            InboxVerb::PkMsg | InboxVerb::Msg => self.receive_message(row, now),
        };
        if outcome.acknowledge() {
            self.seen.insert(row.id);
        }
        outcome
    }

    fn receive_message(&mut self, row: &InboxRow, now: i64) -> RowOutcome {
        let entry = self.peers.get(&row.from_did).cloned();
        let nick = entry
            .as_ref()
            .map_or(row.from.as_str(), |entry| entry.nick.as_str())
            .to_string();
        // The persisted trust decides, also after a restart: a restored
        // session of a revoked device is not used.
        let trust = self.state.trust();
        if self.revoked_dids.contains(&row.from_did)
            || trust.is_did_revoked(&self.network, &nick, &row.from_did)
            || entry
                .as_ref()
                .is_some_and(|entry| self.entry_revoked(entry, &trust))
        {
            return RowOutcome::Undecryptable;
        }
        let Some(mut decrypted) = self.decrypt_row(row, entry.as_ref(), &nick) else {
            if entry.is_none() && !self.keys_wanted.contains(&nick) {
                self.keys_wanted.push(nick);
            }
            return RowOutcome::Undecryptable;
        };
        // A copy of an own device names its peer in the plaintext. A copy
        // that does not read is acknowledged and not stored.
        let (peer, row_id, sender_device, text) = if row.own {
            let Some(body) = CopyBody::parse(&decrypted.text) else {
                return RowOutcome::Undecryptable;
            };
            (
                body.peer,
                format!("{}:own:{}", self.network, row.id),
                OWN_DEVICE.to_string(),
                body.text,
            )
        } else {
            (
                nick.clone(),
                format!("{}:in:{}", self.network, row.id),
                row.from_did.clone(),
                std::mem::take(&mut decrypted.text),
            )
        };
        let conversation = conversation_id(&self.network, &peer);
        let stored = self
            .history
            .messages(&conversation)
            .iter()
            .any(|message| message.id == row_id);
        if !stored {
            let message = E2eMessage {
                id: row_id,
                conversation_id: conversation,
                sender_device,
                sent_at: now,
                text,
                encrypted: true,
            };
            if self.history.append(message).is_err() {
                return RowOutcome::StoreFailed;
            }
        }
        // The state is saved after the history write. A failed history write
        // leaves the old state, so the next drain decrypts the item again.
        let saved = self.save_state(&nick, &row.from_did, &decrypted);
        if saved.is_err() {
            return RowOutcome::StoreFailed;
        }
        self.note_changed(&peer);
        RowOutcome::Stored
    }

    fn save_state(
        &mut self,
        nick: &str,
        did: &str,
        decrypted: &Decrypted,
    ) -> Result<(), E2eStoreError> {
        self.state.set_inbound(
            &self.network,
            nick,
            did,
            &decrypted.session,
            decrypted.identity.as_ref(),
            decrypted.replay.as_ref(),
        )
    }

    /// Decrypts one `pkmsg` or `msg` row. It changes no stored state.
    fn decrypt_row(
        &self,
        row: &InboxRow,
        entry: Option<&PeerEntry>,
        nick: &str,
    ) -> Option<Decrypted> {
        let payload = MessagePayload::parse(&row.payload).ok()?;
        if let Some(entry) = entry {
            let expected = recipient_binding(entry.device.ed25519(), &self.own_ed25519);
            if payload.fb != expected {
                return None;
            }
        }
        match row.verb {
            InboxVerb::PkMsg => {
                let entry = entry?;
                let mut replay = self.state.replay();
                replay
                    .accept_first_message(&self.network, nick, &row.from_did, &row.msgid)
                    .ok()?;
                let curve = Curve25519PublicKey::from_base64(entry.device.curve25519()).ok()?;
                let message = PreKeyMessage::from_base64(&payload.ct).ok()?;
                // Olm keeps sending pre-key messages until the peer answers.
                // A message of the session that exists is opened with it.
                if let Some(mut session) = self
                    .state
                    .peer_session(&self.network, nick, &row.from_did)
                    .ok()?
                {
                    if session.session_id() == message.session_id() {
                        let plain = session.decrypt(&OlmMessage::PreKey(message)).ok()?;
                        let text = String::from_utf8(plain).ok()?;
                        return Some(Decrypted {
                            text,
                            identity: None,
                            session,
                            replay: Some(replay),
                        });
                    }
                }
                let mut identity = self.state.olm_identity().ok()??;
                let created = identity
                    .create_inbound_session(SessionConfig::version_1(), curve, &message)
                    .ok()?;
                replay
                    .accept_new_session(
                        &self.network,
                        nick,
                        &row.from_did,
                        &created.session.session_id(),
                    )
                    .ok()?;
                let text = String::from_utf8(created.plaintext).ok()?;
                Some(Decrypted {
                    text,
                    identity: Some(identity),
                    session: created.session,
                    replay: Some(replay),
                })
            }
            _ => {
                let mut session = self
                    .state
                    .peer_session(&self.network, nick, &row.from_did)
                    .ok()??;
                let message = Message::from_base64(&payload.ct).ok()?;
                let plain = session.decrypt(&OlmMessage::Normal(message)).ok()?;
                let text = String::from_utf8(plain).ok()?;
                Some(Decrypted {
                    text,
                    identity: None,
                    session,
                    replay: None,
                })
            }
        }
    }

    /// Acknowledges inbox ids, 100 at a time. An empty list does nothing.
    pub async fn ack(
        &self,
        client: &GrappaClient,
        token: &str,
        server_protocol: Option<u32>,
        ids: &[u64],
    ) -> Result<(), EngineError> {
        for chunk in ids.chunks(INBOX_PAGE_MAX) {
            let request = InboxAckRequest::new(chunk)?;
            client
                .ack_e2e_inbox(
                    token,
                    &self.network,
                    &self.own_did,
                    server_protocol,
                    &request,
                )
                .await?;
        }
        Ok(())
    }

    /// Reads one `e2e_message` event of the session and acknowledges the
    /// item when the outcome allows it.
    pub async fn handle_event(
        &mut self,
        client: &GrappaClient,
        token: &str,
        server_protocol: Option<u32>,
        row: &InboxRow,
        now: i64,
    ) -> Result<RowOutcome, EngineError> {
        let outcome = self.handle_row(row, now);
        if outcome.acknowledge() && outcome != RowOutcome::Duplicate {
            self.ack(client, token, server_protocol, &[row.id]).await?;
        }
        Ok(outcome)
    }

    /// Drains the inbox of the device: fetch a page, process it, acknowledge
    /// the processed ids, go on with the next page.
    pub async fn drain(
        &mut self,
        client: &GrappaClient,
        token: &str,
        server_protocol: Option<u32>,
        now: i64,
    ) -> Result<Vec<(u64, RowOutcome)>, EngineError> {
        let mut after = None;
        let mut outcomes = Vec::new();
        loop {
            let page = client
                .fetch_e2e_inbox(token, &self.network, &self.own_did, after, server_protocol)
                .await?;
            let Some(last) = page.iter().map(|row| row.id).max() else {
                break;
            };
            let mut acks = Vec::new();
            for row in &page {
                let outcome = self.handle_row(row, now);
                if outcome.acknowledge() {
                    acks.push(row.id);
                }
                outcomes.push((row.id, outcome));
            }
            self.ack(client, token, server_protocol, &acks).await?;
            if page.len() < INBOX_PAGE_MAX || after == Some(last) {
                break;
            }
            after = Some(last);
        }
        Ok(outcomes)
    }

    /// Takes one key of the device `did` of `nick` and reads the KEYS answer.
    pub async fn claim_keys(
        &mut self,
        client: &GrappaClient,
        token: &str,
        server_protocol: Option<u32>,
        nick: &str,
        did: &str,
    ) -> Result<String, EngineError> {
        let request = ClaimRequest::new(&self.own_did)?;
        let answer = client
            .claim_e2e_device_key(token, &self.network, did, server_protocol, &request)
            .await?;
        self.accept_keys(nick, answer.keys())
    }

    /// Sends a KEYREQ for `nick` through the send door. The pacer allows one
    /// request each 30 seconds for each nick.
    pub async fn request_keys(
        &mut self,
        client: &GrappaClient,
        token: &str,
        nick: &str,
    ) -> Result<(), EngineError> {
        self.keyreq
            .try_send(nick, CaseMapping::Rfc1459, self.clock.now())
            .map_err(EngineError::Paced)?;
        let payload = format!(r#"{{"v":{PAYLOAD_VERSION}}}"#);
        let request = E2eSendRequest::new(
            nick,
            E2eSendVerb::KeyReq,
            &self.own_did,
            WILDCARD,
            &payload,
            Some(E2eSendPriority::Control),
            None,
        )?;
        let answer = client
            .send_e2e_message(token, &self.network, &request)
            .await?;
        match answer.response {
            SendResponse::Accepted => Ok(()),
            other => Err(EngineError::Rejected(other)),
        }
    }

    /// The device of `nick` to send to: not revoked and ready, with a session
    /// first. The order of the devices does not decide; the `did` breaks a tie.
    fn pick_device(&self, nick: &str) -> Option<PeerEntry> {
        let trust = self.state.trust();
        self.peers
            .values()
            .filter(|entry| entry.nick == nick && self.entry_ready(entry, &trust))
            .min_by_key(|entry| {
                let has_session = self
                    .state
                    .peer_session(&self.network, nick, entry.device.did())
                    .ok()
                    .flatten()
                    .is_some();
                (!has_session, entry.device.did().to_string())
            })
            .cloned()
    }

    /// Encrypts `text` for `nick` and sends it. `nick` is the real nick of the
    /// peer; the label of the locked query is refused. Any failure before the
    /// 202 answer returns an error and sends nothing in clear.
    pub async fn send_text(
        &mut self,
        client: &GrappaClient,
        token: &str,
        nick: &str,
        text: &str,
        now: i64,
    ) -> Result<SentText, EngineError> {
        if nick.contains(QUERY_LOCK_LABEL) {
            return Err(EngineError::Wire(WireError::BadTarget));
        }
        let entry = self.pick_device(nick).ok_or(EngineError::NotReady)?;
        let did = entry.device.did().to_string();
        let mut session = match self.state.peer_session(&self.network, nick, &did)? {
            Some(session) => session,
            None => {
                let one_time = entry.one_time_key.as_deref().ok_or(EngineError::NotReady)?;
                let identity = self.state.olm_identity()?.ok_or(EngineError::NotReady)?;
                let curve = Curve25519PublicKey::from_base64(entry.device.curve25519())
                    .map_err(|_| EngineError::EncryptionFailed)?;
                let one_time = Curve25519PublicKey::from_base64(one_time)
                    .map_err(|_| EngineError::EncryptionFailed)?;
                identity
                    .create_outbound_session(SessionConfig::version_1(), curve, one_time)
                    .map_err(|_| EngineError::EncryptionFailed)?
            }
        };
        let (verb, ct) = match session.encrypt(text.as_bytes()) {
            Ok(OlmMessage::PreKey(message)) => (E2eSendVerb::PkMsg, message.to_base64()),
            Ok(OlmMessage::Normal(message)) => (E2eSendVerb::Msg, message.to_base64()),
            Err(_) => return Err(EngineError::EncryptionFailed),
        };
        let payload = MessagePayload {
            v: PAYLOAD_VERSION,
            fb: recipient_binding(&self.own_ed25519, entry.device.ed25519()),
            ct,
        }
        .to_json();
        let request = E2eSendRequest::new(
            nick,
            verb,
            &self.own_did,
            &did,
            &payload,
            Some(E2eSendPriority::Text),
            None,
        )?;
        // Save the session before the send: a skipped Olm message is
        // harmless, a reused one is not.
        self.state
            .set_peer_session(&self.network, nick, &did, &session)?;
        if let Some(entry) = self.peers.get_mut(&did) {
            entry.one_time_key = None;
        }
        let answer = client
            .send_e2e_message(token, &self.network, &request)
            .await?;
        if answer.response != SendResponse::Accepted {
            return Err(EngineError::Rejected(answer.response));
        }
        let key = answer
            .msgid
            .as_deref()
            .map(|msgid| SendKey::new(&self.network, nick, msgid));
        if let Some(key) = &key {
            self.book.start(key.clone());
            self.book.apply_response(key, SendResponse::Accepted);
        }
        self.local_sends += 1;
        let suffix = answer
            .msgid
            .clone()
            .unwrap_or_else(|| format!("local{}", self.local_sends));
        let message = E2eMessage {
            id: format!("{}:out:{suffix}", self.network),
            conversation_id: conversation_id(&self.network, nick),
            sender_device: OWN_DEVICE.to_string(),
            sent_at: now,
            text: text.to_string(),
            encrypted: true,
        };
        self.history.append(message)?;
        self.note_changed(nick);
        Ok(SentText {
            msgid: answer.msgid,
            key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_device::{build_device_certificate, build_signed_list_signature};
    use crate::e2e_store::E2eKeyProvider;
    use crate::e2e_wire::bundle_key_signed_text;
    use crate::phoenix::PhoenixMessage;
    use crate::session::{route_e2e_message, spawn_session, SessionEvent};
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NET: &str = "net";
    const TOKEN: &str = "tok";
    const PROTOCOL: Option<u32> = Some(50);

    struct FixedKey([u8; 32]);

    impl E2eKeyProvider for FixedKey {
        fn load_or_create_key(&self) -> Result<[u8; 32], E2eStoreError> {
            Ok(self.0)
        }
    }

    fn scratch_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "cordiale-engine-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn ed(device: &Account) -> String {
        device.identity_keys().ed25519.to_base64()
    }

    fn curve(device: &Account) -> String {
        device.identity_keys().curve25519.to_base64()
    }

    /// The KEYS text of `device`, listed by `master` in a list of `listed`
    /// at `version`, for the user with the Ed25519 key `recipient`.
    fn keys_payload(
        master: &Account,
        device: &Account,
        listed: &[String],
        version: u32,
        recipient: &str,
        with_one_time_key: bool,
    ) -> String {
        let device_ed = ed(device);
        let certificate = build_device_certificate(version, &device_ed, &ed(master), |text| {
            master.sign(text).to_base64()
        })
        .expect("certificate");
        let list_signature =
            build_signed_list_signature(version, listed, |text| master.sign(text).to_base64())
                .expect("list");
        let curve_text = bundle_key_signed_text(&curve(device)).expect("text");
        let one_time_key = with_one_time_key.then(|| {
            device
                .one_time_keys()
                .values()
                .next()
                .expect("one-time key")
                .to_base64()
        });
        serde_json::to_string(&KeysPayload {
            v: 2,
            master: ed(master),
            list_version: version,
            list_keys: listed.to_vec(),
            list_signature,
            cert_version: version,
            cert_signature: certificate.signature,
            ed25519: device_ed.clone(),
            did: did_from_key_text(&device_ed).expect("did"),
            curve25519: curve(device),
            curve_signature: device.sign(&curve_text).to_base64(),
            fb: recipient_binding(&device_ed, recipient),
            one_time_key,
        })
        .expect("json")
    }

    /// One user with a master key and one device, as a test double.
    struct Ident {
        master: Account,
        device: Account,
        dir: PathBuf,
    }

    impl Ident {
        fn new(name: &str) -> Self {
            let mut device = Account::new();
            device.generate_one_time_keys(1);
            Self {
                master: Account::new(),
                device,
                dir: scratch_dir(name),
            }
        }

        fn engine(&self) -> E2eEngine {
            let mut state =
                E2eStateStore::open(self.dir.join("state.bin"), &FixedKey([7; 32])).expect("state");
            state.set_account(&self.device).expect("account");
            let history = E2eHistoryStore::open(self.dir.join("history.bin"), &FixedKey([9; 32]))
                .expect("history");
            E2eEngine::new(NET, state, history).expect("engine")
        }

        /// The KEYS text of this user for the user with the Ed25519 key
        /// `recipient`.
        fn keys_for(&self, recipient: &str, with_one_time_key: bool) -> String {
            keys_payload(
                &self.master,
                &self.device,
                &[ed(&self.device)],
                1,
                recipient,
                with_one_time_key,
            )
        }

        /// The KEYS text of a list 2 that holds `new_device` only. The
        /// device of this user is revoked.
        fn newer_keys_for(&self, new_device: &Account, recipient: &str) -> String {
            keys_payload(
                &self.master,
                new_device,
                &[ed(new_device)],
                2,
                recipient,
                false,
            )
        }
    }

    fn row(
        id: u64,
        from: &str,
        from_did: &str,
        to_did: &str,
        verb: &str,
        msgid: &str,
        payload: &str,
    ) -> Value {
        json!({
            "kind": "e2e_message", "network": NET, "id": id, "from": from,
            "from_did": from_did, "to_did": to_did, "verb": verb,
            "msgid": msgid, "payload": payload
        })
    }

    /// Alice sends "hello" to Bob through a mock server. Returns the body of
    /// the request that the server got.
    async fn alice_sends(
        alice: &mut E2eEngine,
        server: &MockServer,
        text: &str,
    ) -> (SentText, Value) {
        let before = server.received_requests().await.expect("requests").len();
        let sent = alice
            .send_text(&GrappaClient::new(server.uri()), TOKEN, "bob", text, 100)
            .await
            .expect("send");
        let requests = server.received_requests().await.expect("requests");
        let body: Value = serde_json::from_slice(&requests[before].body).expect("body");
        (sent, body)
    }

    async fn mount_send(server: &MockServer, msgid: &str) {
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/e2e/messages")))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(json!({"id": 1, "msgid": msgid})),
            )
            .mount(server)
            .await;
    }

    struct Pair {
        alice: E2eEngine,
        bob: E2eEngine,
        alice_did: String,
        bob_did: String,
    }

    fn pair() -> Pair {
        let alice_id = Ident::new("alice");
        let bob_id = Ident::new("bob");
        let mut alice = alice_id.engine();
        let mut bob = bob_id.engine();
        alice
            .accept_keys("bob", &bob_id.keys_for(&ed(&alice_id.device), true))
            .expect("alice reads bob");
        bob.accept_keys("alice", &alice_id.keys_for(&ed(&bob_id.device), false))
            .expect("bob reads alice");
        let alice_did = did_from_key_text(&ed(&alice_id.device)).expect("did");
        let bob_did = did_from_key_text(&ed(&bob_id.device)).expect("did");
        assert_eq!(alice.own_did(), alice_did);
        assert_eq!(bob.own_did(), bob_did);
        Pair {
            alice,
            bob,
            alice_did,
            bob_did,
        }
    }

    #[tokio::test]
    async fn one_message_goes_out_and_one_comes_in_with_the_encrypted_mark() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;

        let (sent, body) = alice_sends(&mut p.alice, &server, "hello bob").await;
        assert_eq!(body["verb"], "pkmsg");
        assert_eq!(body["target"], "bob");
        assert_eq!(body["from"], p.alice_did.as_str());
        assert_eq!(body["to"], p.bob_did.as_str());
        assert!(!body.to_string().contains("hello bob"));
        assert!(!body.to_string().contains(QUERY_LOCK_LABEL));
        let key = sent.key.expect("send key");
        assert_eq!(p.alice.send_status(&key), Some(SendStatus::Accepted));

        // The mock server of Bob serves the request of Alice in his inbox
        // and takes the ack.
        let inbox = MockServer::start().await;
        let payload = body["payload"].as_str().expect("payload");
        Mock::given(method("GET"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox",
                p.bob_did
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "messages": [row(5, "alice", &p.alice_did, &p.bob_did, "pkmsg", "msgid1", payload)]
            })))
            .mount(&inbox)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox/ack",
                p.bob_did
            )))
            .and(body_json(json!({"ids": [5]})))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&inbox)
            .await;
        let outcomes = p
            .bob
            .drain(&GrappaClient::new(inbox.uri()), TOKEN, PROTOCOL, 200)
            .await
            .expect("drain");
        assert_eq!(outcomes, vec![(5, RowOutcome::Stored)]);

        let conversation = conversation_id(NET, "alice");
        let rows = p.bob.history().messages(&conversation);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "hello bob");
        assert!(rows[0].encrypted);
        let sent_rows = p.alice.history().messages(&conversation_id(NET, "bob"));
        assert_eq!(sent_rows.len(), 1);
        assert!(sent_rows[0].encrypted);
    }

    #[tokio::test]
    async fn a_repeated_event_or_inbox_item_gives_one_row() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, body) = alice_sends(&mut p.alice, &server, "once").await;
        let payload = body["payload"].as_str().expect("payload").to_string();
        let value = row(
            5,
            "alice",
            &p.alice_did,
            &p.bob_did,
            "pkmsg",
            "msgid1",
            &payload,
        );

        // The same item comes as an event, again as an event and in the inbox.
        let frame = PhoenixMessage {
            join_ref: None,
            message_ref: None,
            topic: "grappa:user:bob".to_string(),
            event: "event".to_string(),
            payload: value,
        };
        let event = route_e2e_message(&frame, PROTOCOL).expect("event row");
        assert_eq!(p.bob.handle_row(&event, 200), RowOutcome::Stored);
        assert_eq!(p.bob.handle_row(&event, 201), RowOutcome::Duplicate);
        let same_item_new_run = row(
            5,
            "alice",
            &p.alice_did,
            &p.bob_did,
            "pkmsg",
            "msgid1",
            &payload,
        );
        let again = InboxRow::from_value(&same_item_new_run, PROTOCOL).expect("row");
        assert_eq!(p.bob.handle_row(&again, 202), RowOutcome::Duplicate);
        assert_eq!(
            p.bob
                .history()
                .messages(&conversation_id(NET, "alice"))
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn an_undecryptable_item_is_acknowledged() {
        let mut p = pair();
        let inbox = MockServer::start().await;
        let bad = row(
            8,
            "alice",
            &p.alice_did,
            &p.bob_did,
            "msg",
            "m8",
            r#"{"v":2,"fb":"x","ct":"y"}"#,
        );
        Mock::given(method("GET"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox",
                p.bob_did
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"messages": [bad]})))
            .mount(&inbox)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox/ack",
                p.bob_did
            )))
            .and(body_json(json!({"ids": [8]})))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&inbox)
            .await;
        let outcomes = p
            .bob
            .drain(&GrappaClient::new(inbox.uri()), TOKEN, PROTOCOL, 200)
            .await
            .expect("drain");
        assert_eq!(outcomes, vec![(8, RowOutcome::Undecryptable)]);
        assert!(p
            .bob
            .history()
            .messages(&conversation_id(NET, "alice"))
            .is_empty());
    }

    #[tokio::test]
    async fn an_item_with_a_failed_history_write_is_not_acknowledged() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, body) = alice_sends(&mut p.alice, &server, "keep me").await;
        let payload = body["payload"].as_str().expect("payload").to_string();

        // A history path that is a folder makes the write fail.
        let bob_dir = scratch_dir("bob-broken");
        let mut state =
            E2eStateStore::open(bob_dir.join("state.bin"), &FixedKey([7; 32])).expect("state");
        let bob_identity = p.bob.state.olm_identity().expect("identity").expect("some");
        state.set_account(&bob_identity).expect("identity");
        let history = E2eHistoryStore::open(bob_dir.join("history.bin"), &FixedKey([9; 32]))
            .expect("history");
        let mut broken = E2eEngine::new(NET, state, history).expect("engine");
        broken.peers = p.bob.peers.clone();
        std::fs::remove_file(bob_dir.join("history.bin")).ok();
        std::fs::create_dir_all(bob_dir.join("history.bin")).expect("folder in place of file");

        let inbox = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox",
                p.bob_did
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "messages": [row(5, "alice", &p.alice_did, &p.bob_did, "pkmsg", "msgid1", &payload)]
            })))
            .mount(&inbox)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox/ack",
                p.bob_did
            )))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&inbox)
            .await;
        let outcomes = broken
            .drain(&GrappaClient::new(inbox.uri()), TOKEN, PROTOCOL, 200)
            .await
            .expect("drain");
        assert_eq!(outcomes, vec![(5, RowOutcome::StoreFailed)]);
    }

    #[tokio::test]
    async fn two_pre_key_messages_before_a_reply_are_both_stored() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, first) = alice_sends(&mut p.alice, &server, "one").await;
        let (_, second) = alice_sends(&mut p.alice, &server, "two").await;
        assert_eq!(first["verb"], "pkmsg");
        assert_eq!(second["verb"], "pkmsg");
        for (id, msgid, body) in [(5, "msgid1", &first), (6, "msgid2", &second)] {
            let payload = body["payload"].as_str().expect("payload");
            let value = row(
                id,
                "alice",
                &p.alice_did,
                &p.bob_did,
                "pkmsg",
                msgid,
                payload,
            );
            let inbox_row = InboxRow::from_value(&value, PROTOCOL).expect("row");
            assert_eq!(p.bob.handle_row(&inbox_row, 200), RowOutcome::Stored);
        }
        let rows = p.bob.history().messages(&conversation_id(NET, "alice"));
        let texts: Vec<&str> = rows.iter().map(|row| row.text.as_str()).collect();
        assert_eq!(texts, ["one", "two"]);
    }

    #[tokio::test]
    async fn a_list_that_revokes_a_cached_device_ends_the_send() {
        let alice_id = Ident::new("alice-revoke");
        let bob_id = Ident::new("bob-revoke");
        let mut alice = alice_id.engine();
        alice
            .accept_keys("bob", &bob_id.keys_for(&ed(&alice_id.device), true))
            .expect("alice reads bob");
        assert!(alice.is_ready("bob"));
        // Bob signs list 2 with a new device only. The old device is revoked.
        let new_device = Account::new();
        let newer = bob_id.newer_keys_for(&new_device, &ed(&alice_id.device));
        // The new device has no one-time key and no session: not ready.
        alice.accept_keys("bob", &newer).expect("newer list");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let old_did = did_from_key_text(&ed(&bob_id.device)).expect("did");
        assert!(!alice.peers.contains_key(&old_did));
        let sent = alice
            .send_text(&GrappaClient::new(server.uri()), TOKEN, "bob", "late", 1)
            .await;
        assert!(matches!(sent, Err(EngineError::NotReady)));
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    #[tokio::test]
    async fn a_refused_newer_list_still_drops_the_revoked_device() {
        let alice_id = Ident::new("alice-refused");
        let bob_id = Ident::new("bob-refused");
        let mut alice = alice_id.engine();
        alice
            .accept_keys("bob", &bob_id.keys_for(&ed(&alice_id.device), true))
            .expect("alice reads bob");
        assert!(alice.is_ready("bob"));
        // List 2 revokes the old device, but its new device binds to a wrong
        // recipient: the device is refused, the list stays.
        let new_device = Account::new();
        let wrong = bob_id.newer_keys_for(&new_device, &ed(&bob_id.master));
        let refused = alice.accept_keys("bob", &wrong);
        assert!(matches!(
            refused,
            Err(EngineError::Device(E2eError::RecipientMismatch))
        ));
        assert!(alice.peers.is_empty());
        assert!(!alice.is_ready("bob"));
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let sent = alice
            .send_text(&GrappaClient::new(server.uri()), TOKEN, "bob", "late", 1)
            .await;
        assert!(matches!(sent, Err(EngineError::NotReady)));
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    #[tokio::test]
    async fn a_persisted_revocation_stops_a_restored_session_after_a_restart() {
        let alice_id = Ident::new("alice-restart");
        let bob_id = Ident::new("bob-restart");
        let mut alice = alice_id.engine();
        let mut bob = bob_id.engine();
        alice
            .accept_keys("bob", &bob_id.keys_for(&ed(&alice_id.device), true))
            .expect("alice reads bob");
        bob.accept_keys("alice", &alice_id.keys_for(&ed(&bob_id.device), false))
            .expect("bob reads alice");
        let alice_did = did_from_key_text(&ed(&alice_id.device)).expect("did");
        let bob_did = did_from_key_text(&ed(&bob_id.device)).expect("did");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let client = GrappaClient::new(server.uri());

        // Alice opens the session, Bob answers, so the next message is a
        // normal one that Bob opens with the session in his state.
        let (_, first) = alice_sends(&mut alice, &server, "one").await;
        let value = row(
            5,
            "alice",
            &alice_did,
            &bob_did,
            "pkmsg",
            "msgid1",
            first["payload"].as_str().expect("payload"),
        );
        let first_row = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(bob.handle_row(&first_row, 200), RowOutcome::Stored);
        let before = server.received_requests().await.expect("requests").len();
        bob.send_text(&client, TOKEN, "alice", "reply", 210)
            .await
            .expect("reply");
        let requests = server.received_requests().await.expect("requests");
        let reply: Value = serde_json::from_slice(&requests[before].body).expect("body");
        let value = row(
            6,
            "bob",
            &bob_did,
            &alice_did,
            reply["verb"].as_str().expect("verb"),
            "msgid1",
            reply["payload"].as_str().expect("payload"),
        );
        let reply_row = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(alice.handle_row(&reply_row, 220), RowOutcome::Stored);
        let (_, second) = alice_sends(&mut alice, &server, "two").await;
        assert_eq!(second["verb"], "msg");

        // Bob learns a list that revokes the device of Alice, then restarts.
        let new_device = Account::new();
        let newer = alice_id.newer_keys_for(&new_device, &ed(&bob_id.device));
        bob.accept_keys("alice", &newer).expect("newer list");
        drop(bob);
        let mut bob = bob_id.engine();
        assert!(bob.peers.is_empty());
        let value = row(
            7,
            "alice",
            &alice_did,
            &bob_did,
            "msg",
            "msgid1",
            second["payload"].as_str().expect("payload"),
        );
        let late = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(bob.handle_row(&late, 230), RowOutcome::Undecryptable);
        let rows = bob.history().messages(&conversation_id(NET, "alice"));
        let texts: Vec<&str> = rows.iter().map(|row| row.text.as_str()).collect();
        // The history holds the received "one" and the sent "reply" only.
        assert_eq!(texts, ["one", "reply"]);
        assert!(!texts.contains(&"two"));
    }

    #[tokio::test]
    async fn a_send_goes_to_the_ready_device_of_a_peer_with_two_devices() {
        let alice_id = Ident::new("alice-two");
        let bob_id = Ident::new("bob-two");
        let other = Account::new();
        let listed = vec![ed(&bob_id.device), ed(&other)];
        let recipient = ed(&alice_id.device);
        let mut alice = alice_id.engine();
        alice
            .accept_keys(
                "bob",
                &keys_payload(&bob_id.master, &other, &listed, 1, &recipient, false),
            )
            .expect("device without key");
        alice
            .accept_keys(
                "bob",
                &keys_payload(&bob_id.master, &bob_id.device, &listed, 1, &recipient, true),
            )
            .expect("device with key");
        assert_eq!(alice.peers.len(), 2);
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, body) = alice_sends(&mut alice, &server, "hello").await;
        let ready = did_from_key_text(&ed(&bob_id.device)).expect("did");
        assert_eq!(body["to"], ready.as_str());
    }

    #[test]
    fn a_failed_trust_write_leaves_the_keys_row_unacknowledged() {
        let alice_id = Ident::new("alice-trust");
        let bob_id = Ident::new("bob-trust");
        let mut alice = alice_id.engine();
        // A folder in place of the state file makes the write fail.
        let state_path = alice_id.dir.join("state.bin");
        std::fs::remove_file(&state_path).ok();
        std::fs::create_dir_all(&state_path).expect("folder in place of file");
        let alice_did = did_from_key_text(&ed(&alice_id.device)).expect("did");
        let value = row(
            3,
            "bob",
            WILDCARD,
            &alice_did,
            "keys",
            "k1",
            &bob_id.keys_for(&ed(&alice_id.device), true),
        );
        let keys_row = InboxRow::from_value(&value, PROTOCOL).expect("row");
        let outcome = alice.handle_row(&keys_row, 1);
        assert_eq!(outcome, RowOutcome::StoreFailed);
        assert!(!outcome.acknowledge());
        assert!(alice.peers.is_empty());
        // The row is not marked as seen: the next drain reads it again.
        assert_eq!(alice.handle_row(&keys_row, 2), RowOutcome::StoreFailed);
    }

    #[tokio::test]
    async fn a_failed_encryption_sends_nothing() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let client = GrappaClient::new(server.uri());
        // No verified device for this nick.
        let unknown = p
            .alice
            .send_text(&client, TOKEN, "carol", "secret", 1)
            .await;
        assert!(matches!(unknown, Err(EngineError::NotReady)));
        // The label of the locked query is never a target.
        let label = locked_label("bob");
        let labeled = p.alice.send_text(&client, TOKEN, &label, "secret", 1).await;
        assert!(matches!(
            labeled,
            Err(EngineError::Wire(WireError::BadTarget))
        ));
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    #[tokio::test]
    async fn a_refused_send_gives_no_accepted_state() {
        let mut p = pair();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/e2e/messages")))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({"error": "too_late"})))
            .mount(&server)
            .await;
        let result = p
            .alice
            .send_text(&GrappaClient::new(server.uri()), TOKEN, "bob", "late", 1)
            .await;
        assert!(matches!(result, Err(EngineError::Rejected(_))));
        assert!(p
            .alice
            .history()
            .messages(&conversation_id(NET, "bob"))
            .is_empty());
    }

    #[tokio::test]
    async fn the_inbox_is_read_page_by_page() {
        let mut p = pair();
        let inbox = MockServer::start().await;
        let nack = |id: u64| row(id, "alice", &p.alice_did, &p.bob_did, "nack", "m", "{}");
        Mock::given(method("GET"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox",
                p.bob_did
            )))
            .and(query_param("after", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"messages": []})))
            .mount(&inbox)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox",
                p.bob_did
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"messages": [nack(1), nack(2)]})),
            )
            .mount(&inbox)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox/ack",
                p.bob_did
            )))
            .and(body_json(json!({"ids": [1, 2]})))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&inbox)
            .await;
        let outcomes = p
            .bob
            .drain(&GrappaClient::new(inbox.uri()), TOKEN, PROTOCOL, 1)
            .await
            .expect("drain");
        assert_eq!(outcomes.len(), 2);
    }

    #[tokio::test]
    async fn keyreq_goes_through_the_send_door_with_wildcard_to() {
        let mut p = pair();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/e2e/messages")))
            .and(body_json(json!({
                "target": "bob", "verb": "keyreq", "from": p.alice_did,
                "to": "*", "payload": "{\"v\":2}", "priority": "control"
            })))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"msgid": "k1"})))
            .expect(1)
            .mount(&server)
            .await;
        let client = GrappaClient::new(server.uri());
        p.alice
            .request_keys(&client, TOKEN, "bob")
            .await
            .expect("keyreq");
        let again = p.alice.request_keys(&client, TOKEN, "bob").await;
        assert!(matches!(again, Err(EngineError::Paced(_))));
    }

    #[test]
    fn plain_and_locked_windows_route_apart() {
        assert_eq!(
            route_for_window("bob"),
            SendRoute::Plain { nick: "bob".into() }
        );
        let label = locked_label("bob");
        let route = route_for_window(&label);
        assert_eq!(route, SendRoute::Encrypted { nick: "bob".into() });
        assert_eq!(route.nick(), "bob");
        assert!(!route.nick().contains(QUERY_LOCK_LABEL));
        // Both entries of one peer share the nick, not the history.
        assert_eq!(
            conversation_id(NET, "bob"),
            conversation_id(NET, route.nick())
        );
    }

    #[test]
    fn a_peer_without_a_verified_device_is_not_ready() {
        let id = Ident::new("solo");
        let engine = id.engine();
        assert!(!engine.is_ready("bob"));
    }

    /// Bob, a second device of Bob that shares his master key, and the KEYS
    /// of the second device that Bob has read.
    struct Siblings {
        bob: E2eEngine,
        bob_id: Ident,
        second: Account,
        second_did: String,
    }

    fn siblings() -> Siblings {
        let mut bob_id = Ident::new("bob-own");
        // Four keys: one for a first peer and one for each copy.
        bob_id.device.generate_one_time_keys(3);
        let mut bob = bob_id.engine();
        let second = Account::new();
        let keys = keys_payload(
            &bob_id.master,
            &second,
            &[ed(&bob_id.device), ed(&second)],
            1,
            &ed(&bob_id.device),
            false,
        );
        bob.accept_keys("bob", &keys)
            .expect("bob reads the second device");
        let second_did = did_from_key_text(&ed(&second)).expect("did");
        Siblings {
            bob,
            bob_id,
            second,
            second_did,
        }
    }

    /// An `own` inbox row: the second device sends the plaintext `plain` to
    /// Bob as a pre-key message. It uses a one-time key of Bob other than
    /// `used`; the row `id` picks the key.
    fn copy_row_raw(s: &Siblings, id: u64, msgid: &str, used: &str, plain: &str) -> Value {
        // Each row id takes another key, because a key opens one session.
        let mut free: Vec<Curve25519PublicKey> = s
            .bob_id
            .device
            .one_time_keys()
            .values()
            .filter(|key| key.to_base64() != used)
            .cloned()
            .collect();
        free.sort_by_key(|key| key.to_base64());
        let one_time_key = free.swap_remove((id % 3) as usize);
        let bob_curve = Curve25519PublicKey::from_base64(&curve(&s.bob_id.device)).expect("curve");
        let mut session =
            s.second
                .create_outbound_session(SessionConfig::version_1(), bob_curve, one_time_key);
        let OlmMessage::PreKey(message) = session.encrypt(plain.as_bytes()) else {
            panic!("the first message is a pre-key message");
        };
        let payload = MessagePayload {
            v: PAYLOAD_VERSION,
            fb: recipient_binding(&ed(&s.second), &ed(&s.bob_id.device)),
            ct: message.to_base64(),
        }
        .to_json();
        let mut value = row(
            id,
            "bob",
            &s.second_did,
            s.bob.own_did(),
            "pkmsg",
            msgid,
            &payload,
        );
        value["own"] = json!(true);
        value
    }

    fn copy_row(s: &Siblings, id: u64, msgid: &str, peer: &str, text: &str, used: &str) -> Value {
        let plain = CopyBody {
            peer: peer.to_string(),
            text: text.to_string(),
        }
        .to_json();
        copy_row_raw(s, id, msgid, used, &plain)
    }

    #[test]
    fn a_copy_of_an_own_device_is_stored_in_the_conversation_of_its_peer() {
        let mut s = siblings();
        let value = copy_row(&s, 3, "msgid2", "carol", "sent from the other device", "");
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert!(item.own);
        assert_eq!(s.bob.handle_row(&item, 50), RowOutcome::Stored);
        assert_eq!(s.bob.handle_row(&item, 51), RowOutcome::Duplicate);

        let rows = s.bob.history().messages(&conversation_id(NET, "carol"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "sent from the other device");
        assert_eq!(rows[0].sender_device, OWN_DEVICE);
        assert!(rows[0].encrypted);
        assert!(s
            .bob
            .history()
            .messages(&conversation_id(NET, "bob"))
            .is_empty());
        assert_eq!(s.bob.take_changed_peers(), vec!["carol".to_string()]);
        assert!(s.bob.take_changed_peers().is_empty());
    }

    #[test]
    fn a_copy_without_a_valid_peer_is_acknowledged_and_not_stored() {
        let mut s = siblings();
        let locked = locked_label("carol");
        let cases = [
            copy_row_raw(&s, 4, "msgid3", "", "not json"),
            copy_row(&s, 5, "msgid4", &locked, "labelled peer", ""),
            copy_row(&s, 6, "msgid5", "", "empty peer", ""),
        ];
        for value in cases {
            let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
            let outcome = s.bob.handle_row(&item, 60);
            assert_eq!(outcome, RowOutcome::Undecryptable);
            assert!(outcome.acknowledge());
        }
        assert!(s.bob.history().conversation_ids().is_empty());
    }

    #[test]
    fn the_history_peers_follow_the_stored_conversations() {
        let mut s = siblings();
        for (id, peer) in [(3, "carol"), (4, "dave")] {
            let msgid = format!("msgid{id}");
            let value = copy_row(&s, id, &msgid, peer, "hi", "");
            let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
            assert_eq!(s.bob.handle_row(&item, 70), RowOutcome::Stored);
        }
        assert_eq!(s.bob.history_peers(), vec!["carol", "dave"]);
    }

    #[tokio::test]
    async fn a_real_websocket_session_feeds_the_receive_path() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let alice_id = Ident::new("alice-ws");
        let mut alice = alice_id.engine();
        let mut s = siblings();
        let bob_keys = s.bob_id.keys_for(&ed(&alice_id.device), true);
        let used = KeysPayload::parse(&bob_keys)
            .expect("keys")
            .one_time_key
            .expect("one-time key");
        alice
            .accept_keys("bob", &bob_keys)
            .expect("alice reads bob");
        s.bob
            .accept_keys("alice", &alice_id.keys_for(&ed(&s.bob_id.device), false))
            .expect("bob reads alice");
        let alice_did = alice.own_did().to_string();
        let bob_did = s.bob.own_did().to_string();

        let send_server = MockServer::start().await;
        mount_send(&send_server, "msgid1").await;
        let (_, body) = alice_sends(&mut alice, &send_server, "over the socket").await;
        let payload = body["payload"].as_str().expect("payload").to_string();
        let message = row(
            7, "alice", &alice_did, &bob_did, "pkmsg", "msgid1", &payload,
        );
        let copy = copy_row(&s, 8, "msgid2", "carol", "from the second device", &used);

        // The server joins the user topic, then pushes the message twice and
        // the copy once.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let ws_url = format!(
            "ws://{}/socket/websocket",
            listener.local_addr().expect("address")
        );
        let pushes = vec![message.clone(), message, copy];
        let server_topic = "grappa:user:bob".to_string();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("handshake");
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let frame = PhoenixMessage::from_json(text.as_str()).expect("frame");
                if frame.event != "phx_join" || frame.topic != server_topic {
                    continue;
                }
                let reply = PhoenixMessage {
                    join_ref: frame.join_ref.clone(),
                    message_ref: frame.message_ref.clone(),
                    topic: server_topic.clone(),
                    event: "phx_reply".to_string(),
                    payload: json!({"status": "ok", "response": {"protocol_version": 50}}),
                };
                socket
                    .send(Message::from(reply.to_json().expect("json")))
                    .await
                    .expect("reply");
                for payload in pushes {
                    let push = PhoenixMessage {
                        join_ref: None,
                        message_ref: None,
                        topic: server_topic.clone(),
                        event: "event".to_string(),
                        payload,
                    };
                    socket
                        .send(Message::from(push.to_json().expect("json")))
                        .await
                        .expect("push");
                }
                break;
            }
            // Keep the socket open until the client ends the session.
            while socket.next().await.is_some() {}
        });

        let ack_server = MockServer::start().await;
        for id in [7, 8] {
            Mock::given(method("POST"))
                .and(path(format!(
                    "/networks/{NET}/e2e/devices/{bob_did}/inbox/ack"
                )))
                .and(body_json(json!({"ids": [id]})))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(&ack_server)
                .await;
        }
        let client = GrappaClient::new(ack_server.uri());

        let (handle, mut events) = spawn_session(ws_url, TOKEN.to_string(), "bob".to_string());
        let mut protocol = None;
        let mut outcomes = Vec::new();
        while outcomes.len() < 3 {
            let event = tokio::time::timeout(Duration::from_secs(10), events.recv())
                .await
                .expect("a session event in time")
                .expect("the session is open");
            match event {
                SessionEvent::Connected { protocol_version } => protocol = protocol_version,
                SessionEvent::Frame(frame) => {
                    if let Some(item) = route_e2e_message(&frame, protocol) {
                        let outcome = s
                            .bob
                            .handle_event(&client, TOKEN, protocol, &item, 300)
                            .await
                            .expect("handled");
                        outcomes.push(outcome);
                    }
                }
                other => panic!("unexpected session event: {other:?}"),
            }
        }
        handle.shutdown();
        server.abort();

        assert_eq!(protocol, Some(50));
        assert_eq!(
            outcomes,
            vec![
                RowOutcome::Stored,
                RowOutcome::Duplicate,
                RowOutcome::Stored
            ]
        );
        let received = s.bob.history().messages(&conversation_id(NET, "alice"));
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].text, "over the socket");
        assert!(received[0].encrypted);
        let copies = s.bob.history().messages(&conversation_id(NET, "carol"));
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].text, "from the second device");
        assert_eq!(copies[0].sender_device, OWN_DEVICE);
        assert!(copies[0].encrypted);
    }
}
