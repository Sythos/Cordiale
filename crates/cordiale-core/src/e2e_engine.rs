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
//! inner message is a `copy` that names the peer, and the text goes to the
//! conversation of that peer as an own row.
//!
//! The label of the locked query ([`locked_label`]) is for display only. A
//! peer is pinned on its `did`; the nick is a routing hint.
//!
//! irc-olm is the public repository `vjt/irc-olm`.
//!
//! The payloads follow the wire v2 of irc-olm (MD-3) and of cicchetto:
//!
//! - KEYS: `{"v":2,"master":{…},"devices":[{"id":{…},"otk":{…}}]}`. The master
//!   block holds the signed list. Each entry holds the id block of one device
//!   and one key to start a session. See [`KeysPayload`].
//! - `pkmsg`: `{"v":2,"id":{…},"master":{"ed25519","ver","cert"},"bodies":{…}}`.
//! - `msg`: `{"v":2,"ck":<curve key>,"bodies":{…}}`.
//!
//! `bodies` maps the `did` of a recipient device to the Olm message in base64.
//! The Olm plaintext is a compact JSON object [`Inner`]: `t` is the kind
//! (`text` for chat text, `copy` for an own copy), `lv` is the version of the
//! list of the sender, and a body of a `pkmsg` also holds `fb`, the binding of
//! the two device keys. The engine reads `text` and `copy`. It does not act on
//! a list (`list`, `listreq`) inside an Olm message: it keeps the session and
//! stores no row.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vodozemac::olm::{Account, Message, OlmMessage, PreKeyMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

use crate::client::{GrappaClient, GrappaClientError};
use crate::e2e_device::{verify_signature, verify_signed_list, E2eError, PeerDevice};
use crate::e2e_device_routes::{
    ClaimRequest, CopyRequest, CopyVerb, InboxAckRequest, InboxRow, InboxVerb,
};
use crate::e2e_manage::SignedList;
use crate::e2e_pacing::{
    check_send_deadline, md3_pacing, DropReason, IntervalLimiter, KeyReqPacer, KeyReqRefusal,
    MonotonicClock, OutgoingQueue, QueuedSend, SendBook, SendDecision, SendDropped, SendFailure,
    SendKey, SendResponse, SendStatus,
};
use crate::e2e_pairing_flow::JoinerDevice;
use crate::e2e_peer::{
    apply_peer_list, verify_certified_device, verify_peer_device, CertifiedBundle, PeerBundle,
    ReplayState,
};
use crate::e2e_refusal::{E2eRefusal, E2eRouteError};
use crate::e2e_selfcopy::{inbox_accepts, is_expired, DeliveryTracker};
use crate::e2e_state::E2eStateStore;
use crate::e2e_store::{E2eHistoryStore, E2eMessage, E2eStoreError, KeyringKeyProvider};
use crate::e2e_trust::PeerTrust;
use crate::e2e_wire::{
    bundle_key_signed_text, device_id_signed_text, did_from_key_text, is_did_shape, parse_payload,
    recipient_binding, WireError, INBOX_PAGE_MAX, MAX_LIST_DEVICES, MAX_VERSION, WILDCARD,
};
use crate::isupport::CaseMapping;
use crate::persistence::data_dir;
use crate::rest::{E2eSendPriority, E2eSendRequest, E2eSendVerb, QUERY_LOCK_LABEL};

/// Version number in the payloads that the engine writes.
const PAYLOAD_VERSION: u32 = 2;

/// How long a fragmented KEYS answer may stay in reassembly. The value comes
/// from the final source and is recorded in [`md3_pacing`].
const KEYS_REASSEMBLY_TIMEOUT: Duration = md3_pacing::REASSEMBLY_TIMEOUT;

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

/// The part of the engine file names for one network of one account on one
/// server: a hash, so two servers or two accounts with the same network slug
/// never share an identity or a history. A guest (`visitor:`) or an empty
/// value has no engine files.
fn storage_part(server: &str, account: &str, network: &str) -> Option<String> {
    if server.is_empty()
        || account.is_empty()
        || account.starts_with("visitor:")
        || network.is_empty()
    {
        return None;
    }
    let hash = Sha256::digest(format!("{server}\u{0}{account}\u{0}{network}").as_bytes());
    let mut part = String::new();
    for byte in &hash[..16] {
        part.push_str(&format!("{byte:02x}"));
    }
    Some(part)
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
    /// The peer is known to have no E2E capability. No KEYREQ went out.
    PeerNotCapable,
    /// The nickname already has the most messages that may wait for keys.
    QueueFull,
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

/// Reads `ver`, `lv` and the like: an integral JSON number from 1 to 2^31 - 1.
/// A number such as `1.0` counts by its value. Booleans, strings, null and
/// fractions are not versions.
fn version_from_value(value: &Value) -> Option<u32> {
    let Value::Number(number) = value else {
        return None;
    };
    let whole = match number.as_u64() {
        Some(whole) => whole,
        None => {
            let float = number.as_f64()?;
            if float.fract() != 0.0 || float < 0.0 {
                return None;
            }
            float as u64
        }
    };
    u32::try_from(whole)
        .ok()
        .filter(|version| (1..=MAX_VERSION).contains(version))
}

fn de_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    version_from_value(&value).ok_or_else(|| serde::de::Error::custom("bad version"))
}

fn check_payload_version(version: u32) -> Result<(), WireError> {
    if version == PAYLOAD_VERSION {
        Ok(())
    } else {
        Err(WireError::BadVersion)
    }
}

/// The id block of a device: its keys and its signature over its curve key
/// and its master key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdBlock {
    pub curve25519: String,
    pub ed25519: String,
    pub sig: String,
}

/// The signed device list in the master block of a KEYS payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterList {
    #[serde(deserialize_with = "de_version")]
    pub ver: u32,
    pub devices: Vec<String>,
}

/// The master block of a KEYS payload: the master key, its device list and
/// the signature of the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterBlock {
    pub ed25519: String,
    pub list: MasterList,
    pub sig: String,
}

/// The master block of a `pkmsg`: the master key and its certificate for the
/// sending device, with the list version N that the certificate names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterRef {
    pub ed25519: String,
    #[serde(deserialize_with = "de_version")]
    pub ver: u32,
    pub cert: String,
}

/// A key to start a session, signed by the device. It is a one-time key or
/// the fallback key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeKey {
    pub key: String,
    #[serde(default)]
    pub fallback: bool,
    pub sig: String,
}

/// One device in a KEYS payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysEntry {
    pub id: IdBlock,
    pub otk: OneTimeKey,
}

/// The payload of a KEYS row or of a claim answer (wire v2): the master block
/// with the signed list, and one entry for each device, 4 at most. A KEYS from
/// the server describes the user, so the entries are the devices of the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysPayload {
    pub v: u32,
    pub master: MasterBlock,
    pub devices: Vec<KeysEntry>,
}

impl KeysPayload {
    pub fn parse(text: &str) -> Result<Self, WireError> {
        let value = parse_payload(text)?;
        let payload: Self = serde_json::from_value(value).map_err(|_| WireError::BadPayload)?;
        check_payload_version(payload.v)?;
        if payload.devices.len() > MAX_LIST_DEVICES {
            return Err(WireError::BadDeviceCount);
        }
        Ok(payload)
    }
}

/// The payload of a `pkmsg` (wire v2): the id block and the master block of
/// the sender, and the Olm message for each recipient device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyPayload {
    pub v: u32,
    pub id: IdBlock,
    pub master: MasterRef,
    pub bodies: BTreeMap<String, String>,
}

/// The payload of a `msg` (wire v2): the curve key of the sender and the Olm
/// message for each recipient device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsgPayload {
    pub v: u32,
    pub ck: String,
    pub bodies: BTreeMap<String, String>,
}

/// The payload of a `pkmsg` or `msg` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessagePayload {
    PreKey(PreKeyPayload),
    Normal(MsgPayload),
}

impl MessagePayload {
    /// Reads the payload of a row with the verb `verb`: `PkMsg` or `Msg`.
    pub fn parse(verb: InboxVerb, text: &str) -> Result<Self, WireError> {
        let value = parse_payload(text)?;
        let payload = match verb {
            InboxVerb::PkMsg => {
                Self::PreKey(serde_json::from_value(value).map_err(|_| WireError::BadPayload)?)
            }
            InboxVerb::Msg => {
                Self::Normal(serde_json::from_value(value).map_err(|_| WireError::BadPayload)?)
            }
            _ => return Err(WireError::BadVerb),
        };
        let version = match &payload {
            Self::PreKey(payload) => payload.v,
            Self::Normal(payload) => payload.v,
        };
        check_payload_version(version)?;
        let bodies = payload.bodies();
        if bodies.is_empty() || bodies.len() > MAX_LIST_DEVICES {
            return Err(WireError::BadDeviceCount);
        }
        if !bodies.keys().all(|did| is_did_shape(did)) {
            return Err(WireError::BadDid);
        }
        Ok(payload)
    }

    /// The Olm message in base64 for each recipient `did`.
    pub fn bodies(&self) -> &BTreeMap<String, String> {
        match self {
            Self::PreKey(payload) => &payload.bodies,
            Self::Normal(payload) => &payload.bodies,
        }
    }

    fn to_json(&self) -> String {
        match self {
            Self::PreKey(payload) => serde_json::to_string(payload),
            Self::Normal(payload) => serde_json::to_string(payload),
        }
        .unwrap_or_default()
    }
}

/// What an inner message says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerKind {
    /// Chat text from a person: `{"t":"text","body":…}`.
    Text { body: String },
    /// A copy of the text that another device of the account sent to `peer`:
    /// `{"t":"copy","peer":…,"body":…}`.
    Copy { peer: String, body: String },
    /// Any other kind: a list, a list request, a challenge, an unknown one.
    /// The engine keeps the session and stores nothing.
    Other,
}

/// The decrypted Olm plaintext: a JSON object with the kind `t`, the version
/// `lv` of the list of the sender and, in a `pkmsg`, the binding `fb`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inner {
    pub kind: InnerKind,
    pub lv: Option<u32>,
    pub fb: Option<String>,
}

impl Inner {
    /// Reads the plaintext. `None` when it is not a JSON object with a string
    /// `t`.
    pub fn parse(plain: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(plain).ok()?;
        let value: Value = serde_json::from_str(text).ok()?;
        let map = value.as_object()?;
        let field = |name: &str| map.get(name).and_then(Value::as_str);
        let kind = match map.get("t")?.as_str()? {
            "text" => field("body").map_or(InnerKind::Other, |body| InnerKind::Text {
                body: body.to_string(),
            }),
            "copy" => match (field("peer"), field("body")) {
                (Some(peer), Some(body)) => InnerKind::Copy {
                    peer: peer.to_string(),
                    body: body.to_string(),
                },
                _ => InnerKind::Other,
            },
            _ => InnerKind::Other,
        };
        Some(Self {
            kind,
            lv: map.get("lv").and_then(version_from_value),
            fb: field("fb").map(str::to_string),
        })
    }
}

/// The inner message that the engine writes.
#[derive(Serialize)]
struct InnerOut<'a> {
    t: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<&'a str>,
    body: &'a str,
    lv: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    fb: Option<&'a str>,
}

impl InnerOut<'_> {
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// The inner message of a `pkmsg` body when its `fb` binds the two device
/// keys, else `None`.
fn bound_to(inner: Inner, expected_fb: &str) -> Option<Inner> {
    (inner.fb.as_deref() == Some(expected_fb)).then_some(inner)
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
    /// A row that is not stored: a NACK, or a message of another kind than
    /// text (a list or a list request). The session of such a message is kept.
    Ignored,
    /// The write to the history or the state failed. Do not acknowledge the
    /// row: it stays in the inbox for the next drain.
    StoreFailed,
    /// A copy comes from a sibling with a newer list than the own list. Do
    /// not acknowledge it and stop the drain before it. Sync the own list,
    /// then drain again.
    StaleList,
}

impl RowOutcome {
    /// True when the caller acknowledges the row.
    pub fn acknowledge(self) -> bool {
        !matches!(self, RowOutcome::StoreFailed | RowOutcome::StaleList)
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

/// A text that waits for keys, or for a re-send after a NACK.
#[derive(Debug, Clone)]
struct PendingText {
    text: String,
    /// 1 for a first send, 2 for a re-send after a NACK.
    sends: u8,
    /// The history row of the text. A re-send adds no second row.
    row_id: String,
    /// The device that must get the text: the one that sent the NACK. A first
    /// send has none and goes to the best ready device.
    did: Option<String>,
}

/// A text that went out. It stays available for one re-send after a NACK.
#[derive(Debug, Clone)]
struct SentRecord {
    nick: String,
    /// The device the message was for. Only this device may NACK it.
    did: String,
    text: String,
    sends: u8,
    row_id: String,
    at: Duration,
}

/// Why the copy for one sibling device was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyFailure {
    /// The relay says the target is this device.
    SameDevice,
    /// The sibling holds no key. It is unreachable until it uploads more.
    KeylessDevice,
    /// The key went between the pick and the hand-out, also after a new ask.
    KeyTaken,
    /// The sibling was dropped meanwhile, or the server list removes it.
    RemovedDevice,
    /// The inbox of the sibling is full. The copy is missing there. No retry.
    InboxFull,
    /// The claim gave no usable key.
    NoKey,
    /// The copy is larger than an inbox takes.
    TooLarge,
    /// The text waited longer than the inbox lifetime.
    Expired,
    /// Any other failure, after the last try.
    Failed,
}

/// What [`E2eEngine::send_copies`] did. A queued copy is an acceptance of the
/// relay. It never proves that the peer got the original.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// The `did` of each sibling whose copy the relay accepted.
    pub queued: Vec<String>,
    /// The `did` of each sibling that gets no copy, with the reason.
    pub failed: Vec<(String, CopyFailure)>,
    /// The signed list of a sibling or of this device is behind. The call
    /// stopped before that copy. Sync with [`E2eEngine::sync_own_list`], then
    /// call again.
    pub needs_sync: bool,
}

/// A text that waits for its copies.
#[derive(Debug, Clone)]
struct CopyJob {
    id: String,
    peer: String,
    text: String,
    created_at: i64,
    /// Siblings that are final: queued, or dropped for good.
    done: HashSet<String>,
    tries: HashMap<String, u8>,
}

/// How one copy step ended when it did not queue the copy.
enum CopyStep {
    Drop(CopyFailure),
    Retry,
    Sync,
}

#[derive(Debug, Clone)]
struct PeerEntry {
    nick: String,
    device: PeerDevice,
    /// A one-time key from a KEYS answer, used once to open the session.
    one_time_key: Option<String>,
}

/// What this device writes about itself in a message: its id block, its
/// master block and the version of its list.
struct OwnWire {
    id: IdBlock,
    master: MasterRef,
    lv: u32,
}

/// The decrypted inner message and the state to save after the history write.
struct Decrypted {
    inner: Inner,
    identity: Option<Account>,
    session: Session,
    replay: Option<ReplayState>,
    /// The device of a first message and the trust state that holds it. The
    /// state is saved with the rest and the device is cached after that.
    learned: Option<(PeerEntry, PeerTrust)>,
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
    /// Casemapping of the network, read again for every pacing decision.
    casemapping: CaseMapping,
    clock: MonotonicClock,
    /// Devices that a newer signed list revoked. Their rows are not read.
    revoked_dids: HashSet<String>,
    /// Nicks that sent a message the engine could not read for lack of keys.
    keys_wanted: Vec<String>,
    /// Texts that wait for the keys of their peer, oldest first.
    queue: OutgoingQueue,
    pending: HashMap<SendKey, PendingText>,
    /// Texts that went out, by `msgid`, for a re-send after a NACK.
    sent: HashMap<String, SentRecord>,
    /// At most one re-key for each nick in the re-key interval.
    rekey: IntervalLimiter,
    /// The history row of each send. A drop shows on this row.
    row_ids: HashMap<SendKey, String>,
    /// Rows whose send was dropped, with the reason. Only the locked query
    /// reads them; the plain query never sees a drop.
    dropped_rows: HashMap<String, DropReason>,
    /// Peers with a known E2E capability. An absent peer is not known.
    capability: Vec<(String, bool)>,
    /// Peers whose conversation got a new row since the last call of
    /// [`E2eEngine::take_changed_peers`].
    changed_peers: Vec<String>,
    local_sends: u64,
    /// Texts whose original got a 202 answer and whose copies for the other
    /// devices of the account are not all queued yet.
    copy_jobs: Vec<CopyJob>,
    /// The state of each queued copy. A queued copy is never a delivery.
    copy_tracker: DeliveryTracker,
    /// How often a copy row waited for a newer own list, by inbox id.
    stale_tries: HashMap<u64, u8>,
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
            casemapping: CaseMapping::Rfc1459,
            clock: MonotonicClock::new(),
            revoked_dids: HashSet::new(),
            keys_wanted: Vec::new(),
            queue: OutgoingQueue::new(),
            pending: HashMap::new(),
            sent: HashMap::new(),
            rekey: IntervalLimiter::new(md3_pacing::REKEY_INTERVAL),
            row_ids: HashMap::new(),
            dropped_rows: HashMap::new(),
            capability: Vec::new(),
            changed_peers: Vec::new(),
            local_sends: 0,
            copy_jobs: Vec::new(),
            copy_tracker: DeliveryTracker::default(),
            stale_tries: HashMap::new(),
        })
    }

    /// Opens the engine of `network` from the sealed files in the data
    /// folder. `server` is the base URL of Grappa and `account` the signed-in
    /// account: both are part of the file names. A network without a state
    /// file, or without an Olm identity in it, is `NotReady`: the provisioning
    /// makes the identity first, and this call never makes a key or a file of
    /// its own.
    pub fn open_for_network(
        server: &str,
        account: &str,
        network: &str,
    ) -> Result<Self, EngineError> {
        let part = storage_part(server, account, network).ok_or(EngineError::NotReady)?;
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

    /// Like [`Self::open_for_network`], but for a device that joins by X1
    /// pairing: the state file and the Olm identity of the device are made
    /// when they are missing. The pairing needs the identity first, because
    /// the creator signs its key.
    pub fn open_for_pairing(
        server: &str,
        account: &str,
        network: &str,
    ) -> Result<Self, EngineError> {
        let part = storage_part(server, account, network).ok_or(EngineError::NotReady)?;
        let dir = data_dir().ok_or(EngineError::Store(E2eStoreError::NoDataDir))?;
        let mut state = E2eStateStore::open(
            dir.join(format!("e2e_state_{part}.bin")),
            &KeyringKeyProvider,
        )?;
        JoinerDevice::from_store(&mut state).map_err(|_| EngineError::NotReady)?;
        let history = E2eHistoryStore::open(
            dir.join(format!("e2e_history_{part}.bin")),
            &KeyringKeyProvider,
        )?;
        Self::new(network, state, history)
    }

    /// The sealed state of the device, for the pairing flow. The engine owns
    /// the one open handle on the file, so the flow writes through it.
    pub fn state_mut(&mut self) -> &mut E2eStateStore {
        &mut self.state
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

    /// Sets the casemapping of the network. Call it when the ISUPPORT
    /// snapshot changes. The pacers use the value on their next decision.
    pub fn set_casemapping(&mut self, casemapping: CaseMapping) {
        self.casemapping = casemapping;
    }

    /// The session ended: every open send and every queued text becomes a
    /// `session_ended` drop. The queue and the re-send memory are cleared.
    pub fn end_session(&mut self) -> Vec<SendDropped> {
        // A queued text is also a pending send of the book, so the book
        // gives one drop for it.
        self.queue.end_session();
        self.pending.clear();
        self.sent.clear();
        let ended = self.book.end_session();
        self.note_drops(&ended);
        ended
    }

    /// Applies an `e2e_send_dropped` event to the send book.
    pub fn apply_send_dropped(&mut self, payload: &Value) -> Option<SendDropped> {
        let dropped = self.book.apply_payload(payload)?;
        self.note_drops(std::slice::from_ref(&dropped));
        Some(dropped)
    }

    /// The reason a send was dropped, for the history row `row_id`. Only the
    /// locked query uses it: a plain row never has one.
    pub fn dropped_reason(&self, row_id: &str) -> Option<DropReason> {
        self.dropped_rows.get(row_id).copied()
    }

    /// Records the known E2E capability of a peer. The caller sets it from
    /// the signal that tells it. Proof of E2E (keys or a message that the
    /// engine read) sets it to true by itself.
    pub fn set_peer_capability(&mut self, nick: &str, capable: bool) {
        let cm = self.casemapping;
        let wanted = cm.fold(nick);
        match self
            .capability
            .iter_mut()
            .find(|(known, _)| cm.fold(known) == wanted)
        {
            Some(entry) => entry.1 = capable,
            None => self.capability.push((nick.to_string(), capable)),
        }
    }

    /// False only when the peer is known to have no E2E capability. A peer
    /// that is not known may be a first contact, so it can get a KEYREQ.
    fn peer_capable(&self, nick: &str) -> bool {
        let cm = self.casemapping;
        let wanted = cm.fold(nick);
        self.capability
            .iter()
            .find(|(known, _)| cm.fold(known) == wanted)
            .is_none_or(|(_, capable)| *capable)
    }

    /// Records the drops on the history rows of their sends and marks the
    /// conversations as changed.
    fn note_drops(&mut self, drops: &[SendDropped]) {
        for drop in drops {
            if let Some(row_id) = self.row_ids.get(&drop.key).cloned() {
                self.dropped_rows.entry(row_id).or_insert(drop.reason);
            }
            self.note_changed(&drop.key.target);
        }
    }

    /// A local failure of a send: `send_failed` for a pending or accepted
    /// send. A final send stays as it is.
    fn fail_send(&mut self, key: &SendKey, reason: DropReason) -> Option<SendDropped> {
        if !self.book.drop_local(key, reason) {
            return None;
        }
        let dropped = SendDropped {
            key: key.clone(),
            reason,
        };
        self.note_drops(std::slice::from_ref(&dropped));
        Some(dropped)
    }

    /// True when a text waits for keys or for a re-send.
    pub fn has_queued_text(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Removes the texts that waited too long for keys. Each is a `late` drop.
    pub fn expire_queue(&mut self) -> Vec<SendDropped> {
        let late = self.queue.expire(self.clock.now());
        self.settle_late(late)
    }

    fn settle_late(&mut self, late: Vec<SendDropped>) -> Vec<SendDropped> {
        for drop in &late {
            self.pending.remove(&drop.key);
            self.book.drop_local(&drop.key, drop.reason);
        }
        self.note_drops(&late);
        late
    }

    /// The nicks for which a KEYREQ is useful. The list is cleared.
    pub fn take_keys_wanted(&mut self) -> Vec<String> {
        std::mem::take(&mut self.keys_wanted)
    }

    /// Reads a KEYS text into the engine: a KEYS row or a claim answer. Each
    /// device of the answer must pass [`verify_peer_device`] and carry a good
    /// signature on its key. A device that is refused is skipped, the others
    /// stay. Returns the `did` of the devices that were accepted, or the first
    /// error when none was. The signed list is applied first, also when the
    /// answer has no device. The trust state is saved also when every device
    /// is refused, because a newer list stays.
    pub fn accept_keys(&mut self, nick: &str, keys: &str) -> Result<Vec<String>, EngineError> {
        let payload = KeysPayload::parse(keys)?;
        let master = &payload.master;
        let mut trust = self.state.trust();
        let mut accepted = Vec::new();
        let mut first_error = None;
        // The list revokes the devices that it drops, with or without a
        // device entry in the answer.
        if let Err(err) = apply_peer_list(
            &mut trust,
            &self.network,
            nick,
            &master.ed25519,
            master.list.ver,
            &master.list.devices,
            &master.sig,
        ) {
            first_error = Some(err);
        }
        let mut seen = HashSet::new();
        for entry in &payload.devices {
            // The first entry of a device key counts.
            if !seen.insert(entry.id.ed25519.as_str()) {
                continue;
            }
            let bundle = PeerBundle {
                master: &master.ed25519,
                list_version: master.list.ver,
                list_keys: &master.list.devices,
                list_signature: &master.sig,
                device_ed25519: &entry.id.ed25519,
                curve25519: &entry.id.curve25519,
                id_signature: &entry.id.sig,
            };
            let checked = verify_peer_device(&mut trust, &self.network, nick, None, &bundle)
                .and_then(|device| {
                    let text = bundle_key_signed_text(&entry.otk.key)?;
                    verify_signature(&entry.id.ed25519, &entry.otk.sig, &text)?;
                    Ok(device)
                });
            match checked {
                Ok(device) => accepted.push((device, entry.otk.key.clone())),
                Err(err) => {
                    first_error.get_or_insert(err);
                }
            }
        }
        self.state.set_trust(&trust)?;
        // A newer list stays even when a device is refused: drop every
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
        let mut dids = Vec::new();
        for (device, one_time_key) in accepted {
            let did = device.did().to_string();
            self.revoked_dids.remove(&did);
            self.peers.insert(
                did.clone(),
                PeerEntry {
                    nick: nick.to_string(),
                    device,
                    one_time_key: Some(one_time_key),
                },
            );
            dids.push(did);
        }
        match (dids.is_empty(), first_error) {
            (false, _) => {
                // Keys are proof of E2E capability.
                self.set_peer_capability(nick, true);
                Ok(dids)
            }
            (true, Some(err)) => Err(err.into()),
            (true, None) => Err(WireError::BadDeviceCount.into()),
        }
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
            InboxVerb::Nack => {
                self.on_nack(row);
                RowOutcome::Ignored
            }
            InboxVerb::PkMsg | InboxVerb::Msg => self.receive_message(row, now),
        };
        if outcome.acknowledge() {
            self.seen.insert(row.id);
        }
        outcome
    }

    /// Reads a copy of a message that a sibling device sent. The own signed
    /// list decides who is a sibling. The checks of a peer message do not
    /// apply: a copy is never a message from a person.
    fn receive_copy(&mut self, row: &InboxRow, now: i64) -> RowOutcome {
        let Some((list, _)) = self.own_list() else {
            return RowOutcome::Undecryptable;
        };
        let listed = self
            .sibling_dids()
            .iter()
            .any(|(did, _)| *did == row.from_did);
        let entry = self.peers.get(&row.from_did).cloned();
        let nick = entry
            .as_ref()
            .map_or(row.from.as_str(), |entry| entry.nick.as_str())
            .to_string();
        if !listed
            || self.revoked_dids.contains(&row.from_did)
            || self
                .state
                .trust()
                .is_did_revoked(&self.network, &nick, &row.from_did)
        {
            return RowOutcome::Undecryptable;
        }
        let Some(decrypted) = self.decrypt_row(row, entry.as_ref(), &nick) else {
            return RowOutcome::Undecryptable;
        };
        // The sender knows a newer list: this device is behind.
        if decrypted.inner.lv.is_some_and(|lv| lv > list.version) {
            let tries = self.stale_tries.entry(row.id).or_insert(0);
            *tries += 1;
            if *tries < md3_pacing::MAX_SENDS {
                return RowOutcome::StaleList;
            }
            return RowOutcome::Undecryptable;
        }
        match decrypted.inner.kind.clone() {
            InnerKind::Copy { peer, body } if valid_peer(&peer) => self.store_decrypted(
                &nick,
                row,
                &decrypted,
                peer,
                format!("{}:own:{}", self.network, row.id),
                OWN_DEVICE.to_string(),
                body,
                now,
            ),
            InnerKind::Other => match self.save_state(&nick, &row.from_did, &decrypted) {
                Ok(()) => RowOutcome::Ignored,
                Err(_) => RowOutcome::StoreFailed,
            },
            _ => RowOutcome::Undecryptable,
        }
    }

    fn receive_message(&mut self, row: &InboxRow, now: i64) -> RowOutcome {
        if row.own {
            return self.receive_copy(row, now);
        }
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
        let Some(decrypted) = self.decrypt_row(row, entry.as_ref(), &nick) else {
            if entry.is_none() && !self.keys_wanted.contains(&nick) {
                self.keys_wanted.push(nick);
            }
            return RowOutcome::Undecryptable;
        };
        // A message that the engine read is proof of E2E capability.
        self.set_peer_capability(&nick, true);
        // Text from a person goes to the conversation of the sender. A message
        // that does not fit is acknowledged and not stored. A kind that is no
        // text only moves the session on.
        match &decrypted.inner.kind {
            InnerKind::Text { body } => self.store_decrypted(
                &nick,
                row,
                &decrypted,
                nick.clone(),
                format!("{}:in:{}", self.network, row.id),
                row.from_did.clone(),
                body.clone(),
                now,
            ),
            InnerKind::Other => match self.save_state(&nick, &row.from_did, &decrypted) {
                Ok(()) => RowOutcome::Ignored,
                Err(_) => RowOutcome::StoreFailed,
            },
            InnerKind::Copy { .. } => RowOutcome::Undecryptable,
        }
    }

    /// Writes the text of a decrypted row to the conversation of `peer`, then
    /// saves the state. A row that is in the history already adds no second
    /// row. A failed history write leaves the old state, so the next drain
    /// decrypts the item again.
    #[allow(clippy::too_many_arguments)]
    fn store_decrypted(
        &mut self,
        nick: &str,
        row: &InboxRow,
        decrypted: &Decrypted,
        peer: String,
        row_id: String,
        sender_device: String,
        text: String,
        now: i64,
    ) -> RowOutcome {
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
        if self.save_state(nick, &row.from_did, decrypted).is_err() {
            return RowOutcome::StoreFailed;
        }
        self.note_changed(&peer);
        RowOutcome::Stored
    }

    /// Saves the trust state of a new device, then the session, the account
    /// and the replay state, and caches the device.
    fn save_state(
        &mut self,
        nick: &str,
        did: &str,
        decrypted: &Decrypted,
    ) -> Result<(), E2eStoreError> {
        if let Some((_, trust)) = &decrypted.learned {
            self.state.set_trust(trust)?;
        }
        self.state.set_inbound(
            &self.network,
            nick,
            did,
            &decrypted.session,
            decrypted.identity.as_ref(),
            decrypted.replay.as_ref(),
        )?;
        if let Some((entry, _)) = &decrypted.learned {
            self.revoked_dids.remove(entry.device.did());
            self.peers
                .insert(entry.device.did().to_string(), entry.clone());
        }
        Ok(())
    }

    /// Decrypts one `pkmsg` or `msg` row. It changes no stored state.
    fn decrypt_row(
        &self,
        row: &InboxRow,
        entry: Option<&PeerEntry>,
        nick: &str,
    ) -> Option<Decrypted> {
        let payload = MessagePayload::parse(row.verb, &row.payload).ok()?;
        // The body for this device. A message for other devices only is not
        // for this one.
        let body = payload.bodies().get(&self.own_did)?;
        match &payload {
            MessagePayload::PreKey(pre) => {
                if did_from_key_text(&pre.id.ed25519).ok()? != row.from_did {
                    return None;
                }
                // The message carries no list: the certificate of the master
                // and the id block say who the sender is.
                let mut trust = self.state.trust();
                let device = verify_certified_device(
                    &mut trust,
                    &self.network,
                    nick,
                    &CertifiedBundle {
                        master: &pre.master.ed25519,
                        certificate_version: pre.master.ver,
                        certificate_signature: &pre.master.cert,
                        device_ed25519: &pre.id.ed25519,
                        curve25519: &pre.id.curve25519,
                        id_signature: &pre.id.sig,
                    },
                )
                .ok()?;
                // A device keeps its curve key.
                if entry.is_some_and(|entry| entry.device.curve25519() != device.curve25519()) {
                    return None;
                }
                let expected_fb = recipient_binding(device.ed25519(), &self.own_ed25519);
                let mut replay = self.state.replay();
                replay
                    .accept_first_message(&self.network, nick, &row.from_did, &row.msgid)
                    .ok()?;
                let curve = Curve25519PublicKey::from_base64(device.curve25519()).ok()?;
                let message = PreKeyMessage::from_base64(body).ok()?;
                let learned = Some((
                    PeerEntry {
                        nick: nick.to_string(),
                        one_time_key: entry.and_then(|entry| entry.one_time_key.clone()),
                        device,
                    },
                    trust,
                ));
                // Olm keeps sending pre-key messages until the peer answers.
                // A message of the session that exists is opened with it.
                if let Some(mut session) = self
                    .state
                    .peer_session(&self.network, nick, &row.from_did)
                    .ok()?
                {
                    if session.session_id() == message.session_id() {
                        let plain = session.decrypt(&OlmMessage::PreKey(message)).ok()?;
                        return Some(Decrypted {
                            inner: bound_to(Inner::parse(&plain)?, &expected_fb)?,
                            identity: None,
                            session,
                            replay: Some(replay),
                            learned,
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
                // A message that is not bound to the key of the sender and to
                // this device is dropped with its new session.
                let inner = bound_to(Inner::parse(&created.plaintext)?, &expected_fb)?;
                Some(Decrypted {
                    inner,
                    identity: Some(identity),
                    session: created.session,
                    replay: Some(replay),
                    learned,
                })
            }
            MessagePayload::Normal(normal) => {
                if entry.is_some_and(|entry| entry.device.curve25519() != normal.ck) {
                    return None;
                }
                let mut session = self
                    .state
                    .peer_session(&self.network, nick, &row.from_did)
                    .ok()??;
                let message = Message::from_base64(body).ok()?;
                let plain = session.decrypt(&OlmMessage::Normal(message)).ok()?;
                // The message moved the session on, so the session is saved
                // also when the plaintext is not an inner message.
                let inner = Inner::parse(&plain).unwrap_or(Inner {
                    kind: InnerKind::Other,
                    lv: None,
                    fb: None,
                });
                Some(Decrypted {
                    inner,
                    identity: None,
                    session,
                    replay: None,
                    learned: None,
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
            let mut stale = false;
            for row in &page {
                let outcome = self.handle_row(row, now);
                if outcome.acknowledge() {
                    acks.push(row.id);
                }
                outcomes.push((row.id, outcome));
                if outcome == RowOutcome::StaleList {
                    // Stop before the copy: the caller syncs the own list and
                    // drains again.
                    stale = true;
                    break;
                }
            }
            self.ack(client, token, server_protocol, &acks).await?;
            if stale || page.len() < INBOX_PAGE_MAX || after == Some(last) {
                break;
            }
            after = Some(last);
        }
        Ok(outcomes)
    }

    /// Takes one key of the device `did` of `nick` and reads the KEYS answer.
    /// Returns the `did` of the devices that the answer gave.
    pub async fn claim_keys(
        &mut self,
        client: &GrappaClient,
        token: &str,
        server_protocol: Option<u32>,
        nick: &str,
        did: &str,
    ) -> Result<Vec<String>, EngineError> {
        let request = ClaimRequest::new(&self.own_did)?;
        let answer = client
            .claim_e2e_device_key(token, &self.network, did, server_protocol, &request)
            .await?;
        self.accept_keys(nick, answer.keys())
    }

    /// The own signed list with its master key, when the list is valid. It is
    /// the only authority for the sibling devices.
    fn own_list(&self) -> Option<(SignedList, String)> {
        let list = self.state.signed_list()?;
        let master = self.state.device_certificate()?.master_ed25519;
        verify_signed_list(list.version, &list.keys, &master, &list.signature).ok()?;
        Some((list, master))
    }

    /// The other devices of the own account, as `(did, ed25519)`: the keys of
    /// the own signed list except this device and the revoked ones.
    fn sibling_dids(&self) -> Vec<(String, String)> {
        let Some((list, _)) = self.own_list() else {
            return Vec::new();
        };
        let revoked = self.state.own_revoked();
        list.keys
            .iter()
            .filter(|key| **key != self.own_ed25519 && !revoked.contains(key))
            .filter_map(|key| Some((did_from_key_text(key).ok()?, key.clone())))
            .filter(|(did, _)| !self.revoked_dids.contains(did))
            .collect()
    }

    /// True when a text waits for its copies.
    pub fn has_pending_copies(&self) -> bool {
        !self.copy_jobs.is_empty()
    }

    fn queue_copies(&mut self, peer: &str, text: &str, id: &str, now: i64) {
        if self.sibling_dids().is_empty() {
            return;
        }
        while self.copy_jobs.len() >= md3_pacing::OUTGOING_QUEUE_MAX {
            self.copy_jobs.remove(0);
        }
        self.copy_jobs.push(CopyJob {
            id: id.to_string(),
            peer: peer.to_string(),
            text: text.to_string(),
            created_at: now,
            done: HashSet::new(),
            tries: HashMap::new(),
        });
    }

    /// Reads the own list on the server. A newer valid list of the same
    /// master that keeps this device replaces the stored one. Returns true
    /// when the list changed.
    pub async fn sync_own_list(
        &mut self,
        client: &GrappaClient,
        token: &str,
        server_protocol: Option<u32>,
    ) -> Result<bool, EngineError> {
        let (list, master) = self.own_list().ok_or(EngineError::NotReady)?;
        let held = client
            .fetch_e2e_list(token, &self.network, server_protocol)
            .await?;
        if held.master != master {
            return Err(EngineError::Wire(WireError::BadKey));
        }
        verify_signed_list(
            held.list.version,
            &held.list.keys,
            &master,
            &held.list.signature,
        )?;
        if held.list.version <= list.version || !held.list.keys.contains(&self.own_ed25519) {
            return Ok(false);
        }
        self.state.set_signed_list(&held.list)?;
        Ok(true)
    }

    /// Queues the waiting copies in the inbox of each sibling device. Each
    /// copy is an Olm message for one sibling, sent through the copies route
    /// and never over IRC. `own_nick` is the nick of the account.
    ///
    /// A sibling without a session gets one claimed key first. The own signed
    /// list names the siblings. A server list can remove a sibling and never
    /// adds one. When a list is behind, the call stops before that copy and
    /// sets [`CopyReport::needs_sync`]. A copy gets two tries, then it is
    /// dropped. A refusal of the relay is final, except `key_taken`, which
    /// asks for a new key once.
    pub async fn send_copies(
        &mut self,
        client: &GrappaClient,
        token: &str,
        server_protocol: Option<u32>,
        own_nick: &str,
        now: i64,
    ) -> CopyReport {
        let mut report = CopyReport::default();
        let mut jobs = std::mem::take(&mut self.copy_jobs).into_iter();
        let mut kept = Vec::new();
        while let Some(mut job) = jobs.next() {
            let expired = u64::try_from(job.created_at)
                .ok()
                .zip(u64::try_from(now).ok())
                .is_some_and(|(created, now)| is_expired(created, now));
            let mut open = false;
            for (did, ed25519) in self.sibling_dids() {
                if job.done.contains(&did) {
                    continue;
                }
                if report.needs_sync {
                    open = true;
                    continue;
                }
                let step = if expired {
                    Err(CopyStep::Drop(CopyFailure::Expired))
                } else {
                    self.copy_to(
                        client,
                        token,
                        server_protocol,
                        own_nick,
                        &job,
                        (did.as_str(), ed25519.as_str()),
                    )
                    .await
                };
                match step {
                    Ok(()) => {
                        job.done.insert(did.clone());
                        let created = u64::try_from(now).unwrap_or(0);
                        self.copy_tracker
                            .queued(&format!("{}.{did}", job.id), &did, created);
                        report.queued.push(did);
                    }
                    Err(CopyStep::Drop(failure)) => {
                        job.done.insert(did.clone());
                        report.failed.push((did, failure));
                    }
                    Err(step) => {
                        let tries = job.tries.entry(did.clone()).or_insert(0);
                        *tries += 1;
                        if *tries >= md3_pacing::MAX_SENDS {
                            job.done.insert(did.clone());
                            report.failed.push((did, CopyFailure::Failed));
                        } else {
                            open = true;
                        }
                        if matches!(step, CopyStep::Sync) {
                            report.needs_sync = true;
                        }
                    }
                }
            }
            if open {
                kept.push(job);
            }
        }
        kept.extend(jobs);
        self.copy_jobs = kept;
        report
    }

    /// Makes and queues the copy of `job` for one sibling.
    async fn copy_to(
        &mut self,
        client: &GrappaClient,
        token: &str,
        server_protocol: Option<u32>,
        own_nick: &str,
        job: &CopyJob,
        (did, sibling_ed25519): (&str, &str),
    ) -> Result<(), CopyStep> {
        let failed = || CopyStep::Drop(CopyFailure::Failed);
        let identity = self
            .state
            .olm_identity()
            .ok()
            .flatten()
            .ok_or_else(failed)?;
        let own = self.own_wire(&identity).map_err(|_| failed())?;
        let existing = self
            .state
            .peer_session(&self.network, own_nick, did)
            .map_err(|_| failed())?;
        let mut session = match existing {
            Some(session) => session,
            None => {
                let (curve, one_time) = self
                    .claim_sibling_key(client, token, server_protocol, did, sibling_ed25519)
                    .await?;
                let curve = Curve25519PublicKey::from_base64(&curve).map_err(|_| failed())?;
                let one_time = Curve25519PublicKey::from_base64(&one_time).map_err(|_| failed())?;
                identity
                    .create_outbound_session(SessionConfig::version_1(), curve, one_time)
                    .map_err(|_| failed())?
            }
        };
        let fb = (!session.has_received_message())
            .then(|| recipient_binding(&self.own_ed25519, sibling_ed25519));
        let inner = InnerOut {
            t: "copy",
            peer: Some(&job.peer),
            body: &job.text,
            lv: own.lv,
            fb: fb.as_deref(),
        }
        .to_json();
        let message = session.encrypt(inner.as_bytes()).map_err(|_| failed())?;
        let (verb, payload) = match message {
            OlmMessage::PreKey(message) => (
                CopyVerb::PkMsg,
                MessagePayload::PreKey(PreKeyPayload {
                    v: PAYLOAD_VERSION,
                    id: own.id,
                    master: own.master,
                    bodies: BTreeMap::from([(did.to_string(), message.to_base64())]),
                })
                .to_json(),
            ),
            OlmMessage::Normal(message) => (
                CopyVerb::Msg,
                MessagePayload::Normal(MsgPayload {
                    v: PAYLOAD_VERSION,
                    ck: own.id.curve25519,
                    bodies: BTreeMap::from([(did.to_string(), message.to_base64())]),
                })
                .to_json(),
            ),
        };
        let too_large = || CopyStep::Drop(CopyFailure::TooLarge);
        if !inbox_accepts(0, 0, payload.len()) {
            return Err(too_large());
        }
        let request = CopyRequest::new(&self.own_did, verb, &payload).map_err(|_| too_large())?;
        // Save the session before the send: a skipped Olm message is
        // harmless, a reused one is not.
        self.state
            .set_peer_session(&self.network, own_nick, did, &session)
            .map_err(|_| failed())?;
        client
            .send_e2e_copy(token, &self.network, did, server_protocol, &request)
            .await
            .map(|_| ())
            .map_err(copy_step)
    }

    /// Claims one key of the sibling `did` and checks the KEYS answer against
    /// the own signed list. Returns the curve key and the one-time key. A
    /// `key_taken` refusal asks again once.
    async fn claim_sibling_key(
        &self,
        client: &GrappaClient,
        token: &str,
        server_protocol: Option<u32>,
        did: &str,
        sibling_ed25519: &str,
    ) -> Result<(String, String), CopyStep> {
        let request =
            ClaimRequest::new(&self.own_did).map_err(|_| CopyStep::Drop(CopyFailure::Failed))?;
        let mut answer = None;
        for _ in 0..md3_pacing::MAX_SENDS {
            match client
                .claim_e2e_device_key(token, &self.network, did, server_protocol, &request)
                .await
            {
                Ok(keys) => {
                    answer = Some(keys);
                    break;
                }
                Err(E2eRouteError::Refused {
                    refusal: E2eRefusal::KeyTaken,
                    ..
                }) => continue,
                Err(error) => return Err(copy_step(error)),
            }
        }
        let answer = answer.ok_or(CopyStep::Drop(CopyFailure::KeyTaken))?;
        let no_key = || CopyStep::Drop(CopyFailure::NoKey);
        let (list, master) = self.own_list().ok_or_else(no_key)?;
        let payload = KeysPayload::parse(answer.keys()).map_err(|_| no_key())?;
        let block = &payload.master;
        verify_signed_list(
            block.list.ver,
            &block.list.devices,
            &block.ed25519,
            &block.sig,
        )
        .map_err(|_| no_key())?;
        if block.ed25519 != master {
            return Err(no_key());
        }
        // The server list can remove the sibling. It never adds one: only the
        // entry of the sibling in the own list is read.
        let listed = block.list.devices.iter().any(|key| key == sibling_ed25519);
        if block.list.ver >= list.version && !listed {
            return Err(CopyStep::Drop(CopyFailure::RemovedDevice));
        }
        if block.list.ver != list.version {
            return Err(CopyStep::Sync);
        }
        let entry = payload
            .devices
            .iter()
            .find(|entry| entry.id.ed25519 == sibling_ed25519)
            .ok_or_else(no_key)?;
        let id_text = device_id_signed_text(&entry.id.curve25519, &master);
        verify_signature(&entry.id.ed25519, &entry.id.sig, id_text.as_bytes())
            .map_err(|_| no_key())?;
        let otk_text = bundle_key_signed_text(&entry.otk.key).map_err(|_| no_key())?;
        verify_signature(&entry.id.ed25519, &entry.otk.sig, &otk_text).map_err(|_| no_key())?;
        Ok((entry.id.curve25519.clone(), entry.otk.key.clone()))
    }

    /// Sends a KEYREQ for `nick` through the send door. The pacer allows one
    /// request each 30 seconds for each nick.
    pub async fn request_keys(
        &mut self,
        client: &GrappaClient,
        token: &str,
        nick: &str,
    ) -> Result<(), EngineError> {
        if !self.peer_capable(nick) {
            return Err(EngineError::PeerNotCapable);
        }
        self.keyreq
            .try_send(nick, self.casemapping, self.clock.now())
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

    /// The id block, the master block and the list version that this device
    /// writes in its messages. They come from the provisioning: a device
    /// without a master key, a certificate or a signed list is not ready.
    fn own_wire(&self, identity: &Account) -> Result<OwnWire, EngineError> {
        let master = self.state.master_key()?.ok_or(EngineError::NotReady)?;
        let master_ed25519 = master.identity_keys().ed25519.to_base64();
        let certificate = self
            .state
            .device_certificate()
            .ok_or(EngineError::NotReady)?;
        let list = self.state.signed_list().ok_or(EngineError::NotReady)?;
        if certificate.device_ed25519 != self.own_ed25519
            || certificate.master_ed25519 != master_ed25519
        {
            return Err(EngineError::NotReady);
        }
        let curve25519 = identity.identity_keys().curve25519.to_base64();
        let text = device_id_signed_text(&curve25519, &master_ed25519);
        Ok(OwnWire {
            id: IdBlock {
                sig: identity.sign(text).to_base64(),
                curve25519,
                ed25519: self.own_ed25519.clone(),
            },
            master: MasterRef {
                ed25519: master_ed25519,
                ver: certificate.first_list_version,
                cert: certificate.signature,
            },
            lv: list.version,
        })
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

    /// The device `did` of `nick`, when it is not revoked and ready. No other
    /// device takes its place.
    fn pick_specific_device(&self, nick: &str, did: &str) -> Option<PeerEntry> {
        let trust = self.state.trust();
        self.peers
            .get(did)
            .filter(|entry| entry.nick == nick && self.entry_ready(entry, &trust))
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
        self.deliver(client, token, nick, text, entry, 1, None, now)
            .await
    }

    /// Like [`E2eEngine::send_text`], but a peer without keys is not an
    /// error: the text waits in the queue and the engine asks for the keys
    /// (see [`E2eEngine::take_keys_wanted`]). The row shows at once. A text
    /// that waits more than the queue lifetime is a `late` drop. Nothing goes
    /// in clear text. A peer known to have no E2E capability is refused.
    pub async fn send_or_queue(
        &mut self,
        client: &GrappaClient,
        token: &str,
        nick: &str,
        text: &str,
        now: i64,
    ) -> Result<SentText, EngineError> {
        match self.send_text(client, token, nick, text, now).await {
            Err(EngineError::NotReady) => self.queue_text(nick, text, now),
            other => other,
        }
    }

    /// Puts a text in the queue and writes its row in the history.
    fn queue_text(&mut self, nick: &str, text: &str, now: i64) -> Result<SentText, EngineError> {
        if !self.peer_capable(nick) {
            return Err(EngineError::PeerNotCapable);
        }
        // A device that cannot write messages makes the wait useless.
        let identity = self.state.olm_identity()?.ok_or(EngineError::NotReady)?;
        self.own_wire(&identity)?;
        self.local_sends += 1;
        // The time makes the row id unique across runs of the program.
        let key = SendKey::new(&self.network, nick, &format!("q{now}-{}", self.local_sends));
        if !self
            .queue
            .push(key.clone(), self.casemapping, self.clock.now())
        {
            return Err(EngineError::QueueFull);
        }
        let row_id = format!("{}:out:{}", self.network, key.msgid);
        let message = E2eMessage {
            id: row_id.clone(),
            conversation_id: conversation_id(&self.network, nick),
            sender_device: OWN_DEVICE.to_string(),
            sent_at: now,
            text: text.to_string(),
            encrypted: true,
        };
        if let Err(error) = self.history.append(message) {
            self.queue.remove(&key);
            return Err(error.into());
        }
        self.book.start(key.clone());
        self.row_ids.insert(key.clone(), row_id.clone());
        self.pending.insert(
            key.clone(),
            PendingText {
                text: text.to_string(),
                sends: 1,
                row_id,
                did: None,
            },
        );
        self.want_keys(nick);
        self.note_changed(nick);
        Ok(SentText {
            msgid: None,
            key: Some(key),
        })
    }

    fn want_keys(&mut self, nick: &str) {
        if !self.keys_wanted.iter().any(|known| known == nick) {
            self.keys_wanted.push(nick.to_string());
        }
    }

    /// Sends the queued texts whose peer has keys now, oldest first, and asks
    /// again for the keys of the others. A text past its lifetime is a `late`
    /// drop. A text that the send door refuses is a `send_failed` drop; a
    /// busy relay (429) keeps it in the queue until its lifetime ends. Return
    /// the drops.
    pub async fn flush_queue(
        &mut self,
        client: &GrappaClient,
        token: &str,
        now: i64,
    ) -> Vec<SendDropped> {
        if self.queue.is_empty() {
            return Vec::new();
        }
        let cm = self.casemapping;
        let ready: HashSet<String> = self
            .ready_peers()
            .iter()
            .map(|nick| cm.fold(nick))
            .collect();
        let (taken, late) = self
            .queue
            .take_matching(self.clock.now(), |item: &QueuedSend| {
                ready.contains(&cm.fold(&item.key.target))
            });
        let mut drops = self.settle_late(late);
        let mut retry = Vec::new();
        for item in taken {
            let Some(pending) = self.pending.remove(&item.key) else {
                continue;
            };
            let nick = item.key.target.clone();
            // The sends before this one took time: check the deadline again.
            if check_send_deadline(self.clock.now(), item.deadline) == SendDecision::TooLate {
                drops.extend(self.fail_send(&item.key, DropReason::Late));
                continue;
            }
            let entry = match &pending.did {
                Some(did) => self.pick_specific_device(&nick, did),
                None => self.pick_device(&nick),
            };
            let Some(entry) = entry else {
                self.pending.insert(item.key.clone(), pending);
                retry.push(item);
                continue;
            };
            let result = self
                .deliver(
                    client,
                    token,
                    &nick,
                    &pending.text,
                    entry,
                    pending.sends,
                    Some(pending.row_id.clone()),
                    now,
                )
                .await;
            match result {
                Ok(_) => {
                    self.book.remove(&item.key);
                }
                Err(EngineError::Rejected(SendResponse::Unexpected(429))) => {
                    self.pending.insert(item.key.clone(), pending);
                    retry.push(item);
                }
                Err(EngineError::Rejected(SendResponse::Failed(SendFailure::TooLate))) => {
                    drops.extend(self.fail_send(&item.key, DropReason::Late));
                }
                Err(_) => {
                    drops.extend(self.fail_send(&item.key, DropReason::SendFailed));
                }
            }
        }
        for item in retry.into_iter().rev() {
            self.queue.restore(item);
        }
        for nick in self.queue.targets() {
            self.want_keys(&nick);
        }
        drops
    }

    /// Sends `text` to `entry`, a device of `nick`. `row_id` is the history
    /// row of a text that waited in the queue or that goes out again after a
    /// NACK; without it the call writes the row. `sends` counts the sends of
    /// the text.
    #[allow(clippy::too_many_arguments)]
    async fn deliver(
        &mut self,
        client: &GrappaClient,
        token: &str,
        nick: &str,
        text: &str,
        entry: PeerEntry,
        sends: u8,
        row_id: Option<String>,
        now: i64,
    ) -> Result<SentText, EngineError> {
        let did = entry.device.did().to_string();
        let identity = self.state.olm_identity()?.ok_or(EngineError::NotReady)?;
        let own = self.own_wire(&identity)?;
        let mut session = match self.state.peer_session(&self.network, nick, &did)? {
            Some(session) => session,
            None => {
                let one_time = entry.one_time_key.as_deref().ok_or(EngineError::NotReady)?;
                let curve = Curve25519PublicKey::from_base64(entry.device.curve25519())
                    .map_err(|_| EngineError::EncryptionFailed)?;
                let one_time = Curve25519PublicKey::from_base64(one_time)
                    .map_err(|_| EngineError::EncryptionFailed)?;
                identity
                    .create_outbound_session(SessionConfig::version_1(), curve, one_time)
                    .map_err(|_| EngineError::EncryptionFailed)?
            }
        };
        // A session that has not received a message writes pre-key messages.
        // The inner message of a pre-key message holds `fb`, the binding of
        // the two device keys.
        let fb = (!session.has_received_message())
            .then(|| recipient_binding(&self.own_ed25519, entry.device.ed25519()));
        let inner = InnerOut {
            t: "text",
            peer: None,
            body: text,
            lv: own.lv,
            fb: fb.as_deref(),
        }
        .to_json();
        let message = session
            .encrypt(inner.as_bytes())
            .map_err(|_| EngineError::EncryptionFailed)?;
        let (verb, payload) = match message {
            OlmMessage::PreKey(message) => (
                E2eSendVerb::PkMsg,
                MessagePayload::PreKey(PreKeyPayload {
                    v: PAYLOAD_VERSION,
                    id: own.id,
                    master: own.master,
                    bodies: BTreeMap::from([(did.clone(), message.to_base64())]),
                })
                .to_json(),
            ),
            OlmMessage::Normal(message) => (
                E2eSendVerb::Msg,
                MessagePayload::Normal(MsgPayload {
                    v: PAYLOAD_VERSION,
                    ck: own.id.curve25519,
                    bodies: BTreeMap::from([(did.clone(), message.to_base64())]),
                })
                .to_json(),
            ),
        };
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
        let row_id = match row_id {
            Some(row_id) => row_id,
            None => {
                let row_id = format!("{}:out:{suffix}", self.network);
                let message = E2eMessage {
                    id: row_id.clone(),
                    conversation_id: conversation_id(&self.network, nick),
                    sender_device: OWN_DEVICE.to_string(),
                    sent_at: now,
                    text: text.to_string(),
                    encrypted: true,
                };
                self.history.append(message)?;
                row_id
            }
        };
        if let (Some(key), Some(msgid)) = (&key, &answer.msgid) {
            self.row_ids.insert(key.clone(), row_id.clone());
            self.remember_sent(msgid, nick, &did, text, sends, &row_id);
        }
        // The copies for the other devices of the account follow the 202
        // answer. A re-send after a NACK makes no second copy.
        if sends == 1 {
            self.queue_copies(nick, text, &suffix, now);
        }
        self.note_changed(nick);
        Ok(SentText {
            msgid: answer.msgid,
            key,
        })
    }

    /// Keeps the text of a send for a re-send after a NACK. The memory is
    /// bounded in time and in count.
    fn remember_sent(
        &mut self,
        msgid: &str,
        nick: &str,
        did: &str,
        text: &str,
        sends: u8,
        row_id: &str,
    ) {
        let record = SentRecord {
            nick: nick.to_string(),
            did: did.to_string(),
            text: text.to_string(),
            sends,
            row_id: row_id.to_string(),
            at: self.clock.now(),
        };
        self.sent.insert(msgid.to_string(), record);
        self.trim_sent();
    }

    fn trim_sent(&mut self) {
        let now = self.clock.now();
        self.sent
            .retain(|_, record| now.saturating_sub(record.at) < md3_pacing::SENT_MEMORY);
        while self.sent.len() > md3_pacing::SENT_MAX {
            let oldest = self
                .sent
                .iter()
                .min_by_key(|(_, record)| record.at)
                .map(|(msgid, _)| msgid.clone());
            match oldest {
                Some(msgid) => self.sent.remove(&msgid),
                None => break,
            };
        }
    }

    /// Reads a NACK: the device that got a message could not read it. The
    /// text goes out again once, on a new session. The engine drops the
    /// failed session, asks for fresh keys and queues the text.
    ///
    /// Rules of irc-olm (`_on_nack`): only the device that got the message
    /// may NACK it. The nick must be the one the text went to. A message goes
    /// out at most twice. A nick gets at most one re-key each minute. When a
    /// rule stops the re-send, the send is a `send_failed` drop.
    fn on_nack(&mut self, row: &InboxRow) {
        self.trim_sent();
        let Some(reference) = nack_reference(&row.payload) else {
            return;
        };
        if self
            .sent
            .get(&reference)
            .is_none_or(|record| record.did != row.from_did)
        {
            return;
        }
        let Some(record) = self.sent.remove(&reference) else {
            return;
        };
        let cm = self.casemapping;
        let key = SendKey::new(&self.network, &record.nick, &reference);
        if cm.fold(&record.nick) != cm.fold(&row.from)
            || record.sends >= md3_pacing::MAX_SENDS
            || !self.rekey.try_acquire(&record.nick, cm, self.clock.now())
        {
            self.fail_send(&key, DropReason::SendFailed);
            return;
        }
        if self
            .state
            .remove_peer_session(&self.network, &record.nick, &record.did)
            .is_err()
        {
            self.fail_send(&key, DropReason::SendFailed);
            return;
        }
        self.local_sends += 1;
        let queue_key = SendKey::new(
            &self.network,
            &record.nick,
            &format!("q{}", self.local_sends),
        );
        if !self.queue.push(queue_key.clone(), cm, self.clock.now()) {
            self.fail_send(&key, DropReason::SendFailed);
            return;
        }
        // The old send stays accepted. The row of both sends is the same, and
        // the queue key carries the drop of the re-send.
        self.book.start(queue_key.clone());
        self.row_ids
            .insert(queue_key.clone(), record.row_id.clone());
        self.pending.insert(
            queue_key,
            PendingText {
                text: record.text,
                sends: record.sends + 1,
                row_id: record.row_id,
                did: Some(record.did),
            },
        );
        self.want_keys(&record.nick);
    }
}

/// Maps a failed call of a copy route to the next step. The tokens of the
/// relay are final. A busy relay or a broken connection gets a new try.
fn copy_step(error: E2eRouteError) -> CopyStep {
    match error {
        E2eRouteError::Refused { refusal, .. } => match refusal {
            E2eRefusal::SameDevice => CopyStep::Drop(CopyFailure::SameDevice),
            E2eRefusal::KeylessDevice => CopyStep::Drop(CopyFailure::KeylessDevice),
            E2eRefusal::KeyTaken => CopyStep::Drop(CopyFailure::KeyTaken),
            E2eRefusal::RemovedDevice => CopyStep::Drop(CopyFailure::RemovedDevice),
            E2eRefusal::InboxFull => CopyStep::Drop(CopyFailure::InboxFull),
            _ => CopyStep::Retry,
        },
        E2eRouteError::Client(_) | E2eRouteError::Wire(_) => CopyStep::Retry,
        E2eRouteError::Unavailable => CopyStep::Drop(CopyFailure::Failed),
    }
}

/// The `ref` of a NACK payload: the `msgid` of the message that failed.
fn nack_reference(payload: &str) -> Option<String> {
    let value: Value = serde_json::from_str(payload).ok()?;
    let reference = value.get("ref")?.as_str()?;
    (!reference.is_empty()).then(|| reference.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_device::{build_device_certificate, build_signed_list_signature};
    use crate::e2e_manage::SignedList;
    use crate::e2e_store::E2eKeyProvider;
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

    /// A device with one one-time key.
    fn fresh_device() -> Account {
        let mut device = Account::new();
        device.generate_one_time_keys(1);
        device
    }

    /// The id block of `device`, signed for `master`.
    fn id_block(device: &Account, master: &Account) -> IdBlock {
        let text = device_id_signed_text(&curve(device), &ed(master));
        IdBlock {
            curve25519: curve(device),
            ed25519: ed(device),
            sig: device.sign(text).to_base64(),
        }
    }

    /// The KEYS payload with the entry of `device`, listed by `master` in a
    /// list of `listed` at `version`.
    fn keys_struct(
        master: &Account,
        device: &Account,
        listed: &[String],
        version: u32,
    ) -> KeysPayload {
        let list_signature =
            build_signed_list_signature(version, listed, |text| master.sign(text).to_base64())
                .expect("list");
        let one_time_key = device
            .one_time_keys()
            .values()
            .next()
            .expect("one-time key")
            .to_base64();
        let otk_text = bundle_key_signed_text(&one_time_key).expect("text");
        let mut devices = listed.to_vec();
        devices.sort();
        KeysPayload {
            v: 2,
            master: MasterBlock {
                ed25519: ed(master),
                list: MasterList {
                    ver: version,
                    devices,
                },
                sig: list_signature,
            },
            devices: vec![KeysEntry {
                id: id_block(device, master),
                otk: OneTimeKey {
                    key: one_time_key,
                    fallback: false,
                    sig: device.sign(&otk_text).to_base64(),
                },
            }],
        }
    }

    fn keys_payload(master: &Account, device: &Account, listed: &[String], version: u32) -> String {
        serde_json::to_string(&keys_struct(master, device, listed, version)).expect("json")
    }

    /// The `pkmsg` payload that `sender`, a device of `master`, sends to the
    /// device `to_did`. `cert_version` is the N of its certificate.
    fn pre_key_json(
        master: &Account,
        sender: &Account,
        cert_version: u32,
        to_did: &str,
        message: &PreKeyMessage,
    ) -> String {
        let certificate =
            build_device_certificate(cert_version, &ed(sender), &ed(master), |text| {
                master.sign(text).to_base64()
            })
            .expect("certificate");
        MessagePayload::PreKey(PreKeyPayload {
            v: PAYLOAD_VERSION,
            id: id_block(sender, master),
            master: MasterRef {
                ed25519: ed(master),
                ver: cert_version,
                cert: certificate.signature,
            },
            bodies: BTreeMap::from([(to_did.to_string(), message.to_base64())]),
        })
        .to_json()
    }

    /// One user with a master key and one device, as a test double.
    struct Ident {
        master: Account,
        device: Account,
        dir: PathBuf,
    }

    impl Ident {
        fn new(name: &str) -> Self {
            Self {
                master: Account::new(),
                device: fresh_device(),
                dir: scratch_dir(name),
            }
        }

        /// The engine of this user, as the provisioning leaves it: the Olm
        /// account, the master key, the list 1 and the certificate N = 1.
        fn engine(&self) -> E2eEngine {
            let mut state =
                E2eStateStore::open(self.dir.join("state.bin"), &FixedKey([7; 32])).expect("state");
            state.set_account(&self.device).expect("account");
            state.set_master_key(&self.master).expect("master");
            let keys = vec![ed(&self.device)];
            let signature =
                build_signed_list_signature(1, &keys, |text| self.master.sign(text).to_base64())
                    .expect("list");
            state
                .set_signed_list(&SignedList {
                    version: 1,
                    keys,
                    signature,
                })
                .expect("signed list");
            let certificate =
                build_device_certificate(1, &ed(&self.device), &ed(&self.master), |text| {
                    self.master.sign(text).to_base64()
                })
                .expect("certificate");
            state
                .set_device_certificate(&certificate)
                .expect("certificate");
            let history = E2eHistoryStore::open(self.dir.join("history.bin"), &FixedKey([9; 32]))
                .expect("history");
            E2eEngine::new(NET, state, history).expect("engine")
        }

        /// The KEYS payload of this user.
        fn keys_struct(&self) -> KeysPayload {
            keys_struct(&self.master, &self.device, &[ed(&self.device)], 1)
        }

        /// The KEYS text of this user.
        fn keys(&self) -> String {
            serde_json::to_string(&self.keys_struct()).expect("json")
        }

        /// The KEYS payload of a list 2 that holds `new_device` only. The
        /// device of this user is revoked.
        fn newer_keys_struct(&self, new_device: &Account) -> KeysPayload {
            keys_struct(&self.master, new_device, &[ed(new_device)], 2)
        }

        fn newer_keys(&self, new_device: &Account) -> String {
            serde_json::to_string(&self.newer_keys_struct(new_device)).expect("json")
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
        let bob = bob_id.engine();
        // Only Alice reads the KEYS of Bob. Bob learns the device of Alice
        // from the certificate in her first message.
        alice
            .accept_keys("bob", &bob_id.keys())
            .expect("alice reads bob");
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
    async fn the_pkmsg_and_msg_payloads_follow_the_wire_v2_shape() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, first) = alice_sends(&mut p.alice, &server, "hello bob").await;
        let payload: Value =
            serde_json::from_str(first["payload"].as_str().expect("payload")).expect("json");
        let object = payload.as_object().expect("object");
        let mut names: Vec<&str> = object.keys().map(String::as_str).collect();
        names.sort();
        assert_eq!(names, ["bodies", "id", "master", "v"]);
        assert_eq!(payload["v"], 2);
        let id = payload["id"].as_object().expect("id block");
        assert_eq!(id.len(), 3);
        assert_eq!(payload["id"]["ed25519"], p.alice.own_ed25519.as_str());
        assert_eq!(payload["master"]["ver"], 1);
        assert!(payload["master"]["cert"].is_string());
        let bodies = payload["bodies"].as_object().expect("bodies");
        assert_eq!(bodies.len(), 1);
        assert!(bodies.contains_key(&p.bob_did));
        assert!(bodies[&p.bob_did].is_string());
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
    async fn a_list_that_revokes_a_cached_device_moves_the_send_to_the_new_one() {
        let alice_id = Ident::new("alice-revoke");
        let bob_id = Ident::new("bob-revoke");
        let mut alice = alice_id.engine();
        alice
            .accept_keys("bob", &bob_id.keys())
            .expect("alice reads bob");
        assert!(alice.is_ready("bob"));
        // Bob signs list 2 with a new device only. The old device is revoked.
        let new_device = fresh_device();
        alice
            .accept_keys("bob", &bob_id.newer_keys(&new_device))
            .expect("newer list");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let old_did = did_from_key_text(&ed(&bob_id.device)).expect("did");
        let new_did = did_from_key_text(&ed(&new_device)).expect("did");
        assert!(!alice.peers.contains_key(&old_did));
        let (_, body) = alice_sends(&mut alice, &server, "late").await;
        assert_eq!(body["to"], new_did.as_str());
    }

    #[tokio::test]
    async fn a_refused_newer_list_still_drops_the_revoked_device() {
        let alice_id = Ident::new("alice-refused");
        let bob_id = Ident::new("bob-refused");
        let mut alice = alice_id.engine();
        alice
            .accept_keys("bob", &bob_id.keys())
            .expect("alice reads bob");
        assert!(alice.is_ready("bob"));
        // List 2 revokes the old device, but its new device has a wrong id
        // signature: the device is refused, the list stays.
        let new_device = fresh_device();
        let mut wrong = bob_id.newer_keys_struct(&new_device);
        wrong.devices[0].id.sig = bob_id.master.sign("other text").to_base64();
        let refused = alice.accept_keys("bob", &serde_json::to_string(&wrong).expect("json"));
        assert!(matches!(
            refused,
            Err(EngineError::Device(E2eError::BadSignature))
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
    async fn a_newer_list_without_devices_still_drops_the_revoked_device() {
        let alice_id = Ident::new("alice-no-devices");
        let bob_id = Ident::new("bob-no-devices");
        let mut alice = alice_id.engine();
        alice
            .accept_keys("bob", &bob_id.keys())
            .expect("alice reads bob");
        assert!(alice.is_ready("bob"));
        // List 2 drops the device of Bob. The answer has no device entry.
        let mut empty = bob_id.newer_keys_struct(&fresh_device());
        empty.devices.clear();
        let empty = serde_json::to_string(&empty).expect("json");
        let refused = alice.accept_keys("bob", &empty);
        assert!(matches!(
            refused,
            Err(EngineError::Wire(WireError::BadDeviceCount))
        ));
        assert!(alice.peers.is_empty());
        assert!(!alice.is_ready("bob"));
        // The revocation is in the saved trust state.
        let bob_ed = ed(&bob_id.device);
        assert!(alice.state.trust().is_revoked(NET, "bob", &bob_ed, None));
        // As a KEYS row, the answer is acknowledged and gives no device.
        let alice_did = alice.own_did().to_string();
        let value = row(4, "bob", WILDCARD, &alice_did, "keys", "k2", &empty);
        let keys_row = InboxRow::from_value(&value, PROTOCOL).expect("row");
        let outcome = alice.handle_row(&keys_row, 1);
        assert_eq!(outcome, RowOutcome::Undecryptable);
        assert!(outcome.acknowledge());
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
            .accept_keys("bob", &bob_id.keys())
            .expect("alice reads bob");
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
        // A `msg` holds the curve key of the sender and a body for each
        // device, and nothing else.
        let msg: Value =
            serde_json::from_str(second["payload"].as_str().expect("payload")).expect("json");
        let mut names: Vec<&str> = msg
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        names.sort();
        assert_eq!(names, ["bodies", "ck", "v"]);
        assert_eq!(msg["ck"], curve(&alice_id.device).as_str());
        assert!(msg["bodies"][&bob_did].is_string());

        // Bob learns a list that revokes the device of Alice, then restarts.
        // The certificate of the first message put the device in his trust
        // state, so the list revokes it though he never read a KEYS of Alice.
        let new_device = fresh_device();
        bob.accept_keys("alice", &alice_id.newer_keys(&new_device))
            .expect("newer list");
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
    async fn a_send_goes_to_a_ready_device_of_a_peer_with_two_devices() {
        let alice_id = Ident::new("alice-two");
        let bob_id = Ident::new("bob-two");
        let other = fresh_device();
        let broken = fresh_device();
        let listed = vec![ed(&bob_id.device), ed(&other), ed(&broken)];
        let mut alice = alice_id.engine();
        for device in [&other, &bob_id.device] {
            alice
                .accept_keys("bob", &keys_payload(&bob_id.master, device, &listed, 1))
                .expect("device with a key");
        }
        // The key of the third device has a wrong signature: the answer is
        // refused and the device is not used.
        let mut bad = keys_struct(&bob_id.master, &broken, &listed, 1);
        bad.devices[0].otk.sig = broken.sign("other text").to_base64();
        let refused = alice.accept_keys("bob", &serde_json::to_string(&bad).expect("json"));
        assert!(matches!(
            refused,
            Err(EngineError::Device(E2eError::BadSignature))
        ));
        assert_eq!(alice.peers.len(), 2);
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, body) = alice_sends(&mut alice, &server, "hello").await;
        // Neither device has a session: the lowest `did` wins.
        let lowest = [&other, &bob_id.device]
            .iter()
            .map(|device| did_from_key_text(&ed(device)).expect("did"))
            .min()
            .expect("two devices");
        assert_eq!(body["to"], lowest.as_str());
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
        let value = row(3, "bob", WILDCARD, &alice_did, "keys", "k1", &bob_id.keys());
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

    /// True when the request has the lock label in its URL or in its body.
    fn carries_the_label(request: &wiremock::Request) -> bool {
        request.url.as_str().contains(QUERY_LOCK_LABEL)
            || request.url.as_str().contains("%F0%9F%94%92")
            || String::from_utf8_lossy(&request.body).contains(QUERY_LOCK_LABEL)
    }

    async fn mount_plain_send(server: &MockServer, peer: &str) {
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/channels/{peer}/messages")))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 9})))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_202_answer_sets_the_accepted_state_only() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (sent, _) = alice_sends(&mut p.alice, &server, "hello").await;
        let key = sent.key.expect("send key");
        assert_eq!(p.alice.send_status(&key), Some(SendStatus::Accepted));
        // Nothing but an event of the server moves the state on: a second
        // send does not change the first one.
        let (second, _) = alice_sends(&mut p.alice, &server, "again").await;
        assert_eq!(p.alice.send_status(&key), Some(SendStatus::Accepted));
        assert_eq!(
            p.alice.send_status(&second.key.expect("send key")),
            Some(SendStatus::Accepted)
        );
    }

    #[tokio::test]
    async fn plain_and_locked_sends_stay_in_their_own_entries() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        mount_plain_send(&server, "bob").await;
        let client = GrappaClient::new(server.uri());

        // Both entries of Bob are open. The selected name picks the route.
        let plain_route = route_for_window("bob");
        let locked_route = route_for_window(&locked_label("bob"));
        assert!(matches!(plain_route, SendRoute::Plain { .. }));
        assert!(matches!(locked_route, SendRoute::Encrypted { .. }));
        assert_eq!(plain_route.nick(), "bob");
        assert_eq!(locked_route.nick(), "bob");

        client
            .send_message(
                TOKEN,
                NET,
                plain_route.nick(),
                &crate::rest::SendMessageRequest::plain("clear words"),
            )
            .await
            .expect("plain send");
        p.alice
            .send_text(&client, TOKEN, locked_route.nick(), "sealed words", 100)
            .await
            .expect("locked send");

        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 2);
        let plain_body = String::from_utf8_lossy(&requests[0].body).to_string();
        let locked_body = String::from_utf8_lossy(&requests[1].body).to_string();
        assert_eq!(
            requests[0].url.path(),
            format!("/networks/{NET}/channels/bob/messages")
        );
        assert!(plain_body.contains("clear words"));
        assert_eq!(
            requests[1].url.path(),
            format!("/networks/{NET}/e2e/messages")
        );
        assert!(!locked_body.contains("sealed words"));
        assert!(!locked_body.contains("clear words"));
        // The label is in no URL and in no body.
        assert!(requests.iter().all(|request| !carries_the_label(request)));

        // Only the locked text is in the sealed history, with the mark.
        let rows = p.alice.history().messages(&conversation_id(NET, "bob"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "sealed words");
        assert!(rows[0].encrypted);
        assert!(p
            .alice
            .history()
            .messages(&conversation_id(NET, &locked_label("bob")))
            .is_empty());
    }

    #[tokio::test]
    async fn the_lock_label_is_in_no_request_of_the_e2e_paths() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/networks/{NET}/e2e/devices/{}/inbox",
                p.alice_did
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"messages": []})))
            .mount(&server)
            .await;
        let client = GrappaClient::new(server.uri());
        p.alice
            .request_keys(&client, TOKEN, "bob")
            .await
            .expect("keyreq");
        p.alice
            .send_text(&client, TOKEN, "bob", "hello", 100)
            .await
            .expect("send");
        p.alice
            .drain(&client, TOKEN, PROTOCOL, 101)
            .await
            .expect("drain");
        // A name with the label is refused before any request.
        let label = locked_label("bob");
        assert!(p.alice.request_keys(&client, TOKEN, &label).await.is_err());
        assert!(p
            .alice
            .send_text(&client, TOKEN, &label, "hello", 102)
            .await
            .is_err());
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|request| !carries_the_label(request)));
    }

    #[tokio::test]
    async fn a_peer_without_a_verified_device_keeps_the_plain_query() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        mount_plain_send(&server, "carol").await;
        let client = GrappaClient::new(server.uri());

        // Carol has no verified device: she has no locked entry to offer.
        assert!(!p.alice.is_ready("carol"));
        assert!(!p.alice.ready_peers().contains(&"carol".to_string()));
        // The plain query of Carol sends as before.
        client
            .send_message(
                TOKEN,
                NET,
                route_for_window("carol").nick(),
                &crate::rest::SendMessageRequest::plain("clear words"),
            )
            .await
            .expect("plain send");
        // The locked path refuses, and the text does not move to the plain
        // path or to the E2E door.
        let locked = p
            .alice
            .send_text(&client, TOKEN, "carol", "clear words", 100)
            .await;
        assert!(matches!(locked, Err(EngineError::NotReady)));
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url.path(),
            format!("/networks/{NET}/channels/carol/messages")
        );
        assert!(p
            .alice
            .history()
            .messages(&conversation_id(NET, "carol"))
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

    #[tokio::test]
    async fn keyreq_pacing_follows_the_current_casemapping() {
        let mut p = pair();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/e2e/messages")))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"msgid": "k1"})))
            .expect(2)
            .mount(&server)
            .await;
        let client = GrappaClient::new(server.uri());
        p.alice.set_casemapping(CaseMapping::Ascii);
        p.alice
            .request_keys(&client, TOKEN, "[bob]")
            .await
            .expect("first");
        // Under ASCII, "{bob}" is another nick: no interval applies.
        p.alice
            .request_keys(&client, TOKEN, "{bob}")
            .await
            .expect("second");
    }

    #[test]
    fn end_session_leaves_no_open_send() {
        let mut p = pair();
        assert!(p.alice.end_session().is_empty());
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
    fn the_engine_files_are_apart_for_each_server_and_account() {
        let base = storage_part("https://a.example", "anna", NET).expect("part");
        assert_eq!(base.len(), 32);
        assert!(base.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(
            storage_part("https://a.example", "anna", NET).as_deref(),
            Some(base.as_str())
        );
        assert_ne!(
            storage_part("https://b.example", "anna", NET).as_deref(),
            Some(base.as_str())
        );
        assert_ne!(
            storage_part("https://a.example", "bruno", NET).as_deref(),
            Some(base.as_str())
        );
        assert_ne!(
            storage_part("https://a.example", "anna", "other").as_deref(),
            Some(base.as_str())
        );
        // A guest and an unknown account have no engine files.
        assert_eq!(storage_part("https://a.example", "visitor:7", NET), None);
        assert_eq!(storage_part("https://a.example", "", NET), None);
        assert_eq!(storage_part("", "anna", NET), None);
    }

    #[test]
    fn versions_are_integral_numbers_in_range() {
        for good in [json!(1), json!(1.0), json!(2147483647)] {
            assert!(version_from_value(&good).is_some(), "{good}");
        }
        let bad = [
            json!(0),
            json!(-1),
            json!(1.5),
            json!(2147483648u64),
            json!(true),
            json!("1"),
            json!(null),
        ];
        for value in bad {
            assert_eq!(version_from_value(&value), None, "{value}");
        }
    }

    #[test]
    fn a_keys_payload_is_read_by_the_wire_v2_rules() {
        let bob = Ident::new("keys-shape");
        let good: Value = serde_json::from_str(&bob.keys()).expect("json");
        // A version that is a whole number in float form counts.
        let mut value = good.clone();
        value["master"]["list"]["ver"] = json!(1.0);
        let payload = KeysPayload::parse(&value.to_string()).expect("keys");
        assert_eq!(payload.master.list.ver, 1);
        assert_eq!(payload.devices.len(), 1);
        assert_eq!(payload.devices[0].id.ed25519, ed(&bob.device));
        // Fields that a later version adds are ignored.
        let mut value = good.clone();
        value["extra"] = json!(true);
        value["devices"][0]["otk"]["extra"] = json!(1);
        assert!(KeysPayload::parse(&value.to_string()).is_ok());
        // The fallback flag is optional.
        let mut value = good.clone();
        value["devices"][0]["otk"]
            .as_object_mut()
            .expect("otk")
            .remove("fallback");
        assert!(KeysPayload::parse(&value.to_string()).is_ok());
        // Another wire version, a missing key block and a bad `ver` are
        // refused.
        let mut value = good.clone();
        value["v"] = json!(1);
        assert_eq!(
            KeysPayload::parse(&value.to_string()),
            Err(WireError::BadVersion)
        );
        let mut value = good.clone();
        value["devices"][0]
            .as_object_mut()
            .expect("entry")
            .remove("otk");
        assert_eq!(
            KeysPayload::parse(&value.to_string()),
            Err(WireError::BadPayload)
        );
        let mut value = good.clone();
        value["master"]["list"]["ver"] = json!(0);
        assert_eq!(
            KeysPayload::parse(&value.to_string()),
            Err(WireError::BadPayload)
        );
        // At most 4 devices.
        let mut value = good;
        let entry = value["devices"][0].clone();
        value["devices"] = json!([entry, entry, entry, entry, entry]);
        assert_eq!(
            KeysPayload::parse(&value.to_string()),
            Err(WireError::BadDeviceCount)
        );
    }

    #[test]
    fn a_message_payload_is_read_by_the_wire_v2_rules() {
        let did = did_from_key_text(&ed(&Account::new())).expect("did");
        let msg = |value: Value| MessagePayload::parse(InboxVerb::Msg, &value.to_string());
        let good = json!({"v": 2, "ck": "k", "bodies": {(did.clone()): "body"}});
        match msg(good.clone()).expect("msg") {
            MessagePayload::Normal(payload) => {
                assert_eq!(payload.ck, "k");
                assert_eq!(payload.bodies.get(&did).map(String::as_str), Some("body"));
            }
            other => panic!("not a msg: {other:?}"),
        }
        let mut value = good.clone();
        value["v"] = json!(1);
        assert_eq!(msg(value), Err(WireError::BadVersion));
        let mut value = good.clone();
        value["bodies"] = json!({});
        assert_eq!(msg(value), Err(WireError::BadDeviceCount));
        let mut value = good.clone();
        value["bodies"] = json!({"not a did": "body"});
        assert_eq!(msg(value), Err(WireError::BadDid));
        let mut value = good.clone();
        value["bodies"] = json!({(did.clone()): 5});
        assert_eq!(msg(value), Err(WireError::BadPayload));
        // The old shape with a single `ct` is not a message of wire v2.
        assert_eq!(
            msg(json!({"v": 2, "fb": "x", "ct": "y"})),
            Err(WireError::BadPayload)
        );
        // A `pkmsg` needs the id block and the master block.
        assert_eq!(
            MessagePayload::parse(InboxVerb::PkMsg, &good.to_string()),
            Err(WireError::BadPayload)
        );
        assert_eq!(
            MessagePayload::parse(InboxVerb::Keys, &good.to_string()),
            Err(WireError::BadVerb)
        );
    }

    #[test]
    fn the_inner_message_has_a_kind_a_list_version_and_a_binding() {
        let text = InnerOut {
            t: "text",
            peer: None,
            body: "héllo",
            lv: 3,
            fb: Some("FB"),
        }
        .to_json();
        assert_eq!(text, r#"{"t":"text","body":"héllo","lv":3,"fb":"FB"}"#);
        let inner = Inner::parse(text.as_bytes()).expect("inner");
        assert_eq!(
            inner.kind,
            InnerKind::Text {
                body: "héllo".to_string()
            }
        );
        assert_eq!(inner.lv, Some(3));
        assert_eq!(inner.fb.as_deref(), Some("FB"));

        let copy = InnerOut {
            t: "copy",
            peer: Some("carol"),
            body: "hi",
            lv: 1,
            fb: None,
        }
        .to_json();
        assert_eq!(copy, r#"{"t":"copy","peer":"carol","body":"hi","lv":1}"#);
        let inner = Inner::parse(copy.as_bytes()).expect("inner");
        assert_eq!(
            inner.kind,
            InnerKind::Copy {
                peer: "carol".to_string(),
                body: "hi".to_string()
            }
        );
        assert_eq!(inner.fb, None);

        // Other kinds and incomplete texts are not chat text.
        for plain in [
            r#"{"t":"list","lv":2}"#,
            r#"{"t":"listreq","lv":2}"#,
            r#"{"t":"text"}"#,
            r#"{"t":"copy","peer":"x"}"#,
            r#"{"t":"chal","nonce":"n"}"#,
        ] {
            let inner = Inner::parse(plain.as_bytes()).expect("inner");
            assert_eq!(inner.kind, InnerKind::Other, "{plain}");
        }
        // Not an object with a string `t`.
        for plain in ["not json", "[]", r#"{"body":"x"}"#, r#"{"t":1}"#] {
            assert_eq!(Inner::parse(plain.as_bytes()), None, "{plain}");
        }
        // A bad `lv` is no version.
        let inner = Inner::parse(br#"{"t":"text","body":"x","lv":0}"#).expect("inner");
        assert_eq!(inner.lv, None);
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

    /// Replaces the own signed list of `engine` with a list of `devices`.
    fn set_own_list(engine: &mut E2eEngine, master: &Account, version: u32, devices: &[&Account]) {
        let keys: Vec<String> = devices.iter().map(|device| ed(device)).collect();
        let signature =
            build_signed_list_signature(version, &keys, |text| master.sign(text).to_base64())
                .expect("list");
        engine
            .state_mut()
            .set_signed_list(&SignedList {
                version,
                keys,
                signature,
            })
            .expect("own list");
    }

    fn siblings() -> Siblings {
        let mut bob_id = Ident::new("bob-own");
        // Four keys: one for a first peer and one for each copy.
        bob_id.device.generate_one_time_keys(3);
        let mut bob = bob_id.engine();
        let second = fresh_device();
        let keys = keys_payload(
            &bob_id.master,
            &second,
            &[ed(&bob_id.device), ed(&second)],
            1,
        );
        bob.accept_keys("bob", &keys)
            .expect("bob reads the second device");
        set_own_list(&mut bob, &bob_id.master, 1, &[&bob_id.device, &second]);
        let second_did = did_from_key_text(&ed(&second)).expect("did");
        Siblings {
            bob,
            bob_id,
            second,
            second_did,
        }
    }

    /// An inbox row from the second device: it sends the plaintext `plain` to
    /// Bob as a pre-key message, with the certificate of the master. `own`
    /// marks the row as a copy. It uses a one-time key of Bob other than
    /// `used`; the row `id` picks the key.
    fn second_row(s: &Siblings, id: u64, msgid: &str, used: &str, plain: &str, own: bool) -> Value {
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
        let mut session = s
            .second
            .create_outbound_session(SessionConfig::version_1(), bob_curve, one_time_key)
            .expect("outbound session");
        let OlmMessage::PreKey(message) = session.encrypt(plain.as_bytes()).expect("encrypt")
        else {
            panic!("the first message is a pre-key message");
        };
        let payload = pre_key_json(&s.bob_id.master, &s.second, 1, s.bob.own_did(), &message);
        let mut value = row(
            id,
            "bob",
            &s.second_did,
            s.bob.own_did(),
            "pkmsg",
            msgid,
            &payload,
        );
        if own {
            value["own"] = json!(true);
        }
        value
    }

    /// The inner message of a copy of `text` to `peer`, bound to Bob.
    fn copy_plain(peer: &str, text: &str, fb: Option<&str>) -> String {
        InnerOut {
            t: "copy",
            peer: Some(peer),
            body: text,
            lv: 1,
            fb,
        }
        .to_json()
    }

    /// The `fb` that the second device writes for Bob.
    fn second_fb(s: &Siblings) -> String {
        recipient_binding(&ed(&s.second), &ed(&s.bob_id.device))
    }

    fn copy_row(s: &Siblings, id: u64, msgid: &str, peer: &str, text: &str, used: &str) -> Value {
        let plain = copy_plain(peer, text, Some(&second_fb(s)));
        second_row(s, id, msgid, used, &plain, true)
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
    fn a_revoked_own_device_gets_no_inbox_work_and_is_never_a_target() {
        let mut s = siblings();
        let mut trust = s.bob.state_mut().trust();
        let master = ed(&s.bob_id.master);
        trust
            .revoke_device(NET, "bob", &master, &ed(&s.second))
            .expect("revoke");
        s.bob.state_mut().set_trust(&trust).expect("trust");

        let value = copy_row(&s, 3, "msgid2", "carol", "from the revoked device", "");
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(s.bob.handle_row(&item, 50), RowOutcome::Undecryptable);
        assert!(s
            .bob
            .history()
            .messages(&conversation_id(NET, "carol"))
            .is_empty());
        assert!(!s.bob.is_ready("bob"));
        assert!(s.bob.ready_peers().is_empty());
    }

    #[test]
    fn a_copy_without_a_valid_peer_is_acknowledged_and_not_stored() {
        let mut s = siblings();
        let locked = locked_label("carol");
        let fb = second_fb(&s);
        let wrong_fb = recipient_binding(&ed(&s.second), &ed(&Account::new()));
        let no_fb = copy_plain("carol", "no binding", None);
        let bad_fb = copy_plain("carol", "wrong binding", Some(&wrong_fb));
        // A text is not a copy, and a copy is not a text from a person.
        let text = InnerOut {
            t: "text",
            peer: None,
            body: "text in a copy row",
            lv: 1,
            fb: Some(&fb),
        }
        .to_json();
        let cases = [
            second_row(&s, 4, "msgid3", "", "not json", true),
            copy_row(&s, 5, "msgid4", &locked, "labelled peer", ""),
            copy_row(&s, 6, "msgid5", "", "empty peer", ""),
            second_row(&s, 7, "msgid6", "", &no_fb, true),
            second_row(&s, 8, "msgid7", "", &bad_fb, true),
            second_row(&s, 9, "msgid8", "", &text, true),
            second_row(
                &s,
                10,
                "msgid9",
                "",
                &copy_plain("carol", "copy in a peer row", Some(&fb)),
                false,
            ),
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
    fn an_engine_message_keeps_the_session_and_stores_nothing() {
        let mut s = siblings();
        let fb = second_fb(&s);
        let request = format!(r#"{{"t":"listreq","lv":1,"fb":"{fb}"}}"#);
        let value = second_row(&s, 3, "msgid2", "", &request, false);
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        let outcome = s.bob.handle_row(&item, 80);
        assert_eq!(outcome, RowOutcome::Ignored);
        assert!(outcome.acknowledge());
        assert!(s.bob.history().conversation_ids().is_empty());
        assert!(s.bob.take_changed_peers().is_empty());
        // The session is saved: the second device has one with Bob now.
        assert!(s
            .bob
            .state
            .peer_session(NET, "bob", &s.second_did)
            .expect("session")
            .is_some());
    }

    #[test]
    fn text_from_a_person_goes_to_the_conversation_of_the_sender() {
        let mut s = siblings();
        let fb = second_fb(&s);
        let plain = InnerOut {
            t: "text",
            peer: None,
            body: "hello from the other device",
            lv: 1,
            fb: Some(&fb),
        }
        .to_json();
        let value = second_row(&s, 3, "msgid2", "", &plain, false);
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(s.bob.handle_row(&item, 90), RowOutcome::Stored);
        let rows = s.bob.history().messages(&conversation_id(NET, "bob"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "hello from the other device");
        assert_eq!(rows[0].sender_device, s.second_did);
        assert!(rows[0].encrypted);
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
        use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
        use tokio_tungstenite::tungstenite::http::HeaderValue;
        use tokio_tungstenite::tungstenite::Message;

        let alice_id = Ident::new("alice-ws");
        let mut alice = alice_id.engine();
        let mut s = siblings();
        let bob_keys = s.bob_id.keys();
        let used = KeysPayload::parse(&bob_keys)
            .expect("keys")
            .devices
            .remove(0)
            .otk
            .key;
        alice
            .accept_keys("bob", &bob_keys)
            .expect("alice reads bob");
        s.bob
            .accept_keys("alice", &alice_id.keys())
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
            // The client offers subprotocols, so the server must select one
            // of them: "phoenix", as Grappa does. The tungstenite `Callback`
            // trait sets the error type, so the closure cannot box it.
            #[allow(clippy::result_large_err)]
            let select_phoenix =
                |_request: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                    response.headers_mut().insert(
                        "sec-websocket-protocol",
                        HeaderValue::from_static("phoenix"),
                    );
                    Ok(response)
                };
            let mut socket = tokio_tungstenite::accept_hdr_async(stream, select_phoenix)
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

    // --- queue, NACK and drops (final KEYS and send rules) -------------------

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Alice has no keys of Bob. Returns her engine and Bob as a test double.
    fn alice_without_keys(name: &str) -> (E2eEngine, Ident) {
        let alice = Ident::new(&format!("alice-{name}"));
        let bob = Ident::new(&format!("bob-{name}"));
        (alice.engine(), bob)
    }

    fn nack_row(id: u64, alice: &E2eEngine, bob: &Ident, reference: &str) -> InboxRow {
        let bob_did = did_from_key_text(&ed(&bob.device)).expect("did");
        let payload = json!({"v": 2, "ref": reference}).to_string();
        let value = row(id, "bob", &bob_did, alice.own_did(), "nack", "n", &payload);
        InboxRow::from_value(&value, PROTOCOL).expect("nack row")
    }

    fn dropped_event(msgid: &str, reason: &str) -> Value {
        json!({
            "kind": "e2e_send_dropped", "network": NET, "target": "bob",
            "msgid": msgid, "reason": reason
        })
    }

    async fn mount_status(server: &MockServer, status: u16, code: &str) {
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/e2e/messages")))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({"error": code})))
            .mount(server)
            .await;
    }

    fn row_of(engine: &E2eEngine, key: &SendKey) -> String {
        engine.row_ids.get(key).cloned().expect("row of the send")
    }

    #[tokio::test]
    async fn a_text_for_a_peer_without_keys_waits_and_goes_with_the_keys() {
        let (mut alice, bob) = alice_without_keys("wait");
        let server = MockServer::start().await;
        mount_send(&server, "m1").await;
        let client = GrappaClient::new(server.uri());
        let queued = alice
            .send_or_queue(&client, TOKEN, "bob", "hi bob", 100)
            .await
            .expect("queued");
        assert!(queued.msgid.is_none());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
        assert_eq!(alice.take_keys_wanted(), vec!["bob".to_string()]);
        // Without keys the queue sends nothing.
        assert!(alice.flush_queue(&client, TOKEN, 101).await.is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());

        alice.accept_keys("bob", &bob.keys()).expect("keys");
        assert!(alice.flush_queue(&client, TOKEN, 102).await.is_empty());
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(!String::from_utf8_lossy(&requests[0].body).contains("hi bob"));
        // One row, written when the text was queued.
        let rows = alice.history().messages(&conversation_id(NET, "bob"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "hi bob");
        assert!(alice.queue.is_empty());
    }

    #[tokio::test]
    async fn a_queued_text_that_waits_too_long_is_a_late_drop() {
        let (mut alice, _bob) = alice_without_keys("late");
        let client = GrappaClient::new("http://127.0.0.1:9");
        let queued = alice
            .send_or_queue(&client, TOKEN, "bob", "too slow", 100)
            .await
            .expect("queued");
        let key = queued.key.expect("key");
        let row_id = row_of(&alice, &key);
        // The deadline is 90 s; the margin of 2 s makes 88 s too late.
        alice.clock.advance(secs(87));
        assert!(alice.expire_queue().is_empty());
        alice.clock.advance(secs(1));
        let late = alice.expire_queue();
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].reason, DropReason::Late);
        assert_eq!(
            alice.send_status(&key),
            Some(SendStatus::Dropped(DropReason::Late))
        );
        assert_eq!(alice.dropped_reason(&row_id), Some(DropReason::Late));
        assert!(alice.queue.is_empty());
        // The late text is not sent when the keys come.
        assert!(alice.pending.is_empty());
    }

    #[tokio::test]
    async fn the_queue_refuses_the_seventeenth_text_of_a_nick() {
        let (mut alice, _bob) = alice_without_keys("full");
        let client = GrappaClient::new("http://127.0.0.1:9");
        for n in 0..md3_pacing::OUTGOING_QUEUE_MAX {
            alice
                .send_or_queue(&client, TOKEN, "bob", &format!("t{n}"), 100)
                .await
                .expect("queued");
        }
        let refused = alice
            .send_or_queue(&client, TOKEN, "bob", "extra", 100)
            .await;
        assert!(matches!(refused, Err(EngineError::QueueFull)));
        // Another nick has its own room.
        alice
            .send_or_queue(&client, TOKEN, "carol", "hello", 100)
            .await
            .expect("other nick");
    }

    #[tokio::test]
    async fn a_failed_send_of_a_queued_text_is_a_send_failed_drop() {
        let (mut alice, bob) = alice_without_keys("failed");
        let server = MockServer::start().await;
        mount_status(&server, 400, "bad_request").await;
        let client = GrappaClient::new(server.uri());
        let queued = alice
            .send_or_queue(&client, TOKEN, "bob", "x", 100)
            .await
            .expect("queued");
        let row_id = row_of(&alice, &queued.key.expect("key"));
        alice.accept_keys("bob", &bob.keys()).expect("keys");
        let drops = alice.flush_queue(&client, TOKEN, 101).await;
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].reason, DropReason::SendFailed);
        assert_eq!(alice.dropped_reason(&row_id), Some(DropReason::SendFailed));
        assert!(alice.queue.is_empty());
    }

    #[tokio::test]
    async fn a_too_late_answer_to_a_queued_text_is_a_late_drop() {
        let (mut alice, bob) = alice_without_keys("toolate");
        let server = MockServer::start().await;
        mount_status(&server, 422, "too_late").await;
        let client = GrappaClient::new(server.uri());
        let queued = alice
            .send_or_queue(&client, TOKEN, "bob", "x", 100)
            .await
            .expect("queued");
        let row_id = row_of(&alice, &queued.key.expect("key"));
        alice.accept_keys("bob", &bob.keys()).expect("keys");
        let drops = alice.flush_queue(&client, TOKEN, 101).await;
        assert_eq!(drops[0].reason, DropReason::Late);
        assert_eq!(alice.dropped_reason(&row_id), Some(DropReason::Late));
    }

    #[tokio::test]
    async fn a_busy_relay_keeps_the_text_in_the_queue() {
        let (mut alice, bob) = alice_without_keys("busy");
        let server = MockServer::start().await;
        mount_status(&server, 429, "rate_limited").await;
        let client = GrappaClient::new(server.uri());
        alice
            .send_or_queue(&client, TOKEN, "bob", "x", 100)
            .await
            .expect("queued");
        alice.accept_keys("bob", &bob.keys()).expect("keys");
        assert!(alice.flush_queue(&client, TOKEN, 101).await.is_empty());
        assert_eq!(alice.queue.len(), 1);
        assert_eq!(alice.pending.len(), 1);
    }

    #[tokio::test]
    async fn an_accepted_send_can_become_a_dropped_send_and_never_a_delivered_one() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (sent, _) = alice_sends(&mut p.alice, &server, "hello").await;
        let key = sent.key.expect("key");
        let row_id = row_of(&p.alice, &key);
        assert_eq!(p.alice.send_status(&key), Some(SendStatus::Accepted));
        assert_eq!(p.alice.dropped_reason(&row_id), None);
        let dropped = p
            .alice
            .apply_send_dropped(&dropped_event("msgid1", "send_failed"))
            .expect("dropped");
        assert_eq!(dropped.reason, DropReason::SendFailed);
        assert_eq!(
            p.alice.send_status(&key),
            Some(SendStatus::Dropped(DropReason::SendFailed))
        );
        assert_eq!(
            p.alice.dropped_reason(&row_id),
            Some(DropReason::SendFailed)
        );
        // The same event again changes nothing.
        assert!(p
            .alice
            .apply_send_dropped(&dropped_event("msgid1", "late"))
            .is_none());
        assert_eq!(
            p.alice.dropped_reason(&row_id),
            Some(DropReason::SendFailed)
        );
        // A row that is not an own send has no drop.
        assert_eq!(p.alice.dropped_reason(&format!("{NET}:in:5")), None);
    }

    #[tokio::test]
    async fn end_session_drops_accepted_and_queued_sends() {
        let (mut alice, bob) = alice_without_keys("ended");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let client = GrappaClient::new(server.uri());
        alice.accept_keys("bob", &bob.keys()).expect("keys");
        let accepted = alice
            .send_or_queue(&client, TOKEN, "bob", "sent", 100)
            .await
            .expect("sent");
        let accepted_row = row_of(&alice, &accepted.key.expect("key"));
        let queued = alice
            .send_or_queue(&client, TOKEN, "carol", "waits", 101)
            .await
            .expect("queued");
        let queued_row = row_of(&alice, &queued.key.expect("key"));
        let ended = alice.end_session();
        assert_eq!(ended.len(), 2);
        assert!(ended.iter().all(|d| d.reason == DropReason::SessionEnded));
        assert_eq!(
            alice.dropped_reason(&accepted_row),
            Some(DropReason::SessionEnded)
        );
        assert_eq!(
            alice.dropped_reason(&queued_row),
            Some(DropReason::SessionEnded)
        );
        assert!(alice.queue.is_empty());
        assert!(alice.pending.is_empty());
    }

    #[tokio::test]
    async fn a_nack_sends_the_text_again_once_on_a_new_session() {
        let (mut alice, bob) = alice_without_keys("nack");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/e2e/messages")))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"msgid": "msgid1"})))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount_send(&server, "msgid2").await;
        let client = GrappaClient::new(server.uri());
        let bob_did = did_from_key_text(&ed(&bob.device)).expect("did");
        alice.accept_keys("bob", &bob.keys()).expect("keys");
        let sent = alice
            .send_text(&client, TOKEN, "bob", "again please", 100)
            .await
            .expect("send");
        let row_id = row_of(&alice, &sent.key.clone().expect("key"));

        let nack = nack_row(9, &alice, &bob, "msgid1");
        assert_eq!(alice.handle_row(&nack, 101), RowOutcome::Ignored);
        // The failed session is gone and the keys are asked for again.
        assert!(alice
            .state
            .peer_session(NET, "bob", &bob_did)
            .expect("session")
            .is_none());
        assert_eq!(alice.take_keys_wanted(), vec!["bob".to_string()]);
        assert_eq!(alice.queue.len(), 1);
        assert!(!alice.is_ready("bob"));

        alice.accept_keys("bob", &bob.keys()).expect("fresh keys");
        assert!(alice.flush_queue(&client, TOKEN, 102).await.is_empty());
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 2);
        let second: Value = serde_json::from_slice(&requests[1].body).expect("body");
        assert_eq!(second["verb"], "pkmsg");
        // The history keeps one row for the text.
        assert_eq!(
            alice.history().messages(&conversation_id(NET, "bob")).len(),
            1
        );

        // The second NACK is the last: a message goes out twice at most.
        let again = nack_row(10, &alice, &bob, "msgid2");
        assert_eq!(alice.handle_row(&again, 103), RowOutcome::Ignored);
        assert!(alice.queue.is_empty());
        assert_eq!(alice.dropped_reason(&row_id), Some(DropReason::SendFailed));
    }

    #[tokio::test]
    async fn the_deadline_is_checked_again_before_each_queued_send() {
        let (mut alice, bob) = alice_without_keys("deadline");
        let server = MockServer::start().await;
        // The answer takes longer than the time that is left to the texts.
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/e2e/messages")))
            .respond_with(
                ResponseTemplate::new(202)
                    .set_body_json(json!({"msgid": "m1"}))
                    .set_delay(Duration::from_millis(800)),
            )
            .mount(&server)
            .await;
        let client = GrappaClient::new(server.uri());
        alice
            .send_or_queue(&client, TOKEN, "bob", "first", 100)
            .await
            .expect("first");
        let second = alice
            .send_or_queue(&client, TOKEN, "bob", "second", 100)
            .await
            .expect("second");
        let second_row = row_of(&alice, &second.key.expect("key"));
        alice.accept_keys("bob", &bob.keys()).expect("keys");
        // Both texts are live now: 87.5 s plus the 2 s margin is before 90 s.
        alice.clock.advance(Duration::from_millis(87_500));
        let drops = alice.flush_queue(&client, TOKEN, 101).await;
        // The first send took 0.8 s, so the second text is too late.
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].reason, DropReason::Late);
        assert_eq!(alice.dropped_reason(&second_row), Some(DropReason::Late));
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(alice.queue.is_empty());
    }

    #[tokio::test]
    async fn a_nack_re_send_goes_to_the_device_that_sent_the_nack() {
        let alice_id = Ident::new("alice-two");
        let mut alice = alice_id.engine();
        let master = Account::new();
        let (d1, d2) = (fresh_device(), fresh_device());
        let listed = vec![ed(&d1), ed(&d2)];
        let mut keys = keys_struct(&master, &d1, &listed, 1);
        keys.devices
            .extend(keys_struct(&master, &d2, &listed, 1).devices);
        let keys_text = serde_json::to_string(&keys).expect("json");
        alice.accept_keys("bob", &keys_text).expect("keys");
        assert_eq!(alice.peers.len(), 2);

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/e2e/messages")))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"msgid": "msgid1"})))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount_send(&server, "msgid2").await;
        let client = GrappaClient::new(server.uri());
        let (_, body) = alice_sends(&mut alice, &server, "hi").await;
        let first = body["to"].as_str().expect("to").to_string();

        // The other device has a session, so a plain pick would prefer it.
        let other = if did_from_key_text(&ed(&d1)).expect("did") == first {
            &d2
        } else {
            &d1
        };
        let other_did = did_from_key_text(&ed(other)).expect("did");
        let identity = alice.state.olm_identity().expect("state").expect("account");
        let other_key = *other.one_time_keys().values().next().expect("key");
        let session = identity
            .create_outbound_session(
                SessionConfig::version_1(),
                Curve25519PublicKey::from_base64(&curve(other)).expect("curve"),
                other_key,
            )
            .expect("session");
        alice
            .state
            .set_peer_session(NET, "bob", &other_did, &session)
            .expect("save");

        let payload = json!({"v": 2, "ref": "msgid1"}).to_string();
        let value = row(9, "bob", &first, alice.own_did(), "nack", "n", &payload);
        let nack = InboxRow::from_value(&value, PROTOCOL).expect("nack row");
        assert_eq!(alice.handle_row(&nack, 101), RowOutcome::Ignored);
        alice.accept_keys("bob", &keys_text).expect("fresh keys");
        assert!(alice.flush_queue(&client, TOKEN, 102).await.is_empty());
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 2);
        let second: Value = serde_json::from_slice(&requests[1].body).expect("body");
        assert_eq!(second["to"], first.as_str());
        assert_eq!(second["verb"], "pkmsg");
    }

    #[tokio::test]
    async fn a_nack_that_is_not_ours_changes_nothing() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (sent, _) = alice_sends(&mut p.alice, &server, "hello").await;
        let key = sent.key.expect("key");
        let other = Ident::new("bob-other");
        // An unknown reference.
        let unknown = nack_row(11, &p.alice, &other, "nope");
        assert_eq!(p.alice.handle_row(&unknown, 1), RowOutcome::Ignored);
        // A known reference from a device that did not get the message.
        let wrong_device = nack_row(12, &p.alice, &other, "msgid1");
        assert_eq!(p.alice.handle_row(&wrong_device, 1), RowOutcome::Ignored);
        assert_eq!(p.alice.send_status(&key), Some(SendStatus::Accepted));
        assert!(p.alice.queue.is_empty());
        assert!(p.alice.take_keys_wanted().is_empty());
    }

    #[tokio::test]
    async fn one_re_key_for_each_nick_in_a_minute() {
        let (mut alice, bob) = alice_without_keys("rekey");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/networks/{NET}/e2e/messages")))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"msgid": "ma"})))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount_send(&server, "mb").await;
        let client = GrappaClient::new(server.uri());
        alice.accept_keys("bob", &bob.keys()).expect("keys");
        let first = alice
            .send_text(&client, TOKEN, "bob", "a", 100)
            .await
            .expect("a");
        let second = alice
            .send_text(&client, TOKEN, "bob", "b", 100)
            .await
            .expect("b");
        let second_row = row_of(&alice, &second.key.expect("key"));
        let first_row = row_of(&alice, &first.key.expect("key"));
        assert_eq!(
            alice.handle_row(&nack_row(1, &alice, &bob, "ma"), 1),
            RowOutcome::Ignored
        );
        assert_eq!(alice.queue.len(), 1);
        // The second NACK comes in the same minute: no second re-key.
        assert_eq!(
            alice.handle_row(&nack_row(2, &alice, &bob, "mb"), 1),
            RowOutcome::Ignored
        );
        assert_eq!(alice.queue.len(), 1);
        assert_eq!(
            alice.dropped_reason(&second_row),
            Some(DropReason::SendFailed)
        );
        assert_eq!(alice.dropped_reason(&first_row), None);
    }

    #[tokio::test]
    async fn no_keyreq_goes_to_a_peer_without_e2e_capability() {
        let (mut alice, _bob) = alice_without_keys("capability");
        let server = MockServer::start().await;
        mount_send(&server, "k1").await;
        let client = GrappaClient::new(server.uri());
        alice.set_peer_capability("Carol", false);
        let refused = alice.request_keys(&client, TOKEN, "carol").await;
        assert!(matches!(refused, Err(EngineError::PeerNotCapable)));
        let queued = alice.send_or_queue(&client, TOKEN, "carol", "hi", 1).await;
        assert!(matches!(queued, Err(EngineError::PeerNotCapable)));
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
        // The refusal used no interval: a peer with the capability asks at once.
        alice.set_peer_capability("carol", true);
        alice
            .request_keys(&client, TOKEN, "carol")
            .await
            .expect("keyreq");
    }

    #[tokio::test]
    async fn a_message_that_the_engine_reads_sets_the_peer_capability() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, body) = alice_sends(&mut p.alice, &server, "hello bob").await;
        let payload = body["payload"].as_str().expect("payload");
        p.bob.set_peer_capability("Alice", false);
        assert!(!p.bob.peer_capable("alice"));
        let value = row(
            5,
            "alice",
            &p.alice_did,
            &p.bob_did,
            "pkmsg",
            "msgid1",
            payload,
        );
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(p.bob.handle_row(&item, 200), RowOutcome::Stored);
        assert!(p.bob.peer_capable("ALICE"));
    }

    #[test]
    fn the_reassembly_timeout_is_the_final_value() {
        assert_eq!(KEYS_REASSEMBLY_TIMEOUT, secs(60));
    }

    // --- S1 copies between the devices of one account (protocol 50) ---------

    /// The engine of one device of the account of `master`. The device holds
    /// the list 1 of `listed` and its certificate N = 1.
    fn engine_of(name: &str, master: &Account, device: &Account, listed: &[&Account]) -> E2eEngine {
        let dir = scratch_dir(name);
        let mut state =
            E2eStateStore::open(dir.join("state.bin"), &FixedKey([7; 32])).expect("state");
        state.set_account(device).expect("account");
        state.set_master_key(master).expect("master");
        let certificate = build_device_certificate(1, &ed(device), &ed(master), |text| {
            master.sign(text).to_base64()
        })
        .expect("certificate");
        state
            .set_device_certificate(&certificate)
            .expect("certificate");
        let history =
            E2eHistoryStore::open(dir.join("history.bin"), &FixedKey([9; 32])).expect("history");
        let mut engine = E2eEngine::new(NET, state, history).expect("engine");
        set_own_list(&mut engine, master, 1, listed);
        engine
    }

    /// Two devices of one account and a third device that no list names.
    /// `first` sends to carol, `second` is its sibling.
    struct Twins {
        master: Account,
        first_device: Account,
        second_device: Account,
        third_device: Account,
        first: E2eEngine,
        second: E2eEngine,
        first_did: String,
        second_did: String,
    }

    fn twins(name: &str) -> Twins {
        let master = Account::new();
        let first_device = fresh_device();
        let second_device = fresh_device();
        let third_device = fresh_device();
        let listed = [&first_device, &second_device];
        let mut first = engine_of(&format!("{name}-1"), &master, &first_device, &listed);
        let second = engine_of(&format!("{name}-2"), &master, &second_device, &listed);
        let carol = Ident::new(&format!("{name}-carol"));
        first
            .accept_keys("carol", &carol.keys())
            .expect("keys of carol");
        let first_did = first.own_did().to_string();
        let second_did = second.own_did().to_string();
        Twins {
            master,
            first_device,
            second_device,
            third_device,
            first,
            second,
            first_did,
            second_did,
        }
    }

    impl Twins {
        /// The KEYS answer for the second device, with a list of `listed` at
        /// `version`.
        fn second_keys(&self, version: u32, listed: &[&Account]) -> Value {
            let keys: Vec<String> = listed.iter().map(|device| ed(device)).collect();
            json!({"keys": keys_payload(&self.master, &self.second_device, &keys, version)})
        }

        fn both(&self) -> [&Account; 2] {
            [&self.first_device, &self.second_device]
        }
    }

    fn device_route(did: &str, tail: &str) -> String {
        format!("/networks/{NET}/e2e/devices/{did}/{tail}")
    }

    async fn mount_route(server: &MockServer, route: String, status: u16, body: Value) {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }

    /// The first device sends "hello carol" and queues its copies.
    async fn send_and_copy(t: &mut Twins, server: &MockServer, now: i64) -> CopyReport {
        let client = GrappaClient::new(server.uri());
        t.first
            .send_text(&client, TOKEN, "carol", "hello carol", 100)
            .await
            .expect("send");
        t.first
            .send_copies(&client, TOKEN, PROTOCOL, "bob", now)
            .await
    }

    async fn paths_of(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .map(|request| request.url.path().to_string())
            .collect()
    }

    /// The body of the `index`-th request that the server got.
    async fn body_of(server: &MockServer, index: usize) -> Value {
        let requests = server.received_requests().await.expect("requests");
        serde_json::from_slice(&requests[index].body).expect("body")
    }

    /// The inbox row that the second device reads for a queued copy.
    fn copy_inbox_row(t: &Twins, id: u64, copy: &Value) -> Value {
        json!({
            "kind": "e2e_message", "network": NET, "id": id, "from": "bob",
            "from_did": t.first_did, "to_did": t.second_did, "verb": copy["verb"],
            "msgid": "c1", "payload": copy["payload"], "own": true
        })
    }

    async fn mount_copy_routes(server: &MockServer, t: &Twins) {
        mount_send(server, "msgid1").await;
        mount_route(
            server,
            device_route(&t.second_did, "claim"),
            200,
            t.second_keys(1, &t.both()),
        )
        .await;
        mount_route(
            server,
            device_route(&t.second_did, "copies"),
            202,
            json!({"id": 5, "msgid": "c1"}),
        )
        .await;
    }

    #[tokio::test]
    async fn a_claimed_key_gives_one_copy_per_sibling_and_none_goes_over_irc() {
        let mut t = twins("copy-queue");
        let server = MockServer::start().await;
        mount_copy_routes(&server, &t).await;

        let report = send_and_copy(&mut t, &server, 100).await;
        assert_eq!(report.queued, vec![t.second_did.clone()]);
        assert!(report.failed.is_empty() && !report.needs_sync);
        assert!(!t.first.has_pending_copies());

        // The original goes first. The copy follows the 202 answer, after one
        // claim, and only through the copies route.
        let messages = format!("/networks/{NET}/e2e/messages");
        assert_eq!(
            paths_of(&server).await,
            vec![
                messages.clone(),
                device_route(&t.second_did, "claim"),
                device_route(&t.second_did, "copies"),
            ]
        );
        assert_eq!(
            body_of(&server, 1).await,
            json!({"from_did": t.first_did.as_str()})
        );
        let copy = body_of(&server, 2).await;
        assert_eq!(copy["from_did"], t.first_did.as_str());
        assert_eq!(copy["verb"], "pkmsg");
        assert!(!copy.to_string().contains("hello carol"));
        let to_irc = paths_of(&server)
            .await
            .iter()
            .filter(|route| **route == messages)
            .count();
        assert_eq!(to_irc, 1, "only the original is a send to IRC");
    }

    #[tokio::test]
    async fn a_server_list_that_adds_a_device_gives_that_device_no_copy() {
        let mut t = twins("copy-added");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let listed = [&t.first_device, &t.second_device, &t.third_device];
        mount_route(
            &server,
            device_route(&t.second_did, "claim"),
            200,
            t.second_keys(1, &listed),
        )
        .await;
        mount_route(
            &server,
            device_route(&t.second_did, "copies"),
            202,
            json!({"id": 5, "msgid": "c1"}),
        )
        .await;

        let report = send_and_copy(&mut t, &server, 100).await;
        assert_eq!(report.queued, vec![t.second_did.clone()]);
        let third_did = did_from_key_text(&ed(&t.third_device)).expect("did");
        assert!(paths_of(&server)
            .await
            .iter()
            .all(|route| !route.contains(&third_did)));
    }

    #[tokio::test]
    async fn a_server_list_that_removes_the_sibling_gives_no_copy() {
        let mut t = twins("copy-removed");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        mount_route(
            &server,
            device_route(&t.second_did, "claim"),
            200,
            t.second_keys(1, &[&t.first_device]),
        )
        .await;
        let report = send_and_copy(&mut t, &server, 100).await;
        assert!(report.queued.is_empty());
        assert_eq!(
            report.failed,
            vec![(t.second_did.clone(), CopyFailure::RemovedDevice)]
        );
        assert!(!paths_of(&server)
            .await
            .contains(&device_route(&t.second_did, "copies")));
    }

    #[tokio::test]
    async fn a_claim_without_a_key_of_the_sibling_gives_no_copy() {
        let mut t = twins("copy-nokey");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let keys = keys_payload(
            &t.master,
            &t.third_device,
            &[ed(&t.first_device), ed(&t.second_device)],
            1,
        );
        mount_route(
            &server,
            device_route(&t.second_did, "claim"),
            200,
            json!({ "keys": keys }),
        )
        .await;
        let report = send_and_copy(&mut t, &server, 100).await;
        assert_eq!(
            report.failed,
            vec![(t.second_did.clone(), CopyFailure::NoKey)]
        );
    }

    #[tokio::test]
    async fn a_copy_shows_as_sent_in_the_locked_query_and_once_only() {
        let mut t = twins("copy-receive");
        let server = MockServer::start().await;
        mount_copy_routes(&server, &t).await;
        send_and_copy(&mut t, &server, 100).await;
        let value = copy_inbox_row(&t, 9, &body_of(&server, 2).await);
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");

        // A repeated push gives one row.
        assert_eq!(t.second.handle_row(&item, 150), RowOutcome::Stored);
        assert_eq!(t.second.handle_row(&item, 151), RowOutcome::Duplicate);
        // A repeated drain gives the same row again. It is acknowledged and
        // not stored a second time.
        let inbox = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(device_route(&t.second_did, "inbox")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"messages": [value]})))
            .mount(&inbox)
            .await;
        Mock::given(method("POST"))
            .and(path(device_route(&t.second_did, "inbox/ack")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&inbox)
            .await;
        let outcomes = t
            .second
            .drain(&GrappaClient::new(inbox.uri()), TOKEN, PROTOCOL, 152)
            .await
            .expect("drain");
        assert_eq!(outcomes, vec![(9, RowOutcome::Duplicate)]);

        // The device never opened the query, and the row is in the locked
        // conversation of carol as an own row. The plain query has no row.
        assert_eq!(t.second.history_peers(), vec!["carol"]);
        assert_eq!(t.second.take_changed_peers(), vec!["carol".to_string()]);
        let rows = t.second.history().messages(&conversation_id(NET, "carol"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "hello carol");
        assert_eq!(rows[0].sender_device, OWN_DEVICE);
        assert!(rows[0].encrypted);
        assert!(t
            .second
            .history()
            .messages(&conversation_id(NET, "bob"))
            .is_empty());
    }

    #[tokio::test]
    async fn the_accepted_original_that_is_dropped_leaves_a_sent_copy_and_a_failed_row() {
        let mut t = twins("copy-accepted");
        let server = MockServer::start().await;
        mount_copy_routes(&server, &t).await;
        send_and_copy(&mut t, &server, 100).await;
        let value = copy_inbox_row(&t, 9, &body_of(&server, 2).await);
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(t.second.handle_row(&item, 150), RowOutcome::Stored);

        // Grappa accepted the original with 202, then dropped it unsent.
        let dropped = t
            .first
            .apply_send_dropped(&json!({
                "kind": "e2e_send_dropped", "network": NET, "target": "carol",
                "msgid": "msgid1", "reason": "send_failed"
            }))
            .expect("dropped");
        assert_eq!(dropped.reason, DropReason::SendFailed);

        let conversation = conversation_id(NET, "carol");
        let failed = t.first.history().messages(&conversation);
        assert_eq!(failed.len(), 1);
        assert_eq!(
            t.first.dropped_reason(&failed[0].id),
            Some(DropReason::SendFailed)
        );
        let sent = t.second.history().messages(&conversation);
        assert_eq!(sent.len(), 1);
        assert_eq!(t.second.dropped_reason(&sent[0].id), None);
        assert_eq!(sent[0].sender_device, OWN_DEVICE);
    }

    #[tokio::test]
    async fn each_refusal_token_of_the_relay_ends_the_copy_for_that_sibling() {
        let cases = [
            ("same_device", 409, false, CopyFailure::SameDevice),
            ("keyless_device", 409, true, CopyFailure::KeylessDevice),
            ("key_taken", 409, true, CopyFailure::KeyTaken),
            ("removed_device", 409, false, CopyFailure::RemovedDevice),
            ("inbox_full", 413, false, CopyFailure::InboxFull),
        ];
        for (token, status, at_claim, failure) in cases {
            let mut t = twins(&format!("copy-{token}"));
            let server = MockServer::start().await;
            mount_send(&server, "msgid1").await;
            let refusal = json!({ "error": token });
            if at_claim {
                mount_route(
                    &server,
                    device_route(&t.second_did, "claim"),
                    status,
                    refusal,
                )
                .await;
            } else {
                mount_route(
                    &server,
                    device_route(&t.second_did, "claim"),
                    200,
                    t.second_keys(1, &t.both()),
                )
                .await;
                mount_route(
                    &server,
                    device_route(&t.second_did, "copies"),
                    status,
                    refusal,
                )
                .await;
            }
            let report = send_and_copy(&mut t, &server, 100).await;
            assert!(report.queued.is_empty(), "{token}");
            assert_eq!(
                report.failed,
                vec![(t.second_did.clone(), failure)],
                "{token}"
            );
            // The refusal is final: no retry stays in the queue.
            assert!(!t.first.has_pending_copies(), "{token}");
            let paths = paths_of(&server).await;
            let claims = device_route(&t.second_did, "claim");
            let expected_claims = if token == "key_taken" { 2 } else { 1 };
            assert_eq!(
                paths.iter().filter(|route| **route == claims).count(),
                expected_claims,
                "{token}"
            );
        }
    }

    #[tokio::test]
    async fn a_copy_that_waited_longer_than_the_inbox_lifetime_is_dropped() {
        let mut t = twins("copy-expired");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let late = 100 + i64::try_from(crate::e2e_wire::INBOX_EXPIRY_SECS).expect("seconds");
        let report = send_and_copy(&mut t, &server, late).await;
        assert_eq!(
            report.failed,
            vec![(t.second_did.clone(), CopyFailure::Expired)]
        );
        assert_eq!(paths_of(&server).await.len(), 1);
    }

    #[tokio::test]
    async fn a_stale_list_stops_the_copies_and_the_last_try_drops_the_copy() {
        let mut t = twins("copy-stale");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let listed = [&t.first_device, &t.second_device, &t.third_device];
        mount_route(
            &server,
            device_route(&t.second_did, "claim"),
            200,
            t.second_keys(2, &listed),
        )
        .await;
        let report = send_and_copy(&mut t, &server, 100).await;
        assert!(report.needs_sync && report.queued.is_empty());
        assert!(t.first.has_pending_copies());

        let client = GrappaClient::new(server.uri());
        let again = t
            .first
            .send_copies(&client, TOKEN, PROTOCOL, "bob", 101)
            .await;
        assert_eq!(
            again.failed,
            vec![(t.second_did.clone(), CopyFailure::Failed)]
        );
        assert!(!t.first.has_pending_copies());
        assert!(!paths_of(&server)
            .await
            .contains(&device_route(&t.second_did, "copies")));
    }

    #[tokio::test]
    async fn the_own_list_syncs_to_a_newer_valid_list_of_the_same_master() {
        let mut t = twins("copy-sync");
        let mut keys = vec![
            ed(&t.first_device),
            ed(&t.second_device),
            ed(&t.third_device),
        ];
        keys.sort();
        let signature =
            build_signed_list_signature(2, &keys, |text| t.master.sign(text).to_base64())
                .expect("list");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/networks/{NET}/e2e/list")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "master": ed(&t.master), "ver": 2, "devices": keys, "sig": signature
            })))
            .mount(&server)
            .await;
        let client = GrappaClient::new(server.uri());
        assert!(t
            .first
            .sync_own_list(&client, TOKEN, PROTOCOL)
            .await
            .expect("sync"));
        assert_eq!(t.first.state_mut().signed_list().expect("list").version, 2);
        assert_eq!(t.first.sibling_dids().len(), 2);
        assert!(!t
            .first
            .sync_own_list(&client, TOKEN, PROTOCOL)
            .await
            .expect("sync"));
    }

    #[tokio::test]
    async fn a_copy_of_a_device_that_the_own_list_does_not_name_is_not_read() {
        let mut t = twins("copy-unlisted");
        let server = MockServer::start().await;
        mount_copy_routes(&server, &t).await;
        send_and_copy(&mut t, &server, 100).await;
        let value = copy_inbox_row(&t, 9, &body_of(&server, 2).await);
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        set_own_list(&mut t.second, &t.master, 1, &[&t.second_device]);
        let outcome = t.second.handle_row(&item, 150);
        assert_eq!(outcome, RowOutcome::Undecryptable);
        assert!(outcome.acknowledge());
        assert!(t.second.history().conversation_ids().is_empty());
    }

    #[tokio::test]
    async fn a_copy_from_a_newer_list_waits_until_the_own_list_syncs() {
        let mut t = twins("copy-newer");
        set_own_list(
            &mut t.first,
            &t.master,
            2,
            &[&t.first_device, &t.second_device],
        );
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        mount_route(
            &server,
            device_route(&t.second_did, "claim"),
            200,
            t.second_keys(2, &t.both()),
        )
        .await;
        mount_route(
            &server,
            device_route(&t.second_did, "copies"),
            202,
            json!({"id": 5, "msgid": "c1"}),
        )
        .await;
        send_and_copy(&mut t, &server, 100).await;
        let value = copy_inbox_row(&t, 9, &body_of(&server, 2).await);
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");

        let outcome = t.second.handle_row(&item, 150);
        assert_eq!(outcome, RowOutcome::StaleList);
        assert!(!outcome.acknowledge());
        assert!(t.second.history().conversation_ids().is_empty());
        set_own_list(
            &mut t.second,
            &t.master,
            2,
            &[&t.first_device, &t.second_device],
        );
        assert_eq!(t.second.handle_row(&item, 151), RowOutcome::Stored);
    }
}
