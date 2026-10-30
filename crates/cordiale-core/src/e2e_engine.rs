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
//! the two device keys. The engine reads `text` and `copy`.
//!
//! Lists inside Olm messages: a `listreq` gets the own signed list as a
//! `{"t":"list","master":{…}}` message. A `list` is applied only when its
//! signature and its master verify and its version is higher. A higher `lv`
//! of a peer causes one `listreq`. The engine queues these answers and
//! requests; [`E2eEngine::send_list_messages`] sends them. A message for a
//! peer goes to every trusted device of the peer, one body for each device.

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
use crate::e2e_provision::{provision_device_at, ProvisionError, Provisioned};
use crate::e2e_refusal::{E2eRefusal, E2eRouteError};
use crate::e2e_selfcopy::{inbox_accepts, is_expired, DeliveryTracker};
use crate::e2e_state::E2eStateStore;
use crate::e2e_store::{E2eHistoryStore, E2eMessage, E2eStoreError, KeyringKeyProvider};
use crate::e2e_trust::PeerTrust;
use crate::e2e_wire::{
    bundle_key_signed_text, device_id_signed_text, did_from_key_text, is_did_shape, parse_payload,
    recipient_binding, ListDecision, WireError, INBOX_PAGE_MAX, MAX_LIST_DEVICES, MAX_VERSION,
    SEND_PAYLOAD_MAX_BYTES, WILDCARD,
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

/// The nicks that have a conversation on `network` in `history`.
pub fn history_peers_of(history: &E2eHistoryStore, network: &str) -> Vec<String> {
    let prefix = conversation_id(network, "");
    let mut peers: Vec<String> = history
        .conversation_ids()
        .iter()
        .filter_map(|id| id.strip_prefix(&prefix).map(str::to_string))
        .collect();
    peers.sort();
    peers
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
    /// The signed list of the sender: `{"t":"list","master":{…}}`.
    List { master: MasterBlock },
    /// A request for the signed list of the receiver: `{"t":"listreq"}`.
    ListReq,
    /// Any other kind: a challenge, an unknown one. The engine keeps the
    /// session and stores nothing.
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
            "list" => map
                .get("master")
                .and_then(|master| serde_json::from_value(master.clone()).ok())
                .map_or(InnerKind::Other, |master| InnerKind::List { master }),
            "listreq" => InnerKind::ListReq,
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
    /// A copy comes from a sender that the own list does not name, or from a
    /// sibling with a newer list than the own list. Do not acknowledge it and
    /// stop the drain before it. Sync the own list, then read the row again.
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
    /// The devices the message was for. Only these devices may NACK it.
    dids: Vec<String>,
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
    /// The siblings at the time of the 202 answer. A later list never adds one.
    recipients: HashSet<String>,
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
#[derive(Clone)]
struct OwnWire {
    id: IdBlock,
    master: MasterRef,
    lv: u32,
}

/// What the engine writes in an Olm message.
enum Outgoing<'a> {
    Text(&'a str),
    List(&'a MasterBlock),
    ListReq,
}

impl Outgoing<'_> {
    fn to_json(&self, lv: u32, fb: Option<&str>) -> String {
        let (t, master) = match self {
            Outgoing::Text(body) => {
                return InnerOut {
                    t: "text",
                    peer: None,
                    body,
                    lv,
                    fb,
                }
                .to_json()
            }
            Outgoing::List(master) => ("list", Some(*master)),
            Outgoing::ListReq => ("listreq", None),
        };
        let mut map = serde_json::Map::new();
        map.insert("t".to_string(), Value::from(t));
        if let Some(master) = master {
            map.insert(
                "master".to_string(),
                serde_json::to_value(master).unwrap_or(Value::Null),
            );
        }
        map.insert("lv".to_string(), Value::from(lv));
        if let Some(fb) = fb {
            map.insert("fb".to_string(), Value::from(fb));
        }
        Value::Object(map).to_string()
    }
}

/// The Olm message for one device, with the session that wrote it.
struct Sealed {
    did: String,
    prekey: bool,
    body: String,
    session: Session,
}

/// A request that the relay accepted: the devices it holds a body for.
struct Emitted {
    dids: Vec<String>,
    msgid: Option<String>,
}

/// A list message that waits to go to one device of a peer.
#[derive(Debug, Clone)]
struct ListJob {
    nick: String,
    did: String,
    /// True for the own list (an answer), false for a `listreq`.
    reply: bool,
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
    /// Nicks whose KEYS or first message came under a master key that is not
    /// the stored one. The view shows the trust alarm for them.
    trust_changed: Vec<String>,
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
    /// List answers and list requests that wait to go out.
    list_jobs: Vec<ListJob>,
    /// When a list went to a device of a peer, by folded nick and `did`.
    list_answered: HashMap<(String, String), Duration>,
    /// At most one `listreq` for each nick in the list request interval.
    listreq: IntervalLimiter,
    /// The list versions that a `listreq` asked for, by folded nick.
    listreq_lv: HashMap<String, HashSet<u32>>,
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
        let dropped_rows = state
            .dropped_rows()
            .iter()
            .filter_map(|(id, reason)| Some((id.clone(), DropReason::from_wire(reason)?)))
            .collect();
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
            trust_changed: Vec::new(),
            queue: OutgoingQueue::new(),
            pending: HashMap::new(),
            sent: HashMap::new(),
            rekey: IntervalLimiter::new(md3_pacing::REKEY_INTERVAL),
            row_ids: HashMap::new(),
            dropped_rows,
            capability: Vec::new(),
            changed_peers: Vec::new(),
            local_sends: 0,
            copy_jobs: Vec::new(),
            copy_tracker: DeliveryTracker::default(),
            stale_tries: HashMap::new(),
            list_jobs: Vec::new(),
            list_answered: HashMap::new(),
            listreq: IntervalLimiter::new(md3_pacing::LISTREQ_INTERVAL),
            listreq_lv: HashMap::new(),
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

    /// Opens only the sealed history of `network`, without a device
    /// identity. A reset removes the identity but keeps the history, so this
    /// is the way to read it in a later session. `None` when there is no
    /// history file.
    pub fn open_history_for_network(
        server: &str,
        account: &str,
        network: &str,
    ) -> Result<Option<E2eHistoryStore>, EngineError> {
        let part = storage_part(server, account, network).ok_or(EngineError::NotReady)?;
        let dir = data_dir().ok_or(EngineError::Store(E2eStoreError::NoDataDir))?;
        let path = dir.join(format!("e2e_history_{part}.bin"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(E2eHistoryStore::open(path, &KeyringKeyProvider)?))
    }

    /// Makes the E2E identity of this device on first use, with the state
    /// file in the data folder, and publishes its bundle. On a later run it
    /// only completes what is missing. Call it before [`Self::open_for_network`]
    /// so a first device gets its master key and its state file.
    pub async fn provision_for_network(
        client: &GrappaClient,
        token: &str,
        server: &str,
        account: &str,
        network: &str,
        server_protocol: Option<u32>,
    ) -> Result<Provisioned, ProvisionError> {
        let part = storage_part(server, account, network).ok_or(E2eStoreError::NoDataDir)?;
        let dir = data_dir().ok_or(E2eStoreError::NoDataDir)?;
        provision_device_at(
            client,
            token,
            network,
            server_protocol,
            dir.join(format!("e2e_state_{part}.bin")),
            &KeyringKeyProvider,
        )
        .await
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
        history_peers_of(&self.history, &self.network)
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

    /// A copy of the trust state of the peers, for the views.
    pub fn trust(&self) -> PeerTrust {
        self.state.trust()
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
    /// engine read) sets it to true by itself. No source publishes a signal
    /// that a peer has no E2E, and silence is not one: see
    /// `docs/protocol-notes.md`, issue 482.
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
                // A failed save leaves the mark in memory for this run.
                let _ = self.state.set_dropped_row(&row_id, drop.reason.wire_name());
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

    /// The nicks whose master key changed since the last call. The list is
    /// cleared. The stored master stays: the engine reads nothing under the
    /// new master.
    pub fn take_trust_changed(&mut self) -> Vec<String> {
        std::mem::take(&mut self.trust_changed)
    }

    fn note_trust_changed(&mut self, nick: &str) {
        if !self.trust_changed.iter().any(|known| known == nick) {
            self.trust_changed.push(nick.to_string());
        }
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
        let mut master_changed = false;
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
            master_changed |= err == E2eError::MasterChanged;
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
                    master_changed |= err == E2eError::MasterChanged;
                    first_error.get_or_insert(err);
                }
            }
        }
        if master_changed {
            self.note_trust_changed(nick);
        }
        self.state.set_trust(&trust)?;
        // A newer list stays even when a device is refused.
        self.forget_revoked(&trust);
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

    /// Drops every cached device that `trust` revokes.
    fn forget_revoked(&mut self, trust: &PeerTrust) {
        let revoked: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, entry)| self.entry_revoked(entry, trust))
            .map(|(did, _)| did.clone())
            .collect();
        for did in revoked {
            self.peers.remove(&did);
            self.revoked_dids.insert(did);
        }
    }

    /// Applies the signed list of a `list` message. The list must verify, come
    /// from the stored master and have a higher version. Anything else changes
    /// nothing; another master is a trust alarm.
    fn apply_list_message(&mut self, nick: &str, block: &MasterBlock) -> Result<(), EngineError> {
        let mut trust = self.state.trust();
        let decision = apply_peer_list(
            &mut trust,
            &self.network,
            nick,
            &block.ed25519,
            block.list.ver,
            &block.list.devices,
            &block.sig,
        );
        match decision {
            Ok(ListDecision::Replace) => {
                self.state.set_trust(&trust)?;
                self.forget_revoked(&trust);
                self.listreq_lv.remove(&self.casemapping.fold(nick));
                Ok(())
            }
            Ok(_) => Ok(()),
            Err(err) => {
                if err == E2eError::MasterChanged {
                    self.note_trust_changed(nick);
                }
                Err(err.into())
            }
        }
    }

    /// Queues the own list for the device `did` of `nick`: once for each
    /// device in the list request interval.
    fn queue_list_reply(&mut self, nick: &str, did: &str) {
        let now = self.clock.now();
        self.list_answered
            .retain(|_, at| now.saturating_sub(*at) < md3_pacing::LISTREQ_INTERVAL);
        let key = (self.casemapping.fold(nick), did.to_string());
        if self.list_answered.contains_key(&key) {
            return;
        }
        self.list_answered.insert(key, now);
        self.list_jobs.push(ListJob {
            nick: nick.to_string(),
            did: did.to_string(),
            reply: true,
        });
    }

    /// Queues one `listreq` when the sender holds a list newer than the
    /// stored one: once for each list version, and once for each nick in the
    /// list request interval.
    fn maybe_list_request(&mut self, nick: &str, did: &str, lv: u32) {
        let version = self.state.trust().list_version(&self.network, nick);
        let key = self.casemapping.fold(nick);
        let asked = self.listreq_lv.entry(key).or_default();
        asked.retain(|asked| *asked > version);
        if lv <= version || asked.contains(&lv) {
            return;
        }
        if !self
            .listreq
            .try_acquire(nick, self.casemapping, self.clock.now())
        {
            return;
        }
        asked.insert(lv);
        self.list_jobs.push(ListJob {
            nick: nick.to_string(),
            did: did.to_string(),
            reply: false,
        });
    }

    /// Sends the queued list answers and list requests, each to the device
    /// that caused it. A device that is not ready gets nothing. Returns the
    /// number of requests that the relay accepted.
    pub async fn send_list_messages(&mut self, client: &GrappaClient, token: &str) -> usize {
        let mut sent = 0;
        for job in std::mem::take(&mut self.list_jobs) {
            if self.send_list_job(client, token, &job).await {
                sent += 1;
            } else if !job.reply {
                // The request did not go out: a later message that shows the
                // same version can ask again when the interval allows it.
                let key = self.casemapping.fold(&job.nick);
                self.listreq_lv.remove(&key);
            }
        }
        sent
    }

    /// Sends one queued list message. True when the relay accepted it.
    async fn send_list_job(&mut self, client: &GrappaClient, token: &str, job: &ListJob) -> bool {
        let Some(entry) = self.pick_specific_device(&job.nick, &job.did) else {
            return false;
        };
        let Ok(Some(identity)) = self.state.olm_identity() else {
            return false;
        };
        let Ok(own) = self.own_wire(&identity) else {
            return false;
        };
        let block;
        let outgoing = if job.reply {
            let Some((list, master)) = self.own_list() else {
                return false;
            };
            block = MasterBlock {
                ed25519: master,
                list: MasterList {
                    ver: list.version,
                    devices: list.keys,
                },
                sig: list.signature,
            };
            Outgoing::List(&block)
        } else {
            Outgoing::ListReq
        };
        let Ok(sealed) = self.seal(&identity, &job.nick, &[entry], &outgoing, own.lv) else {
            return false;
        };
        self.emit(
            client,
            token,
            &job.nick,
            sealed,
            &own,
            E2eSendPriority::Control,
        )
        .await
        .is_ok_and(|emitted| !emitted.is_empty())
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
        let revoked_key = self
            .state
            .own_revoked()
            .iter()
            .any(|key| did_from_key_text(key).is_ok_and(|did| did == row.from_did));
        if revoked_key
            || row.from_did == self.own_did
            || self.revoked_dids.contains(&row.from_did)
            || self
                .state
                .trust()
                .is_did_revoked(&self.network, &nick, &row.from_did)
        {
            return RowOutcome::Undecryptable;
        }
        // An unknown sender may be a device paired while this device was
        // away: the own list is behind. Read it again before a final refusal.
        // No session or key changes before that.
        if !listed {
            return self.stale_or_refuse(row.id);
        }
        let Some(decrypted) = self.decrypt_row(row, entry.as_ref(), &nick) else {
            return RowOutcome::Undecryptable;
        };
        // The sender knows a newer list: this device is behind.
        if decrypted.inner.lv.is_some_and(|lv| lv > list.version) {
            return self.stale_or_refuse(row.id);
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
            // A list message from a sibling keeps the session. The own list
            // comes from the server, never from a copy.
            InnerKind::Other | InnerKind::List { .. } | InnerKind::ListReq => {
                match self.save_state(&nick, &row.from_did, &decrypted) {
                    Ok(()) => RowOutcome::Ignored,
                    Err(_) => RowOutcome::StoreFailed,
                }
            }
            _ => RowOutcome::Undecryptable,
        }
    }

    /// A copy that waits for a newer own list gets `StaleList` for the first
    /// tries of its row, then it is refused for good.
    fn stale_or_refuse(&mut self, row_id: u64) -> RowOutcome {
        let tries = self.stale_tries.entry(row_id).or_insert(0);
        *tries += 1;
        if *tries < md3_pacing::MAX_SENDS {
            RowOutcome::StaleList
        } else {
            RowOutcome::Undecryptable
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
            // A first message under another master than the stored one is a
            // trust alarm, not only an unread row.
            if let Ok(MessagePayload::PreKey(pre)) = MessagePayload::parse(row.verb, &row.payload) {
                if trust
                    .master(&self.network, &nick)
                    .is_some_and(|master| master != pre.master.ed25519)
                {
                    self.note_trust_changed(&nick);
                }
            }
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
        let outcome = match &decrypted.inner.kind {
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
            InnerKind::Other | InnerKind::List { .. } | InnerKind::ListReq => {
                match self.save_state(&nick, &row.from_did, &decrypted) {
                    Ok(()) => {
                        match &decrypted.inner.kind {
                            InnerKind::List { master } => {
                                // A list that does not verify changes nothing.
                                // A failed write loses a valid list: leave the
                                // row open and let a later `listreq` ask again.
                                if let Err(EngineError::Store(_)) =
                                    self.apply_list_message(&nick, master)
                                {
                                    let key = self.casemapping.fold(&nick);
                                    self.listreq_lv.remove(&key);
                                    return RowOutcome::StoreFailed;
                                }
                            }
                            InnerKind::ListReq => self.queue_list_reply(&nick, &row.from_did),
                            _ => {}
                        }
                        RowOutcome::Ignored
                    }
                    Err(_) => RowOutcome::StoreFailed,
                }
            }
            InnerKind::Copy { .. } => RowOutcome::Undecryptable,
        };
        // The sender holds a newer list than the stored one: ask for it.
        if matches!(outcome, RowOutcome::Stored | RowOutcome::Ignored) {
            if let Some(lv) = decrypted.inner.lv {
                self.maybe_list_request(&nick, &row.from_did, lv);
            }
        }
        outcome
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
        let recipients: HashSet<String> = self
            .sibling_dids()
            .into_iter()
            .map(|(did, _)| did)
            .collect();
        if recipients.is_empty() {
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
            recipients,
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
        let mut kept = Vec::new();
        for mut job in std::mem::take(&mut self.copy_jobs) {
            let expired = u64::try_from(job.created_at)
                .ok()
                .zip(u64::try_from(now).ok())
                .is_some_and(|(created, now)| is_expired(created, now));
            let mut open = false;
            for (did, ed25519) in self.sibling_dids() {
                // A device paired after the original was accepted gets no
                // earlier text.
                if job.done.contains(&did) || !job.recipients.contains(&did) {
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
    /// without a certificate or a signed list is not ready. A device that
    /// joined by pairing holds no master secret: the master public key is the
    /// one in its certificate. A master holder must match that key.
    fn own_wire(&self, identity: &Account) -> Result<OwnWire, EngineError> {
        let certificate = self
            .state
            .device_certificate()
            .ok_or(EngineError::NotReady)?;
        let master_ed25519 = certificate.master_ed25519.clone();
        if let Some(master) = self.state.master_key()? {
            if master.identity_keys().ed25519.to_base64() != master_ed25519 {
                return Err(EngineError::NotReady);
            }
        }
        let list = self.state.signed_list().ok_or(EngineError::NotReady)?;
        if certificate.device_ed25519 != self.own_ed25519 {
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

    /// The trusted devices of `nick` to send to: not revoked and ready. The
    /// trust state holds the verified signed list of the peer and revokes a
    /// device that a newer list drops. A request holds [`MAX_LIST_DEVICES`]
    /// bodies at most, so the list of the peer bounds the result. The `did`
    /// gives the order.
    fn pick_devices(&self, nick: &str) -> Vec<PeerEntry> {
        let trust = self.state.trust();
        let mut entries: Vec<PeerEntry> = self
            .peers
            .values()
            .filter(|entry| entry.nick == nick && self.entry_ready(entry, &trust))
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.device.did().cmp(b.device.did()));
        entries.truncate(MAX_LIST_DEVICES);
        entries
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
        let entries = self.pick_devices(nick);
        if entries.is_empty() {
            return Err(EngineError::NotReady);
        }
        self.deliver(client, token, nick, text, entries, 1, None, now)
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
            let entries: Vec<PeerEntry> = match &pending.did {
                Some(did) => self.pick_specific_device(&nick, did).into_iter().collect(),
                None => self.pick_devices(&nick),
            };
            if entries.is_empty() {
                self.pending.insert(item.key.clone(), pending);
                retry.push(item);
                continue;
            }
            let result = self
                .deliver(
                    client,
                    token,
                    &nick,
                    &pending.text,
                    entries,
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

    /// Sends `text` to `entries`, the devices of `nick`: one request for each
    /// kind of Olm message, with one body for each device. `row_id` is the
    /// history row of a text that waited in the queue or that goes out again
    /// after a NACK; without it the call writes the row. `sends` counts the
    /// sends of the text.
    #[allow(clippy::too_many_arguments)]
    async fn deliver(
        &mut self,
        client: &GrappaClient,
        token: &str,
        nick: &str,
        text: &str,
        entries: Vec<PeerEntry>,
        sends: u8,
        row_id: Option<String>,
        now: i64,
    ) -> Result<SentText, EngineError> {
        let identity = self.state.olm_identity()?.ok_or(EngineError::NotReady)?;
        let own = self.own_wire(&identity)?;
        let sealed = self.seal(&identity, nick, &entries, &Outgoing::Text(text), own.lv)?;
        let emitted = self
            .emit(client, token, nick, sealed, &own, E2eSendPriority::Text)
            .await?;
        let first = emitted.first().ok_or(EngineError::NotReady)?;
        let first_msgid = first.msgid.clone();
        let key = first_msgid
            .as_deref()
            .map(|msgid| SendKey::new(&self.network, nick, msgid));
        self.local_sends += 1;
        let suffix = first_msgid
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
        for sent in &emitted {
            let Some(msgid) = &sent.msgid else {
                continue;
            };
            let sent_key = SendKey::new(&self.network, nick, msgid);
            self.book.start(sent_key.clone());
            self.book.apply_response(&sent_key, SendResponse::Accepted);
            self.row_ids.insert(sent_key, row_id.clone());
            self.remember_sent(msgid, nick, &sent.dids, text, sends, &row_id);
        }
        // The copies for the other devices of the account follow the 202
        // answer. A re-send after a NACK makes no second copy.
        if sends == 1 {
            self.queue_copies(nick, text, &suffix, now);
        }
        self.note_changed(nick);
        Ok(SentText {
            msgid: first_msgid,
            key,
        })
    }

    /// Writes `out` as an Olm message for each of `entries`. A device without
    /// a session starts one with its one-time key. Nothing is saved or sent.
    fn seal(
        &self,
        identity: &Account,
        nick: &str,
        entries: &[PeerEntry],
        out: &Outgoing<'_>,
        lv: u32,
    ) -> Result<Vec<Sealed>, EngineError> {
        let mut sealed = Vec::new();
        for entry in entries {
            let did = entry.device.did().to_string();
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
            // A session that has not received a message writes pre-key
            // messages. The inner message of a pre-key message holds `fb`, the
            // binding of the two device keys.
            let fb = (!session.has_received_message())
                .then(|| recipient_binding(&self.own_ed25519, entry.device.ed25519()));
            let inner = out.to_json(lv, fb.as_deref());
            let (prekey, body) = match session
                .encrypt(inner.as_bytes())
                .map_err(|_| EngineError::EncryptionFailed)?
            {
                OlmMessage::PreKey(message) => (true, message.to_base64()),
                OlmMessage::Normal(message) => (false, message.to_base64()),
            };
            sealed.push(Sealed {
                did,
                prekey,
                body,
                session,
            });
        }
        if sealed.is_empty() {
            return Err(EngineError::NotReady);
        }
        Ok(sealed)
    }

    /// Sends sealed messages. A `msg` and a `pkmsg` never share a request; a
    /// request holds at most [`MAX_LIST_DEVICES`] bodies and at most
    /// `SEND_PAYLOAD_MAX_BYTES` bytes of payload. The first request decides the result: when it fails, the call fails. A later failure
    /// leaves that group without the message.
    async fn emit(
        &mut self,
        client: &GrappaClient,
        token: &str,
        nick: &str,
        sealed: Vec<Sealed>,
        own: &OwnWire,
        priority: E2eSendPriority,
    ) -> Result<Vec<Emitted>, EngineError> {
        let mut emitted = Vec::new();
        for prekey in [false, true] {
            let group: Vec<&Sealed> = sealed.iter().filter(|s| s.prekey == prekey).collect();
            for chunk in split_by_payload_size(&group, own) {
                match self
                    .emit_group(client, token, nick, &chunk, own, priority)
                    .await
                {
                    Ok(sent) => emitted.push(sent),
                    Err(err) if emitted.is_empty() => return Err(err),
                    Err(_) => {}
                }
            }
        }
        Ok(emitted)
    }

    /// Sends one request with a body for each of `chunk`.
    async fn emit_group(
        &mut self,
        client: &GrappaClient,
        token: &str,
        nick: &str,
        chunk: &[&Sealed],
        own: &OwnWire,
        priority: E2eSendPriority,
    ) -> Result<Emitted, EngineError> {
        let (verb, payload) = chunk_payload(chunk, own);
        let to = match chunk {
            [only] => only.did.as_str(),
            _ => WILDCARD,
        };
        let request = E2eSendRequest::new(
            nick,
            verb,
            &self.own_did,
            to,
            &payload,
            Some(priority),
            None,
        )?;
        // Save the sessions before the send: a skipped Olm message is
        // harmless, a reused one is not.
        for sealed in chunk {
            self.state
                .set_peer_session(&self.network, nick, &sealed.did, &sealed.session)?;
            if let Some(entry) = self.peers.get_mut(&sealed.did) {
                entry.one_time_key = None;
            }
        }
        let answer = client
            .send_e2e_message(token, &self.network, &request)
            .await?;
        if answer.response != SendResponse::Accepted {
            return Err(EngineError::Rejected(answer.response));
        }
        Ok(Emitted {
            dids: chunk.iter().map(|sealed| sealed.did.clone()).collect(),
            msgid: answer.msgid,
        })
    }

    /// Keeps the text of a send for a re-send after a NACK. The memory is
    /// bounded in time and in count.
    fn remember_sent(
        &mut self,
        msgid: &str,
        nick: &str,
        dids: &[String],
        text: &str,
        sends: u8,
        row_id: &str,
    ) {
        let record = SentRecord {
            nick: nick.to_string(),
            dids: dids.to_vec(),
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
            .is_none_or(|record| !record.dids.contains(&row.from_did))
        {
            return;
        }
        let Some(mut record) = self.sent.remove(&reference) else {
            return;
        };
        // The other devices of the message keep their NACK right.
        let nacked = row.from_did.clone();
        let others: Vec<String> = record
            .dids
            .iter()
            .filter(|did| **did != nacked)
            .cloned()
            .collect();
        if !others.is_empty() {
            let mut rest = record.clone();
            rest.dids = others;
            self.sent.insert(reference.clone(), rest);
        }
        record.dids = vec![nacked];
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
            .remove_peer_session(&self.network, &record.nick, &record.dids[0])
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
                did: Some(record.dids[0].clone()),
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

/// Builds the verb and the JSON payload for a request that carries a body for
/// each of `chunk`. All of `chunk` use the same Olm message type.
fn chunk_payload(chunk: &[&Sealed], own: &OwnWire) -> (E2eSendVerb, String) {
    let bodies: BTreeMap<String, String> = chunk
        .iter()
        .map(|sealed| (sealed.did.clone(), sealed.body.clone()))
        .collect();
    if chunk.first().is_some_and(|sealed| sealed.prekey) {
        (
            E2eSendVerb::PkMsg,
            MessagePayload::PreKey(PreKeyPayload {
                v: PAYLOAD_VERSION,
                id: own.id.clone(),
                master: own.master.clone(),
                bodies,
            })
            .to_json(),
        )
    } else {
        (
            E2eSendVerb::Msg,
            MessagePayload::Normal(MsgPayload {
                v: PAYLOAD_VERSION,
                ck: own.id.curve25519.clone(),
                bodies,
            })
            .to_json(),
        )
    }
}

/// Splits `group` into requests of at most [`MAX_LIST_DEVICES`] bodies whose
/// payload fits `SEND_PAYLOAD_MAX_BYTES`. A body that does not fit alone stays
/// in a request of its own: the request builder refuses it.
fn split_by_payload_size<'a>(group: &[&'a Sealed], own: &OwnWire) -> Vec<Vec<&'a Sealed>> {
    let mut chunks: Vec<Vec<&'a Sealed>> = Vec::new();
    let mut current: Vec<&'a Sealed> = Vec::new();
    for &sealed in group {
        current.push(sealed);
        if current.len() > 1
            && (current.len() > MAX_LIST_DEVICES
                || chunk_payload(&current, own).1.len() > SEND_PAYLOAD_MAX_BYTES)
        {
            let last = current.pop();
            chunks.push(std::mem::take(&mut current));
            current.extend(last);
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
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

    /// The checks that `_on_pkmsg`, `_on_msg` and `_own_body` of irc-olm make
    /// on the shape of a payload before they read a body. `dst` is the `to` of
    /// the frame. The error is the name of the drop reason of irc-olm.
    fn irc_olm_takes(
        verb: &str,
        payload: &Value,
        dst: &str,
        from_did: &str,
        own_did: &str,
    ) -> Result<(), &'static str> {
        use crate::e2e_wire::{decode_key, decode_signature, device_certificate_signed_text};
        let key = |value: &Value| {
            value
                .as_str()
                .filter(|text| decode_key(text).is_ok())
                .map(str::to_string)
        };
        if payload["v"] != 2 {
            return Err("bad-version");
        }
        if verb == "pkmsg" {
            let id = &payload["id"];
            let ed = key(&id["ed25519"]).ok_or("malformed-id")?;
            let curve = key(&id["curve25519"]).ok_or("malformed-id")?;
            let id_sig = id["sig"].as_str().ok_or("malformed-id")?;
            if did_from_key_text(&ed).ok().as_deref() != Some(from_did) {
                return Err("from-mismatch");
            }
            let master = key(&payload["master"]["ed25519"]).ok_or("invalid-master")?;
            let ver = payload["master"]["ver"]
                .as_u64()
                .and_then(|ver| u32::try_from(ver).ok())
                .filter(|ver| (1..=MAX_VERSION).contains(ver))
                .ok_or("invalid-master")?;
            let cert = payload["master"]["cert"]
                .as_str()
                .filter(|cert| decode_signature(cert).is_ok())
                .ok_or("invalid-master")?;
            let cert_text =
                device_certificate_signed_text(ver, &ed).map_err(|_| "invalid-master")?;
            verify_signature(&master, cert, &cert_text).map_err(|_| "bad-certificate")?;
            let id_text = device_id_signed_text(&curve, &master);
            verify_signature(&ed, id_sig, id_text.as_bytes()).map_err(|_| "bad-id-block")?;
        } else if key(&payload["ck"]).is_none() {
            return Err("malformed-ck");
        }
        let bodies = payload["bodies"].as_object().ok_or("malformed-bodies")?;
        if !(1..=MAX_LIST_DEVICES).contains(&bodies.len())
            || (dst == WILDCARD) != (bodies.len() > 1)
        {
            return Err("malformed-bodies");
        }
        match bodies.get(own_did) {
            Some(Value::String(_)) => Ok(()),
            _ => Err("not-for-this-device"),
        }
    }

    #[tokio::test]
    async fn the_payloads_that_cordiale_sends_pass_the_shape_checks_of_irc_olm() {
        let alice_id = Ident::new("alice-olm");
        let bob_id = Ident::new("bob-olm");
        let mut alice = alice_id.engine();
        let mut bob = bob_id.engine();
        alice
            .accept_keys("bob", &bob_id.keys())
            .expect("alice reads bob");
        let alice_did = did_from_key_text(&ed(&alice_id.device)).expect("did");
        let bob_did = did_from_key_text(&ed(&bob_id.device)).expect("did");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;

        // The first message of Alice is a pre-key message with the id block
        // and the certificate of the master.
        let (_, first) = alice_sends(&mut alice, &server, "one").await;
        assert_eq!(first["verb"], "pkmsg");
        let payload: Value =
            serde_json::from_str(first["payload"].as_str().expect("payload")).expect("json");
        let to = first["to"].as_str().expect("to");
        assert_eq!(
            irc_olm_takes("pkmsg", &payload, to, &alice_did, &bob_did),
            Ok(())
        );
        // The same payload is refused for the wrong sender, the wrong
        // recipient and the wrong address form.
        assert_eq!(
            irc_olm_takes("pkmsg", &payload, to, &bob_did, &bob_did),
            Err("from-mismatch")
        );
        assert_eq!(
            irc_olm_takes("pkmsg", &payload, to, &alice_did, &alice_did),
            Err("not-for-this-device")
        );
        assert_eq!(
            irc_olm_takes("pkmsg", &payload, WILDCARD, &alice_did, &bob_did),
            Err("malformed-bodies")
        );

        // Bob answers, so the next message of Alice is a normal one.
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
        let client = GrappaClient::new(server.uri());
        let before = server.received_requests().await.expect("requests").len();
        bob.send_text(&client, TOKEN, "alice", "reply", 210)
            .await
            .expect("reply");
        let requests = server.received_requests().await.expect("requests");
        let reply: Value = serde_json::from_slice(&requests[before].body).expect("body");
        let reply_verb = reply["verb"].as_str().expect("verb");
        let reply_payload: Value =
            serde_json::from_str(reply["payload"].as_str().expect("payload")).expect("json");
        assert_eq!(
            irc_olm_takes(
                reply_verb,
                &reply_payload,
                reply["to"].as_str().expect("to"),
                &bob_did,
                &alice_did
            ),
            Ok(())
        );
        let value = row(
            6,
            "bob",
            &bob_did,
            &alice_did,
            reply_verb,
            "msgid1",
            reply["payload"].as_str().expect("payload"),
        );
        let reply_row = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(alice.handle_row(&reply_row, 220), RowOutcome::Stored);

        let (_, second) = alice_sends(&mut alice, &server, "two").await;
        assert_eq!(second["verb"], "msg");
        let msg: Value =
            serde_json::from_str(second["payload"].as_str().expect("payload")).expect("json");
        assert_eq!(
            irc_olm_takes(
                "msg",
                &msg,
                second["to"].as_str().expect("to"),
                &alice_did,
                &bob_did
            ),
            Ok(())
        );
        // A `msg` without the sender curve key is dropped.
        let mut no_ck = msg.clone();
        no_ck.as_object_mut().expect("object").remove("ck");
        assert_eq!(
            irc_olm_takes(
                "msg",
                &no_ck,
                second["to"].as_str().expect("to"),
                &alice_did,
                &bob_did
            ),
            Err("malformed-ck")
        );
    }

    #[tokio::test]
    async fn a_replayed_pkmsg_gives_no_second_row_under_any_row_id_or_msgid() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, body) = alice_sends(&mut p.alice, &server, "once").await;
        let payload = body["payload"].as_str().expect("payload").to_string();
        let original = row(
            5,
            "alice",
            &p.alice_did,
            &p.bob_did,
            "pkmsg",
            "msgid1",
            &payload,
        );
        let item = InboxRow::from_value(&original, PROTOCOL).expect("row");
        assert_eq!(p.bob.handle_row(&item, 200), RowOutcome::Stored);

        // The same message under a new row id: the msgid is a replay.
        let same_msgid = row(
            6,
            "alice",
            &p.alice_did,
            &p.bob_did,
            "pkmsg",
            "msgid1",
            &payload,
        );
        let item = InboxRow::from_value(&same_msgid, PROTOCOL).expect("row");
        assert_eq!(p.bob.handle_row(&item, 201), RowOutcome::Undecryptable);

        // The same ciphertext under a new row id and a new msgid: the Olm
        // message key is used up.
        let new_msgid = row(
            7,
            "alice",
            &p.alice_did,
            &p.bob_did,
            "pkmsg",
            "msgid-new",
            &payload,
        );
        let item = InboxRow::from_value(&new_msgid, PROTOCOL).expect("row");
        assert_eq!(p.bob.handle_row(&item, 202), RowOutcome::Undecryptable);

        let rows = p.bob.history().messages(&conversation_id(NET, "alice"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].text, "once");
    }

    #[tokio::test]
    async fn a_message_for_another_device_gives_no_row() {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, body) = alice_sends(&mut p.alice, &server, "not for you").await;
        let mut payload: Value =
            serde_json::from_str(body["payload"].as_str().expect("payload")).expect("json");
        // The only body names a device that is not this one.
        let sealed = payload["bodies"][&p.bob_did].clone();
        let mut bodies = serde_json::Map::new();
        bodies.insert(p.alice_did.clone(), sealed);
        payload["bodies"] = Value::Object(bodies);
        let value = row(
            5,
            "alice",
            &p.alice_did,
            &p.bob_did,
            "pkmsg",
            "msgid1",
            &payload.to_string(),
        );
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(p.bob.handle_row(&item, 200), RowOutcome::Undecryptable);
        assert!(p
            .bob
            .history()
            .messages(&conversation_id(NET, "alice"))
            .is_empty());
    }

    #[test]
    fn the_inner_text_of_cordiale_equals_the_bytes_of_irc_olm() {
        let all: Value =
            serde_json::from_str(include_str!("../tests/fixtures/e2e/irc_olm_v2.json"))
                .expect("fixture file is JSON");
        let cases = all["from_irc_olm"]["inner"].as_array().expect("cases");
        let mut checked = 0;
        for case in cases.iter().filter(|case| case["kind"] == "text") {
            let lv = u32::try_from(case["lv"].as_u64().expect("lv")).expect("lv");
            let written = InnerOut {
                t: "text",
                peer: None,
                body: case["body"].as_str().expect("body"),
                lv,
                fb: case["fb"].as_str(),
            }
            .to_json();
            assert_eq!(written, case["plain"].as_str().expect("plain"));
            checked += 1;
        }
        assert_eq!(checked, 3);
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
        // The revocation is in the trust state, not in the current list.
        assert!(alice.trust().has_revoked_devices(NET, "bob"));
        assert!(!alice.trust().has_revoked_devices(NET, "carol"));
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

    #[test]
    fn a_keys_row_under_another_master_is_a_trust_change() {
        let alice_id = Ident::new("alice-master");
        let bob_id = Ident::new("bob-master");
        let other_id = Ident::new("bob-other-master");
        let mut alice = alice_id.engine();
        alice
            .accept_keys("bob", &bob_id.keys())
            .expect("alice reads bob");
        assert!(alice.take_trust_changed().is_empty());
        let alice_did = alice.own_did().to_string();
        let value = row(
            4,
            "bob",
            WILDCARD,
            &alice_did,
            "keys",
            "k2",
            &other_id.keys(),
        );
        let keys_row = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(alice.handle_row(&keys_row, 1), RowOutcome::Undecryptable);
        assert_eq!(alice.take_trust_changed(), ["bob"]);
        assert!(alice.take_trust_changed().is_empty());
        // The stored master stays.
        assert!(alice.is_ready("bob"));
    }

    #[tokio::test]
    async fn a_first_message_under_another_master_is_a_trust_change() {
        let mut p = pair();
        // Bob knows another master for the nick of Alice.
        let other_id = Ident::new("alice-other-master");
        p.bob
            .accept_keys("alice", &other_id.keys())
            .expect("bob reads the other master");
        assert!(p.bob.take_trust_changed().is_empty());
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, body) = alice_sends(&mut p.alice, &server, "hello").await;
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
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        assert_eq!(p.bob.handle_row(&item, 200), RowOutcome::Undecryptable);
        assert_eq!(p.bob.take_trust_changed(), ["alice"]);
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
    async fn a_send_goes_to_every_ready_device_of_a_peer_with_two_devices() {
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
        // Both ready devices get a body; the refused device gets none.
        let mut ready = [&other, &bob_id.device]
            .iter()
            .map(|device| did_from_key_text(&ed(device)).expect("did"))
            .collect::<Vec<_>>();
        ready.sort();
        assert_eq!(body["to"], WILDCARD);
        assert_eq!(bodies_of(&body), ready);
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
            r#"{"t":"text"}"#,
            r#"{"t":"copy","peer":"x"}"#,
            r#"{"t":"chal","nonce":"n"}"#,
        ] {
            let inner = Inner::parse(plain.as_bytes()).expect("inner");
            assert_eq!(inner.kind, InnerKind::Other, "{plain}");
        }
        // A list request and a list with a master block.
        let inner = Inner::parse(br#"{"t":"listreq","lv":2}"#).expect("inner");
        assert_eq!(inner.kind, InnerKind::ListReq);
        let list = r#"{"t":"list","master":{"ed25519":"M","list":{"ver":2,"devices":["D"]},"sig":"S"},"lv":2}"#;
        let inner = Inner::parse(list.as_bytes()).expect("inner");
        assert_eq!(
            inner.kind,
            InnerKind::List {
                master: MasterBlock {
                    ed25519: "M".to_string(),
                    list: MasterList {
                        ver: 2,
                        devices: vec!["D".to_string()]
                    },
                    sig: "S".to_string()
                }
            }
        );
        // Not an object with a string `t`.
        for plain in ["not json", "[]", r#"{"body":"x"}"#, r#"{"t":1}"#] {
            assert_eq!(Inner::parse(plain.as_bytes()), None, "{plain}");
        }
        // A bad `lv` is no version.
        let inner = Inner::parse(br#"{"t":"text","body":"x","lv":0}"#).expect("inner");
        assert_eq!(inner.lv, None);
    }

    fn bob_keys_text(bob_id: &Ident, device: &Account, listed: &[String], version: u32) -> String {
        serde_json::to_string(&keys_struct(&bob_id.master, device, listed, version)).expect("json")
    }

    fn inbox_row(id: u64, from: &str, from_did: &str, to_did: &str, sent: &Value) -> InboxRow {
        let value = row(
            id,
            from,
            from_did,
            to_did,
            sent["verb"].as_str().expect("verb"),
            &format!("m{id}"),
            sent["payload"].as_str().expect("payload"),
        );
        InboxRow::from_value(&value, PROTOCOL).expect("row")
    }

    async fn sent_requests(server: &MockServer) -> Vec<Value> {
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .map(|request| serde_json::from_slice(&request.body).expect("body"))
            .collect()
    }

    fn bodies_of(sent: &Value) -> Vec<String> {
        let payload: Value =
            serde_json::from_str(sent["payload"].as_str().expect("payload")).expect("json");
        let mut dids: Vec<String> = payload["bodies"]
            .as_object()
            .expect("bodies")
            .keys()
            .cloned()
            .collect();
        dids.sort();
        dids
    }

    /// Gives the engine a signed own list of `version` with its own device.
    fn raise_own_list(engine: &mut E2eEngine, version: u32) {
        let master = engine.state.master_key().expect("key").expect("master");
        let keys = vec![engine.own_ed25519.clone()];
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

    #[tokio::test]
    async fn a_peer_with_two_trusted_devices_gets_one_message_with_two_bodies() {
        let alice_id = Ident::new("alice");
        let bob_id = Ident::new("bob");
        let second = fresh_device();
        let mut alice = alice_id.engine();
        let listed = [ed(&bob_id.device), ed(&second)];
        alice
            .accept_keys("bob", &bob_keys_text(&bob_id, &bob_id.device, &listed, 1))
            .expect("first device");
        alice
            .accept_keys("bob", &bob_keys_text(&bob_id, &second, &listed, 1))
            .expect("second device");
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (sent, body) = alice_sends(&mut alice, &server, "hello both").await;
        assert_eq!(sent_requests(&server).await.len(), 1);
        assert_eq!(body["verb"], "pkmsg");
        assert_eq!(body["to"], WILDCARD);
        assert!(!body.to_string().contains("hello both"));
        let mut expected = vec![
            did_from_key_text(&ed(&bob_id.device)).expect("did"),
            did_from_key_text(&ed(&second)).expect("did"),
        ];
        expected.sort();
        assert_eq!(bodies_of(&body), expected);
        assert!(sent.key.is_some());
    }

    #[tokio::test]
    async fn a_device_that_is_not_on_the_verified_list_gets_no_body() {
        let alice_id = Ident::new("alice");
        let bob_id = Ident::new("bob");
        let outsider = fresh_device();
        let mut alice = alice_id.engine();
        let listed = [ed(&bob_id.device)];
        alice
            .accept_keys("bob", &bob_keys_text(&bob_id, &bob_id.device, &listed, 1))
            .expect("listed device");
        assert!(alice
            .accept_keys("bob", &bob_keys_text(&bob_id, &outsider, &listed, 1))
            .is_err());
        let server = MockServer::start().await;
        mount_send(&server, "msgid1").await;
        let (_, body) = alice_sends(&mut alice, &server, "only the listed one").await;
        let bob_did = did_from_key_text(&ed(&bob_id.device)).expect("did");
        assert_eq!(bodies_of(&body), vec![bob_did.clone()]);
        assert_eq!(body["to"], bob_did.as_str());
    }

    /// Alice sends a first text to Bob, and Bob reads it: both have a session.
    async fn started_pair() -> Pair {
        let mut p = pair();
        let server = MockServer::start().await;
        mount_send(&server, "first").await;
        let (_, body) = alice_sends(&mut p.alice, &server, "start").await;
        let item = inbox_row(1, "alice", &p.alice_did, &p.bob_did, &body);
        assert_eq!(p.bob.handle_row(&item, 10), RowOutcome::Stored);
        // Bob knows Alice only from the certificate, so her `lv` 1 is higher
        // than his stored version 0.
        assert_eq!(p.bob.list_jobs.len(), 1);
        assert!(!p.bob.list_jobs[0].reply);
        p.bob.list_jobs.clear();
        p
    }

    #[tokio::test]
    async fn a_listreq_gets_the_own_signed_list_and_the_list_is_applied() {
        let mut p = started_pair().await;
        // Bob has a newer list than Alice knows.
        raise_own_list(&mut p.bob, 2);

        // Alice asks for the list of Bob.
        p.alice.list_jobs.push(ListJob {
            nick: "bob".to_string(),
            did: p.bob_did.clone(),
            reply: false,
        });
        let alice_server = MockServer::start().await;
        mount_send(&alice_server, "ask").await;
        let client = GrappaClient::new(alice_server.uri());
        assert_eq!(p.alice.send_list_messages(&client, TOKEN).await, 1);
        let ask = sent_requests(&alice_server).await.remove(0);
        assert_eq!(ask["to"], p.bob_did.as_str());
        let item = inbox_row(2, "alice", &p.alice_did, &p.bob_did, &ask);
        assert_eq!(p.bob.handle_row(&item, 20), RowOutcome::Ignored);

        // Bob answers with the own signed list.
        let bob_server = MockServer::start().await;
        mount_send(&bob_server, "answer").await;
        let client = GrappaClient::new(bob_server.uri());
        assert_eq!(p.bob.send_list_messages(&client, TOKEN).await, 1);
        let answer = sent_requests(&bob_server).await.remove(0);
        assert_eq!(answer["verb"], "msg");
        assert_eq!(bodies_of(&answer), vec![p.alice_did.clone()]);
        assert_eq!(p.alice.state.trust().list_version(NET, "bob"), 1);
        let item = inbox_row(3, "bob", &p.bob_did, &p.alice_did, &answer);
        assert_eq!(p.alice.handle_row(&item, 30), RowOutcome::Ignored);
        assert_eq!(p.alice.state.trust().list_version(NET, "bob"), 2);
        // The list brought the version up: no listreq follows.
        assert!(p.alice.list_jobs.is_empty());
    }

    #[tokio::test]
    async fn a_second_listreq_of_the_same_device_in_a_minute_gets_no_answer() {
        let mut p = started_pair().await;
        let did = p.alice_did.clone();
        p.bob.queue_list_reply("alice", &did);
        p.bob.queue_list_reply("alice", &did);
        assert_eq!(p.bob.list_jobs.len(), 1);
    }

    #[test]
    fn a_list_that_does_not_verify_or_is_not_newer_changes_nothing() {
        let mut p = pair();
        let master = p.bob.state.master_key().expect("key").expect("master");
        let devices = vec![p.bob.own_ed25519.clone()];
        let block = |version: u32, signer: &Account| MasterBlock {
            ed25519: ed(&master),
            list: MasterList {
                ver: version,
                devices: devices.clone(),
            },
            sig: build_signed_list_signature(version, &devices, |text| {
                signer.sign(text).to_base64()
            })
            .expect("list"),
        };
        assert_eq!(p.alice.state.trust().list_version(NET, "bob"), 1);
        p.alice
            .apply_list_message("bob", &block(3, &master))
            .expect("newer list");
        assert_eq!(p.alice.state.trust().list_version(NET, "bob"), 3);
        // A lower version.
        let _ = p.alice.apply_list_message("bob", &block(2, &master));
        assert_eq!(p.alice.state.trust().list_version(NET, "bob"), 3);
        // A signature of another key.
        let other = Account::new();
        assert!(p
            .alice
            .apply_list_message("bob", &block(4, &other))
            .is_err());
        assert_eq!(p.alice.state.trust().list_version(NET, "bob"), 3);
        // Another master is a trust alarm.
        let foreign = MasterBlock {
            ed25519: ed(&other),
            list: MasterList {
                ver: 5,
                devices: devices.clone(),
            },
            sig: build_signed_list_signature(5, &devices, |text| other.sign(text).to_base64())
                .expect("list"),
        };
        assert!(p.alice.apply_list_message("bob", &foreign).is_err());
        assert_eq!(p.alice.take_trust_changed(), vec!["bob".to_string()]);
        assert_eq!(p.alice.state.trust().list_version(NET, "bob"), 3);
    }

    #[tokio::test]
    async fn a_higher_lv_of_a_peer_causes_one_listreq() {
        let mut p = started_pair().await;
        raise_own_list(&mut p.bob, 2);
        let bob_server = MockServer::start().await;
        for msgid in ["text1", "text2"] {
            Mock::given(method("POST"))
                .and(path(format!("/networks/{NET}/e2e/messages")))
                .respond_with(
                    ResponseTemplate::new(202).set_body_json(json!({"id": 1, "msgid": msgid})),
                )
                .up_to_n_times(1)
                .mount(&bob_server)
                .await;
        }
        let client = GrappaClient::new(bob_server.uri());
        for (text, at) in [("one", 40), ("two", 41)] {
            p.bob
                .send_text(&client, TOKEN, "alice", text, at)
                .await
                .expect("text");
        }
        let texts = sent_requests(&bob_server).await;
        let first = inbox_row(4, "bob", &p.bob_did, &p.alice_did, &texts[0]);
        assert_eq!(p.alice.handle_row(&first, 50), RowOutcome::Stored);
        let second = inbox_row(5, "bob", &p.bob_did, &p.alice_did, &texts[1]);
        assert_eq!(p.alice.handle_row(&second, 51), RowOutcome::Stored);
        assert_eq!(p.alice.list_jobs.len(), 1);

        let alice_server = MockServer::start().await;
        mount_send(&alice_server, "ask").await;
        let client = GrappaClient::new(alice_server.uri());
        assert_eq!(p.alice.send_list_messages(&client, TOKEN).await, 1);
        let requests = sent_requests(&alice_server).await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["to"], p.bob_did.as_str());
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
        assert_eq!(body["to"], WILDCARD);
        let first = bodies_of(&body)[0].clone();

        // The other device has a session; the re-send goes only to the
        // device that sent the NACK.
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

    #[tokio::test]
    async fn a_peer_that_never_answers_is_never_refused() {
        // No source says that a peer has no E2E, and silence is not a signal.
        // The text expires as late, the peer stays capable, and the next text
        // asks for the keys again (issue 482).
        let (mut alice, _bob) = alice_without_keys("silent");
        let client = GrappaClient::new("http://127.0.0.1:9");
        alice
            .send_or_queue(&client, TOKEN, "bob", "first", 100)
            .await
            .expect("queued");
        assert_eq!(alice.take_keys_wanted(), vec!["bob".to_string()]);
        alice.clock.advance(secs(88));
        let late = alice.expire_queue();
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].reason, DropReason::Late);
        assert!(alice.peer_capable("bob"));
        let again = alice
            .send_or_queue(&client, TOKEN, "bob", "second", 200)
            .await
            .expect("queued again");
        assert!(again.msgid.is_none());
        assert_eq!(alice.take_keys_wanted(), vec!["bob".to_string()]);
        assert!(alice.peer_capable("bob"));
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
        // The own list may be behind, so the row waits. After the last try
        // the row is refused for good and acknowledged.
        let outcome = t.second.handle_row(&item, 150);
        assert_eq!(outcome, RowOutcome::StaleList);
        assert!(!outcome.acknowledge());
        let outcome = t.second.handle_row(&item, 151);
        assert_eq!(outcome, RowOutcome::Undecryptable);
        assert!(outcome.acknowledge());
        assert!(t.second.history().conversation_ids().is_empty());
    }

    #[tokio::test]
    async fn a_copy_from_a_newly_paired_device_is_read_after_the_own_list_syncs() {
        let mut t = twins("copy-paired");
        let server = MockServer::start().await;
        mount_copy_routes(&server, &t).await;
        send_and_copy(&mut t, &server, 100).await;
        let value = copy_inbox_row(&t, 9, &body_of(&server, 2).await);
        let item = InboxRow::from_value(&value, PROTOCOL).expect("row");
        set_own_list(&mut t.second, &t.master, 1, &[&t.second_device]);
        assert_eq!(t.second.handle_row(&item, 150), RowOutcome::StaleList);
        set_own_list(
            &mut t.second,
            &t.master,
            2,
            &[&t.first_device, &t.second_device],
        );
        assert_eq!(t.second.handle_row(&item, 151), RowOutcome::Stored);
    }

    #[tokio::test]
    async fn a_device_paired_after_the_original_gets_no_copy_of_it() {
        let mut t = twins("copy-backfill");
        let server = MockServer::start().await;
        mount_copy_routes(&server, &t).await;
        let client = GrappaClient::new(server.uri());
        t.first
            .send_text(&client, TOKEN, "carol", "hello carol", 100)
            .await
            .expect("send");
        // A third device joins before the copies go out.
        let all = [&t.first_device, &t.second_device, &t.third_device];
        set_own_list(&mut t.first, &t.master, 1, &all);
        let report = t
            .first
            .send_copies(&client, TOKEN, PROTOCOL, "bob", 100)
            .await;
        assert_eq!(report.queued, vec![t.second_did.clone()]);
        let third_did = did_from_key_text(&ed(&t.third_device)).expect("did");
        assert!(paths_of(&server)
            .await
            .iter()
            .all(|route| !route.contains(&third_did)));
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
