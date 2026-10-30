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

//! Data for the E2E views: the state of one message, local history search
//! and the delete confirmation. This module reads the sealed history of
//! the core and holds no crypto and no wire rule. The Slint views and the
//! worker commands use it; the store calls run on the worker thread, never
//! on the Slint event thread.

// The views and the worker commands that call this module are a later step.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::sync::Mutex;

use cordiale_core::e2e_engine::{locked_label, route_for_window, SendRoute};
use cordiale_core::e2e_pacing::DropReason;
use cordiale_core::e2e_pairing::{ClosedReason, PairingCallError};
use cordiale_core::e2e_pairing_flow::{DriveError, EndReason, FlowError, PairingStatus};
use cordiale_core::e2e_refusal::E2eRouteError;
use cordiale_core::e2e_revoke::{RevokeError, Revoked};
use cordiale_core::e2e_store::{E2eHistoryStore, E2eMessage, E2eStoreError};

/// What the user sees for one E2E message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageState {
    /// Decrypted and checked.
    Encrypted,
    /// Waiting for a key or a device list.
    Pending,
    /// Decryption or a check failed.
    Failed,
    /// The text is not on this device.
    Unavailable,
}

impl MessageState {
    /// The `status-kind` style key that selects the translated label.
    pub fn key(self) -> &'static str {
        match self {
            MessageState::Encrypted => "e2e-state-encrypted",
            MessageState::Pending => "e2e-state-pending",
            MessageState::Failed => "e2e-state-failed",
            MessageState::Unavailable => "e2e-state-unavailable",
        }
    }

    /// Parses a key from `key`; any other text is `None`.
    pub fn from_key(key: &str) -> Option<MessageState> {
        [
            MessageState::Encrypted,
            MessageState::Pending,
            MessageState::Failed,
            MessageState::Unavailable,
        ]
        .into_iter()
        .find(|state| state.key() == key)
    }

    /// Only an encrypted message shows its text.
    pub fn shows_text(self) -> bool {
        self == MessageState::Encrypted
    }
}

/// The local data a delete removes. The view shows it before the user
/// confirms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletePlan {
    /// `Some` for one conversation, `None` for the whole E2E history.
    pub conversation_id: Option<String>,
    pub conversations: usize,
    pub messages: usize,
}

/// Counts what `delete_conversation` (or `delete_all` when `conversation_id`
/// is `None`) would remove. It changes nothing.
pub fn delete_plan(store: &E2eHistoryStore, conversation_id: Option<&str>) -> DeletePlan {
    match conversation_id {
        Some(id) => {
            let messages = store.messages(id).len();
            DeletePlan {
                conversation_id: Some(id.to_string()),
                conversations: usize::from(messages > 0),
                messages,
            }
        }
        None => {
            let ids = store.conversation_ids();
            let messages = ids.iter().map(|id| store.messages(id).len()).sum();
            DeletePlan {
                conversation_id: None,
                conversations: ids.len(),
                messages,
            }
        }
    }
}

/// Runs a confirmed delete. `confirmed` is false until the user accepts the
/// plan, and then nothing is removed. Only the named data goes.
pub fn delete_confirmed(
    store: &mut E2eHistoryStore,
    plan: &DeletePlan,
    confirmed: bool,
) -> Result<bool, E2eStoreError> {
    if !confirmed {
        return Ok(false);
    }
    match &plan.conversation_id {
        Some(id) => store.delete_conversation(id)?,
        None => store.delete_all()?,
    }
    Ok(true)
}

/// Local search for the history view. The core folds the case, so the
/// result follows its Unicode rules. Nothing leaves the device.
pub fn search_history<'a>(
    store: &'a E2eHistoryStore,
    conversation_id: Option<&str>,
    needle: &str,
) -> Vec<&'a E2eMessage> {
    store.search(conversation_id, needle)
}

/// The `status-kind` key and the hint text of a pairing state. Pairing is
/// E2E control state shown in the status bar: no pairing text is ever a chat
/// line of a query. The hint is the two-digit code or empty.
pub fn pairing_status_key(status: &PairingStatus) -> (&'static str, String) {
    match status {
        PairingStatus::Waiting => ("e2e-pair-waiting", String::new()),
        PairingStatus::Code(code) => ("e2e-pair-code", code.clone()),
        PairingStatus::AwaitingPeer => ("e2e-pair-await", String::new()),
        PairingStatus::Done => ("e2e-pair-done", String::new()),
        PairingStatus::Ended(reason) => (pairing_end_key(*reason), String::new()),
    }
}

fn pairing_end_key(reason: EndReason) -> &'static str {
    match reason {
        EndReason::Cancelled | EndReason::Closed(ClosedReason::Closed | ClosedReason::Replaced) => {
            "e2e-pair-cancelled"
        }
        EndReason::Timeout | EndReason::Closed(ClosedReason::Expired) => "e2e-pair-timeout",
        EndReason::WrongCode => "e2e-pair-wrong-code",
        EndReason::BadChannel | EndReason::BadMessage | EndReason::Failed => "e2e-pair-failed",
    }
}

/// The `status-kind` key of a failed pairing step.
pub fn pairing_error_key(error: &DriveError) -> &'static str {
    match error {
        DriveError::Call(call) if matches!(**call, PairingCallError::Unavailable) => {
            "e2e-pair-unavailable"
        }
        DriveError::Flow(FlowError::WrongCode) => "e2e-pair-wrong-code",
        DriveError::Flow(FlowError::NotActive | FlowError::NoChannel) => "e2e-pair-none",
        _ => "e2e-pair-failed",
    }
}

/// The `status-kind` key and the hint of a revoke result. The hint is the id
/// of the revoked device after a success, and empty otherwise. A failed
/// network step keeps the revoke pending: the user tries again. The result
/// is E2E control state shown in the status bar. It never enters a query.
pub fn revoke_status_key(result: &Result<Revoked, RevokeError>) -> (&'static str, String) {
    match result {
        Ok(done) => ("e2e-revoke-done", done.did.clone()),
        Err(RevokeError::Route(E2eRouteError::Unavailable)) => {
            ("e2e-revoke-unavailable", String::new())
        }
        Err(RevokeError::Route(_) | RevokeError::Store(_)) => ("e2e-revoke-pending", String::new()),
        Err(_) => ("e2e-revoke-failed", String::new()),
    }
}

/// The `status-kind` key of a reset result. The locked query has no identity
/// after a reset and never falls back to clear text.
pub fn reset_status_key(result: &Result<(), RevokeError>) -> &'static str {
    match result {
        Ok(()) => "e2e-reset-done",
        Err(RevokeError::Route(E2eRouteError::Unavailable)) => "e2e-reset-unavailable",
        Err(RevokeError::Route(_) | RevokeError::Store(_)) => "e2e-reset-pending",
        Err(_) => "e2e-reset-failed",
    }
}

/// The two lanes of one peer. The plain lane is the legacy query `<user>`.
/// The locked lane is the local E2E entry `🔒<user>`. A row is in one lane
/// only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryLane {
    Plain,
    Locked,
}

/// The identity of a local query window: network, lane and the real peer
/// nick. The display label is made from the parts and is never stored in the
/// nick.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalQuery {
    pub network: String,
    pub lane: QueryLane,
    pub nick: String,
}

impl LocalQuery {
    pub fn new(network: &str, lane: QueryLane, nick: &str) -> Self {
        LocalQuery {
            network: network.to_string(),
            lane,
            nick: nick.to_string(),
        }
    }

    /// Reads the identity of a window from its network and window name.
    pub fn from_window(network: &str, window_name: &str) -> Self {
        match route_for_window(window_name) {
            SendRoute::Encrypted { nick } => LocalQuery::new(network, QueryLane::Locked, &nick),
            SendRoute::Plain { nick } => LocalQuery::new(network, QueryLane::Plain, &nick),
        }
    }

    /// The window name used in the keys of selection, history, drafts,
    /// unread counts and message status. The two lanes of one peer give two
    /// different names.
    pub fn window_name(&self) -> String {
        match self.lane {
            QueryLane::Plain => self.nick.clone(),
            QueryLane::Locked => locked_label(&self.nick),
        }
    }

    /// The `(network, window name)` key of the window.
    pub fn key(&self) -> (String, String) {
        (self.network.clone(), self.window_name())
    }

    pub fn is_locked(&self) -> bool {
        self.lane == QueryLane::Locked
    }
}

/// What the open chat knows about its encryption. The order of the variants
/// is the order of priority when two states apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatState {
    /// A legacy query: clear text.
    ClearText,
    /// The E2E identity of this device was reset.
    Reset,
    /// No engine for this network.
    Unavailable,
    /// The master key of the peer changed.
    TrustAlarm,
    /// A device pairing is open.
    Pairing,
    /// A device of the peer was revoked and no device is left to send to.
    Revoked,
    /// The keys of the peer are missing.
    MissingKeys,
    /// The last sent text was not sent.
    SendFailed,
    /// The last sent text waited too long for keys.
    Expired,
    /// The master key of the peer has no SAS check.
    SasPending,
    /// Encryption is active.
    Active,
}

impl ChatState {
    /// The `status-kind` style key that selects the translated banner text.
    pub fn key(self) -> &'static str {
        match self {
            ChatState::ClearText => "e2e-chat-clear",
            ChatState::Reset => "e2e-chat-reset",
            ChatState::Unavailable => "e2e-chat-unavailable",
            ChatState::TrustAlarm => "e2e-chat-trust",
            ChatState::Pairing => "e2e-chat-pairing",
            ChatState::Revoked => "e2e-chat-revoked",
            ChatState::MissingKeys => "e2e-chat-keys",
            ChatState::SendFailed => "e2e-chat-send-failed",
            ChatState::Expired => "e2e-chat-expired",
            ChatState::SasPending => "e2e-chat-sas",
            ChatState::Active => "e2e-chat-active",
        }
    }
}

/// The facts about one locked entry. The worker reads them from the engine
/// and the session; the state follows from them.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChatSignals {
    pub reset: bool,
    pub engine: bool,
    pub trust_alarm: bool,
    pub pairing: bool,
    pub peer_revoked: bool,
    pub ready: bool,
    pub sas_verified: bool,
    /// The drop reason of the newest sent row, if it was dropped.
    pub last_drop: Option<DropReason>,
}

/// The state of a locked entry.
pub fn locked_chat_state(signals: &ChatSignals) -> ChatState {
    if signals.reset {
        ChatState::Reset
    } else if !signals.engine {
        ChatState::Unavailable
    } else if signals.trust_alarm {
        ChatState::TrustAlarm
    } else if signals.pairing {
        ChatState::Pairing
    } else if !signals.ready && signals.peer_revoked {
        ChatState::Revoked
    } else if !signals.ready {
        ChatState::MissingKeys
    } else if matches!(
        signals.last_drop,
        Some(DropReason::SendFailed | DropReason::SessionEnded)
    ) {
        ChatState::SendFailed
    } else if signals.last_drop == Some(DropReason::Late) {
        ChatState::Expired
    } else if !signals.sas_verified {
        ChatState::SasPending
    } else {
        ChatState::Active
    }
}

/// The own devices of the open engines. The notice of an undeliverable row
/// compares its device with this list.
static OWN_DEVICES: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Records the `did` of the device of an open engine.
pub fn register_own_device(did: &str) {
    if let Ok(mut devices) = OWN_DEVICES.lock() {
        devices.insert(did.to_string());
    }
}

fn is_own_device(did: &str) -> bool {
    OWN_DEVICES
        .lock()
        .map(|devices| devices.contains(did))
        .unwrap_or(false)
}

/// The text of the row that Grappa writes when a device will never read some
/// messages of a peer: `meta.e2e_undeliverable` is the count and
/// `meta.e2e_device` the `did` of the device. `None` when the row is not such
/// a row. A row without a device comes from a server before protocol 49 and
/// counts for this device.
pub fn undeliverable_text(payload: &serde_json::Value, peer: &str) -> Option<String> {
    undeliverable_text_for(payload, peer, is_own_device)
}

fn undeliverable_text_for(
    payload: &serde_json::Value,
    peer: &str,
    is_own: impl Fn(&str) -> bool,
) -> Option<String> {
    let meta = payload.get("meta")?;
    let count = meta.get("e2e_undeliverable")?.as_u64()?;
    let messages = if count == 1 { "message" } else { "messages" };
    match meta.get("e2e_device").and_then(serde_json::Value::as_str) {
        Some(did) if !is_own(did) => Some(format!(
            "*** {peer} sent {count} encrypted {messages} that cannot be read on your other device {did}"
        )),
        _ => Some(format!(
            "*** {peer} sent you {count} encrypted {messages} that cannot be read here"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{Generate, Key};
    use chacha20poly1305::XChaCha20Poly1305;
    use cordiale_core::e2e_store::E2eKeyProvider;

    struct FixedKey([u8; 32]);

    impl E2eKeyProvider for FixedKey {
        fn load_or_create_key(&self) -> Result<[u8; 32], E2eStoreError> {
            Ok(self.0)
        }
    }

    /// A random key for one test; no key is written in the source.
    fn fresh_key() -> FixedKey {
        let key = Key::<XChaCha20Poly1305>::generate();
        FixedKey(<[u8; 32]>::try_from(key.as_slice()).expect("key length"))
    }

    fn row(id: &str, conversation: &str, at: i64, text: &str) -> E2eMessage {
        E2eMessage {
            id: id.into(),
            conversation_id: conversation.into(),
            sender_device: "device".into(),
            sent_at: at,
            text: text.into(),
            encrypted: true,
        }
    }

    fn open(dir: &tempfile::TempDir) -> E2eHistoryStore {
        E2eHistoryStore::open(dir.path().join("history.bin"), &fresh_key()).expect("open")
    }

    #[test]
    fn pairing_states_map_to_distinct_status_keys() {
        let code = pairing_status_key(&PairingStatus::Code("42".to_string()));
        assert_eq!(code, ("e2e-pair-code", "42".to_string()));
        let cases = [
            (PairingStatus::Waiting, "e2e-pair-waiting"),
            (PairingStatus::AwaitingPeer, "e2e-pair-await"),
            (PairingStatus::Done, "e2e-pair-done"),
            (
                PairingStatus::Ended(EndReason::Cancelled),
                "e2e-pair-cancelled",
            ),
            (PairingStatus::Ended(EndReason::Timeout), "e2e-pair-timeout"),
            (
                PairingStatus::Ended(EndReason::Closed(ClosedReason::Expired)),
                "e2e-pair-timeout",
            ),
            (
                PairingStatus::Ended(EndReason::WrongCode),
                "e2e-pair-wrong-code",
            ),
            (PairingStatus::Ended(EndReason::Failed), "e2e-pair-failed"),
        ];
        for (status, key) in cases {
            let (found, hint) = pairing_status_key(&status);
            assert_eq!(found, key, "{status:?}");
            assert!(hint.is_empty());
        }
    }

    #[test]
    fn pairing_errors_map_to_status_keys() {
        let old = DriveError::Call(Box::new(PairingCallError::Unavailable));
        assert_eq!(pairing_error_key(&old), "e2e-pair-unavailable");
        let wrong = DriveError::Flow(FlowError::WrongCode);
        assert_eq!(pairing_error_key(&wrong), "e2e-pair-wrong-code");
        let none = DriveError::Flow(FlowError::NotActive);
        assert_eq!(pairing_error_key(&none), "e2e-pair-none");
        let other = DriveError::Flow(FlowError::TooLarge);
        assert_eq!(pairing_error_key(&other), "e2e-pair-failed");
    }

    #[test]
    fn revoke_and_reset_results_map_to_status_keys() {
        let done = Revoked {
            did: "abcdefghijk".to_string(),
            list_version: 2,
        };
        assert_eq!(
            revoke_status_key(&Ok(done)),
            ("e2e-revoke-done", "abcdefghijk".to_string())
        );
        let old = RevokeError::Route(E2eRouteError::Unavailable);
        assert_eq!(revoke_status_key(&Err(old)).0, "e2e-revoke-unavailable");
        let old = RevokeError::Route(E2eRouteError::Unavailable);
        assert_eq!(reset_status_key(&Err(old)), "e2e-reset-unavailable");
        let unknown = RevokeError::UnknownDevice;
        assert_eq!(revoke_status_key(&Err(unknown)).0, "e2e-revoke-failed");
        assert_eq!(reset_status_key(&Ok(())), "e2e-reset-done");
        let pending = RevokeError::ResetPending;
        assert_eq!(reset_status_key(&Err(pending)), "e2e-reset-failed");
    }

    #[test]
    fn message_states_have_distinct_keys_and_only_encrypted_shows_text() {
        let all = [
            MessageState::Encrypted,
            MessageState::Pending,
            MessageState::Failed,
            MessageState::Unavailable,
        ];
        for state in all {
            assert_eq!(MessageState::from_key(state.key()), Some(state));
            assert_eq!(state.shows_text(), state == MessageState::Encrypted);
        }
        let mut keys: Vec<&str> = all.iter().map(|state| state.key()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), all.len());
        assert_eq!(MessageState::from_key("other"), None);
    }

    #[test]
    fn delete_plan_counts_only_the_named_data() {
        let dir = tempfile::tempdir().expect("dir");
        let mut store = open(&dir);
        store.append(row("1", "a", 1, "one")).expect("append");
        store.append(row("2", "a", 2, "two")).expect("append");
        store.append(row("3", "b", 3, "three")).expect("append");

        let one = delete_plan(&store, Some("a"));
        assert_eq!((one.conversations, one.messages), (1, 2));
        let all = delete_plan(&store, None);
        assert_eq!((all.conversations, all.messages), (2, 3));
        let none = delete_plan(&store, Some("missing"));
        assert_eq!((none.conversations, none.messages), (0, 0));
    }

    #[test]
    fn delete_needs_confirmation_and_keeps_other_conversations() {
        let dir = tempfile::tempdir().expect("dir");
        let mut store = open(&dir);
        store.append(row("1", "a", 1, "one")).expect("append");
        store.append(row("2", "b", 2, "two")).expect("append");
        let plan = delete_plan(&store, Some("a"));

        assert!(!delete_confirmed(&mut store, &plan, false).expect("declined"));
        assert_eq!(store.messages("a").len(), 1);

        assert!(delete_confirmed(&mut store, &plan, true).expect("confirmed"));
        assert!(store.messages("a").is_empty());
        assert_eq!(store.messages("b").len(), 1);
    }

    #[test]
    fn the_two_lanes_of_one_peer_have_two_keys_and_one_real_nick() {
        let plain = LocalQuery::new("net", QueryLane::Plain, "ada");
        let locked = LocalQuery::new("net", QueryLane::Locked, "ada");
        assert_ne!(plain.key(), locked.key());
        assert_eq!(plain.window_name(), "ada");
        assert_eq!(locked.window_name(), locked_label("ada"));
        // The label is for display: the identity keeps the real nick.
        assert_eq!(
            LocalQuery::from_window("net", &locked.window_name()),
            locked
        );
        assert_eq!(LocalQuery::from_window("net", "ada"), plain);
        assert_eq!(locked.nick, "ada");
        assert!(locked.is_locked() && !plain.is_locked());
    }

    fn ready() -> ChatSignals {
        ChatSignals {
            engine: true,
            ready: true,
            sas_verified: true,
            ..ChatSignals::default()
        }
    }

    #[test]
    fn every_listed_chat_state_is_reachable_and_has_its_own_key() {
        let cases = [
            (
                ChatSignals {
                    reset: true,
                    ..ready()
                },
                ChatState::Reset,
            ),
            (
                ChatSignals {
                    engine: false,
                    ..ready()
                },
                ChatState::Unavailable,
            ),
            (
                ChatSignals {
                    trust_alarm: true,
                    ..ready()
                },
                ChatState::TrustAlarm,
            ),
            (
                ChatSignals {
                    pairing: true,
                    ..ready()
                },
                ChatState::Pairing,
            ),
            (
                ChatSignals {
                    ready: false,
                    peer_revoked: true,
                    ..ready()
                },
                ChatState::Revoked,
            ),
            (
                ChatSignals {
                    ready: false,
                    ..ready()
                },
                ChatState::MissingKeys,
            ),
            (
                ChatSignals {
                    last_drop: Some(DropReason::SendFailed),
                    ..ready()
                },
                ChatState::SendFailed,
            ),
            (
                ChatSignals {
                    last_drop: Some(DropReason::SessionEnded),
                    ..ready()
                },
                ChatState::SendFailed,
            ),
            (
                ChatSignals {
                    last_drop: Some(DropReason::Late),
                    ..ready()
                },
                ChatState::Expired,
            ),
            (
                ChatSignals {
                    sas_verified: false,
                    ..ready()
                },
                ChatState::SasPending,
            ),
            (ready(), ChatState::Active),
        ];
        let mut keys = vec![ChatState::ClearText.key()];
        for (signals, expected) in cases {
            let state = locked_chat_state(&signals);
            assert_eq!(state, expected);
            keys.push(state.key());
        }
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 11);
    }

    #[test]
    fn a_reset_wins_over_every_other_chat_state() {
        let signals = ChatSignals {
            reset: true,
            trust_alarm: true,
            pairing: true,
            ..ready()
        };
        assert_eq!(locked_chat_state(&signals), ChatState::Reset);
    }

    #[test]
    fn an_undeliverable_notice_names_the_device_of_the_meta() {
        let row = serde_json::json!({
            "kind": "server_event",
            "meta": {"e2e_undeliverable": 3, "e2e_device": "other-device"}
        });
        let here = |did: &str| did == "this-device";
        let text = undeliverable_text_for(&row, "ada", here).expect("notice");
        assert!(text.contains("other-device") && text.contains("other device"));
        assert!(!text.contains("cannot be read here"));

        let row = serde_json::json!({
            "kind": "server_event",
            "meta": {"e2e_undeliverable": 1, "e2e_device": "this-device"}
        });
        let text = undeliverable_text_for(&row, "ada", here).expect("notice");
        assert_eq!(
            text,
            "*** ada sent you 1 encrypted message that cannot be read here"
        );

        let old = serde_json::json!({"kind": "server_event", "meta": {"e2e_undeliverable": 2}});
        let text = undeliverable_text_for(&old, "ada", here).expect("notice");
        assert!(text.ends_with("cannot be read here"));

        let other = serde_json::json!({"kind": "server_event", "meta": {}});
        assert!(undeliverable_text_for(&other, "ada", here).is_none());
    }

    #[test]
    fn search_is_local_and_ignores_case() {
        let dir = tempfile::tempdir().expect("dir");
        let mut store = open(&dir);
        store
            .append(row("1", "a", 1, "Hello World"))
            .expect("append");
        store.append(row("2", "b", 2, "other")).expect("append");
        assert_eq!(search_history(&store, None, "hello").len(), 1);
        assert!(search_history(&store, Some("b"), "hello").is_empty());
        assert!(search_history(&store, None, "").is_empty());
    }
}
