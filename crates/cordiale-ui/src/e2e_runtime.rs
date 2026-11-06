//! The E2E engines of the signed-in session and the locked query windows.
//!
//! Each network has at most one engine of the core. The worker opens it when
//! the session connects and the network has an E2E identity on this device.
//! A network without an identity has no engine, and then nothing here shows a
//! locked entry.
//!
//! A peer has two query entries. `<user>` is the legacy query of Grappa and
//! keeps the existing plain path. `🔒<user>` is a local entry: its rows come
//! from the sealed E2E history and its sends go through the engine only. The
//! label is for display. The engine and the requests get the real nick, and a
//! failed encryption shows an error and sends nothing.

use super::*;

use std::collections::{BTreeSet, VecDeque};

use cordiale_core::e2e_device::E2eError;
use cordiale_core::e2e_engine::{
    action_body, action_text, conversation_id, history_peers_of, locked_label, route_for_window,
    E2eEngine, EngineError, RowOutcome, SendRoute, OWN_DEVICE,
};
use cordiale_core::e2e_pacing::DropReason;
use cordiale_core::e2e_pairing::{PairingOffer, PairingPush};
use cordiale_core::e2e_pairing_flow::{
    self as pairing, PairingContext, PairingSession, PairingStatus, StalePairing,
};
use cordiale_core::e2e_protocol::{
    pairing_offer_available, E2eOperation, CONSENT_MIN_PROTOCOL, NO_SUCH_NICK_MIN_PROTOCOL,
};
use cordiale_core::e2e_provision::{provision_device, ProvisionError};
use cordiale_core::e2e_revoke::{
    finish_pending_revoke, reset_identity, resume_reset, revoke_device, OwnRoutes,
    ResetConfirmation,
};
use cordiale_core::e2e_store::{E2eHistoryStore, E2eMessage};
use cordiale_core::e2e_wire::did_from_key_text;
use cordiale_core::phoenix::PhoenixMessage;
use cordiale_core::rest::{E2eConsentLine, E2eRequest, E2eRequestCreate, E2eRequestState};
use cordiale_core::session::{route_e2e_message, route_e2e_pairing, route_e2e_pairing_offer};
use cordiale_core::slash::{E2eManageAction, E2ePairAction};

use crate::e2e_view::{
    device_rows, devices_reason, locked_chat_state, pairing_error_key, pairing_help,
    pairing_status_key, recovery_for_provision, register_own_device, reset_status_key,
    revoke_status_key, ChatSignals, ChatState, DeviceRow, KeyRequest, LocalQuery, QueryLane,
    RecoveryReason,
};

/// How often the timers of the engines run: queued texts expire or go out.
pub(crate) const E2E_TICK: std::time::Duration = std::time::Duration::from_secs(15);

/// The engines of the session and the locked entries of the sidebar.
#[derive(Default)]
pub(crate) struct E2eRuntime {
    pub(crate) engines: HashMap<String, E2eEngine>,
    /// The sealed history of a network whose identity is gone (after a
    /// reset and a restart). It is read only: no engine work uses it.
    histories: HashMap<String, E2eHistoryStore>,
    /// Networks that have no engine in this session: no identity on this
    /// device, a store that does not open, or a server without the E2E routes.
    unavailable: HashSet<String>,
    /// `(network, nick)` of each peer that has a locked entry.
    locked: BTreeSet<(String, String)>,
    /// What this session observed about the key request of each peer:
    /// `(network, nick)`. A peer without a record has no request.
    key_requests: HashMap<(String, String), KeyRequest>,
    /// Current server consent requests, keyed by network and request id.
    requests: HashMap<(String, u64), E2eRequest>,
    /// Accepted request IDs already used to start an E2E lane this session.
    activated_requests: HashSet<(String, u64)>,
    /// The one open X1 pairing of this session, if any.
    pairing: Option<ActivePairing>,
    /// Rendezvous that an earlier run left open. They are closed when the
    /// session is ready, and their slot is already empty.
    stale_pairings: Vec<(String, StalePairing)>,
    /// The network for which the user got the question to confirm a reset.
    /// Any other `/e2e` step clears it.
    reset_asked: Option<String>,
    /// The network for which the user got the question to confirm that this
    /// device forgets its keys of a replaced identity. Any other `/e2e` step
    /// clears it.
    forget_asked: Option<String>,
    /// Networks whose local keys this device removed with `/e2e forget`. They
    /// are also in `reset`. The server keeps the identity, so the confirmed
    /// server reset stays available for them.
    forgotten: HashSet<String>,
    /// Networks whose identity this device reset. They have no engine work:
    /// no inbox, no key request and no send. The sealed history stays.
    reset: HashSet<String>,
    /// Peers whose master key changed: `(network, nick)`. The locked entry
    /// of such a peer shows the trust alarm.
    trust_alarm: HashSet<(String, String)>,
    /// How many incoming rows of each locked entry the user has seen. Rows
    /// above it are unread. It is not saved: after a restart every entry
    /// starts read.
    read_incoming: HashMap<(String, String), usize>,
    /// Locked entries `(network, nick)` that show the captured ciphertext
    /// and not the text. It is a display choice of this session only: it is
    /// never saved, and a close of the entry or a change of the identity
    /// clears it.
    cipher_view: HashSet<(String, String)>,
    /// Networks whose provisioning ended with success in this session. An
    /// open engine is not proof: a run that failed after the Olm account was
    /// saved still opens one, so the next connect provisions again.
    provisioned: HashSet<String>,
    /// The one open SAS check, if any. It holds the master key that the
    /// shown code was made from. It is not saved.
    sas_check: Option<SasCheck>,
    /// Networks where this session saw that the account has an identity this
    /// device does not hold. Only such a network can take a pairing offer.
    needs_pairing: HashSet<String>,
    /// The one pairing offer that waits for the user to accept or dismiss
    /// it. It is not saved, and it is the only source of the join data.
    offer: Option<PairingOffer>,
    /// Rendezvous ids of the offers this session already took, newest last.
    /// An offer seen again is a duplicate.
    seen_offers: VecDeque<String>,
    /// Why this device cannot use the identity of a network, when the last
    /// provisioning run found out. A failed read sets no reason.
    recovery: HashMap<String, RecoveryReason>,
}

/// How many rendezvous ids of earlier offers a session remembers.
const SEEN_OFFERS_MAX: usize = 32;

/// What the session does with a pairing offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OfferDecision {
    /// The offer waits for the user.
    Show,
    /// The server protocol is below 55: it has no offer.
    Unsupported,
    /// The end time is past, or too far ahead.
    Expired,
    /// The offer was seen before.
    Duplicate,
    /// The offer is the rendezvous that this device opened.
    Own,
    /// The session has no network.
    WrongNetwork,
    /// This device already has the identity of every network.
    AlreadyPaired,
    /// A pairing of this session is open.
    Busy,
}

/// An open SAS check of a locked entry: the peer and the exact master key
/// that the user compares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SasCheck {
    network: String,
    nick: String,
    master: String,
}

/// A step of the SAS check, chosen by the user in the banner of the locked
/// entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SasStep {
    /// Show the code of the stored master key.
    Start,
    /// The codes match: mark the master as verified.
    Confirm,
    /// The codes differ: the peer stays unverified.
    Reject,
    /// Close the check without a result.
    Cancel,
}

impl SasStep {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "start" => Some(SasStep::Start),
            "confirm" => Some(SasStep::Confirm),
            "reject" => Some(SasStep::Reject),
            "cancel" => Some(SasStep::Cancel),
            _ => None,
        }
    }
}

/// An open pairing and the network whose identity it changes.
struct ActivePairing {
    network: String,
    session: PairingSession,
    /// The code that the user types on the new device. Only a creator on a
    /// server without the pairing offer holds it. It lasts as long as the
    /// open rendezvous.
    manual_code: Option<String>,
}

impl E2eRuntime {
    /// Decides on a pairing offer. Only `Show` keeps it: it waits in the
    /// offer slot and replaces an older one. Nothing is sent to the server
    /// and no join starts. The user must accept, and the code check of the
    /// pairing still follows an accept. `known` lists the networks of the
    /// session.
    pub(crate) fn admit_offer(
        &mut self,
        offer: PairingOffer,
        known: &[String],
        server_protocol: Option<u32>,
        now: i64,
    ) -> OfferDecision {
        if !pairing_offer_available(server_protocol) {
            return OfferDecision::Unsupported;
        }
        let id = offer.rendezvous_id();
        if !offer.is_current(now) {
            return OfferDecision::Expired;
        }
        if self.seen_offers.iter().any(|seen| seen == id) {
            return OfferDecision::Duplicate;
        }
        if self
            .pairing
            .as_ref()
            .is_some_and(|active| active.session.rendezvous_id() == id)
        {
            return OfferDecision::Own;
        }
        if known.is_empty() {
            return OfferDecision::WrongNetwork;
        }
        if self.eligible_networks(known).is_empty() {
            return OfferDecision::AlreadyPaired;
        }
        if self.pairing.is_some() {
            return OfferDecision::Busy;
        }
        self.remember_offer(id);
        self.offer = Some(offer);
        OfferDecision::Show
    }

    fn remember_offer(&mut self, id: &str) {
        if self.seen_offers.iter().any(|seen| seen == id) {
            return;
        }
        self.seen_offers.push_back(id.to_string());
        while self.seen_offers.len() > SEEN_OFFERS_MAX {
            self.seen_offers.pop_front();
        }
    }

    /// True when this device lacks the identity of `network` and can join.
    fn can_take_offer(&self, network: &str) -> bool {
        !self.provisioned.contains(network)
            && (self.needs_pairing.contains(network) || self.reset.contains(network))
    }

    /// The networks that an offer can join, in name order: those in `known`
    /// that lack the identity on this device. The offer names no network. The
    /// holder names it in its sealed `offer`, so the join step picks one of
    /// these networks then.
    fn eligible_networks(&self, known: &[String]) -> Vec<String> {
        let mut networks: Vec<String> = known
            .iter()
            .filter(|network| self.can_take_offer(network))
            .cloned()
            .collect();
        networks.sort();
        networks.dedup();
        networks
    }

    /// Takes the waiting offer for an accept. The slot is empty after this
    /// call, so one accept gives the offer once. An offer that ended, or
    /// whose networks no longer need a pairing, gives `None`. The result is
    /// the candidate networks and the code (`<id>.<key>`) for the join step.
    fn take_offer(&mut self, known: &[String], now: i64) -> Option<(Vec<String>, String)> {
        let offer = self.offer.take()?;
        if !offer.is_current(now) || self.pairing.is_some() {
            return None;
        }
        let candidates = self.eligible_networks(known);
        if candidates.is_empty() {
            return None;
        }
        Some((candidates, offer.link().code()))
    }

    /// Drops the waiting offer when its end time passed. True when it did.
    pub(crate) fn expire_offer(&mut self, now: i64) -> bool {
        if self.offer.as_ref().is_some_and(|o| !o.is_current(now)) {
            self.offer = None;
            return true;
        }
        false
    }

    /// The rendezvous `id` is closed, expired or replaced. A later offer
    /// for it is a duplicate, and a waiting offer for it is dropped. True
    /// when it dropped one.
    fn close_offer_of(&mut self, id: &str) -> bool {
        self.remember_offer(id);
        self.drop_offer_of(id)
    }

    /// Someone joined the rendezvous `id`: the offer for it is gone. True
    /// when the waiting offer was that one.
    fn drop_offer_of(&mut self, id: &str) -> bool {
        if self.offer.as_ref().is_some_and(|o| o.rendezvous_id() == id) {
            self.offer = None;
            return true;
        }
        false
    }

    /// The locked entries as query windows for the sidebar. The target is the
    /// display label; no request uses it.
    pub(crate) fn locked_windows(&self) -> Vec<QueryWindow> {
        self.locked
            .iter()
            .map(|(network, nick)| QueryWindow {
                network: network.clone(),
                target_nick: LocalQuery::new(network, QueryLane::Locked, nick).window_name(),
                opened_at: String::new(),
                dm_conversation_id: None,
            })
            .collect()
    }

    /// Adds the locked entry of `nick`; true when it is new.
    pub(crate) fn add_locked(&mut self, network: &str, nick: &str) -> bool {
        self.locked.insert((network.to_string(), nick.to_string()))
    }

    /// True when the locked entry shows the captured ciphertext.
    pub(crate) fn shows_ciphertext(&self, network: &str, nick: &str) -> bool {
        self.cipher_view
            .contains(&(network.to_string(), nick.to_string()))
    }

    /// Switches the view of one locked entry; returns the new value
    /// (true is ciphertext).
    pub(crate) fn toggle_ciphertext(&mut self, network: &str, nick: &str) -> bool {
        let key = (network.to_string(), nick.to_string());
        if self.cipher_view.remove(&key) {
            false
        } else {
            self.cipher_view.insert(key);
            true
        }
    }

    /// Resets the view of every locked entry of `network`.
    pub(crate) fn clear_ciphertext_views(&mut self, network: &str) {
        self.cipher_view
            .retain(|(known_network, _)| known_network != network);
    }

    /// The key request state of a peer.
    pub(crate) fn key_request(&self, network: &str, nick: &str) -> KeyRequest {
        self.key_requests
            .get(&(network.to_string(), nick.to_string()))
            .copied()
            .unwrap_or_default()
    }

    /// Notes the result of a key request. A 202 answer means only that the API
    /// accepted it. A request that the pacing holds back leaves an open request
    /// waiting. A peer that cannot do E2E gets no request.
    pub(crate) fn note_key_request(
        &mut self,
        network: &str,
        nick: &str,
        result: &Result<(), EngineError>,
    ) {
        let current = self.key_request(network, nick);
        let next = match result {
            Ok(()) => KeyRequest::Accepted,
            Err(EngineError::Paced(_)) if current != KeyRequest::NotSent => {
                if current == KeyRequest::Failed {
                    KeyRequest::Failed
                } else {
                    KeyRequest::Waiting
                }
            }
            Err(EngineError::Paced(_) | EngineError::PeerNotCapable) => current,
            Err(_) => KeyRequest::Failed,
        };
        if next != KeyRequest::NotSent {
            self.key_requests
                .insert((network.to_string(), nick.to_string()), next);
        }
    }

    fn put_request(&mut self, network: &str, request: E2eRequest) {
        self.requests
            .insert((network.to_string(), request.id), request);
    }

    fn remove_request(&mut self, network: &str, id: u64) {
        self.requests.remove(&(network.to_string(), id));
        self.activated_requests.remove(&(network.to_string(), id));
    }

    fn replace_requests(&mut self, network: &str, requests: Vec<E2eRequest>) {
        self.requests
            .retain(|(known_network, _), _| known_network != network);
        self.activated_requests
            .retain(|(known_network, _)| known_network != network);
        for request in requests {
            self.put_request(network, request);
        }
    }

    fn request_for_peer(
        &self,
        network: &str,
        peer: &str,
        casemapping: cordiale_core::isupport::CaseMapping,
    ) -> Option<&E2eRequest> {
        self.requests
            .iter()
            .filter(|((known_network, _), request)| {
                known_network == network && casemapping.nick_eq(&request.peer, peer)
            })
            .max_by_key(|((_, id), _)| *id)
            .map(|(_, request)| request)
    }

    fn request_was_activated(&mut self, network: &str, id: u64) -> bool {
        !self.activated_requests.insert((network.to_string(), id))
    }

    fn remove_outgoing_request_for_peer(
        &mut self,
        network: &str,
        peer: &str,
        casemapping: cordiale_core::isupport::CaseMapping,
    ) {
        let ids: Vec<u64> = self
            .requests
            .iter()
            .filter(|((known_network, _), request)| {
                known_network == network
                    && request.state == E2eRequestState::Outgoing
                    && casemapping.nick_eq(&request.peer, peer)
            })
            .map(|((_, id), _)| *id)
            .collect();
        for id in ids {
            self.remove_request(network, id);
        }
    }

    fn mark_key_request_failed_for_peer(
        &mut self,
        network: &str,
        nick: &str,
        casemapping: cordiale_core::isupport::CaseMapping,
    ) {
        for ((known_network, known_nick), status) in &mut self.key_requests {
            if known_network == network
                && casemapping.nick_eq(known_nick, nick)
                && *status != KeyRequest::NotSent
            {
                *status = KeyRequest::Failed;
            }
        }
    }

    /// Notes an engine failure of a peer. A changed master key is the trust
    /// alarm of the locked entry.
    pub(crate) fn note_engine_error(&mut self, network: &str, nick: &str, error: &EngineError) {
        if matches!(error, EngineError::Device(E2eError::MasterChanged)) {
            self.trust_alarm
                .insert((network.to_string(), nick.to_string()));
        }
    }

    /// The sealed history of `network`, from its engine or, without an
    /// identity, from the history-only store.
    fn history_of(&self, network: &str) -> Option<&E2eHistoryStore> {
        self.engines
            .get(network)
            .map(E2eEngine::history)
            .or_else(|| self.histories.get(network))
    }

    pub(crate) fn engine_mut(&mut self, network: &str) -> Option<&mut E2eEngine> {
        self.engines.get_mut(network)
    }
}

fn e2e_now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The `(network, nick)` of the open window when it is a locked entry. The
/// nick is the real nick, without the label.
pub(crate) fn open_locked_window(state: &WorkerState) -> Option<(String, String)> {
    if !state.windows.current_query {
        return None;
    }
    let (network, name) = state.windows.current_channel.as_ref()?;
    match route_for_window(name) {
        SendRoute::Encrypted { nick } => Some((network.clone(), nick)),
        SendRoute::Plain { .. } => None,
    }
}

/// True when `name` is the name of a locked entry: it starts with the lock
/// label.
pub(crate) fn is_locked_name(name: &str) -> bool {
    matches!(route_for_window(name), SendRoute::Encrypted { .. })
}

/// The status key for a failed E2E send. A peer that is not ready gets its
/// own text; every other failure gets the general one.
pub(crate) fn e2e_send_error_kind(error: &EngineError) -> &'static str {
    match error {
        EngineError::NotReady | EngineError::Paced(_) | EngineError::PeerNotCapable => {
            "e2e-not-ready"
        }
        _ => "e2e-send-failed",
    }
}

/// How many rows of the locked entry of `nick` the peer sent.
fn incoming_rows(history: &E2eHistoryStore, network: &str, nick: &str) -> usize {
    history
        .messages(&conversation_id(network, nick))
        .iter()
        .filter(|message| message.sender_device != OWN_DEVICE)
        .count()
}

/// The unread counts of the locked entries, keyed like the counts of the
/// plain windows. Only the entries with unread rows are in the map.
pub(crate) fn locked_unread_counts(state: &WorkerState) -> HashMap<(String, String), u64> {
    let mut counts = HashMap::new();
    for (network, nick) in &state.e2e.locked {
        let Some(history) = state.e2e.history_of(network) else {
            continue;
        };
        let seen = state
            .e2e
            .read_incoming
            .get(&(network.clone(), nick.clone()))
            .copied()
            .unwrap_or(0);
        let unread = incoming_rows(history, network, nick).saturating_sub(seen);
        if unread > 0 {
            let name = LocalQuery::new(network, QueryLane::Locked, nick).window_name();
            counts.insert(window_counts_key(network, &name), unread as u64);
        }
    }
    counts
}

/// Marks every incoming row of the locked entry as seen.
pub(crate) fn mark_locked_read(state: &mut WorkerState, network: &str, nick: &str) -> bool {
    let seen = state
        .e2e
        .history_of(network)
        .map(|history| incoming_rows(history, network, nick))
        .unwrap_or(0);
    state
        .e2e
        .read_incoming
        .insert((network.to_string(), nick.to_string()), seen)
        != Some(seen)
}

/// The state of the locked entry of `nick`, read from the engine and the
/// session.
pub(crate) fn locked_entry_state(state: &WorkerState, network: &str, nick: &str) -> ChatState {
    let engine = state.e2e.engines.get(network);
    let mut signals = ChatSignals {
        reset: state.e2e.reset.contains(network),
        engine: engine.is_some(),
        trust_alarm: state
            .e2e
            .trust_alarm
            .contains(&(network.to_string(), nick.to_string())),
        pairing: state
            .e2e
            .pairing
            .as_ref()
            .is_some_and(|active| active.network == network),
        key_request: state.e2e.key_request(network, nick),
        ..ChatSignals::default()
    };
    if let Some(engine) = engine {
        signals.ready = engine.is_ready(nick);
        signals.last_drop = engine
            .history()
            .messages(&conversation_id(network, nick))
            .into_iter()
            .rev()
            .find(|message| message.sender_device == OWN_DEVICE)
            .and_then(|message| engine.dropped_reason(&message.id));
        let trust = engine.trust();
        signals.sas_verified = trust.is_sas_verified(network, nick);
        signals.key_verified = trust.is_key_verified(network, nick);
        // The current list never holds a revoked key: read the revoked set.
        signals.peer_revoked = trust.has_revoked_devices(network, nick);
    }
    locked_chat_state(&signals)
}

/// The state key of a plain query: clear text when the network has E2E.
pub(crate) fn plain_entry_state_key(state: &WorkerState, network: &str) -> &'static str {
    if state.e2e.engines.contains_key(network) {
        ChatState::ClearText.key()
    } else {
        ""
    }
}

fn request_view_state(request: &E2eRequest) -> &'static str {
    let expired = request
        .expires_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|expires| expires.timestamp_millis() <= chrono::Utc::now().timestamp_millis());
    match (request.state, expired) {
        (E2eRequestState::Incoming, true) => "gone",
        (E2eRequestState::Outgoing, true) => "expired",
        _ => request.state.as_str(),
    }
}

fn query_consent_view(
    state: &WorkerState,
    network: &str,
    peer: &str,
) -> (String, String, bool, bool, bool) {
    let casemapping = network_casemapping(state, network);
    let request = state
        .e2e
        .request_for_peer(network, peer, casemapping)
        .filter(|request| request_view_state(request) != "gone");
    let request_state = request
        .map_or("", |request| request_view_state(request))
        .to_string();
    let request_id = request.map_or(String::new(), |request| request.id.to_string());
    let engine = state.e2e.engines.get(network);
    let can_accept = engine.is_some_and(|engine| engine.own_consent_line().is_ok());
    let can_start = state
        .conn
        .server_protocol_version
        .is_some_and(|version| version >= CONSENT_MIN_PROTOCOL)
        && can_accept;
    let has_locked =
        state.e2e.locked.iter().any(|(known_network, nick)| {
            known_network == network && casemapping.nick_eq(nick, peer)
        });
    (request_state, request_id, can_start, can_accept, has_locked)
}

/// Updates the consent controls when the currently open plain query changes.
pub(crate) fn push_open_query_consent(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    if !state.windows.current_query {
        return;
    }
    let Some((network, window)) = state.windows.current_channel.as_ref() else {
        return;
    };
    let SendRoute::Plain { nick } = route_for_window(window) else {
        return;
    };
    let peer = crate::queries::query_send_target(state, network, &nick);
    let (request_state, request_id, can_start, can_accept, has_locked) =
        query_consent_view(state, network, &peer);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_query_e2e_request_state(request_state.clone().into());
        ui.set_current_query_e2e_request_id(request_id.into());
        ui.set_current_query_e2e_can_start(can_start);
        ui.set_current_query_e2e_can_accept(can_accept);
        ui.set_current_query_e2e_has_locked(has_locked);
        if !request_state.is_empty() {
            ui.set_current_query_e2e_start_confirm_open(false);
        }
    });
}

fn set_e2e_status(ui: &slint::Weak<AppWindow>, kind: &'static str) {
    let _ = ui.upgrade_in_event_loop(move |ui| ui.set_status_kind(kind.into()));
}

/// One sealed history row as a row of the locked window. The row keeps the
/// encrypted mark. A row whose send was dropped (`late`, `send_failed` or
/// `session_ended`) is marked with a warning sign and shown in italics: the
/// text did not reach the peer, and nothing shows it as delivered. Only the
/// locked window has this mark; a plain row never gets it.
pub(crate) fn locked_row_with_drop(
    message: &E2eMessage,
    own_nick: &str,
    peer: &str,
    dropped: Option<DropReason>,
) -> RenderedMessage {
    let nick = if message.sender_device == OWN_DEVICE {
        own_nick
    } else {
        peer
    };
    let timestamp = chrono::DateTime::from_timestamp(message.sent_at, 0)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_default();
    // An action row has the shape of a plain `/me` row: no nick cell and
    // the line `* nick words`.
    let action = action_body(&message.text);
    let shown = match action {
        Some(words) => format!("* {nick} {words}"),
        None => message.text.clone(),
    };
    RenderedMessage {
        timestamp,
        nick: action.is_none().then(|| nick.to_string()),
        text: if dropped.is_some() {
            format!("\u{26A0} {shown}")
        } else {
            shown
        },
        italic: dropped.is_some() || action.is_some(),
        message_id: None,
        server_time: message.sent_at.checked_mul(1000),
        presence_noise: false,
        rename_to: None,
        encrypted: true,
    }
}

/// The text of a row in the ciphertext view that has no captured payload.
pub(crate) const NO_CIPHERTEXT_TEXT: &str = "[No ciphertext on this device]";

/// The rows of one history message for the view that is active. The plain
/// view gives the one row of [`locked_row_with_drop`]. The ciphertext view
/// gives one row for each captured payload, in the form
/// `E2E <VERB> <MESSAGE_ID> <PAYLOAD>`, and never the text: a message with no
/// payload gets a placeholder row. A dropped send shows no payload, because
/// the payload did not reach the peer. The rows keep the time and the sender
/// of the message.
pub(crate) fn locked_rows_for_view(
    message: &E2eMessage,
    own_nick: &str,
    peer: &str,
    dropped: Option<DropReason>,
    ciphertext: bool,
) -> Vec<RenderedMessage> {
    let plain = locked_row_with_drop(message, own_nick, peer, dropped);
    if !ciphertext {
        return vec![plain];
    }
    let mark = if dropped.is_some() { "\u{26A0} " } else { "" };
    let lines: Vec<String> = if message.captures.is_empty() {
        vec![format!("{mark}{NO_CIPHERTEXT_TEXT}")]
    } else {
        message
            .captures
            .iter()
            .map(|capture| {
                let msgid = capture.msgid.as_deref().unwrap_or("-");
                let verb = capture.verb.to_uppercase();
                match dropped {
                    Some(reason) => format!(
                        "{mark}E2E {verb} {msgid} [dropped: {}; not sent]",
                        reason.wire_name()
                    ),
                    None => format!("E2E {verb} {msgid} {}", capture.payload),
                }
            })
            .collect()
    };
    lines
        .into_iter()
        .map(|text| RenderedMessage {
            text,
            nick: Some(if message.sender_device == OWN_DEVICE {
                own_nick.to_string()
            } else {
                peer.to_string()
            }),
            italic: dropped.is_some(),
            ..plain.clone()
        })
        .collect()
}

/// Opens the engine of `network` once for the session. False when the
/// network has none.
fn ensure_engine(state: &mut WorkerState, network: &str) -> bool {
    // A reset network has no engine work, even when its engine is still in
    // the map for the sealed history.
    if state.e2e.reset.contains(network) {
        return false;
    }
    if state.e2e.engines.contains_key(network) {
        return true;
    }
    if state.e2e.unavailable.contains(network) {
        return false;
    }
    // The server version can still be unknown here: ask again later.
    let protocol = state.conn.server_protocol_version;
    let routes = [
        E2eOperation::SendMessage,
        E2eOperation::InboxFetch,
        E2eOperation::InboxAck,
    ];
    if !routes.iter().all(|route| route.available(protocol)) {
        return false;
    }
    // The files belong to one account on one server; a guest has none.
    let (Some(client), Some(account)) =
        (state.conn.client.as_ref(), state.conn.identifier.as_ref())
    else {
        return false;
    };
    if state.conn.guest_session {
        return false;
    }
    // The engine takes the one handle on the history file: let go of the
    // history-only handle first.
    state.e2e.histories.remove(network);
    match E2eEngine::open_for_network(client.base_url(), account, network) {
        Ok(mut engine) => {
            // The ISUPPORT snapshot can come before the engine.
            if let Some(isupport) = state.networks.isupport_by_network.get(network) {
                engine.set_casemapping(isupport.casemapping);
                engine.set_frame_budget_base(isupport.frame_budget_base);
            }
            register_own_device(engine.own_did());
            for peer in engine.history_peers() {
                state.e2e.add_locked(network, &peer);
                let seen = incoming_rows(engine.history(), network, &peer);
                state
                    .e2e
                    .read_incoming
                    .insert((network.to_string(), peer), seen);
            }
            // The channel secret of a pairing lives in memory only, so a
            // pairing left in the slot by an earlier run is stale.
            match pairing::take_stale_pairing(engine.state_mut()) {
                Ok(Some(stale)) => state.e2e.stale_pairings.push((network.to_string(), stale)),
                Ok(None) => {}
                Err(error) => {
                    persistence::log_line(&format!("e2e pairing slot for {network}: {error:?}"))
                }
            }
            state.e2e.engines.insert(network.to_string(), engine);
            true
        }
        Err(error) => {
            if !matches!(error, EngineError::NotReady) {
                persistence::log_line(&format!("e2e engine not opened for {network}: {error:?}"));
            }
            state.e2e.unavailable.insert(network.to_string());
            open_history_only(state, network);
            false
        }
    }
}

/// Opens the sealed history of a network that has no engine, so the locked
/// entries stay readable after a reset and a restart.
fn open_history_only(state: &mut WorkerState, network: &str) {
    let (Some(client), Some(account)) =
        (state.conn.client.as_ref(), state.conn.identifier.as_ref())
    else {
        return;
    };
    let history = match E2eEngine::open_history_for_network(client.base_url(), account, network) {
        Ok(Some(history)) => history,
        Ok(None) => return,
        Err(error) => {
            persistence::log_line(&format!("e2e history not opened for {network}: {error:?}"));
            return;
        }
    };
    for peer in history_peers_of(&history, network) {
        state.e2e.add_locked(network, &peer);
        let seen = incoming_rows(&history, network, &peer);
        state
            .e2e
            .read_incoming
            .insert((network.to_string(), peer), seen);
    }
    state.e2e.histories.insert(network.to_string(), history);
}

/// Gives a first device its E2E identity: the master key, the state file and
/// the published bundle. It runs on each connect until one run ends with
/// success, also when an engine is open: a run that failed after the Olm
/// account was saved leaves an engine without a master or a bundle. A reset
/// network and a guest session are left as they are. A failure is logged by
/// kind.
async fn provision_network(state: &mut WorkerState, network: &str) {
    if state.e2e.reset.contains(network)
        || state.e2e.provisioned.contains(network)
        || state.conn.guest_session
    {
        return;
    }
    let (Some(client), Some(token), Some(account)) = (
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.conn.identifier.clone(),
    ) else {
        return;
    };
    let protocol = state.conn.server_protocol_version;
    let result = match state.e2e.engines.remove(network) {
        // The engine owns the one open handle on the state file, so the run
        // writes through it.
        Some(mut engine) => {
            let result =
                provision_device(&client, &token, network, protocol, engine.state_mut()).await;
            state.e2e.engines.insert(network.to_string(), engine);
            result
        }
        None => {
            E2eEngine::provision_for_network(
                &client,
                &token,
                client.base_url(),
                &account,
                network,
                protocol,
            )
            .await
        }
    };
    match result {
        Ok(_) => {
            state.e2e.needs_pairing.remove(network);
            state.e2e.recovery.remove(network);
            state.e2e.provisioned.insert(network.to_string());
            // A network without a state file before this run can open its
            // engine now.
            state.e2e.unavailable.remove(network);
        }
        Err(error) => {
            if matches!(error, ProvisionError::NeedsPairing) {
                state.e2e.needs_pairing.insert(network.to_string());
            }
            // Only an identity outcome sets a reason. A failed read keeps the
            // old state and never offers a new identity.
            if let Some(reason) = recovery_for_provision(&error) {
                state.e2e.recovery.insert(network.to_string(), reason);
            }
            persistence::log_line(&format!("e2e identity not made for {network}: {error:?}"));
        }
    }
}

/// Opens the engines of the signed-in networks and reads their inboxes. Call
/// it when the session connects, also after a reconnect.
pub(crate) async fn start_e2e_engines(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    retire_expired_offer(state, ui);
    let mut networks: Vec<String> = state.networks.own_nicks.keys().cloned().collect();
    networks.sort();
    for network in networks {
        provision_network(state, &network).await;
        if ensure_engine(state, &network) {
            // A revoke or a reset that an earlier run left open ends first,
            // so a revoked device gets no inbox work.
            resume_pending_manage(state, ui, &network).await;
            drain_network(state, ui, &network).await;
        }
        sync_e2e_requests(state, ui, &network).await;
    }
    close_stale_pairings(state).await;
    pump_pairing(state, ui).await;
    refresh_network_groups(state, ui);
}

/// Reads the consent mirror on every session connect. Grappa does not replay
/// request pushes, so this is required after both first connect and reconnect.
async fn sync_e2e_requests(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, network: &str) {
    let Some(protocol) = state.conn.server_protocol_version else {
        return;
    };
    if protocol < CONSENT_MIN_PROTOCOL {
        state.e2e.replace_requests(network, Vec::new());
        return;
    }
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let requests = match client
        .fetch_e2e_requests(&token, network, Some(protocol))
        .await
    {
        Ok(requests) => requests,
        Err(error) => {
            if !matches!(
                error,
                cordiale_core::e2e_refusal::E2eRouteError::Unavailable
            ) {
                persistence::log_line(&format!("e2e request sync failed for {network}: {error:?}"));
            }
            return;
        }
    };
    state.e2e.replace_requests(network, requests.clone());
    for request in requests {
        if request.state == E2eRequestState::Accepted {
            activate_accepted_request(state, ui, network, request).await;
        } else {
            ensure_plain_query_for_request(state, network, &request.peer);
        }
    }
    push_open_query_consent(state, ui);
}

fn ensure_plain_query_for_request(state: &WorkerState, network: &str, peer: &str) {
    if find_query_window(&state.transcript.query_windows, network, peer).is_none() {
        send_user_verb(
            state,
            network,
            "open_query_window",
            serde_json::json!({"target_nick": peer}),
        );
    }
}

async fn activate_accepted_request(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    request: E2eRequest,
) {
    if state
        .e2e
        .activated_requests
        .contains(&(network.to_string(), request.id))
    {
        return;
    }
    if !ensure_engine(state, network) {
        set_e2e_status(ui, "e2e-request-no-identity");
        return;
    }
    if state.e2e.request_was_activated(network, request.id) {
        return;
    }
    let peer = request.peer.clone();
    if state.e2e.add_locked(network, &peer) {
        refresh_network_groups(state, ui);
    }
    let casemapping = network_casemapping(state, network);
    let focus_locked = state.windows.current_query
        && state
            .windows
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, window)| {
                if current_network != network {
                    return false;
                }
                match route_for_window(window) {
                    SendRoute::Plain { nick } => casemapping.nick_eq(&nick, &peer),
                    _ => false,
                }
            });
    if focus_locked {
        handle_select_locked_query(state, ui, network.to_string(), &locked_label(&peer));
    }

    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        push_open_query_consent(state, ui);
        return;
    };
    let result = match state.e2e.engines.get_mut(network) {
        Some(engine) => engine.request_keys(&client, &token, &peer).await,
        None => Err(EngineError::NotReady),
    };
    state.e2e.note_key_request(network, &peer, &result);
    if let Err(error) = result {
        state.e2e.note_engine_error(network, &peer, &error);
        if !matches!(error, EngineError::Paced(_)) {
            persistence::log_line(&format!("e2e keys after consent failed: {error:?}"));
        }
        push_open_locked_state(state, ui);
        push_open_query_consent(state, ui);
        return;
    }

    let protocol = state.conn.server_protocol_version;
    match client
        .dismiss_e2e_request(&token, network, request.id, protocol, None)
        .await
    {
        Ok(()) => state.e2e.remove_request(network, request.id),
        Err(error) => persistence::log_line(&format!(
            "accepted e2e request {} was not dismissed: {error:?}",
            request.id
        )),
    }
    push_open_locked_state(state, ui);
    push_open_query_consent(state, ui);
}

/// Applies one consent request action from the current plain query. The
/// callback carries the network, peer and request ID so a delayed click cannot
/// affect a different query.
pub(crate) async fn handle_e2e_request_action(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    action: String,
    network: String,
    peer: String,
    request_id: String,
) {
    let consent_action = matches!(
        action.as_str(),
        "start" | "retry" | "accept" | "refuse" | "cancel" | "dismiss"
    );
    if consent_action
        && state
            .conn
            .server_protocol_version
            .is_none_or(|version| version < CONSENT_MIN_PROTOCOL)
    {
        set_e2e_status(ui, "e2e-request-unsupported");
        return;
    }
    let request_id = request_id.parse::<u64>().ok().filter(|id| *id > 0);
    if action != "start" && action != "open" && action != "rekey" && request_id.is_none() {
        return;
    }
    if action != "rekey" && action != "open" {
        let casemapping = network_casemapping(state, &network);
        if state
            .e2e
            .request_for_peer(&network, &peer, casemapping)
            .is_some_and(|request| request.id != request_id.unwrap_or_default())
        {
            return;
        }
    }
    match action.as_str() {
        "open" => {
            let accepted = request_id.and_then(|id| {
                state
                    .e2e
                    .requests
                    .get(&(network.clone(), id))
                    .filter(|request| request.state == E2eRequestState::Accepted)
                    .cloned()
            });
            if let Some(request) = accepted {
                state
                    .e2e
                    .activated_requests
                    .remove(&(network.clone(), request.id));
                activate_accepted_request(state, ui, &network, request).await;
            } else {
                let label = locked_label(&peer);
                handle_select_locked_query(state, ui, network, &label);
            }
        }
        "rekey" => handle_e2e_rekey(state, ui, &network, &peer).await,
        "start" | "retry" => {
            let casemapping = network_casemapping(state, &network);
            if state.e2e.locked.iter().any(|(known_network, nick)| {
                known_network == &network && casemapping.nick_eq(nick, &peer)
            }) {
                handle_select_locked_query(state, ui, network.clone(), &locked_label(&peer));
                return;
            }
            let Some((client, token, protocol, line)) = consent_context(state, &network) else {
                set_e2e_status(ui, "e2e-request-no-identity");
                return;
            };
            if action == "retry" {
                let Some(id) = request_id else { return };
                let retryable =
                    state
                        .e2e
                        .requests
                        .get(&(network.clone(), id))
                        .is_some_and(|request| {
                            matches!(request_view_state(request), "expired" | "refused")
                        });
                if !retryable {
                    return;
                }
            }
            let request = match E2eRequestCreate::new(&peer, &line) {
                Ok(request) => request,
                Err(error) => {
                    persistence::log_line(&format!("e2e request refused locally: {error:?}"));
                    set_e2e_status(ui, "e2e-request-failed");
                    return;
                }
            };
            match client
                .create_e2e_request(&token, &network, Some(protocol), &request)
                .await
            {
                Ok(request) => {
                    let accepted = request.state == E2eRequestState::Accepted;
                    state.e2e.put_request(&network, request.clone());
                    ensure_plain_query_for_request(state, &network, &request.peer);
                    if accepted {
                        activate_accepted_request(state, ui, &network, request).await;
                    } else {
                        push_open_query_consent(state, ui);
                    }
                }
                Err(error) => {
                    persistence::log_line(&format!("e2e consent request failed: {error:?}"));
                    set_e2e_status(ui, "e2e-request-failed");
                }
            }
        }
        "accept" => {
            let Some(id) = request_id else { return };
            let Some((client, token, protocol, line)) = consent_context(state, &network) else {
                set_e2e_status(ui, "e2e-request-no-identity");
                return;
            };
            let incoming = state.e2e.requests.get(&(network.clone(), id)).cloned();
            if !incoming
                .as_ref()
                .is_some_and(|request| request.state == E2eRequestState::Incoming)
            {
                return;
            }
            match client
                .accept_e2e_request(&token, &network, id, Some(protocol), &line)
                .await
            {
                Ok(()) => {
                    if let Some(mut request) = incoming {
                        request.state = E2eRequestState::Accepted;
                        state.e2e.put_request(&network, request.clone());
                        activate_accepted_request(state, ui, &network, request).await;
                    }
                }
                Err(error) => {
                    persistence::log_line(&format!("e2e consent accept failed: {error:?}"));
                    set_e2e_status(ui, "e2e-request-failed");
                }
            }
        }
        "refuse" => {
            let Some(id) = request_id else { return };
            let (Some(client), Some(token), Some(protocol)) = (
                state.conn.client.clone(),
                state.conn.token.clone(),
                state.conn.server_protocol_version,
            ) else {
                return;
            };
            if protocol < CONSENT_MIN_PROTOCOL {
                return;
            }
            match client
                .refuse_e2e_request(&token, &network, id, Some(protocol))
                .await
            {
                Ok(()) => {
                    state.e2e.remove_request(&network, id);
                    push_open_query_consent(state, ui);
                }
                Err(error) => persistence::log_line(&format!("e2e refusal failed: {error:?}")),
            }
        }
        "cancel" | "dismiss" => {
            let Some(id) = request_id else { return };
            let Some(request) = state.e2e.requests.get(&(network.clone(), id)).cloned() else {
                return;
            };
            let (Some(client), Some(token), Some(protocol)) = (
                state.conn.client.clone(),
                state.conn.token.clone(),
                state.conn.server_protocol_version,
            ) else {
                return;
            };
            let line = if action == "cancel" && request.state == E2eRequestState::Outgoing {
                match state
                    .e2e
                    .engines
                    .get(&network)
                    .and_then(|engine| engine.own_consent_line().ok())
                {
                    Some(line) => Some(line),
                    None => {
                        set_e2e_status(ui, "e2e-request-no-identity");
                        return;
                    }
                }
            } else {
                None
            };
            match client
                .dismiss_e2e_request(&token, &network, id, Some(protocol), line.as_ref())
                .await
            {
                Ok(()) => {
                    state.e2e.remove_request(&network, id);
                    push_open_query_consent(state, ui);
                }
                Err(error) => {
                    persistence::log_line(&format!("e2e request dismiss failed: {error:?}"));
                    set_e2e_status(ui, "e2e-request-failed");
                }
            }
        }
        _ => {}
    }
}

fn consent_context(
    state: &WorkerState,
    network: &str,
) -> Option<(GrappaClient, String, u32, E2eConsentLine)> {
    let protocol = state.conn.server_protocol_version?;
    if protocol < CONSENT_MIN_PROTOCOL {
        return None;
    }
    let (client, token) = (state.conn.client.clone()?, state.conn.token.clone()?);
    let line = state.e2e.engines.get(network)?.own_consent_line().ok()?;
    Some((client, token, protocol, line))
}

async fn handle_e2e_rekey(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    peer: &str,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        set_e2e_status(ui, "e2e-not-ready");
        return;
    };
    let result = match state.e2e.engines.get_mut(network) {
        Some(engine) => engine.request_keys(&client, &token, peer).await,
        None => Err(EngineError::NotReady),
    };
    state.e2e.note_key_request(network, peer, &result);
    if let Err(error) = result {
        state.e2e.note_engine_error(network, peer, &error);
        persistence::log_line(&format!("manual e2e re-key failed: {error:?}"));
        set_e2e_status(ui, "e2e-request-failed");
    }
    push_open_locked_state(state, ui);
}

/// Applies an E2E consent push. Unknown or malformed events are ignored.
pub(crate) async fn handle_e2e_request_push(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    payload: &Value,
) {
    if state
        .conn
        .server_protocol_version
        .is_none_or(|version| version < CONSENT_MIN_PROTOCOL)
    {
        return;
    }
    let Some(network) = payload.get("network").and_then(Value::as_str) else {
        return;
    };
    let Some(request) = payload
        .get("request")
        .and_then(|value| cordiale_core::rest::E2eRequest::from_value(value).ok())
    else {
        return;
    };
    state.e2e.put_request(network, request.clone());
    if request.state == E2eRequestState::Accepted {
        activate_accepted_request(state, ui, network, request).await;
        push_open_query_consent(state, ui);
    } else {
        ensure_plain_query_for_request(state, network, &request.peer);
        push_open_query_consent(state, ui);
    }
}

pub(crate) fn handle_e2e_request_gone_push(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    payload: &Value,
) {
    let Some(network) = payload.get("network").and_then(Value::as_str) else {
        return;
    };
    let Some(id) = payload.get("id").and_then(Value::as_u64) else {
        return;
    };
    state.e2e.remove_request(network, id);
    push_open_query_consent(state, ui);
}

/// Handles the protocol 54 401 event without touching messages Grappa already
/// accepted for delivery.
pub(crate) fn handle_no_such_nick_push(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    payload: &Value,
) {
    if state
        .conn
        .server_protocol_version
        .is_none_or(|version| version < NO_SUCH_NICK_MIN_PROTOCOL)
    {
        return;
    }
    let Some(network) = payload.get("network").and_then(Value::as_str) else {
        return;
    };
    let Some(nick) = payload.get("nick").and_then(Value::as_str) else {
        return;
    };
    let changed = if let Some(engine) = state.e2e.engines.get_mut(network) {
        let drops = engine.no_such_nick(nick);
        if !drops.is_empty() {
            set_e2e_status(ui, "e2e-no-such-nick");
        }
        engine.take_changed_peers()
    } else {
        Vec::new()
    };
    for peer in changed {
        refresh_locked_view(state, ui, network, &peer);
    }
    let casemapping = network_casemapping(state, network);
    state
        .e2e
        .remove_outgoing_request_for_peer(network, nick, casemapping);
    state
        .e2e
        .mark_key_request_failed_for_peer(network, nick, casemapping);
    push_open_locked_state(state, ui);
    push_open_query_consent(state, ui);
}

/// Closes the rendezvous that an earlier run left open. A failure is
/// ignored: the relay drops a rendezvous after its lifetime.
async fn close_stale_pairings(state: &mut WorkerState) {
    let stale = std::mem::take(&mut state.e2e.stale_pairings);
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let protocol = state.conn.server_protocol_version;
    for (network, record) in stale {
        let ctx = PairingContext {
            client: &client,
            token: &token,
            protocol,
            network_id: &network,
        };
        pairing::close_stale(&ctx, &record).await;
    }
}

/// Takes the engine of `network` out of the map for a pairing step. A joining
/// device may have no engine yet: `create` makes its state and identity.
fn take_pairing_engine(state: &mut WorkerState, network: &str, create: bool) -> Option<E2eEngine> {
    // A device that joins after a reset gets a new identity. The old engine
    // caches the deleted device id and holds the files, so it is dropped
    // first and the new one reads the new device key.
    if create && state.e2e.reset.contains(network) {
        drop(state.e2e.engines.remove(network));
    }
    if !state.e2e.engines.contains_key(network) {
        let opened = if create {
            open_pairing_engine(state, network)
        } else {
            ensure_engine(state, network)
        };
        if !opened {
            return None;
        }
    }
    state.e2e.engines.remove(network)
}

fn open_pairing_engine(state: &mut WorkerState, network: &str) -> bool {
    let (Some(client), Some(account)) =
        (state.conn.client.as_ref(), state.conn.identifier.as_ref())
    else {
        return false;
    };
    if state.conn.guest_session {
        return false;
    }
    // The engine takes the one handle on the history file: let go of the
    // history-only handle first.
    state.e2e.histories.remove(network);
    match E2eEngine::open_for_pairing(client.base_url(), account, network) {
        Ok(engine) => {
            state.e2e.unavailable.remove(network);
            state.e2e.engines.insert(network.to_string(), engine);
            true
        }
        Err(error) => {
            persistence::log_line(&format!("e2e pairing engine not opened: {error:?}"));
            open_history_only(state, network);
            false
        }
    }
}

/// Shows a pairing state in the status bar. It is control state, never a
/// chat line.
fn show_pairing(ui: &slint::Weak<AppWindow>, status: &PairingStatus) {
    let (kind, hint) = pairing_status_key(status);
    show_pairing_kind(ui, kind, hint);
}

/// Opens the pairing dialog of the creator. `offered` tells if the server
/// offers the rendezvous to the other devices (protocol 55). The dialog holds
/// no link, no QR code and no code.
fn show_pairing_dialog(ui: &slint::Weak<AppWindow>, offered: bool) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_e2e_pair_offered(offered);
        ui.set_e2e_pair_dialog_visible(true);
    });
}

/// Closes the pairing dialog. Call it when the pairing ends, expires, is
/// replaced or is cancelled.
fn clear_pairing_dialog(ui: &slint::Weak<AppWindow>) {
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_e2e_pair_dialog_visible(false);
        ui.set_e2e_pair_offered(false);
    });
}

/// Shows or hides the in-app offer of the receiving device. The offer holds
/// no value: the join data stays in the worker until the user accepts.
fn set_offer_dialog(ui: &slint::Weak<AppWindow>, visible: bool) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_e2e_pair_offer_visible(visible);
    });
}

/// The answer of the user to the waiting offer: accept (`true`) or dismiss
/// (`false`). Only an accept starts the join step.
pub(crate) async fn answer_pairing_offer(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    accept: bool,
) {
    let action = if accept {
        E2ePairAction::Accept
    } else {
        E2ePairAction::Decline
    };
    run_e2e_pair(state, ui, String::new(), action).await;
}

fn show_pairing_kind(ui: &slint::Weak<AppWindow>, kind: &'static str, hint: String) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_command_hint(hint.into());
        ui.set_status_kind(kind.into());
    });
}

/// Runs one `/e2e` step on `network`. The pairing link and the code are never
/// logged.
pub(crate) async fn run_e2e_pair(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    action: E2ePairAction,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let now = e2e_now();
    // An accept joins once with the id and the key of the waiting offer. The
    // offer slot is empty after the accept. The join path below keeps the
    // code check.
    // The offer names no network, so the join starts on the first candidate
    // and moves to the network that the sealed offer of the holder names.
    let mut candidates: Vec<String> = Vec::new();
    let (network, action) = match action {
        E2ePairAction::Accept => {
            let known: Vec<String> = state.networks.own_nicks.keys().cloned().collect();
            let taken = state.e2e.take_offer(&known, now);
            set_offer_dialog(ui, false);
            match taken {
                Some((networks, code)) => {
                    let first = networks[0].clone();
                    candidates = networks;
                    (first, E2ePairAction::Join(code))
                }
                None => return show_pairing_kind(ui, "e2e-pair-offer-none", String::new()),
            }
        }
        E2ePairAction::Decline => {
            state.e2e.offer = None;
            set_offer_dialog(ui, false);
            return show_pairing_kind(ui, "e2e-pair-offer-none", String::new());
        }
        other => (network, other),
    };
    let protocol = state.conn.server_protocol_version;
    let ctx = PairingContext {
        client: &client,
        token: &token,
        protocol,
        network_id: &network,
    };
    // A new start replaces the open pairing: the old one is cancelled first.
    // A waiting offer is dropped too: its end would replace the new status.
    if matches!(action, E2ePairAction::Start | E2ePairAction::Join(_)) {
        state.e2e.offer = None;
        set_offer_dialog(ui, false);
        clear_pairing_dialog(ui);
        end_active_pairing(state).await;
    }
    match action {
        E2ePairAction::Start => {
            // A reset device has no master key, so it cannot open a pairing.
            if state.e2e.reset.contains(&network) {
                return show_pairing_kind(ui, "e2e-not-ready", String::new());
            }
            let Some(mut engine) = take_pairing_engine(state, &network, false) else {
                return show_pairing_kind(ui, "e2e-not-ready", String::new());
            };
            let result = pairing::start_creator(&ctx, engine.state_mut(), now).await;
            state.e2e.engines.insert(network.clone(), engine);
            match result {
                Ok((session, link)) => {
                    // With protocol 55 the server offers the rendezvous to the
                    // other devices. An older server cannot: the user types the
                    // code on the new device. No link and no QR code exist.
                    // The code stays with the pairing until the rendezvous ends.
                    let offered = pairing_offer_available(protocol);
                    let manual_code = (!offered).then(|| link.code());
                    state.e2e.pairing = Some(ActivePairing {
                        network: network.clone(),
                        session,
                        manual_code: manual_code.clone(),
                    });
                    push_open_locked_state(state, ui);
                    match manual_code {
                        Some(code) => show_pairing_kind(ui, "e2e-pair-manual", code),
                        None => show_pairing_kind(ui, "e2e-pair-offered", String::new()),
                    }
                    show_pairing_dialog(ui, offered);
                }
                Err(error) => show_pairing_kind(ui, pairing_error_key(&error), String::new()),
            }
        }
        E2ePairAction::Join(mut text) => {
            let Some(mut engine) = take_pairing_engine(state, &network, true) else {
                text.clear();
                return show_pairing_kind(ui, "e2e-not-ready", String::new());
            };
            let result =
                pairing::start_joiner_any(&ctx, engine.state_mut(), &mut text, &candidates, now)
                    .await;
            state.e2e.engines.insert(network.clone(), engine);
            match result {
                Ok(session) => {
                    show_pairing(ui, &session.status());
                    state.e2e.pairing = Some(ActivePairing {
                        network: network.clone(),
                        session,
                        manual_code: None,
                    });
                    push_open_locked_state(state, ui);
                }
                Err(error) => show_pairing_kind(ui, pairing_error_key(&error), String::new()),
            }
        }
        E2ePairAction::Code(typed) => {
            let Some(mut active) = state.e2e.pairing.take() else {
                return show_pairing_kind(ui, "e2e-pair-none", String::new());
            };
            let Some(mut engine) = take_pairing_engine(state, &active.network, false) else {
                return show_pairing_kind(ui, "e2e-pair-failed", String::new());
            };
            // The pairing changes the list of its own network, not the one of
            // the open window.
            let pairing_network = active.network.clone();
            let pairing_ctx = PairingContext {
                client: &client,
                token: &token,
                protocol,
                network_id: &pairing_network,
            };
            let result = pairing::confirm(
                &pairing_ctx,
                engine.state_mut(),
                &mut active.session,
                &typed,
            )
            .await;
            state.e2e.engines.insert(pairing_network.clone(), engine);
            finish_pairing_step(state, ui, active, result.err());
        }
        E2ePairAction::Accept | E2ePairAction::Decline => {}
        E2ePairAction::Cancel => {
            if state.e2e.pairing.is_none() {
                return show_pairing_kind(ui, "e2e-pair-none", String::new());
            }
            clear_pairing_dialog(ui);
            end_active_pairing(state).await;
            push_open_locked_state(state, ui);
            show_pairing(ui, &PairingStatus::Ended(pairing::EndReason::Cancelled));
        }
    }
}

/// Shows the result of a revoke or a reset in the status bar. It is control
/// state, never a chat line. `hint` and `message` fill the text of the kind.
fn show_manage_kind(
    ui: &slint::Weak<AppWindow>,
    kind: &'static str,
    hint: String,
    message: String,
) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_command_hint(hint.into());
        ui.set_status_message(message.into());
        ui.set_status_kind(kind.into());
    });
}

/// What Settings > Admin > E2E Identity shows for one network: the state
/// (`key` or `none`), the network, the account and the public master key.
/// The key is empty unless the state is `key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityPanel {
    pub state: &'static str,
    pub network: String,
    pub account: String,
    pub key: String,
}

/// Builds the panel from the public master key of `network`. A missing key
/// gives the empty state.
pub(crate) fn identity_panel(network: &str, account: &str, key: Option<String>) -> IdentityPanel {
    IdentityPanel {
        state: if key.is_some() { "key" } else { "none" },
        network: network.to_string(),
        account: account.to_string(),
        key: key.unwrap_or_default(),
    }
}

/// The id of a signed-in session: the server and the account. A new account
/// or a new server gives a new id. No session gives an empty id.
pub(crate) fn identity_session_id(server: Option<&str>, account: Option<&str>) -> String {
    match (server, account) {
        (Some(server), Some(account)) => format!("{server}\u{0}{account}"),
        _ => String::new(),
    }
}

/// True when an identity request made in `requested` still belongs to the
/// `current` session. An empty id never matches.
pub(crate) fn identity_reply_applies(requested: &str, current: &str) -> bool {
    !current.is_empty() && requested == current
}

/// The id of the session that the worker holds now.
pub(crate) fn current_identity_session(state: &WorkerState) -> String {
    identity_session_id(
        state.conn.client.as_ref().map(|client| client.base_url()),
        state.conn.identifier.as_deref(),
    )
}

/// Sets the session id of the identity page and hides the old answer. Call it
/// when a session starts and when it ends. An empty id means no session.
pub(crate) fn reset_identity_view(ui: &AppWindow, session: &str) {
    ui.set_admin_e2e_session(session.into());
    ui.set_admin_e2e_network("".into());
    ui.set_admin_e2e_shown_network("".into());
    ui.set_admin_e2e_shown_session("".into());
    ui.set_admin_e2e_account("".into());
    ui.set_admin_e2e_key("".into());
    ui.set_admin_e2e_state("".into());
}

/// Fills the E2E Identity page for `network`. It reads the public master key
/// of the open engine and nothing else. It makes no key, no file and no log
/// line with the key. A request from an old session changes nothing.
pub(crate) fn show_e2e_identity(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    requested_session: String,
) {
    let session = current_identity_session(state);
    if !identity_reply_applies(&requested_session, &session) {
        return;
    }
    let account = state.conn.identifier.clone().unwrap_or_default();
    let key = if ensure_engine(state, &network) {
        state.e2e.engines.get_mut(&network).and_then(|engine| {
            match engine.state_mut().master_public_key() {
                Ok(key) => key,
                Err(error) => {
                    persistence::log_line(&format!(
                        "e2e master key not read for {network}: {error:?}"
                    ));
                    None
                }
            }
        })
    } else {
        None
    };
    let panel = identity_panel(&network, &account, key);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        // The window may have a newer session by now: drop a late answer.
        if !identity_reply_applies(&session, ui.get_admin_e2e_session().as_str()) {
            return;
        }
        ui.set_admin_e2e_shown_session(session.into());
        ui.set_admin_e2e_shown_network(panel.network.into());
        ui.set_admin_e2e_account(panel.account.into());
        ui.set_admin_e2e_key(panel.key.into());
        ui.set_admin_e2e_state(panel.state.into());
    });
}

/// Reads the device list of the server. A failure is logged by kind and gives
/// None, so the caller never shows it as an empty list.
async fn read_device_records(
    client: &cordiale_core::client::GrappaClient,
    token: &str,
    network: &str,
    protocol: Option<u32>,
) -> Option<Vec<cordiale_core::e2e_identity_routes::DeviceRecord>> {
    match client.list_e2e_devices(token, network, protocol).await {
        Ok(records) => Some(records),
        Err(error) => {
            persistence::log_line(&format!("e2e device list for {network}: {error:?}"));
            None
        }
    }
}

/// The text of the device rows inside the window thread. A list that could
/// not be read says so, and an empty list says that it is empty.
fn device_rows_text(ui: &AppWindow, rows: Option<&[DeviceRow]>) -> String {
    match rows {
        None => ui.invoke_e2e_list_unavailable_text().to_string(),
        Some([]) => ui.invoke_e2e_list_empty_text().to_string(),
        Some(rows) => rows
            .iter()
            .map(|row| {
                ui.invoke_e2e_device_row_text(
                    row.did.as_str().into(),
                    row.mine,
                    row.kind.into(),
                    row.time.as_str().into(),
                )
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("; "),
    }
}

/// Shows why this device cannot use the identity, with the listed devices
/// and the pairing advice. The view only explains: it never creates or
/// replaces an identity. `signed_ids` are the ids of the local signed list,
/// or None when the server list gives the devices.
#[allow(clippy::too_many_arguments)]
async fn show_recovery(
    ui: &slint::Weak<AppWindow>,
    client: &cordiale_core::client::GrappaClient,
    token: &str,
    network: &str,
    protocol: Option<u32>,
    own: &str,
    reason: RecoveryReason,
    signed_ids: Option<Vec<String>>,
) {
    let records = read_device_records(client, token, network, protocol).await;
    let ids = match (signed_ids, &records) {
        (Some(ids), _) => Some(ids),
        (None, Some(records)) => Some(records.iter().map(|record| record.did.clone()).collect()),
        (None, None) => None,
    };
    let rows: Option<Vec<DeviceRow>> = ids.map(|ids| device_rows(&ids, own, records.as_deref()));
    let help = pairing_help(rows.as_deref());
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_command_hint(device_rows_text(&ui, rows.as_deref()).into());
        ui.set_status_message(help.into());
        ui.set_status_kind(reason.status_key().into());
    });
}

/// Runs one `/e2e devices`, `revoke` or `reset` step on `network`. A reset
/// runs only after the question and the answer `/e2e reset yes` for the same
/// network.
pub(crate) async fn run_e2e_manage(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    action: E2eManageAction,
) {
    let asked = state.e2e.reset_asked.take();
    let forget_asked = state.e2e.forget_asked.take();
    let not_ready = || show_manage_kind(ui, "e2e-not-ready", String::new(), String::new());
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(own_nick) = state.networks.own_nicks.get(&network).cloned() else {
        return not_ready();
    };
    let protocol = state.conn.server_protocol_version;
    // The forget step runs before the engine check: a replaced identity is
    // the case where the engine does not open.
    if matches!(
        action,
        E2eManageAction::Forget | E2eManageAction::ForgetConfirm
    ) {
        let confirmed = matches!(action, E2eManageAction::ForgetConfirm)
            && forget_asked.as_deref() == Some(network.as_str());
        return run_e2e_forget(state, ui, &network, &own_nick, confirmed);
    }
    if !forgotten_reset_step(state, &network, &action) && !ensure_engine(state, &network) {
        // The list of devices explains why the identity is not open.
        if matches!(action, E2eManageAction::Devices) {
            if let Some(reason) = state.e2e.recovery.get(&network).copied() {
                return show_recovery(ui, &client, &token, &network, protocol, "", reason, None)
                    .await;
            }
        }
        return not_ready();
    }
    match action {
        E2eManageAction::Devices => {
            let Some(engine) = state.e2e.engines.get_mut(&network) else {
                return not_ready();
            };
            let own = engine.own_did().to_string();
            let ids: Option<Vec<String>> = engine.state_mut().signed_list().map(|list| {
                list.keys
                    .iter()
                    .filter_map(|key| did_from_key_text(key).ok())
                    .collect()
            });
            // The reason of the provisioning run comes first: an engine can
            // open with an old local list. Then the local list gives the
            // reason. The view explains and never resets.
            let saved = state.e2e.recovery.get(&network).copied();
            if let Some((reason, from_signed_list)) = devices_reason(saved, &own, ids.as_deref()) {
                // An old local list does not tell the devices of the account.
                let ids = if from_signed_list { ids } else { None };
                return show_recovery(ui, &client, &token, &network, protocol, &own, reason, ids)
                    .await;
            }
            let ids = ids.unwrap_or_default();
            // The server list adds the activity. A failed read keeps the ids
            // of the signed list and shows the activity as unavailable.
            let records = read_device_records(&client, &token, &network, protocol).await;
            let rows = device_rows(&ids, &own, records.as_deref());
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_status_command_hint(device_rows_text(&ui, Some(rows.as_slice())).into());
                ui.set_status_message(own.into());
                ui.set_status_kind("e2e-devices".into());
            });
        }
        E2eManageAction::Revoke(did) => {
            let Some(mut engine) = state.e2e.engines.remove(&network) else {
                return not_ready();
            };
            let routes = OwnRoutes {
                client: &client,
                token: &token,
                network: &network,
                own_nick: &own_nick,
                server_protocol: protocol,
            };
            let result = revoke_device(&routes, engine.state_mut(), &did).await;
            state.e2e.engines.insert(network, engine);
            if let Err(error) = &result {
                persistence::log_line(&format!("e2e revoke not finished: {error:?}"));
            }
            let (kind, hint) = revoke_status_key(&result);
            show_manage_kind(ui, kind, hint, String::new());
        }
        // Both forget steps return before this match.
        E2eManageAction::Forget | E2eManageAction::ForgetConfirm => {}
        E2eManageAction::Reset => {
            state.e2e.reset_asked = Some(network);
            show_manage_kind(ui, "e2e-reset-confirm", String::new(), String::new());
        }
        E2eManageAction::ResetConfirm => {
            // An answer without the question asks the question first.
            if asked.as_deref() != Some(network.as_str()) {
                state.e2e.reset_asked = Some(network);
                return show_manage_kind(ui, "e2e-reset-confirm", String::new(), String::new());
            }
            let Some(mut engine) = state.e2e.engines.remove(&network) else {
                return not_ready();
            };
            let routes = OwnRoutes {
                client: &client,
                token: &token,
                network: &network,
                own_nick: &own_nick,
                server_protocol: protocol,
            };
            let result = reset_identity(
                &routes,
                engine.state_mut(),
                ResetConfirmation::user_confirmed(),
            )
            .await;
            if let Err(error) = &result {
                persistence::log_line(&format!("e2e reset not finished: {error:?}"));
                state.e2e.engines.insert(network, engine);
            } else {
                settle_reset(state, ui, &network, engine);
            }
            show_manage_kind(ui, reset_status_key(&result), String::new(), String::new());
        }
    }
}

/// True for a reset step on a network whose local keys the user forgot. The
/// server still holds the identity, so the confirmed reset stays available
/// although the network has no engine work. A network that is only reset
/// has no identity on the server: it gives false.
fn forgotten_reset_step(state: &WorkerState, network: &str, action: &E2eManageAction) -> bool {
    matches!(
        action,
        E2eManageAction::Reset | E2eManageAction::ResetConfirm
    ) && state.e2e.forgotten.contains(network)
        && state.e2e.engines.contains_key(network)
}

/// Runs `/e2e forget` and `/e2e forget yes`: the recovery step for a replaced
/// identity. The device holds the old master key, so it refuses the grant of a
/// pairing with the identity of the server. The step removes the private state
/// of this device only. It makes no server call: the identity on the server
/// stays. Then `/e2e join` can give this device the identity of the server.
/// The step runs only when the provisioning run found a replaced identity, and
/// only after the question and the answer for the same network. If no listed
/// device can pair, `/e2e reset` stays available in the same session.
fn run_e2e_forget(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    own_nick: &str,
    confirmed: bool,
) {
    let show = |kind: &'static str| show_manage_kind(ui, kind, String::new(), String::new());
    if state.e2e.recovery.get(network).copied() != Some(RecoveryReason::Replaced) {
        return show("e2e-forget-not-needed");
    }
    if !confirmed {
        state.e2e.forget_asked = Some(network.to_string());
        return show("e2e-forget-confirm");
    }
    let Some(mut engine) = take_pairing_engine(state, network, true) else {
        return show("e2e-forget-failed");
    };
    match engine.state_mut().finish_reset(network, own_nick) {
        Ok(()) => {
            settle_reset(state, ui, network, engine);
            state.e2e.forgotten.insert(network.to_string());
            show("e2e-forget-done");
        }
        Err(error) => {
            persistence::log_line(&format!("e2e forget not finished: {error:?}"));
            state.e2e.engines.insert(network.to_string(), engine);
            show("e2e-forget-failed");
        }
    }
}

/// Ends a reset or a revoke that an earlier run left open, for example after
/// a restart or an offline step. A reset here was confirmed by the user
/// before. A failed step keeps the state pending for the next start.
async fn resume_pending_manage(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(own_nick) = state.networks.own_nicks.get(network).cloned() else {
        return;
    };
    let Some(mut engine) = state.e2e.engines.remove(network) else {
        return;
    };
    let routes = OwnRoutes {
        client: &client,
        token: &token,
        network,
        own_nick: &own_nick,
        server_protocol: state.conn.server_protocol_version,
    };
    let mut reset_done = false;
    match resume_reset(&routes, engine.state_mut()).await {
        Ok(true) => {
            reset_done = true;
            show_manage_kind(ui, "e2e-reset-done", String::new(), String::new());
        }
        Ok(false) => match finish_pending_revoke(&routes, engine.state_mut()).await {
            Ok(None) => {}
            Ok(Some(done)) => {
                let (kind, hint) = revoke_status_key(&Ok(done));
                show_manage_kind(ui, kind, hint, String::new());
            }
            Err(error) => {
                persistence::log_line(&format!("e2e revoke not finished: {error:?}"));
                let (kind, hint) = revoke_status_key(&Err(error));
                show_manage_kind(ui, kind, hint, String::new());
            }
        },
        Err(error) => {
            persistence::log_line(&format!("e2e reset not finished: {error:?}"));
            show_manage_kind(
                ui,
                reset_status_key(&Err(error)),
                String::new(),
                String::new(),
            );
        }
    }
    if reset_done {
        settle_reset(state, ui, network, engine);
    } else {
        state.e2e.engines.insert(network.to_string(), engine);
    }
}

/// Marks `network` as reset and puts its engine back. The engine stays in the
/// map for the sealed history only. The end of the session drops the queued
/// texts, so nothing goes out for the deleted device. The reset also clears
/// the provisioning marker: the device no longer has the identity.
fn settle_reset(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    mut engine: E2eEngine,
) {
    engine.end_session();
    let changed = engine.take_changed_peers();
    state.e2e.engines.insert(network.to_string(), engine);
    state.e2e.provisioned.remove(network);
    state.e2e.reset.insert(network.to_string());
    state.e2e.forgotten.remove(network);
    state.e2e.recovery.remove(network);
    state.e2e.clear_ciphertext_views(network);
    for nick in changed {
        refresh_locked_view(state, ui, network, &nick);
    }
}

/// Cancels the open pairing, closes its rendezvous and empties its slot. The
/// calls use the network of the pairing.
async fn end_active_pairing(state: &mut WorkerState) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(mut active) = state.e2e.pairing.take() else {
        return;
    };
    let Some(mut engine) = take_pairing_engine(state, &active.network, false) else {
        return;
    };
    let protocol = state.conn.server_protocol_version;
    let network = active.network.clone();
    let ctx = PairingContext {
        client: &client,
        token: &token,
        protocol,
        network_id: &network,
    };
    pairing::cancel(&ctx, engine.state_mut(), &mut active.session).await;
    state.e2e.engines.insert(network, engine);
}

/// Fetches the messages of the open pairing after its last sequence. Call it
/// after a connect or a reconnect: an event missed while the socket was down
/// is read here. With no open pairing it does nothing.
async fn pump_pairing(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(mut active) = state.e2e.pairing.take() else {
        return;
    };
    if !active.session.is_active() {
        clear_pairing_dialog(ui);
        return;
    }
    let Some(mut engine) = take_pairing_engine(state, &active.network, false) else {
        state.e2e.pairing = Some(active);
        return;
    };
    let protocol = state.conn.server_protocol_version;
    let network = active.network.clone();
    let ctx = PairingContext {
        client: &client,
        token: &token,
        protocol,
        network_id: &network,
    };
    let result = pairing::pump(&ctx, engine.state_mut(), &mut active.session).await;
    state.e2e.engines.insert(network, engine);
    let error = follow_offered_network(state, &mut active, result).await;
    finish_pairing_step(state, ui, active, error);
}

/// The result of a pairing step, after the move of a joiner to the network
/// that the sealed offer of the holder named. A step that failed stays as it
/// is.
async fn follow_offered_network(
    state: &mut WorkerState,
    active: &mut ActivePairing,
    result: Result<(), pairing::DriveError>,
) -> Option<pairing::DriveError> {
    match result {
        Err(error) => Some(error),
        Ok(()) => rebind_joiner(state, active).await.err(),
    }
}

/// A joiner that accepted an offer starts on the first candidate network. When
/// the sealed offer names another network, the pairing moves to the engine of
/// that network: the joiner takes the device of its store, saves the pairing
/// record there, and sends the join if the code is confirmed. The record of
/// the first network is cleared. Nothing changes if the network is the same.
async fn rebind_joiner(
    state: &mut WorkerState,
    active: &mut ActivePairing,
) -> Result<(), pairing::DriveError> {
    let offered = active.session.network().to_string();
    if offered == active.network || !active.session.is_active() {
        return Ok(());
    }
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return Ok(());
    };
    let protocol = state.conn.server_protocol_version;
    let first = active.network.clone();
    let Some(mut engine) = take_pairing_engine(state, &offered, true) else {
        // No engine for the offered network: the pairing cannot go on.
        if let Some(mut old) = take_pairing_engine(state, &first, false) {
            let ctx = PairingContext {
                client: &client,
                token: &token,
                protocol,
                network_id: &first,
            };
            pairing::cancel(&ctx, old.state_mut(), &mut active.session).await;
            state.e2e.engines.insert(first, old);
        }
        return Err(pairing::FlowError::Store.into());
    };
    if let Some(old) = state.e2e.engines.get_mut(&first) {
        let _ = pairing::clear_pending(old.state_mut());
    }
    let ctx = PairingContext {
        client: &client,
        token: &token,
        protocol,
        network_id: &offered,
    };
    let result = pairing::bind_joiner(&ctx, engine.state_mut(), &mut active.session).await;
    state.e2e.engines.insert(offered.clone(), engine);
    active.network = offered;
    result
}

/// Keeps the pairing while it is open and shows its state or its error.
fn finish_pairing_step(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    active: ActivePairing,
    error: Option<pairing::DriveError>,
) {
    match error {
        Some(error) => show_pairing_kind(ui, pairing_error_key(&error), String::new()),
        None => match (&active.manual_code, active.session.status()) {
            // The creator keeps the code on screen while the rendezvous waits.
            (Some(code), PairingStatus::Waiting) => {
                show_pairing_kind(ui, "e2e-pair-manual", code.clone());
            }
            (_, status) => show_pairing(ui, &status),
        },
    }
    // A finished join gave the device a new identity after a reset.
    if matches!(active.session.status(), PairingStatus::Done) {
        state.e2e.needs_pairing.remove(&active.network);
        state.e2e.recovery.remove(&active.network);
        state.e2e.reset.remove(&active.network);
        state.e2e.forgotten.remove(&active.network);
        state.e2e.clear_ciphertext_views(&active.network);
    }
    if active.session.is_active() {
        state.e2e.pairing = Some(active);
    } else {
        clear_pairing_dialog(ui);
    }
    push_open_locked_state(state, ui);
}

/// Reads one `e2e_pairing_message` or `e2e_pairing_closed` frame. An event
/// with no open pairing, or for another rendezvous, changes nothing. The
/// frame is never a chat line.
pub(crate) async fn handle_e2e_pairing(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    frame: &PhoenixMessage,
) {
    let Some(push) = route_e2e_pairing(frame) else {
        return;
    };
    // A closed rendezvous ends a waiting offer for it. The first message of
    // a joiner means that someone joined: the offer is gone too.
    let dropped = match &push {
        PairingPush::Closed { rendezvous_id, .. } => state.e2e.close_offer_of(rendezvous_id),
        PairingPush::Message { rendezvous_id, .. } => state.e2e.drop_offer_of(rendezvous_id),
    };
    if dropped {
        set_offer_dialog(ui, false);
        show_pairing_kind(ui, "e2e-pair-offer-none", String::new());
    }
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(mut active) = state.e2e.pairing.take() else {
        return;
    };
    let Some(mut engine) = take_pairing_engine(state, &active.network, false) else {
        return;
    };
    let protocol = state.conn.server_protocol_version;
    let network = active.network.clone();
    let ctx = PairingContext {
        client: &client,
        token: &token,
        protocol,
        network_id: &network,
    };
    let result = pairing::on_push(&ctx, engine.state_mut(), &mut active.session, &push).await;
    state.e2e.engines.insert(network, engine);
    let error = follow_offered_network(state, &mut active, result).await;
    finish_pairing_step(state, ui, active, error);
}

/// Drops the waiting pairing offer when its end time passed, and tells the
/// user that it ended.
fn retire_expired_offer(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    if state.e2e.expire_offer(e2e_now()) {
        set_offer_dialog(ui, false);
        show_pairing_kind(ui, "e2e-pair-offer-none", String::new());
    }
}

/// Reads one `e2e_pairing_offered` frame (protocol 55). Only the own user
/// topic carries a valid offer. An offer that is not valid or not for this
/// device shows nothing and starts nothing. A valid offer opens the in-app
/// offer and waits for the user: no join starts here. The log names the
/// decision only, never a value of the offer. The frame is never a chat line.
pub(crate) fn handle_e2e_pairing_offer(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    frame: &PhoenixMessage,
) {
    let Some(user) = state.conn.identifier.as_deref() else {
        return;
    };
    if frame.topic != format!("grappa:user:{user}") || state.conn.guest_session {
        return;
    }
    let Some(offer) = route_e2e_pairing_offer(frame) else {
        return;
    };
    let known: Vec<String> = state.networks.own_nicks.keys().cloned().collect();
    let protocol = state.conn.server_protocol_version;
    match state.e2e.admit_offer(offer, &known, protocol, e2e_now()) {
        OfferDecision::Show => set_offer_dialog(ui, true),
        other => persistence::log_line(&format!("e2e pairing offer ignored: {other:?}")),
    }
}

/// Ends a pairing whose lifetime is over. Call it for every E2E tick.
pub(crate) async fn tick_pairing(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    retire_expired_offer(state, ui);
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(mut active) = state.e2e.pairing.take() else {
        return;
    };
    let Some(mut engine) = take_pairing_engine(state, &active.network, false) else {
        state.e2e.pairing = Some(active);
        return;
    };
    let protocol = state.conn.server_protocol_version;
    let network = active.network.clone();
    let ctx = PairingContext {
        client: &client,
        token: &token,
        protocol,
        network_id: &network,
    };
    let ended = pairing::tick(&ctx, engine.state_mut(), &mut active.session, e2e_now()).await;
    state.e2e.engines.insert(network, engine);
    if ended {
        clear_pairing_dialog(ui);
        show_pairing(ui, &active.session.status());
    } else {
        state.e2e.pairing = Some(active);
    }
    push_open_locked_state(state, ui);
}

async fn drain_network(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, network: &str) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let protocol = state.conn.server_protocol_version;
    let Some(mut engine) = state.e2e.engines.remove(network) else {
        return;
    };
    // A copy from a device with a newer list stops the run. The own list is
    // read again, then the inbox is drained once more.
    for _ in 0..2 {
        match engine.drain(&client, &token, protocol, e2e_now()).await {
            Ok(outcomes) => {
                persistence::log_line(&format!(
                    "e2e inbox read for {network}: {} items",
                    outcomes.len()
                ));
                if !outcomes
                    .iter()
                    .any(|(_, outcome)| *outcome == RowOutcome::StaleList)
                {
                    break;
                }
                if let Err(error) = engine.sync_own_list(&client, &token, protocol).await {
                    persistence::log_line(&format!(
                        "e2e own list not read for {network}: {error:?}"
                    ));
                    for (id, outcome) in &outcomes {
                        if *outcome == RowOutcome::StaleList {
                            engine.release_stale_try(*id);
                        }
                    }
                    break;
                }
            }
            Err(error) => {
                persistence::log_line(&format!("e2e inbox not read for {network}: {error:?}"));
                break;
            }
        }
    }
    settle_engine(state, ui, network, engine).await;
}

/// Reads one `e2e_message` frame with the engine of its network.
pub(crate) async fn handle_e2e_message(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    frame: &PhoenixMessage,
) {
    let protocol = state.conn.server_protocol_version;
    let Some(row) = route_e2e_message(frame, protocol) else {
        return;
    };
    if !ensure_engine(state, &row.network) {
        return;
    }
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(mut engine) = state.e2e.engines.remove(&row.network) else {
        return;
    };
    // A copy from a device that the own list does not know yet waits: the
    // own list is read again, then the row is read once more.
    for _ in 0..2 {
        match engine
            .handle_event(&client, &token, protocol, &row, e2e_now())
            .await
        {
            Ok(RowOutcome::StaleList) => {
                if let Err(error) = engine.sync_own_list(&client, &token, protocol).await {
                    persistence::log_line(&format!(
                        "e2e own list not read for {}: {error:?}",
                        row.network
                    ));
                    engine.release_stale_try(row.id);
                    break;
                }
            }
            Ok(_) => break,
            Err(error) => {
                persistence::log_line(&format!("e2e item not read for {}: {error:?}", row.network));
                state.e2e.note_engine_error(&row.network, &row.from, &error);
                break;
            }
        }
    }
    settle_engine(state, ui, &row.network, engine).await;
}

/// Puts the engine back and shows what its last call changed: it asks for
/// the keys of senders it could not read, adds the locked entries of peers
/// that are ready or got a row, and redraws the open locked window.
async fn settle_engine(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    mut engine: E2eEngine,
) {
    if let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) {
        // Texts that wait for keys go out when the keys came, or end as a
        // `late` or `send_failed` drop. The engine marks the rows.
        let drops = engine.expire_queue();
        let drops = [drops, engine.flush_queue(&client, &token, e2e_now()).await].concat();
        if !drops.is_empty() {
            set_e2e_status(ui, "e2e-send-failed");
        }
        send_copies(state, network, &mut engine, &client, &token).await;
        engine.send_list_messages(&client, &token).await;
    }
    let wanted = engine.take_keys_wanted();
    if let (false, Some(client), Some(token)) = (
        wanted.is_empty(),
        state.conn.client.clone(),
        state.conn.token.clone(),
    ) {
        for nick in wanted {
            let result = engine.request_keys(&client, &token, &nick).await;
            state.e2e.note_key_request(network, &nick, &result);
            if let Err(error) = result {
                state.e2e.note_engine_error(network, &nick, &error);
                if !matches!(error, EngineError::Paced(_) | EngineError::PeerNotCapable) {
                    persistence::log_line(&format!("e2e key request failed: {error:?}"));
                }
            }
        }
    }
    // A KEYS row, a claim answer or a first message under another master
    // key: the engine reads it as an unread row, and the entry shows the
    // trust alarm.
    for nick in engine.take_trust_changed() {
        state.e2e.trust_alarm.insert((network.to_string(), nick));
    }
    let changed = engine.take_changed_peers();
    let own_nick = state
        .networks
        .own_nicks
        .get(network)
        .cloned()
        .unwrap_or_default();
    let ready: Vec<String> = engine
        .ready_peers()
        .into_iter()
        .filter(|nick| !nick.eq_ignore_ascii_case(&own_nick))
        .collect();
    state.e2e.engines.insert(network.to_string(), engine);
    let mut sidebar_changed = false;
    for nick in changed.iter().chain(ready.iter()) {
        sidebar_changed |= state.e2e.add_locked(network, nick);
    }
    for nick in &changed {
        refresh_locked_view(state, ui, network, nick);
    }
    // The unread counts of the locked entries change with each new row.
    if sidebar_changed || !changed.is_empty() {
        refresh_network_groups(state, ui);
    }
    push_open_locked_state(state, ui);
    push_open_query_consent(state, ui);
}

/// Queues the copies of the sent texts in the inboxes of the other devices
/// of the account. A list that is behind stops the run: the own list is read
/// again and the run goes on once. A copy never goes over IRC.
async fn send_copies(
    state: &WorkerState,
    network: &str,
    engine: &mut E2eEngine,
    client: &GrappaClient,
    token: &str,
) {
    if !engine.has_pending_copies() {
        return;
    }
    let protocol = state.conn.server_protocol_version;
    let own_nick = state
        .networks
        .own_nicks
        .get(network)
        .cloned()
        .unwrap_or_default();
    for _ in 0..2 {
        let report = engine
            .send_copies(client, token, protocol, &own_nick, e2e_now())
            .await;
        if !report.failed.is_empty() {
            // The log gets the kinds of the failures, never the text.
            persistence::log_line(&format!(
                "e2e copies not queued for {network}: {:?}",
                report.failed
            ));
        }
        if !report.needs_sync {
            return;
        }
        if let Err(error) = engine.sync_own_list(client, token, protocol).await {
            persistence::log_line(&format!("e2e own list not read for {network}: {error:?}"));
        }
    }
}

/// Reloads the rows of the locked window of `nick` from the sealed history
/// and redraws its rows, when that window is the open one. The compose field
/// and the other window values stay as they are.
fn refresh_locked_view(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    nick: &str,
) {
    let is_open = open_locked_window(state)
        .is_some_and(|(open_network, open_nick)| open_network == network && open_nick == nick);
    if is_open {
        mark_active_window_read(state, ui);
        load_locked_rows(state, network, nick);
        show_locked_rows(state, ui, network, nick);
    }
}

fn push_sas_code(ui: &slint::Weak<AppWindow>, code: String) {
    let _ = ui.upgrade_in_event_loop(move |ui| ui.set_e2e_sas_code(code.into()));
}

/// Runs one SAS step for the open locked entry. Only a confirm for the
/// stored master key the code was made from marks the peer as verified. A
/// reject, a cancel or a changed master leaves the peer unverified.
pub(crate) fn handle_e2e_sas(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, step: SasStep) {
    let Some((network, nick)) = open_locked_window(state) else {
        return;
    };
    let alarm = state
        .e2e
        .trust_alarm
        .contains(&(network.clone(), nick.clone()));
    let kind = match step {
        SasStep::Start => {
            let shown = state
                .e2e
                .engines
                .get(&network)
                .filter(|_| !alarm)
                .and_then(|engine| Some((engine.sas_master(&nick)?, engine.sas_code(&nick)?)));
            match shown {
                Some((master, code)) => {
                    state.e2e.sas_check = Some(SasCheck {
                        network,
                        nick,
                        master,
                    });
                    push_sas_code(ui, code);
                    return;
                }
                None => "e2e-sas-unavailable",
            }
        }
        SasStep::Confirm | SasStep::Reject | SasStep::Cancel => {
            let check = state
                .e2e
                .sas_check
                .take()
                .filter(|check| check.network == network && check.nick == nick);
            push_sas_code(ui, String::new());
            match (step, check) {
                (SasStep::Cancel, _) => return,
                (SasStep::Reject, _) => "e2e-sas-rejected",
                (_, None) => "e2e-sas-unavailable",
                (_, Some(_)) if alarm => "e2e-sas-failed",
                (_, Some(check)) => {
                    let saved = state
                        .e2e
                        .engines
                        .get_mut(&network)
                        .map(|engine| engine.confirm_sas(&nick, &check.master));
                    match saved {
                        Some(Ok(())) => "e2e-sas-verified",
                        _ => "e2e-sas-failed",
                    }
                }
            }
        }
    };
    set_e2e_status(ui, kind);
    push_open_locked_state(state, ui);
}

/// A step of the peer key view, chosen by the user in the banner of the
/// locked chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerKeyStep {
    Open,
    Close,
    Verify,
}

impl PeerKeyStep {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "open" => Some(PeerKeyStep::Open),
            "close" => Some(PeerKeyStep::Close),
            "verify" => Some(PeerKeyStep::Verify),
            _ => None,
        }
    }
}

/// The full master key of the peer and its outside check state. It is
/// `None` with a trust alarm, without an engine or without a stored master.
fn peer_key_facts(state: &WorkerState, network: &str, nick: &str) -> Option<(String, bool)> {
    if state
        .e2e
        .trust_alarm
        .contains(&(network.to_string(), nick.to_string()))
    {
        return None;
    }
    let engine = state.e2e.engines.get(network)?;
    Some((engine.sas_master(nick)?, engine.is_key_verified(nick)))
}

/// Marks `key` as verified for the peer. The engine accepts the key only when
/// it is the stored master now, so a delayed request for an old key fails.
fn verify_peer_key(state: &mut WorkerState, network: &str, nick: &str, key: &str) -> bool {
    if peer_key_facts(state, network, nick).is_none() {
        return false;
    }
    state
        .e2e
        .engines
        .get_mut(network)
        .is_some_and(|engine| engine.confirm_key(nick, key).is_ok())
}

fn push_peer_key(
    ui: &slint::Weak<AppWindow>,
    open: bool,
    network: String,
    nick: String,
    key: String,
    verified: bool,
) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_e2e_peer_key_open(open);
        ui.set_e2e_peer_key_network(network.into());
        ui.set_e2e_peer_key_nick(nick.into());
        ui.set_e2e_peer_key(key.into());
        ui.set_e2e_peer_key_verified(verified);
    });
}

fn close_peer_key(ui: &slint::Weak<AppWindow>) {
    push_peer_key(
        ui,
        false,
        String::new(),
        String::new(),
        String::new(),
        false,
    );
}

/// Runs one step of the peer key view for the open locked entry. Open and
/// close never change trust. Only a verify for the network, the peer and the
/// key that the view shows marks the key as verified.
pub(crate) fn handle_e2e_peer_key(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    step: PeerKeyStep,
    network: String,
    nick: String,
    key: String,
) {
    let open = open_locked_window(state);
    if step == PeerKeyStep::Close {
        close_peer_key(ui);
        return;
    }
    // A delayed request for another window or peer is ignored.
    if open.as_ref() != Some(&(network.clone(), nick.clone())) {
        return;
    }
    match step {
        PeerKeyStep::Open => match peer_key_facts(state, &network, &nick) {
            Some((master, verified)) => push_peer_key(ui, true, network, nick, master, verified),
            None => close_peer_key(ui),
        },
        PeerKeyStep::Verify => {
            let kind = if verify_peer_key(state, &network, &nick, &key) {
                "e2e-key-verified"
            } else {
                "e2e-key-failed"
            };
            match peer_key_facts(state, &network, &nick) {
                Some((master, verified)) => {
                    push_peer_key(ui, true, network, nick, master, verified);
                }
                None => close_peer_key(ui),
            }
            set_e2e_status(ui, kind);
            push_open_locked_state(state, ui);
        }
        PeerKeyStep::Close => {}
    }
}

/// Pushes the state banner of the open locked entry.
fn push_open_locked_state(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let Some((network, nick)) = open_locked_window(state) else {
        return;
    };
    let chat_state = locked_entry_state(state, &network, &nick);
    // A trust alarm closes an open peer key view, so it shows no old key.
    if chat_state == ChatState::TrustAlarm {
        close_peer_key(ui);
    }
    let key = chat_state.key();
    let _ = ui.upgrade_in_event_loop(move |ui| ui.set_current_query_e2e_state(key.into()));
}

/// Redraws only the rows of the locked window of `nick`.
fn show_locked_rows(state: &WorkerState, ui: &slint::Weak<AppWindow>, network: &str, nick: &str) {
    let lines = state
        .transcript
        .messages
        .get(&LocalQuery::new(network, QueryLane::Locked, nick).key())
        .cloned()
        .unwrap_or_default();
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        show_chat_lines(&ui, chat_lines_model(&lines, dark_theme));
    });
}

fn load_locked_rows(state: &mut WorkerState, network: &str, nick: &str) {
    let own_nick = state
        .networks
        .own_nicks
        .get(network)
        .cloned()
        .unwrap_or_else(|| "me".to_string());
    let engine = state.e2e.engines.get(network);
    let ciphertext = state.e2e.shows_ciphertext(network, nick);
    let rows: Vec<RenderedMessage> = state
        .e2e
        .history_of(network)
        .map(|history| {
            history
                .messages(&conversation_id(network, nick))
                .into_iter()
                .flat_map(|message| {
                    let dropped = engine.and_then(|engine| engine.dropped_reason(&message.id));
                    locked_rows_for_view(message, &own_nick, nick, dropped, ciphertext)
                })
                .collect()
        })
        .unwrap_or_default();
    state.transcript.messages.insert(
        LocalQuery::new(network, QueryLane::Locked, nick).key(),
        rows,
    );
}

/// Shows the locked window of `nick`. It is not a Grappa window: nothing is
/// fetched, and the peer nick the view gets is the real one.
fn show_locked_window(state: &WorkerState, ui: &slint::Weak<AppWindow>, network: &str, nick: &str) {
    let key = LocalQuery::new(network, QueryLane::Locked, nick).key();
    let chat_state = locked_entry_state(state, network, nick).key();
    let lines = state
        .transcript
        .messages
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let draft = state
        .transcript
        .drafts
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let label = format!("{network} — {}", key.1);
    let source_network = network.to_string();
    let source_target = key.1.clone();
    let window_status = window_status_for(state);
    let peer_nick = nick.to_string();
    crate::queries::push_shared_channels(state, ui, network, nick);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_channel_label(label.into());
        ui.set_window_source_network(source_network.into());
        ui.set_window_source_target(source_target.into());
        ui.set_current_topic("".into());
        ui.set_window_status(window_status.into());
        ui.set_current_window_is_joined(false);
        ui.set_current_server_window(false);
        ui.set_has_selected_channel(true);
        ui.set_current_query(true);
        ui.set_current_query_ready(true);
        ui.set_current_query_e2e(true);
        ui.set_current_query_e2e_state(chat_state.into());
        ui.set_current_query_e2e_start_confirm_open(false);
        ui.set_current_query_e2e_request_state("".into());
        ui.set_current_query_e2e_request_id("".into());
        ui.set_current_query_e2e_can_start(false);
        ui.set_current_query_e2e_can_accept(false);
        ui.set_current_query_e2e_has_locked(false);
        ui.set_current_query_peer_nick(peer_nick.into());
        ui.set_compose_text(draft.into());
        ui.set_reply_target_left(false);
        ui.set_can_moderate_members(false);
        ui.set_history_start_reached(true);
        ui.set_history_loading(false);
        ui.set_history_failed(false);
        let model = chat_lines_model(&lines, dark_theme);
        show_chat_lines(&ui, model);
        let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
        ui.set_channel_members(empty_members.into());
    });
}

/// Selects a locked entry of the sidebar. `label` is the window name with the
/// lock label; an entry that is not in the list is ignored.
pub(crate) fn handle_select_locked_query(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    label: &str,
) {
    state.transcript.pending_query_focus = None;
    let SendRoute::Encrypted { nick } = route_for_window(label) else {
        return;
    };
    if !state.e2e.locked.contains(&(network.clone(), nick.clone())) {
        return;
    }
    close_directory(state, ui);
    let key = (network.clone(), label.to_string());
    prepare_window_selection(state, &key, true);
    state.windows.current_query = true;
    state.windows.current_query_ready = true;
    // A SAS check belongs to the window that opened it.
    state.e2e.sas_check = None;
    push_sas_code(ui, String::new());
    close_peer_key(ui);
    open_window(state, &key);
    load_locked_rows(state, &network, &nick);
    refresh_network_groups(state, ui);
    show_locked_window(state, ui, &network, &nick);
    mark_active_window_read(state, ui);
}

/// The locked entries that show ciphertext, as `(network, window label)`.
/// The sidebar menu reads it to name its switch.
pub(crate) fn ciphertext_view_windows(state: &WorkerState) -> HashSet<(String, String)> {
    state
        .e2e
        .cipher_view
        .iter()
        .map(|(network, nick)| {
            (
                network.clone(),
                LocalQuery::new(network, QueryLane::Locked, nick).window_name(),
            )
        })
        .collect()
}

/// Switches the view of one locked entry between plaintext and ciphertext.
/// The switch changes the display only: the history, the keys and the send
/// path stay as they are. False when `label` is not a locked entry.
pub(crate) fn toggle_ciphertext_view(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    label: &str,
) -> bool {
    let SendRoute::Encrypted { nick } = route_for_window(label) else {
        return false;
    };
    if !state
        .e2e
        .locked
        .contains(&(network.to_string(), nick.clone()))
    {
        return false;
    }
    state.e2e.toggle_ciphertext(network, &nick);
    // An entry that is not open loads its rows when the user opens it.
    refresh_locked_view(state, ui, network, &nick);
    refresh_network_groups(state, ui);
    true
}

/// Closes a locked entry. False when `label` is not a locked entry, so the
/// caller closes the plain query as before. The sealed history stays.
pub(crate) fn close_locked_query(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    label: &str,
) -> bool {
    let SendRoute::Encrypted { nick } = route_for_window(label) else {
        return false;
    };
    let was_open = open_locked_window(state)
        .is_some_and(|(open_network, open_nick)| open_network == network && open_nick == nick);
    state
        .e2e
        .cipher_view
        .remove(&(network.to_string(), nick.clone()));
    state.e2e.locked.remove(&(network.to_string(), nick));
    state
        .transcript
        .messages
        .remove(&(network.to_string(), label.to_string()));
    if was_open {
        state.windows.current_channel = None;
        state.windows.current_query = false;
        state.windows.current_query_ready = false;
        clear_closed_query_view(ui);
    }
    refresh_network_groups(state, ui);
    push_open_query_consent(state, ui);
    true
}

/// Sends `body` from a locked window through the engine. The text goes out
/// as an Olm message or not at all: on any failure the user sees an error and
/// nothing is sent as clear text.
/// What a line typed in a locked window is. Only `Text` and `Action` go to
/// the E2E send path. A command runs as in a plain query and never reaches
/// the peer as an encrypted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LockedInput {
    /// Chat text. A `//text` line is the text `/text`.
    Text(String),
    /// `/me <words>`: chat content that the peer shows as an action.
    Action(String),
    /// `/np`: the radio line as an encrypted action.
    NowPlaying,
    /// A command that has its own handler.
    Command,
    /// A line with a slash that is no command. Nothing is sent.
    Reject,
}

/// Sorts one line of a locked window. Run it before the E2E send path.
pub(crate) fn classify_locked_input(body: &str) -> LockedInput {
    use cordiale_core::slash::{parse, SlashCommand};
    if !body.trim_start().starts_with('/') {
        return LockedInput::Text(body.to_string());
    }
    match parse(body) {
        Some(SlashCommand::Say(text)) => LockedInput::Text(text),
        Some(SlashCommand::Action(text)) => LockedInput::Action(text),
        Some(SlashCommand::NowPlaying) => LockedInput::NowPlaying,
        Some(_) => LockedInput::Command,
        None => LockedInput::Reject,
    }
}

/// The words of `/ctcp <target> ACTION <words>` when the target is the peer of
/// the locked window under the network case mapping. Any other line gives
/// `None` and keeps the normal command path.
pub(crate) fn locked_ctcp_action(
    body: &str,
    peer: &str,
    casemapping: cordiale_core::isupport::CaseMapping,
) -> Option<String> {
    use cordiale_core::slash::{parse, SlashCommand};
    match parse(body) {
        Some(SlashCommand::Ctcp { target, verb, args })
            if verb == "ACTION" && casemapping.nick_eq(&target, peer) =>
        {
            Some(args.unwrap_or_default())
        }
        _ => None,
    }
}

/// Sends `/me <words>` of a locked window as an encrypted action.
pub(crate) async fn handle_send_locked_action(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    nick: String,
    words: String,
) {
    if words.trim().is_empty() {
        return;
    }
    handle_send_locked(state, ui, network, nick, action_text(&words)).await;
}

pub(crate) async fn handle_send_locked(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    nick: String,
    body: String,
) {
    if body.trim().is_empty() {
        return;
    }
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        set_e2e_status(ui, "e2e-not-ready");
        return;
    };
    // After a reset the locked query cannot send, and nothing goes out as
    // clear text.
    if state.e2e.reset.contains(&network) {
        set_e2e_status(ui, "e2e-not-ready");
        return;
    }
    let Some(mut engine) = state.e2e.engines.remove(&network) else {
        set_e2e_status(ui, "e2e-not-ready");
        return;
    };
    let result = engine
        .send_or_queue(&client, &token, &nick, &body, e2e_now())
        .await;
    if result.is_ok() {
        set_chat_follow_bottom(state, ui);
    }
    if let Err(error) = &result {
        // The log gets the kind of the failure, never the text.
        persistence::log_line(&format!("e2e send failed for {network}: {error:?}"));
        set_e2e_status(ui, e2e_send_error_kind(error));
        state.e2e.note_engine_error(&network, &nick, error);
    }
    settle_engine(state, ui, &network, engine).await;
    if result.is_ok() {
        mark_active_window_read(state, ui);
    }
}

/// The session stopped (a disconnect or a reconnect): every open send of
/// every engine becomes a `session_ended` drop, and every queue is emptied.
/// The locked window shows the dropped rows.
pub(crate) fn end_e2e_sessions(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    // An offer of the ended session is stale after a reconnect.
    if state.e2e.offer.take().is_some() {
        set_offer_dialog(ui, false);
        show_pairing_kind(ui, "e2e-pair-offer-none", String::new());
    }
    let mut networks: Vec<String> = state.e2e.engines.keys().cloned().collect();
    networks.sort();
    let mut any = false;
    for network in &networks {
        let Some(engine) = state.e2e.engines.get_mut(network) else {
            continue;
        };
        any |= !engine.end_session().is_empty();
        let changed = engine.take_changed_peers();
        for nick in changed {
            refresh_locked_view(state, ui, network, &nick);
        }
    }
    if any {
        set_e2e_status(ui, "e2e-send-failed");
    }
}

/// Runs the timers of the engines: a text that waits too long for keys is a
/// `late` drop, a queued text goes out when its keys came, and the keys are
/// asked for again.
pub(crate) async fn tick_e2e_engines(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let mut networks: Vec<String> = state.e2e.engines.keys().cloned().collect();
    networks.sort();
    for network in networks {
        if state.e2e.reset.contains(&network) {
            continue;
        }
        if !state
            .e2e
            .engines
            .get(&network)
            .is_some_and(|engine| engine.has_queued_text() || engine.has_pending_copies())
        {
            continue;
        }
        let Some(engine) = state.e2e.engines.remove(&network) else {
            continue;
        };
        settle_engine(state, ui, &network, engine).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_in_a_locked_window_is_not_a_chat_text() {
        let secret = format!("pw{}", std::process::id());
        let identify = format!("/ns identify {secret}");
        assert_eq!(classify_locked_input(&identify), LockedInput::Command);
        assert_eq!(classify_locked_input("/whois"), LockedInput::Command);
        assert_eq!(classify_locked_input("/join #room"), LockedInput::Command);
        assert_eq!(classify_locked_input("/msg alice hi"), LockedInput::Command);
        assert_eq!(classify_locked_input("/e2e devices"), LockedInput::Command);
    }

    #[test]
    fn an_unknown_command_in_a_locked_window_is_not_sent_as_text() {
        // The normal command code shows the error for an unknown command.
        assert_eq!(classify_locked_input("/frob x"), LockedInput::Command);
        // A lone slash is no command and no text.
        assert_eq!(classify_locked_input("/"), LockedInput::Reject);
    }

    #[test]
    fn text_and_the_double_slash_escape_keep_the_encrypted_send_path() {
        assert_eq!(
            classify_locked_input("hello"),
            LockedInput::Text("hello".to_string())
        );
        assert_eq!(
            classify_locked_input("//shrug"),
            LockedInput::Text("/shrug".to_string())
        );
    }

    #[test]
    fn me_in_a_locked_window_is_an_encrypted_action() {
        assert_eq!(
            classify_locked_input("/me waves"),
            LockedInput::Action("waves".to_string())
        );
        assert_eq!(classify_locked_input("/np"), LockedInput::NowPlaying);
    }

    #[test]
    fn ctcp_action_to_the_locked_peer_is_an_encrypted_action() {
        use cordiale_core::isupport::CaseMapping;
        let map = CaseMapping::Rfc1459;
        assert_eq!(
            locked_ctcp_action("/ctcp Alice ACTION waves", "Alice", map),
            Some("waves".to_string())
        );
        assert_eq!(
            locked_ctcp_action("/ctcp ALICE action waves", "alice", map),
            Some("waves".to_string())
        );
        // Empty text stays empty: the send path then sends nothing.
        assert_eq!(
            locked_ctcp_action("/ctcp Alice ACTION", "Alice", map),
            Some(String::new())
        );
    }

    #[test]
    fn ctcp_action_target_follows_the_network_case_mapping() {
        use cordiale_core::isupport::CaseMapping;
        let line = "/ctcp [bob] ACTION waves";
        assert!(locked_ctcp_action(line, "{bob}", CaseMapping::Rfc1459).is_some());
        assert!(locked_ctcp_action(line, "{bob}", CaseMapping::Ascii).is_none());
    }

    #[test]
    fn other_ctcp_lines_keep_the_command_path() {
        use cordiale_core::isupport::CaseMapping;
        let map = CaseMapping::Rfc1459;
        assert_eq!(
            locked_ctcp_action("/ctcp Bob ACTION waves", "Alice", map),
            None
        );
        assert_eq!(
            locked_ctcp_action("/ctcp Alice VERSION", "Alice", map),
            None
        );
        assert_eq!(locked_ctcp_action("/ping Alice", "Alice", map), None);
        assert_eq!(locked_ctcp_action("/me waves", "Alice", map), None);
    }

    #[test]
    fn an_action_row_renders_as_an_action_line() {
        let message = E2eMessage {
            id: "net:in:1".to_string(),
            conversation_id: "c".to_string(),
            sender_device: "did".to_string(),
            sent_at: 100,
            text: action_text("waves"),
            encrypted: true,
            captures: Vec::new(),
        };
        let row = locked_row_with_drop(&message, "me", "alice", None);
        assert_eq!(row.text, "* alice waves");
        assert_eq!(row.nick, None);
        assert!(row.encrypted);
        let own = E2eMessage {
            sender_device: OWN_DEVICE.to_string(),
            ..message
        };
        assert_eq!(
            locked_row_with_drop(&own, "me", "alice", None).text,
            "* me waves"
        );
    }

    #[test]
    fn a_reset_network_gets_no_engine_and_keeps_its_marker() {
        let mut state = WorkerState::new();
        state.e2e.reset.insert("net".to_string());
        assert!(!ensure_engine(&mut state, "net"));
        // With no client the new engine of a join does not open.
        assert!(take_pairing_engine(&mut state, "net", true).is_none());
        assert!(state.e2e.reset.contains("net"));
    }

    #[test]
    fn the_ciphertext_view_names_the_locked_window_and_keeps_the_unread_count() {
        use cordiale_core::e2e_store::{
            CaptureDirection, E2eCapture, E2eKeyProvider, E2eStoreError,
        };
        struct Key;
        impl E2eKeyProvider for Key {
            fn load_or_create_key(&self) -> Result<[u8; 32], E2eStoreError> {
                Ok([7; 32])
            }
        }
        let dir = tempfile::tempdir().expect("dir");
        let mut history =
            E2eHistoryStore::open(dir.path().join("history.bin"), &Key).expect("open");
        // One incoming message with two payloads is one unread row.
        history
            .append(E2eMessage {
                id: "net:in:1".to_string(),
                conversation_id: conversation_id("net", "bob"),
                sender_device: "AAAAAAAAAAA".to_string(),
                sent_at: 10,
                text: "hi".to_string(),
                encrypted: true,
                captures: vec![
                    E2eCapture {
                        verb: "pkmsg".to_string(),
                        msgid: None,
                        payload: "P1".to_string(),
                        direction: CaptureDirection::In,
                    },
                    E2eCapture {
                        verb: "msg".to_string(),
                        msgid: None,
                        payload: "P2".to_string(),
                        direction: CaptureDirection::In,
                    },
                ],
            })
            .expect("append");
        assert_eq!(incoming_rows(&history, "net", "bob"), 1);

        let mut state = WorkerState::new();
        assert!(ciphertext_view_windows(&state).is_empty());
        state.e2e.toggle_ciphertext("net", "bob");
        let windows = ciphertext_view_windows(&state);
        let label = LocalQuery::new("net", QueryLane::Locked, "bob").window_name();
        assert!(windows.contains(&("net".to_string(), label)));
    }

    const OFFER_ID: &str = "AbCdEfGhIjKlMnOpQrStUv";
    const OFFER_KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    /// `2026-10-23T10:00:00Z`.
    const OFFER_END: i64 = 1_792_749_600;
    /// A server that speaks the pairing offer.
    const P55: Option<u32> = Some(55);

    fn offer_payload(id: &str) -> Value {
        serde_json::json!({
            "kind": "e2e_pairing_offered",
            "rendezvous_id": id,
            "curve": OFFER_KEY,
            "expires_at": "2026-10-23T10:00:00Z",
        })
    }

    fn offer(id: &str) -> PairingOffer {
        PairingOffer::from_value(&offer_payload(id)).unwrap()
    }

    fn nets(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    /// A runtime whose device lacks the identity of `libera`.
    fn runtime_needing_pairing() -> E2eRuntime {
        let mut runtime = E2eRuntime::default();
        runtime.needs_pairing.insert("libera".to_string());
        runtime
    }

    #[test]
    fn an_offer_waits_for_the_user_and_starts_no_join() {
        let mut runtime = runtime_needing_pairing();
        let known = nets(&["libera"]);
        let decision = runtime.admit_offer(offer(OFFER_ID), &known, P55, OFFER_END - 60);
        assert_eq!(decision, OfferDecision::Show);
        // The offer only waits: no pairing is open and none starts.
        assert!(runtime.offer.is_some());
        assert!(runtime.pairing.is_none());
    }

    #[test]
    fn a_forgotten_network_keeps_the_server_reset_available() {
        let dir = tempfile::tempdir().expect("dir");
        let (mut state, _peer) = sas_state(&dir);
        let ui = slint::Weak::<AppWindow>::default();
        let engine = state.e2e.engines.remove("net").expect("engine");
        settle_reset(&mut state, &ui, "net", engine);
        // A network that is only reset has no identity on the server.
        for action in [E2eManageAction::Reset, E2eManageAction::ResetConfirm] {
            assert!(!forgotten_reset_step(&state, "net", &action));
        }
        state.e2e.forgotten.insert("net".to_string());
        for action in [E2eManageAction::Reset, E2eManageAction::ResetConfirm] {
            assert!(forgotten_reset_step(&state, "net", &action));
        }
        for action in [
            E2eManageAction::Devices,
            E2eManageAction::Revoke("did".to_string()),
            E2eManageAction::Forget,
        ] {
            assert!(!forgotten_reset_step(&state, "net", &action));
        }
        // A real reset clears the marker.
        let engine = state.e2e.engines.remove("net").expect("engine");
        settle_reset(&mut state, &ui, "net", engine);
        assert!(!state.e2e.forgotten.contains("net"));
        assert!(!forgotten_reset_step(
            &state,
            "net",
            &E2eManageAction::Reset
        ));
    }

    #[test]
    fn one_accept_gives_the_exact_offered_id_and_key_once() {
        let mut runtime = runtime_needing_pairing();
        let known = nets(&["libera"]);
        runtime.admit_offer(offer(OFFER_ID), &known, P55, OFFER_END - 60);
        let (networks, code) = runtime
            .take_offer(&known, OFFER_END - 30)
            .expect("one offer");
        assert_eq!(networks, nets(&["libera"]));
        assert_eq!(code, format!("{OFFER_ID}.{OFFER_KEY}"));
        // The hand-off data is gone: a second accept gets nothing.
        assert!(runtime.offer.is_none());
        assert!(runtime.take_offer(&known, OFFER_END - 30).is_none());
    }

    #[test]
    fn a_failed_accept_still_clears_the_hand_off_data() {
        let mut runtime = runtime_needing_pairing();
        let known = nets(&["libera"]);
        runtime.admit_offer(offer(OFFER_ID), &known, P55, OFFER_END - 60);
        // The offer ended before the accept: it gives nothing and is gone.
        assert!(runtime.take_offer(&known, OFFER_END).is_none());
        assert!(runtime.offer.is_none());
        // The join step clears the text it reads, also when the join fails.
        let mut text = format!("{OFFER_ID}.{OFFER_KEY}");
        let _ = cordiale_core::e2e_pairing::take_pairing_link(&mut text);
        assert!(text.is_empty());
        let mut bad = "broken".to_string();
        assert!(cordiale_core::e2e_pairing::take_pairing_link(&mut bad).is_err());
        assert!(bad.is_empty());
    }

    #[test]
    fn a_reset_device_can_take_an_offer() {
        let mut runtime = E2eRuntime::default();
        runtime.reset.insert("libera".to_string());
        let decision =
            runtime.admit_offer(offer(OFFER_ID), &nets(&["libera"]), P55, OFFER_END - 60);
        assert_eq!(decision, OfferDecision::Show);
    }

    #[test]
    fn a_server_below_protocol_55_shows_no_offer() {
        let mut runtime = runtime_needing_pairing();
        for protocol in [None, Some(48), Some(54)] {
            assert_eq!(
                runtime.admit_offer(
                    offer(OFFER_ID),
                    &nets(&["libera"]),
                    protocol,
                    OFFER_END - 60
                ),
                OfferDecision::Unsupported
            );
        }
        assert!(runtime.offer.is_none());
    }

    #[test]
    fn a_provisioned_device_can_take_an_offer_after_a_reset() {
        let dir = tempfile::tempdir().expect("dir");
        let (mut state, _peer) = sas_state(&dir);
        state.e2e.provisioned.insert("net".to_string());
        assert_eq!(
            state
                .e2e
                .admit_offer(offer(OFFER_ID), &nets(&["net"]), P55, OFFER_END - 60),
            OfferDecision::AlreadyPaired
        );
        let engine = state.e2e.engines.remove("net").expect("engine");
        settle_reset(
            &mut state,
            &slint::Weak::<AppWindow>::default(),
            "net",
            engine,
        );
        assert!(!state.e2e.provisioned.contains("net"));
        assert!(state.e2e.reset.contains("net"));
        assert_eq!(
            state
                .e2e
                .admit_offer(offer(OFFER_ID), &nets(&["net"]), P55, OFFER_END - 60),
            OfferDecision::Show
        );
    }

    #[test]
    fn an_invalid_offer_starts_no_prompt() {
        let now = OFFER_END - 60;
        let known = nets(&["libera"]);
        // An expired offer.
        let mut runtime = runtime_needing_pairing();
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &known, P55, OFFER_END + 1),
            OfferDecision::Expired
        );
        // An end time that is later than one rendezvous lifetime.
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &known, P55, OFFER_END - 3_600),
            OfferDecision::Expired
        );
        // A session with no network.
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &[], P55, now),
            OfferDecision::WrongNetwork
        );
        // Networks that are not the networks of this device.
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &nets(&["other"]), P55, now),
            OfferDecision::AlreadyPaired
        );
        assert!(runtime.offer.is_none());
        // A device that already has the identity.
        let mut paired = E2eRuntime::default();
        paired.provisioned.insert("libera".to_string());
        assert_eq!(
            paired.admit_offer(offer(OFFER_ID), &known, P55, now),
            OfferDecision::AlreadyPaired
        );
        paired.needs_pairing.insert("libera".to_string());
        assert_eq!(
            paired.admit_offer(offer(OFFER_ID), &known, P55, now),
            OfferDecision::AlreadyPaired
        );
        // A network where the device is not known to need a pairing.
        let mut unknown = E2eRuntime::default();
        assert_eq!(
            unknown.admit_offer(offer(OFFER_ID), &known, P55, now),
            OfferDecision::AlreadyPaired
        );
        assert!(paired.offer.is_none() && unknown.offer.is_none());
    }

    fn creator_pairing(id: &str) -> ActivePairing {
        use cordiale_core::e2e_pairing::{PairingRole, Rendezvous};
        let rendezvous = Rendezvous {
            id: id.to_string(),
            role: PairingRole::Creator,
            expires_at: "later".to_string(),
        };
        let (session, _link) = PairingSession::create(&rendezvous, "libera", 0).unwrap();
        ActivePairing {
            network: "libera".to_string(),
            session,
            manual_code: None,
        }
    }

    #[test]
    fn an_offer_is_ignored_while_a_pairing_is_open() {
        let mut runtime = runtime_needing_pairing();
        runtime.pairing = Some(creator_pairing("ZyXwVuTsRqPoNmLkJiHgFe"));
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &nets(&["libera"]), P55, OFFER_END - 60),
            OfferDecision::Busy
        );
        assert!(runtime.offer.is_none());
    }

    #[test]
    fn the_offer_of_the_own_rendezvous_is_ignored() {
        let mut runtime = runtime_needing_pairing();
        runtime.pairing = Some(creator_pairing(OFFER_ID));
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &nets(&["libera"]), P55, OFFER_END - 60),
            OfferDecision::Own
        );
        assert!(runtime.offer.is_none());
    }

    #[test]
    fn a_duplicate_or_closed_offer_is_ignored() {
        let now = OFFER_END - 60;
        let known = nets(&["libera"]);
        let mut runtime = runtime_needing_pairing();
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &known, P55, now),
            OfferDecision::Show
        );
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &known, P55, now),
            OfferDecision::Duplicate
        );
        // The rendezvous closes: the prompt goes, and a replay is a duplicate.
        assert!(runtime.close_offer_of(OFFER_ID));
        assert!(runtime.offer.is_none());
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &known, P55, now),
            OfferDecision::Duplicate
        );
        // A close with no waiting offer still blocks a later offer.
        let other = "ZyXwVuTsRqPoNmLkJiHgFe";
        assert!(!runtime.close_offer_of(other));
        assert_eq!(
            runtime.admit_offer(offer(other), &known, P55, now),
            OfferDecision::Duplicate
        );
    }

    #[test]
    fn a_join_by_someone_removes_the_waiting_offer() {
        let now = OFFER_END - 60;
        let known = nets(&["libera"]);
        let mut runtime = runtime_needing_pairing();
        runtime.admit_offer(offer(OFFER_ID), &known, P55, now);
        assert!(!runtime.drop_offer_of("ZyXwVuTsRqPoNmLkJiHgFe"));
        assert!(runtime.drop_offer_of(OFFER_ID));
        assert!(runtime.offer.is_none());
        // The used offer stays a duplicate.
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &known, P55, now),
            OfferDecision::Duplicate
        );
    }

    #[test]
    fn a_newer_offer_replaces_the_waiting_one() {
        let now = OFFER_END - 60;
        let known = nets(&["libera"]);
        let newer = "ZyXwVuTsRqPoNmLkJiHgFe";
        let mut runtime = runtime_needing_pairing();
        runtime.admit_offer(offer(OFFER_ID), &known, P55, now);
        assert_eq!(
            runtime.admit_offer(offer(newer), &known, P55, now),
            OfferDecision::Show
        );
        let (_, code) = runtime.take_offer(&known, now).expect("offer");
        assert_eq!(code, format!("{newer}.{OFFER_KEY}"));
    }

    #[test]
    fn an_offer_ends_with_its_time_and_a_reconnect_does_not_reopen_it() {
        let now = OFFER_END - 60;
        let known = nets(&["libera"]);
        let mut runtime = runtime_needing_pairing();
        runtime.admit_offer(offer(OFFER_ID), &known, P55, now);
        assert!(!runtime.expire_offer(now));
        assert!(runtime.expire_offer(OFFER_END));
        assert!(runtime.offer.is_none());
        assert!(runtime.take_offer(&known, now).is_none());
        // The same offer replayed after a reconnect is not shown again.
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &known, P55, OFFER_END),
            OfferDecision::Expired
        );
        assert_eq!(
            runtime.admit_offer(offer(OFFER_ID), &known, P55, now),
            OfferDecision::Duplicate
        );
    }

    #[test]
    fn a_reconnect_drops_the_waiting_offer() {
        let ui = slint::Weak::<AppWindow>::default();
        let mut state = WorkerState::new();
        state.e2e.needs_pairing.insert("libera".to_string());
        state
            .e2e
            .admit_offer(offer(OFFER_ID), &nets(&["libera"]), P55, OFFER_END - 60);
        assert!(state.e2e.offer.is_some());
        end_e2e_sessions(&mut state, &ui);
        assert!(state.e2e.offer.is_none());
        // The old offer does not come back as a new one.
        assert_eq!(
            state
                .e2e
                .admit_offer(offer(OFFER_ID), &nets(&["libera"]), P55, OFFER_END - 60),
            OfferDecision::Duplicate
        );
    }

    #[test]
    fn the_pairing_window_has_no_link_qr_code_or_copy_action() {
        let source = include_str!("../ui/appwindow.slint");
        for gone in [
            "e2e-pair-qr",
            "e2e-pair-link",
            "e2e-pair-copy-result",
            "copy-pair-link",
            "send-pair-invite",
            "QR code of the pairing link",
        ] {
            assert!(!source.contains(gone), "{gone}");
        }
        // The in-app offer has an accept and a separate dismiss action.
        assert!(source.contains("callback accept-pair-offer();"));
        assert!(source.contains("callback dismiss-pair-offer();"));
    }

    #[test]
    fn an_accept_after_the_end_or_after_a_pairing_gives_nothing() {
        let now = OFFER_END - 60;
        let known = nets(&["libera"]);
        let mut late = runtime_needing_pairing();
        late.admit_offer(offer(OFFER_ID), &known, P55, now);
        assert!(late.take_offer(&known, OFFER_END).is_none());
        let mut paired = runtime_needing_pairing();
        paired.admit_offer(offer(OFFER_ID), &known, P55, now);
        paired.needs_pairing.remove("libera");
        assert!(paired.take_offer(&known, now).is_none());
        // A pairing opened after the offer: the accept starts nothing.
        let mut busy = runtime_needing_pairing();
        busy.admit_offer(offer(OFFER_ID), &known, P55, now);
        busy.pairing = Some(creator_pairing("ZyXwVuTsRqPoNmLkJiHgFe"));
        assert!(busy.take_offer(&known, now).is_none());
        assert!(busy.offer.is_none());
    }

    #[test]
    fn the_offer_gives_every_network_that_needs_the_identity_and_picks_none() {
        let mut runtime = E2eRuntime::default();
        runtime.needs_pairing.insert("oftc".to_string());
        runtime.needs_pairing.insert("libera".to_string());
        runtime.provisioned.insert("azzurra".to_string());
        let known = nets(&["oftc", "azzurra", "libera"]);
        runtime.admit_offer(offer(OFFER_ID), &known, P55, OFFER_END - 60);
        // The offer names no network: the sealed offer of the holder does.
        let (networks, _) = runtime.take_offer(&known, OFFER_END - 30).expect("offer");
        assert_eq!(networks, nets(&["libera", "oftc"]));
    }

    fn offer_frame(topic: &str, payload: Value) -> PhoenixMessage {
        PhoenixMessage {
            join_ref: None,
            message_ref: None,
            topic: topic.to_string(),
            event: "event".to_string(),
            payload,
        }
    }

    #[test]
    fn only_the_own_user_topic_gives_an_offer_and_it_starts_no_pairing() {
        let ui = slint::Weak::<AppWindow>::default();
        let now = e2e_now();
        let soon = chrono::DateTime::from_timestamp(now + 120, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let mut payload = offer_payload(OFFER_ID);
        payload["expires_at"] = soon.into();
        let mut state = WorkerState::new();
        state.conn.identifier = Some("vjt".to_string());
        state.conn.server_protocol_version = P55;
        state
            .networks
            .own_nicks
            .insert("libera".to_string(), "vjt".to_string());
        state.e2e.needs_pairing.insert("libera".to_string());
        // Another account topic, a channel topic and a guest session.
        for topic in [
            "grappa:user:other",
            "grappa:user:vjt/network:libera/channel:#a",
        ] {
            handle_e2e_pairing_offer(&mut state, &ui, &offer_frame(topic, payload.clone()));
            assert!(state.e2e.offer.is_none(), "{topic}");
        }
        state.conn.guest_session = true;
        handle_e2e_pairing_offer(
            &mut state,
            &ui,
            &offer_frame("grappa:user:vjt", payload.clone()),
        );
        assert!(state.e2e.offer.is_none());
        state.conn.guest_session = false;
        // A server below protocol 55 has no offer to show.
        state.conn.server_protocol_version = Some(54);
        handle_e2e_pairing_offer(
            &mut state,
            &ui,
            &offer_frame("grappa:user:vjt", payload.clone()),
        );
        assert!(state.e2e.offer.is_none());
        state.conn.server_protocol_version = P55;
        // The own topic with a valid offer keeps it and opens no pairing.
        handle_e2e_pairing_offer(&mut state, &ui, &offer_frame("grappa:user:vjt", payload));
        assert!(state.e2e.offer.is_some());
        assert!(state.e2e.pairing.is_none());
    }

    #[test]
    fn one_peer_has_two_entries_with_separate_keys() {
        let mut state = WorkerState::new();
        assert!(state.e2e.add_locked("net", "ada"));
        let locked = LocalQuery::new("net", QueryLane::Locked, "ada");
        let plain = LocalQuery::new("net", QueryLane::Plain, "ada");
        let windows = state.e2e.locked_windows();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].target_nick, locked.window_name());
        assert_ne!(windows[0].target_nick, plain.window_name());

        // History, drafts and the open window use the key of their lane.
        state
            .transcript
            .drafts
            .insert(plain.key(), "plain draft".to_string());
        state
            .transcript
            .drafts
            .insert(locked.key(), "locked draft".to_string());
        assert_eq!(state.transcript.drafts[&plain.key()], "plain draft");
        assert_eq!(state.transcript.drafts[&locked.key()], "locked draft");
        state.windows.current_query = true;
        state.windows.current_channel = Some(locked.key());
        assert_eq!(
            open_locked_window(&state),
            Some(("net".to_string(), "ada".to_string()))
        );
        state.windows.current_channel = Some(plain.key());
        assert_eq!(open_locked_window(&state), None);
        assert!(is_locked_name(&locked.window_name()));
        assert!(!is_locked_name(&plain.window_name()));
    }

    #[test]
    fn the_state_of_an_entry_follows_the_session() {
        let mut state = WorkerState::new();
        // No engine: encryption is unavailable and the plain query has no
        // clear-text banner.
        assert_eq!(
            locked_entry_state(&state, "net", "ada"),
            ChatState::Unavailable
        );
        assert_eq!(plain_entry_state_key(&state, "net"), "");
        // A reset network cannot send.
        state.e2e.reset.insert("net".to_string());
        assert_eq!(locked_entry_state(&state, "net", "ada"), ChatState::Reset);
        // A changed master key is a trust alarm for that peer only.
        let mut state = WorkerState::new();
        state
            .e2e
            .note_engine_error("net", "ada", &EngineError::Device(E2eError::MasterChanged));
        state
            .e2e
            .note_engine_error("net", "bob", &EngineError::NotReady);
        assert!(state
            .e2e
            .trust_alarm
            .contains(&("net".to_string(), "ada".to_string())));
        assert!(!state
            .e2e
            .trust_alarm
            .contains(&("net".to_string(), "bob".to_string())));
    }

    #[test]
    fn the_key_request_state_follows_the_observed_results() {
        let mut runtime = E2eRuntime::default();
        let paced = || {
            Err(EngineError::Paced(
                cordiale_core::e2e_pacing::KeyReqRefusal::Interval,
            ))
        };
        assert_eq!(runtime.key_request("net", "ada"), KeyRequest::NotSent);
        // A paced call before any request, and a peer without E2E, send nothing.
        runtime.note_key_request("net", "ada", &paced());
        runtime.note_key_request("net", "ada", &Err(EngineError::PeerNotCapable));
        assert_eq!(runtime.key_request("net", "ada"), KeyRequest::NotSent);
        // A 202 answer means only that the API accepted the request.
        runtime.note_key_request("net", "ada", &Ok(()));
        assert_eq!(runtime.key_request("net", "ada"), KeyRequest::Accepted);
        // Silence plus a held retry is a waiting state, not a failure.
        runtime.note_key_request("net", "ada", &paced());
        assert_eq!(runtime.key_request("net", "ada"), KeyRequest::Waiting);
        // A refusal is a failure of the request only for that peer.
        runtime.note_key_request("net", "bob", &Err(EngineError::NotReady));
        assert_eq!(runtime.key_request("net", "bob"), KeyRequest::Failed);
        runtime.note_key_request("net", "bob", &paced());
        assert_eq!(runtime.key_request("net", "bob"), KeyRequest::Failed);
        assert_eq!(runtime.key_request("net", "ada"), KeyRequest::Waiting);
    }

    #[test]
    fn an_entry_without_an_engine_has_no_unread_count() {
        let mut state = WorkerState::new();
        state.e2e.add_locked("net", "ada");
        assert!(locked_unread_counts(&state).is_empty());
    }

    #[test]
    fn the_sas_steps_come_from_the_banner_names_only() {
        assert_eq!(SasStep::parse("start"), Some(SasStep::Start));
        assert_eq!(SasStep::parse("confirm"), Some(SasStep::Confirm));
        assert_eq!(SasStep::parse("reject"), Some(SasStep::Reject));
        assert_eq!(SasStep::parse("cancel"), Some(SasStep::Cancel));
        assert_eq!(SasStep::parse("Confirm"), None);
        assert_eq!(SasStep::parse(""), None);
    }

    #[test]
    fn an_unverified_entry_stays_in_the_sas_state_without_a_confirm() {
        // Without a confirm the peer stays unverified: the banner asks for
        // the SAS check and never shows the active state.
        let ready = ChatSignals {
            engine: true,
            ready: true,
            sas_verified: false,
            ..ChatSignals::default()
        };
        assert_eq!(locked_chat_state(&ready), ChatState::SasPending);
        let verified = ChatSignals {
            sas_verified: true,
            ..ready
        };
        assert_eq!(locked_chat_state(&verified), ChatState::Active);
        // A trust alarm wins over an old verification.
        let alarm = ChatSignals {
            trust_alarm: true,
            ..verified
        };
        assert_eq!(locked_chat_state(&alarm), ChatState::TrustAlarm);
    }

    use chacha20poly1305::aead::{Generate, Key};
    use chacha20poly1305::XChaCha20Poly1305;
    use cordiale_core::e2e_state::E2eStateStore;
    use cordiale_core::e2e_store::{E2eKeyProvider, E2eStoreError};
    use vodozemac::olm::Account;

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

    fn master_text(master: &Account) -> String {
        master.identity_keys().ed25519.to_base64()
    }

    /// A worker state whose open window is the locked entry of `ada` on
    /// `net`. The engine holds the own master and the stored master of the
    /// peer, with no SAS check. Returns the master text of the peer.
    fn sas_state(dir: &tempfile::TempDir) -> (WorkerState, String) {
        let peer = master_text(&Account::new());
        let mut store =
            E2eStateStore::open(dir.path().join("state.bin"), &fresh_key()).expect("state");
        store.set_account(&Account::new()).expect("account");
        store.set_master_key(&Account::new()).expect("master");
        let mut trust = store.trust();
        trust.observe_master("net", "ada", &peer).expect("peer");
        store.set_trust(&trust).expect("trust");
        let history =
            E2eHistoryStore::open(dir.path().join("history.bin"), &fresh_key()).expect("history");
        let engine = E2eEngine::new("net", store, history).expect("engine");
        let mut state = WorkerState::new();
        state.e2e.engines.insert("net".to_string(), engine);
        state.e2e.add_locked("net", "ada");
        state.windows.current_query = true;
        state.windows.current_channel =
            Some(LocalQuery::new("net", QueryLane::Locked, "ada").key());
        (state, peer)
    }

    fn sas_verified(state: &WorkerState) -> bool {
        state.e2e.engines["net"]
            .trust()
            .is_sas_verified("net", "ada")
    }

    #[test]
    fn a_reject_or_a_cancel_leaves_the_peer_unverified() {
        let dir = tempfile::tempdir().expect("dir");
        let (mut state, peer) = sas_state(&dir);
        let ui = slint::Weak::<AppWindow>::default();
        for step in [SasStep::Reject, SasStep::Cancel] {
            handle_e2e_sas(&mut state, &ui, SasStep::Start);
            // The check holds the exact master that the code was made from.
            assert_eq!(
                state.e2e.sas_check,
                Some(SasCheck {
                    network: "net".to_string(),
                    nick: "ada".to_string(),
                    master: peer.clone(),
                })
            );
            handle_e2e_sas(&mut state, &ui, step);
            assert_eq!(state.e2e.sas_check, None, "{step:?}");
            assert!(!sas_verified(&state), "{step:?}");
            assert_ne!(locked_entry_state(&state, "net", "ada"), ChatState::Active);
            // A confirm after the close has no check to confirm.
            handle_e2e_sas(&mut state, &ui, SasStep::Confirm);
            assert!(!sas_verified(&state), "{step:?}");
        }
        // Only a confirm after a start marks the stored master.
        handle_e2e_sas(&mut state, &ui, SasStep::Start);
        handle_e2e_sas(&mut state, &ui, SasStep::Confirm);
        assert!(sas_verified(&state));
        assert_eq!(state.e2e.sas_check, None);
    }

    fn key_verified(state: &WorkerState) -> bool {
        state.e2e.engines["net"]
            .trust()
            .is_key_verified("net", "ada")
    }

    #[test]
    fn the_peer_key_view_verifies_only_the_exact_stored_key_on_request() {
        let dir = tempfile::tempdir().expect("dir");
        let (mut state, peer) = sas_state(&dir);
        let ui = slint::Weak::<AppWindow>::default();
        let args = |step, nick: &str, key: &str| (step, nick.to_string(), key.to_string());
        // The facts hold the full key and change nothing.
        assert_eq!(
            peer_key_facts(&state, "net", "ada"),
            Some((peer.clone(), false))
        );
        assert_eq!(peer.len(), 43);
        let (step, nick, key) = args(PeerKeyStep::Open, "ada", "");
        handle_e2e_peer_key(&mut state, &ui, step, "net".into(), nick, key);
        assert!(!key_verified(&state));
        // A key that is not the stored one, or another network, is refused.
        assert!(!verify_peer_key(&mut state, "net", "ada", "other-key"));
        assert!(!verify_peer_key(&mut state, "other-net", "ada", &peer));
        assert!(!key_verified(&state));
        // A verify for another peer is ignored.
        let (step, nick, key) = args(PeerKeyStep::Verify, "bob", &peer);
        handle_e2e_peer_key(&mut state, &ui, step, "net".into(), nick, key);
        assert!(!key_verified(&state));
        // The check does not touch SAS and the peer leaves the SAS state.
        let (step, nick, key) = args(PeerKeyStep::Verify, "ada", &peer);
        handle_e2e_peer_key(&mut state, &ui, step, "net".into(), nick, key);
        assert!(key_verified(&state));
        assert!(!sas_verified(&state));
        assert_eq!(
            peer_key_facts(&state, "net", "ada"),
            Some((peer.clone(), true))
        );
        // The fixture has no peer device. The key check does not make the
        // entry ready.
        assert_eq!(
            locked_entry_state(&state, "net", "ada"),
            ChatState::MissingKeys
        );
        // A trust alarm hides the key and refuses a verify.
        state
            .e2e
            .trust_alarm
            .insert(("net".to_string(), "ada".to_string()));
        assert_eq!(peer_key_facts(&state, "net", "ada"), None);
        assert_eq!(
            locked_entry_state(&state, "net", "ada"),
            ChatState::TrustAlarm
        );
        assert!(!verify_peer_key(&mut state, "net", "ada", &peer));
        let (step, nick, key) = args(PeerKeyStep::Verify, "ada", &peer);
        handle_e2e_peer_key(&mut state, &ui, step, "net".into(), nick, key);
        assert!(key_verified(&state));
        assert!(!sas_verified(&state));
        assert_eq!(PeerKeyStep::parse("verify"), Some(PeerKeyStep::Verify));
        assert_eq!(PeerKeyStep::parse("Verify"), None);
    }

    #[test]
    fn a_sas_check_and_a_key_check_do_not_change_each_other() {
        let dir = tempfile::tempdir().expect("dir");
        let (mut state, peer) = sas_state(&dir);
        let ui = slint::Weak::<AppWindow>::default();
        // A SAS check does not verify the key.
        handle_e2e_sas(&mut state, &ui, SasStep::Start);
        handle_e2e_sas(&mut state, &ui, SasStep::Confirm);
        assert!(sas_verified(&state));
        assert!(!key_verified(&state));
        // A key check on the SAS-verified peer works and keeps the SAS check.
        handle_e2e_peer_key(
            &mut state,
            &ui,
            PeerKeyStep::Verify,
            "net".into(),
            "ada".into(),
            peer,
        );
        assert!(sas_verified(&state));
        assert!(key_verified(&state));
        // A new SAS code after the key check stays available and keeps both.
        handle_e2e_sas(&mut state, &ui, SasStep::Start);
        assert!(state.e2e.sas_check.is_some());
        handle_e2e_sas(&mut state, &ui, SasStep::Cancel);
        assert!(sas_verified(&state));
        assert!(key_verified(&state));
    }

    #[test]
    fn a_trust_alarm_refuses_a_key_check_until_the_explicit_key_change() {
        let dir = tempfile::tempdir().expect("dir");
        let (mut state, peer) = sas_state(&dir);
        let ui = slint::Weak::<AppWindow>::default();
        state
            .e2e
            .note_engine_error("net", "ada", &EngineError::Device(E2eError::MasterChanged));
        assert_eq!(
            locked_entry_state(&state, "net", "ada"),
            ChatState::TrustAlarm
        );
        // The view shows no key and a verify changes nothing.
        assert_eq!(peer_key_facts(&state, "net", "ada"), None);
        handle_e2e_peer_key(
            &mut state,
            &ui,
            PeerKeyStep::Verify,
            "net".into(),
            "ada".into(),
            peer.clone(),
        );
        assert!(!key_verified(&state));
        assert_eq!(
            locked_entry_state(&state, "net", "ada"),
            ChatState::TrustAlarm
        );
        // A SAS check stays refused with the alarm.
        handle_e2e_sas(&mut state, &ui, SasStep::Start);
        assert_eq!(state.e2e.sas_check, None);
        // A key check of the old master is no proof for the new master.
        let other = master_text(&Account::new());
        state
            .e2e
            .engine_mut("net")
            .expect("engine")
            .replace_peer_master("ada", &other)
            .expect("replace");
        assert!(!verify_peer_key(&mut state, "net", "ada", &peer));
        assert!(!key_verified(&state));
    }

    #[test]
    fn a_key_check_never_counts_with_a_trust_alarm() {
        let signals = ChatSignals {
            engine: true,
            ready: true,
            key_verified: true,
            trust_alarm: true,
            ..ChatSignals::default()
        };
        assert_eq!(locked_chat_state(&signals), ChatState::TrustAlarm);
        let signals = ChatSignals {
            trust_alarm: false,
            ..signals
        };
        assert_eq!(locked_chat_state(&signals), ChatState::Active);
    }

    #[test]
    fn a_confirm_does_not_carry_to_a_new_master() {
        let dir = tempfile::tempdir().expect("dir");
        let (mut state, _) = sas_state(&dir);
        let ui = slint::Weak::<AppWindow>::default();
        handle_e2e_sas(&mut state, &ui, SasStep::Start);
        // The user replaces the master while the code is on screen.
        let other = master_text(&Account::new());
        state
            .e2e
            .engine_mut("net")
            .expect("engine")
            .replace_peer_master("ada", &other)
            .expect("replace");
        handle_e2e_sas(&mut state, &ui, SasStep::Confirm);
        assert!(!sas_verified(&state));
        // A trust alarm shows no code at all.
        state
            .e2e
            .note_engine_error("net", "ada", &EngineError::Device(E2eError::MasterChanged));
        handle_e2e_sas(&mut state, &ui, SasStep::Start);
        assert_eq!(state.e2e.sas_check, None);
    }

    #[test]
    fn a_sas_check_keeps_the_two_query_lanes_apart() {
        let dir = tempfile::tempdir().expect("dir");
        let (mut state, _) = sas_state(&dir);
        let ui = slint::Weak::<AppWindow>::default();
        let plain = LocalQuery::new("net", QueryLane::Plain, "ada");
        let locked = LocalQuery::new("net", QueryLane::Locked, "ada");
        let rendered = |text: &str, encrypted: bool| RenderedMessage {
            timestamp: String::new(),
            nick: Some("ada".to_string()),
            text: text.to_string(),
            italic: false,
            message_id: None,
            server_time: None,
            presence_noise: false,
            rename_to: None,
            encrypted,
        };
        state
            .transcript
            .messages
            .insert(plain.key(), vec![rendered("plain text", false)]);
        state
            .transcript
            .messages
            .insert(locked.key(), vec![rendered("locked text", true)]);
        for step in [
            SasStep::Start,
            SasStep::Reject,
            SasStep::Start,
            SasStep::Cancel,
            SasStep::Start,
            SasStep::Confirm,
        ] {
            handle_e2e_sas(&mut state, &ui, step);
            let plain_rows = &state.transcript.messages[&plain.key()];
            assert_eq!(plain_rows.len(), 1, "{step:?}");
            assert_eq!(plain_rows[0].text, "plain text");
            assert!(!plain_rows[0].encrypted);
            let locked_rows = &state.transcript.messages[&locked.key()];
            assert_eq!(locked_rows.len(), 1, "{step:?}");
            assert_eq!(locked_rows[0].text, "locked text");
            assert!(locked_rows[0].encrypted);
            // The open window and the entry list stay the locked ones.
            assert_eq!(state.windows.current_channel, Some(locked.key()));
            let windows = state.e2e.locked_windows();
            assert_eq!(windows.len(), 1);
            assert_eq!(windows[0].target_nick, locked.window_name());
            assert_ne!(windows[0].target_nick, plain.window_name());
        }
        assert!(sas_verified(&state));
    }
}
