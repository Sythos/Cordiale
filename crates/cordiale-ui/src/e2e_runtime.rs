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

use std::collections::BTreeSet;

use cordiale_core::e2e_device::E2eError;
use cordiale_core::e2e_engine::{
    conversation_id, history_peers_of, route_for_window, E2eEngine, EngineError, RowOutcome,
    SendRoute, OWN_DEVICE,
};
use cordiale_core::e2e_pacing::DropReason;
use cordiale_core::e2e_pairing_flow::{
    self as pairing, PairingContext, PairingSession, PairingStatus, StalePairing,
};
use cordiale_core::e2e_protocol::E2eOperation;
use cordiale_core::e2e_provision::provision_device;
use cordiale_core::e2e_revoke::{
    finish_pending_revoke, reset_identity, resume_reset, revoke_device, OwnRoutes,
    ResetConfirmation,
};
use cordiale_core::e2e_store::{E2eHistoryStore, E2eMessage};
use cordiale_core::e2e_wire::did_from_key_text;
use cordiale_core::phoenix::PhoenixMessage;
use cordiale_core::session::{route_e2e_message, route_e2e_pairing};
use cordiale_core::slash::{E2eManageAction, E2ePairAction};

use crate::e2e_view::{
    locked_chat_state, pairing_error_key, pairing_status_key, register_own_device,
    reset_status_key, revoke_status_key, ChatSignals, ChatState, KeyRequest, LocalQuery, QueryLane,
};

/// How often the timers of the engines run: queued texts expire or go out.
pub(crate) const E2E_TICK: std::time::Duration = std::time::Duration::from_secs(15);

/// The engines of the session and the locked entries of the sidebar.
#[derive(Default)]
pub(crate) struct E2eRuntime {
    engines: HashMap<String, E2eEngine>,
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
    /// The one open X1 pairing of this session, if any.
    pairing: Option<ActivePairing>,
    /// Rendezvous that an earlier run left open. They are closed when the
    /// session is ready, and their slot is already empty.
    stale_pairings: Vec<(String, StalePairing)>,
    /// The network for which the user got the question to confirm a reset.
    /// Any other `/e2e` step clears it.
    reset_asked: Option<String>,
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
    /// Networks whose provisioning ended with success in this session. An
    /// open engine is not proof: a run that failed after the Olm account was
    /// saved still opens one, so the next connect provisions again.
    provisioned: HashSet<String>,
    /// The one open SAS check, if any. It holds the master key that the
    /// shown code was made from. It is not saved.
    sas_check: Option<SasCheck>,
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
}

impl E2eRuntime {
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
fn mark_locked_read(state: &mut WorkerState, network: &str, nick: &str) {
    let seen = state
        .e2e
        .history_of(network)
        .map(|history| incoming_rows(history, network, nick))
        .unwrap_or(0);
    state
        .e2e
        .read_incoming
        .insert((network.to_string(), nick.to_string()), seen);
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
    RenderedMessage {
        timestamp,
        nick: Some(nick.to_string()),
        text: if dropped.is_some() {
            format!("\u{26A0} {}", message.text)
        } else {
            message.text.clone()
        },
        italic: dropped.is_some(),
        message_id: None,
        server_time: message.sent_at.checked_mul(1000),
        presence_noise: false,
        rename_to: None,
        encrypted: true,
    }
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
            state.e2e.provisioned.insert(network.to_string());
            // A network without a state file before this run can open its
            // engine now.
            state.e2e.unavailable.remove(network);
        }
        Err(error) => {
            persistence::log_line(&format!("e2e identity not made for {network}: {error:?}"));
        }
    }
}

/// Opens the engines of the signed-in networks and reads their inboxes. Call
/// it when the session connects, also after a reconnect.
pub(crate) async fn start_e2e_engines(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
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
    }
    close_stale_pairings(state).await;
    pump_pairing(state, ui).await;
    refresh_network_groups(state, ui);
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

/// The host part of a server base URL, for the pairing link.
pub(crate) fn pairing_host(base_url: &str) -> String {
    let rest = base_url
        .split_once("://")
        .map_or(base_url, |(_, rest)| rest);
    rest.split('/').next().unwrap_or(rest).to_string()
}

/// Draws the QR code of the pairing link in a dialog. The link and the code
/// are never logged.
fn show_pairing_qr(ui: &slint::Weak<AppWindow>, url: &str, code: String) {
    let qr = crate::totp::qr_rgb(url);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let image = qr
            .map(|(side, rgb)| {
                slint::Image::from_rgb8(slint::SharedPixelBuffer::clone_from_slice(
                    &rgb, side, side,
                ))
            })
            .unwrap_or_default();
        ui.set_e2e_pair_qr(image);
        ui.set_e2e_pair_qr_code(code.into());
        ui.set_e2e_pair_qr_visible(true);
    });
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
    let protocol = state.conn.server_protocol_version;
    let ctx = PairingContext {
        client: &client,
        token: &token,
        protocol,
        network_id: &network,
    };
    let now = e2e_now();
    // A new start replaces the open pairing: the old one is cancelled first.
    if matches!(action, E2ePairAction::Start | E2ePairAction::Join(_)) {
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
                    state.e2e.pairing = Some(ActivePairing {
                        network: network.clone(),
                        session,
                    });
                    push_open_locked_state(state, ui);
                    show_pairing_kind(ui, "e2e-pair-link", link.code());
                    show_pairing_qr(ui, &link.url(&pairing_host(client.base_url())), link.code());
                }
                Err(error) => show_pairing_kind(ui, pairing_error_key(&error), String::new()),
            }
        }
        E2ePairAction::Join(mut text) => {
            let Some(mut engine) = take_pairing_engine(state, &network, true) else {
                text.clear();
                return show_pairing_kind(ui, "e2e-not-ready", String::new());
            };
            let result = pairing::start_joiner(&ctx, engine.state_mut(), &mut text, now).await;
            state.e2e.engines.insert(network.clone(), engine);
            match result {
                Ok(session) => {
                    show_pairing(ui, &session.status());
                    state.e2e.pairing = Some(ActivePairing {
                        network: network.clone(),
                        session,
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
        E2ePairAction::Cancel => {
            if state.e2e.pairing.is_none() {
                return show_pairing_kind(ui, "e2e-pair-none", String::new());
            }
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

/// Fills the E2E Identity page for `network`. It reads the public master key
/// of the open engine and nothing else. It makes no key, no file and no log
/// line with the key.
pub(crate) fn show_e2e_identity(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
) {
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
        ui.set_admin_e2e_shown_network(panel.network.into());
        ui.set_admin_e2e_account(panel.account.into());
        ui.set_admin_e2e_key(panel.key.into());
        ui.set_admin_e2e_state(panel.state.into());
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
    let not_ready = || show_manage_kind(ui, "e2e-not-ready", String::new(), String::new());
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(own_nick) = state.networks.own_nicks.get(&network).cloned() else {
        return not_ready();
    };
    if !ensure_engine(state, &network) {
        return not_ready();
    }
    let protocol = state.conn.server_protocol_version;
    match action {
        E2eManageAction::Devices => {
            let Some(engine) = state.e2e.engines.get_mut(&network) else {
                return not_ready();
            };
            let own = engine.own_did().to_string();
            let Some(list) = engine.state_mut().signed_list() else {
                return not_ready();
            };
            let ids: Vec<String> = list
                .keys
                .iter()
                .filter_map(|key| did_from_key_text(key).ok())
                .collect();
            show_manage_kind(ui, "e2e-devices", ids.join(" "), own);
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
/// texts, so nothing goes out for the deleted device.
fn settle_reset(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    mut engine: E2eEngine,
) {
    engine.end_session();
    let changed = engine.take_changed_peers();
    state.e2e.engines.insert(network.to_string(), engine);
    state.e2e.reset.insert(network.to_string());
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
    finish_pairing_step(state, ui, active, result.err());
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
        None => show_pairing(ui, &active.session.status()),
    }
    // A finished join gave the device a new identity after a reset.
    if matches!(active.session.status(), PairingStatus::Done) {
        state.e2e.reset.remove(&active.network);
    }
    if active.session.is_active() {
        state.e2e.pairing = Some(active);
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
    finish_pairing_step(state, ui, active, result.err());
}

/// Ends a pairing whose lifetime is over. Call it for every E2E tick.
pub(crate) async fn tick_pairing(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
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
        mark_locked_read(state, network, nick);
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

/// Pushes the state banner of the open locked entry.
fn push_open_locked_state(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let Some((network, nick)) = open_locked_window(state) else {
        return;
    };
    let key = locked_entry_state(state, &network, &nick).key();
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
    let rows: Vec<RenderedMessage> = state
        .e2e
        .history_of(network)
        .map(|history| {
            history
                .messages(&conversation_id(network, nick))
                .into_iter()
                .map(|message| {
                    let dropped = engine.and_then(|engine| engine.dropped_reason(&message.id));
                    locked_row_with_drop(message, &own_nick, nick, dropped)
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
    let window_status = window_status_for(state);
    let peer_nick = nick.to_string();
    crate::queries::push_shared_channels(state, ui, network, nick);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_channel_label(label.into());
        ui.set_current_topic("".into());
        ui.set_window_status(window_status.into());
        ui.set_current_window_is_joined(false);
        ui.set_current_server_window(false);
        ui.set_has_selected_channel(true);
        ui.set_current_query(true);
        ui.set_current_query_ready(true);
        ui.set_current_query_e2e(true);
        ui.set_current_query_e2e_state(chat_state.into());
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
    state.windows.current_query = true;
    state.windows.current_query_ready = true;
    // A SAS check belongs to the window that opened it.
    state.e2e.sas_check = None;
    push_sas_code(ui, String::new());
    open_window(state, &key);
    mark_locked_read(state, &network, &nick);
    load_locked_rows(state, &network, &nick);
    refresh_network_groups(state, ui);
    show_locked_window(state, ui, &network, &nick);
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
    true
}

/// After the user opens the plain query of `nick`: shows the locked entry
/// when the peer has a verified device, and asks for its keys otherwise. The
/// plain query stays as it is.
pub(crate) async fn offer_locked_query(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    nick: &str,
) {
    if !ensure_engine(state, network) {
        return;
    }
    let peer = query_send_target(state, network, nick);
    let Some(mut engine) = state.e2e.engines.remove(network) else {
        return;
    };
    if !engine.is_ready(&peer) {
        if let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) {
            let result = engine.request_keys(&client, &token, &peer).await;
            state.e2e.note_key_request(network, &peer, &result);
            if let Err(error) = result {
                state.e2e.note_engine_error(network, &peer, &error);
                if !matches!(error, EngineError::Paced(_)) {
                    persistence::log_line(&format!("e2e key request failed: {error:?}"));
                }
            }
        }
    }
    let ready = engine.is_ready(&peer);
    state.e2e.engines.insert(network.to_string(), engine);
    // A peer with a key request gets its locked entry too: it shows the
    // request state. The entry sends nothing in clear text.
    let asked = state.e2e.key_request(network, &peer) != KeyRequest::NotSent;
    if (ready || asked) && state.e2e.add_locked(network, &peer) {
        refresh_network_groups(state, ui);
    }
    push_open_locked_state(state, ui);
}

/// Sends `body` from a locked window through the engine. The text goes out
/// as an Olm message or not at all: on any failure the user sees an error and
/// nothing is sent as clear text.
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
    if body.trim_start().starts_with('/') {
        set_e2e_status(ui, "e2e-text-only");
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
    if let Err(error) = &result {
        // The log gets the kind of the failure, never the text.
        persistence::log_line(&format!("e2e send failed for {network}: {error:?}"));
        set_e2e_status(ui, e2e_send_error_kind(error));
        state.e2e.note_engine_error(&network, &nick, error);
    }
    settle_engine(state, ui, &network, engine).await;
}

/// The session stopped (a disconnect or a reconnect): every open send of
/// every engine becomes a `session_ended` drop, and every queue is emptied.
/// The locked window shows the dropped rows.
pub(crate) fn end_e2e_sessions(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
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
    fn a_reset_network_gets_no_engine_and_keeps_its_marker() {
        let mut state = WorkerState::new();
        state.e2e.reset.insert("net".to_string());
        assert!(!ensure_engine(&mut state, "net"));
        // With no client the new engine of a join does not open.
        assert!(take_pairing_engine(&mut state, "net", true).is_none());
        assert!(state.e2e.reset.contains("net"));
    }

    #[test]
    fn the_pairing_host_has_no_scheme_or_path() {
        assert_eq!(
            pairing_host("https://grappa.example.org"),
            "grappa.example.org"
        );
        assert_eq!(
            pairing_host("https://grappa.example.org:8443/"),
            "grappa.example.org:8443"
        );
        assert_eq!(pairing_host("grappa.example.org"), "grappa.example.org");
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
}
