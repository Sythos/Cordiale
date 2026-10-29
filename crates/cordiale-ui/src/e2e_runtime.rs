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

use cordiale_core::e2e_engine::{
    conversation_id, locked_label, route_for_window, E2eEngine, EngineError, SendRoute, OWN_DEVICE,
};
use cordiale_core::e2e_pacing::DropReason;
use cordiale_core::e2e_protocol::E2eOperation;
use cordiale_core::e2e_store::E2eMessage;
use cordiale_core::phoenix::PhoenixMessage;
use cordiale_core::session::route_e2e_message;

/// How often the timers of the engines run: queued texts expire or go out.
pub(crate) const E2E_TICK: std::time::Duration = std::time::Duration::from_secs(15);

/// The engines of the session and the locked entries of the sidebar.
#[derive(Default)]
pub(crate) struct E2eRuntime {
    engines: HashMap<String, E2eEngine>,
    /// Networks that have no engine in this session: no identity on this
    /// device, a store that does not open, or a server without the E2E routes.
    unavailable: HashSet<String>,
    /// `(network, nick)` of each peer that has a locked entry.
    locked: BTreeSet<(String, String)>,
}

impl E2eRuntime {
    /// The locked entries as query windows for the sidebar. The target is the
    /// display label; no request uses it.
    pub(crate) fn locked_windows(&self) -> Vec<QueryWindow> {
        self.locked
            .iter()
            .map(|(network, nick)| QueryWindow {
                network: network.clone(),
                target_nick: locked_label(nick),
                opened_at: String::new(),
                dm_conversation_id: None,
            })
            .collect()
    }

    /// Adds the locked entry of `nick`; true when it is new.
    pub(crate) fn add_locked(&mut self, network: &str, nick: &str) -> bool {
        self.locked.insert((network.to_string(), nick.to_string()))
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

fn set_e2e_status(ui: &slint::Weak<AppWindow>, kind: &'static str) {
    let _ = ui.upgrade_in_event_loop(move |ui| ui.set_status_kind(kind.into()));
}

/// One sealed history row as a row of the locked window. The row keeps the
/// encrypted mark.
pub(crate) fn locked_row(message: &E2eMessage, own_nick: &str, peer: &str) -> RenderedMessage {
    locked_row_with_drop(message, own_nick, peer, None)
}

/// Like [`locked_row`]. A row whose send was dropped (`late`, `send_failed`
/// or `session_ended`) is marked with a warning sign and shown in italics:
/// the text did not reach the peer, and nothing shows it as delivered. Only
/// the locked window has this mark; a plain row never gets it.
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
    match E2eEngine::open_for_network(client.base_url(), account, network) {
        Ok(mut engine) => {
            // The ISUPPORT snapshot can come before the engine.
            if let Some(isupport) = state.networks.isupport_by_network.get(network) {
                engine.set_casemapping(isupport.casemapping);
            }
            for peer in engine.history_peers() {
                state.e2e.add_locked(network, &peer);
            }
            state.e2e.engines.insert(network.to_string(), engine);
            true
        }
        Err(error) => {
            if !matches!(error, EngineError::NotReady) {
                persistence::log_line(&format!("e2e engine not opened for {network}: {error:?}"));
            }
            state.e2e.unavailable.insert(network.to_string());
            false
        }
    }
}

/// Opens the engines of the signed-in networks and reads their inboxes. Call
/// it when the session connects, also after a reconnect.
pub(crate) async fn start_e2e_engines(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let mut networks: Vec<String> = state.networks.own_nicks.keys().cloned().collect();
    networks.sort();
    for network in networks {
        if ensure_engine(state, &network) {
            drain_network(state, ui, &network).await;
        }
    }
    refresh_network_groups(state, ui);
}

async fn drain_network(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, network: &str) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let protocol = state.conn.server_protocol_version;
    let Some(mut engine) = state.e2e.engines.remove(network) else {
        return;
    };
    match engine.drain(&client, &token, protocol, e2e_now()).await {
        Ok(outcomes) => persistence::log_line(&format!(
            "e2e inbox read for {network}: {} items",
            outcomes.len()
        )),
        Err(error) => {
            persistence::log_line(&format!("e2e inbox not read for {network}: {error:?}"))
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
    if let Err(error) = engine
        .handle_event(&client, &token, protocol, &row, e2e_now())
        .await
    {
        persistence::log_line(&format!("e2e item not read for {}: {error:?}", row.network));
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
    }
    let wanted = engine.take_keys_wanted();
    if let (false, Some(client), Some(token)) = (
        wanted.is_empty(),
        state.conn.client.clone(),
        state.conn.token.clone(),
    ) {
        for nick in wanted {
            if let Err(error) = engine.request_keys(&client, &token, &nick).await {
                if !matches!(error, EngineError::Paced(_) | EngineError::PeerNotCapable) {
                    persistence::log_line(&format!("e2e key request failed: {error:?}"));
                }
            }
        }
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
    if sidebar_changed {
        refresh_network_groups(state, ui);
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
        load_locked_rows(state, network, nick);
        show_locked_rows(state, ui, network, nick);
    }
}

/// Redraws only the rows of the locked window of `nick`.
fn show_locked_rows(state: &WorkerState, ui: &slint::Weak<AppWindow>, network: &str, nick: &str) {
    let lines = state
        .transcript
        .messages
        .get(&(network.to_string(), locked_label(nick)))
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
    let rows: Vec<RenderedMessage> = state
        .e2e
        .engines
        .get(network)
        .map(|engine| {
            engine
                .history()
                .messages(&conversation_id(network, nick))
                .into_iter()
                .map(|message| {
                    let dropped = engine.dropped_reason(&message.id);
                    locked_row_with_drop(message, &own_nick, nick, dropped)
                })
                .collect()
        })
        .unwrap_or_default();
    state
        .transcript
        .messages
        .insert((network.to_string(), locked_label(nick)), rows);
}

/// Shows the locked window of `nick`. It is not a Grappa window: nothing is
/// fetched, and the peer nick the view gets is the real one.
fn show_locked_window(state: &WorkerState, ui: &slint::Weak<AppWindow>, network: &str, nick: &str) {
    let key = (network.to_string(), locked_label(nick));
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
    open_window(state, &key);
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
            if let Err(error) = engine.request_keys(&client, &token, &peer).await {
                if !matches!(error, EngineError::Paced(_)) {
                    persistence::log_line(&format!("e2e key request failed: {error:?}"));
                }
            }
        }
    }
    let ready = engine.is_ready(&peer);
    state.e2e.engines.insert(network.to_string(), engine);
    if ready && state.e2e.add_locked(network, &peer) {
        refresh_network_groups(state, ui);
    }
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
        if !state
            .e2e
            .engines
            .get(&network)
            .is_some_and(E2eEngine::has_queued_text)
        {
            continue;
        }
        let Some(engine) = state.e2e.engines.remove(&network) else {
            continue;
        };
        settle_engine(state, ui, &network, engine).await;
    }
}
