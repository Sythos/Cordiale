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

slint::include_modules!();

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::sync::mpsc;

use cordiale_core::bootstrap::{bootstrap, BootstrapError, BootstrapOutcome};
use cordiale_core::client::{GrappaClient, LoginError};
use cordiale_core::credentials::resolve_credential_store;
use cordiale_core::domain::{AuthMethod, Profile};
use cordiale_core::persistence::{self, Theme};
use cordiale_core::rest::{DisplayPrefs, LoginRequest, SendMessageRequest};
use cordiale_core::session::{spawn_session, SessionEvent, SessionHandle};

/// The default server offered on first launch, per MEMORY.md §3.3.
const DEFAULT_SERVER_URL: &str = "https://irc.sindro.me";

/// Everything the UI thread can ask the background worker to do. Sent over
/// a plain `tokio::sync::mpsc` channel whose sender is a normal, non-async
/// value — callbacks fire on the UI thread and just call `.send()`.
enum WorkerCommand {
    Connect {
        server_url: String,
        identifier: String,
        password: String,
    },
    SelectChannel {
        network: String,
        channel: String,
    },
    ToggleNetwork(String),
    SendMessage {
        body: String,
    },
    AttachFile,
    ComposeTextChanged(String),
    ToggleTheme,
    SaveDisplayPrefs(DisplayPrefs),
    AdminRefresh,
    AdminDisconnectSession(String),
    AdminUserToggleAdmin(String, bool),
    AdminUserDelete(String),
    AdminVisitorDelete(String),
    AdminNetworkResetCircuit(String),
    AdminReaperRun,
    RequestLinks(String),
    SettingsNetworkSelected(String),
    IdentitySave {
        nick: String,
        ident: String,
        realname: String,
    },
    IgnoreAdd(String),
    IgnoreRemove(String),
    PerformSave(String),
    AliasAdd {
        command: String,
        expansion: String,
    },
    AliasRemove(String),
    VhostToggle(String),
    NotifyAdd(String),
    NotifyRemove(String),
    WatchPatternAdd(String),
    WatchPatternRemove(String),
    Disconnect,
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

    // Settings > Credits: Cordiale's own info only, never a list of
    // Grappa/Cicchetto's contributors — explicit project-owner
    // requirement, see MEMORY.md §0septies.
    ui.set_credits_copyright_text(format!("© {} Sythos", current_year()).into());
    ui.set_app_version(cordiale_core::APP_VERSION.into());

    let remembered_server_url = load_remembered_server_url();
    ui.set_server_url(remembered_server_url.clone().into());
    prefill_remembered_profile(&ui, &remembered_server_url);

    let settings = persistence::load_settings().unwrap_or_default();
    ui.set_next_screen(if settings.language.is_none() {
        "language".into()
    } else {
        "connect".into()
    });
    if let Some(language) = settings.language {
        let _ = slint::select_bundled_translation(language_code(language));
    }
    ui.set_theme(theme_to_slint(settings.theme));
    ui.set_known_servers(known_servers_model());

    let (worker_tx, worker_rx) = mpsc::unbounded_channel::<WorkerCommand>();
    let ui_weak = ui.as_weak();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("failed to start network runtime");
        runtime.block_on(run_worker(worker_rx, ui_weak));
    });

    let weak_for_language = ui.as_weak();
    ui.on_language_selected(move |code| {
        if let Some(language) = language_from_code(&code) {
            let mut settings = persistence::load_settings().unwrap_or_default();
            settings.language = Some(language);
            let _ = persistence::save_settings(&settings);
            let _ = slint::select_bundled_translation(language_code(language));
        }
        if let Some(ui) = weak_for_language.upgrade() {
            ui.set_screen("connect".into());
        }
    });

    let weak_for_server = ui.as_weak();
    ui.on_server_selected(move |server_url| {
        if let Some(ui) = weak_for_server.upgrade() {
            ui.set_server_url(server_url.clone());
            ui.set_identifier("".into());
            ui.set_password("".into());
            prefill_remembered_profile(&ui, &server_url);
        }
    });

    let tx_for_connect = worker_tx.clone();
    let weak_for_connect = ui.as_weak();
    ui.on_connect_requested(move |server_url, identifier, password| {
        if let Some(ui) = weak_for_connect.upgrade() {
            ui.set_connecting(true);
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
        }
        let _ = tx_for_connect.send(WorkerCommand::Connect {
            server_url: server_url.to_string(),
            identifier: identifier.to_string(),
            password: password.to_string(),
        });
    });

    let tx_for_disconnect = worker_tx.clone();
    let weak_for_disconnect = ui.as_weak();
    ui.on_disconnect_requested(move || {
        let _ = tx_for_disconnect.send(WorkerCommand::Disconnect);
        if let Some(ui) = weak_for_disconnect.upgrade() {
            ui.set_screen("connect".into());
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
            let empty_groups = Rc::new(slint::VecModel::from(Vec::<NetworkGroup>::new()));
            ui.set_network_groups(empty_groups.into());
            let empty_lines = Rc::new(slint::VecModel::from(Vec::<ChatLine>::new()));
            ui.set_chat_lines(empty_lines.into());
            ui.set_current_topic("".into());
            ui.set_has_selected_channel(false);
        }
    });

    let tx_for_channel = worker_tx.clone();
    ui.on_channel_selected(move |network, channel| {
        let _ = tx_for_channel.send(WorkerCommand::SelectChannel {
            network: network.to_string(),
            channel: channel.to_string(),
        });
    });

    let tx_for_network_toggle = worker_tx.clone();
    ui.on_network_toggle_requested(move |network| {
        let _ = tx_for_network_toggle.send(WorkerCommand::ToggleNetwork(network.to_string()));
    });

    let tx_for_attach = worker_tx.clone();
    ui.on_attach_file_requested(move || {
        let _ = tx_for_attach.send(WorkerCommand::AttachFile);
    });

    let tx_for_send = worker_tx.clone();
    let weak_for_send = ui.as_weak();
    ui.on_send_chat_message(move |body| {
        let body = body.to_string();
        if body.trim().is_empty() {
            return;
        }
        let _ = tx_for_send.send(WorkerCommand::SendMessage { body });
        if let Some(ui) = weak_for_send.upgrade() {
            ui.set_compose_text("".into());
        }
    });

    let tx_for_draft = worker_tx.clone();
    ui.on_compose_text_changed(move |text| {
        let _ = tx_for_draft.send(WorkerCommand::ComposeTextChanged(text.to_string()));
    });

    let tx_for_theme = worker_tx.clone();
    ui.on_theme_toggle_requested(move || {
        let _ = tx_for_theme.send(WorkerCommand::ToggleTheme);
    });

    let tx_for_prefs = worker_tx.clone();
    let weak_for_prefs = ui.as_weak();
    ui.on_display_prefs_changed(move || {
        if let Some(ui) = weak_for_prefs.upgrade() {
            let prefs = DisplayPrefs {
                colored_nicklist: Some(ui.get_pref_colored_nicklist()),
                show_bottom_bar: Some(ui.get_pref_show_bottom_bar()),
                strip_formatting: Some(ui.get_pref_strip_formatting()),
                show_event_badge: Some(ui.get_pref_show_event_badge()),
                bold_mentions: Some(ui.get_pref_bold_mentions()),
            };
            let _ = tx_for_prefs.send(WorkerCommand::SaveDisplayPrefs(prefs));
        }
    });

    let tx_for_admin_refresh = worker_tx.clone();
    ui.on_admin_refresh_requested(move || {
        let _ = tx_for_admin_refresh.send(WorkerCommand::AdminRefresh);
    });

    let tx_for_admin_disconnect = worker_tx.clone();
    ui.on_admin_disconnect_session(move |session_id| {
        let _ = tx_for_admin_disconnect.send(WorkerCommand::AdminDisconnectSession(
            session_id.to_string(),
        ));
    });

    let tx_for_links = worker_tx.clone();
    ui.on_links_requested(move |network| {
        let _ = tx_for_links.send(WorkerCommand::RequestLinks(network.to_string()));
    });

    // Lazily created, reused across requests rather than spawning a new
    // OS window every click. Only ever touched from this callback, which
    // Slint guarantees runs on the UI thread — safe to be a plain `Rc`.
    let graph_window: Rc<RefCell<Option<LinksGraphWindow>>> = Rc::new(RefCell::new(None));
    let weak_for_graph = ui.as_weak();
    ui.on_links_graph_requested(move || {
        let Some(ui) = weak_for_graph.upgrade() else {
            return;
        };
        let mut slot = graph_window.borrow_mut();
        if slot.is_none() {
            let Ok(window) = LinksGraphWindow::new() else {
                return;
            };
            *slot = Some(window);
        }
        let window = slot.as_ref().expect("just ensured present above");
        window.set_network_label(ui.get_links_network_label());
        window.set_edges_commands(ui.get_links_graph_edges_commands());
        window.set_nodes(ui.get_links_graph_nodes());
        let _ = window.show();
    });

    let tx_for_user_toggle = worker_tx.clone();
    ui.on_admin_user_toggle_admin(move |user_id, is_admin| {
        let _ = tx_for_user_toggle.send(WorkerCommand::AdminUserToggleAdmin(
            user_id.to_string(),
            is_admin,
        ));
    });

    let tx_for_user_delete = worker_tx.clone();
    ui.on_admin_user_delete(move |user_id| {
        let _ = tx_for_user_delete.send(WorkerCommand::AdminUserDelete(user_id.to_string()));
    });

    let tx_for_visitor_delete = worker_tx.clone();
    ui.on_admin_visitor_delete(move |visitor_id| {
        let _ =
            tx_for_visitor_delete.send(WorkerCommand::AdminVisitorDelete(visitor_id.to_string()));
    });

    let tx_for_circuit_reset = worker_tx.clone();
    ui.on_admin_network_reset_circuit(move |network_id| {
        let _ = tx_for_circuit_reset.send(WorkerCommand::AdminNetworkResetCircuit(
            network_id.to_string(),
        ));
    });

    let tx_for_reaper = worker_tx.clone();
    ui.on_admin_reaper_run(move || {
        let _ = tx_for_reaper.send(WorkerCommand::AdminReaperRun);
    });

    let tx_for_network_selected = worker_tx.clone();
    ui.on_settings_network_selected(move |network| {
        let _ = tx_for_network_selected
            .send(WorkerCommand::SettingsNetworkSelected(network.to_string()));
    });

    let tx_for_identity = worker_tx.clone();
    let weak_for_identity = ui.as_weak();
    ui.on_identity_save_requested(move || {
        if let Some(ui) = weak_for_identity.upgrade() {
            let _ = tx_for_identity.send(WorkerCommand::IdentitySave {
                nick: ui.get_identity_nick().to_string(),
                ident: ui.get_identity_ident().to_string(),
                realname: ui.get_identity_realname().to_string(),
            });
        }
    });

    let tx_for_ignore_add = worker_tx.clone();
    ui.on_ignore_add_requested(move |mask| {
        let _ = tx_for_ignore_add.send(WorkerCommand::IgnoreAdd(mask.to_string()));
    });

    let tx_for_ignore_remove = worker_tx.clone();
    ui.on_ignore_remove_requested(move |mask| {
        let _ = tx_for_ignore_remove.send(WorkerCommand::IgnoreRemove(mask.to_string()));
    });

    let tx_for_perform_save = worker_tx.clone();
    ui.on_perform_save_requested(move |text| {
        let _ = tx_for_perform_save.send(WorkerCommand::PerformSave(text.to_string()));
    });

    let tx_for_alias_add = worker_tx.clone();
    ui.on_alias_add_requested(move |command, expansion| {
        let _ = tx_for_alias_add.send(WorkerCommand::AliasAdd {
            command: command.to_string(),
            expansion: expansion.to_string(),
        });
    });

    let tx_for_alias_remove = worker_tx.clone();
    ui.on_alias_remove_requested(move |command| {
        let _ = tx_for_alias_remove.send(WorkerCommand::AliasRemove(command.to_string()));
    });

    let tx_for_vhost_toggle = worker_tx.clone();
    ui.on_vhost_toggle_requested(move |address| {
        let _ = tx_for_vhost_toggle.send(WorkerCommand::VhostToggle(address.to_string()));
    });

    let tx_for_notify_add = worker_tx.clone();
    ui.on_notify_add_requested(move |nick| {
        let _ = tx_for_notify_add.send(WorkerCommand::NotifyAdd(nick.to_string()));
    });

    let tx_for_notify_remove = worker_tx.clone();
    ui.on_notify_remove_requested(move |nick| {
        let _ = tx_for_notify_remove.send(WorkerCommand::NotifyRemove(nick.to_string()));
    });

    let tx_for_watch_add = worker_tx.clone();
    ui.on_watch_pattern_add_requested(move |pattern| {
        let _ = tx_for_watch_add.send(WorkerCommand::WatchPatternAdd(pattern.to_string()));
    });

    let tx_for_watch_remove = worker_tx.clone();
    ui.on_watch_pattern_remove_requested(move |pattern| {
        let _ = tx_for_watch_remove.send(WorkerCommand::WatchPatternRemove(pattern.to_string()));
    });

    ui.run()
}

/// State the worker keeps across the whole connected session. Lives only on
/// the background thread; the UI thread never touches it directly.
struct WorkerState {
    client: Option<GrappaClient>,
    token: Option<String>,
    identifier: Option<String>,
    session: Option<SessionHandle>,
    joined_topics: std::collections::HashSet<String>,
    /// Keyed by `(network, channel)`; holds display lines already rendered
    /// for that channel so switching channels doesn't lose history.
    messages: HashMap<(String, String), Vec<String>>,
    /// Keyed by `(network, channel)`; an unsent compose draft per channel,
    /// mirroring Cicchetto's own per-channel drafts (confirmed by the
    /// Grappa/Cicchetto maintainer, see MEMORY.md §0sexies) so switching
    /// channels doesn't lose or leak what's half-typed.
    drafts: HashMap<(String, String), String>,
    /// Keyed by `(network, channel)`; the channel topic, if the server sent
    /// one — see `topics_from_boot` and `handle_frame`.
    topics: HashMap<(String, String), String>,
    /// Network slug -> whether its channel list is expanded in the sidebar.
    /// Missing entries default to expanded (see `network_groups_data`).
    expanded_networks: HashMap<String, bool>,
    /// `(network, channel, label)` from the last bootstrap, kept around so
    /// `ToggleNetwork` can rebuild the sidebar model without re-fetching.
    channel_entries: Vec<(String, String, String)>,
    current_channel: Option<(String, String)>,
    /// Network slug -> Grappa's own integer `network_id`, read from
    /// `boot.networks`. WS commands like `/links` need the integer id,
    /// never the slug — see `docs/protocol-notes.md` §4ter for why this
    /// isn't just string-vs-int bikeshedding: the server hard-rejects a
    /// non-integer `network_id` (`is_integer/1` guard), no slug fallback.
    network_ids: HashMap<String, i64>,
    /// The network the self-service Identity/Ignores/Perform/Notify
    /// sections currently act on.
    settings_network: Option<String>,
    /// Session-local only: Grappa has no self-service `GET` for either of
    /// these (the presence watchlist arrives via a WS snapshot, the
    /// keyword watchlist has no documented `list` reply shape — see
    /// `docs/protocol-notes.md` §4quater), so these don't survive a
    /// reconnect/relaunch, unlike everything else in Settings.
    notify_nicks: Vec<String>,
    watch_patterns: Vec<String>,
}

impl WorkerState {
    fn new() -> Self {
        WorkerState {
            client: None,
            token: None,
            identifier: None,
            session: None,
            joined_topics: std::collections::HashSet::new(),
            messages: HashMap::new(),
            drafts: HashMap::new(),
            topics: HashMap::new(),
            expanded_networks: HashMap::new(),
            channel_entries: Vec::new(),
            current_channel: None,
            network_ids: HashMap::new(),
            settings_network: None,
            notify_nicks: Vec::new(),
            watch_patterns: Vec::new(),
        }
    }
}

/// The single background worker: owns the tokio runtime, the REST client,
/// and the realtime session for the whole app lifetime. Multiplexes UI
/// commands and realtime session events with `tokio::select!`; when there's
/// no session yet, the event branch parks on `std::future::pending()` so it
/// never fires.
async fn run_worker(
    mut commands: mpsc::UnboundedReceiver<WorkerCommand>,
    ui: slint::Weak<AppWindow>,
) {
    let mut state = WorkerState::new();
    let mut session_events: Option<mpsc::UnboundedReceiver<SessionEvent>> = None;

    loop {
        let next_event = async {
            match &mut session_events {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            command = commands.recv() => {
                match command {
                    None => return,
                    Some(WorkerCommand::Connect { server_url, identifier, password }) => {
                        handle_connect(
                            &mut state,
                            &mut session_events,
                            &ui,
                            server_url,
                            identifier,
                            password,
                        )
                        .await;
                        if let Some(network) = state.settings_network.clone() {
                            let ui_for_network = ui.clone();
                            let _ = ui_for_network.upgrade_in_event_loop(move |ui| {
                                ui.set_settings_network(network.into());
                            });
                            handle_settings_network_refresh(&state, &ui).await;
                        }
                    }
                    Some(WorkerCommand::SelectChannel { network, channel }) => {
                        handle_select_channel(&mut state, &ui, network, channel).await;
                    }
                    Some(WorkerCommand::ToggleNetwork(network)) => {
                        let expanded = state.expanded_networks.entry(network).or_insert(true);
                        *expanded = !*expanded;
                        refresh_network_groups(&state, &ui);
                    }
                    Some(WorkerCommand::AttachFile) => {
                        // No attachment upload path in the Grappa contract
                        // yet (see `docs/protocol-notes.md` §4's "dcc
                        // offer" entity — attachments look DCC-based, not
                        // a plain REST upload) — surfaced as a status
                        // message rather than silently doing nothing.
                        persistence::log_line("attach file requested: not yet implemented");
                        let ui = ui.clone();
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_status_kind("attach-unsupported".into());
                        });
                    }
                    Some(WorkerCommand::SendMessage { body }) => {
                        handle_send_message(&state, &ui, body).await;
                        if let Some(key) = state.current_channel.clone() {
                            state.drafts.remove(&key);
                        }
                    }
                    Some(WorkerCommand::ComposeTextChanged(text)) => {
                        if let Some(key) = state.current_channel.clone() {
                            if text.is_empty() {
                                state.drafts.remove(&key);
                            } else {
                                state.drafts.insert(key, text);
                            }
                        }
                    }
                    Some(WorkerCommand::ToggleTheme) => {
                        handle_toggle_theme(&ui);
                    }
                    Some(WorkerCommand::SaveDisplayPrefs(prefs)) => {
                        handle_save_display_prefs(&state, prefs).await;
                    }
                    Some(WorkerCommand::AdminRefresh) => {
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::AdminDisconnectSession(session_id)) => {
                        handle_admin_disconnect_session(&state, &ui, session_id).await;
                    }
                    Some(WorkerCommand::AdminUserToggleAdmin(user_id, is_admin)) => {
                        if let (Some(client), Some(token)) = (&state.client, &state.token) {
                            let _ = client
                                .set_admin_user_is_admin(token, &user_id, is_admin)
                                .await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::AdminUserDelete(user_id)) => {
                        if let (Some(client), Some(token)) = (&state.client, &state.token) {
                            let _ = client.delete_admin_user(token, &user_id).await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::AdminVisitorDelete(visitor_id)) => {
                        if let (Some(client), Some(token)) = (&state.client, &state.token) {
                            let _ = client.delete_admin_visitor(token, &visitor_id).await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::AdminNetworkResetCircuit(network_id)) => {
                        if let (Some(client), Some(token)) = (&state.client, &state.token) {
                            let _ = client.reset_admin_circuit(token, &network_id).await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::AdminReaperRun) => {
                        if let (Some(client), Some(token)) = (&state.client, &state.token) {
                            let _ = client.run_admin_reaper(token).await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::RequestLinks(network)) => {
                        handle_request_links(&state, network);
                    }
                    Some(WorkerCommand::SettingsNetworkSelected(network)) => {
                        state.settings_network = Some(network);
                        handle_settings_network_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::IdentitySave {
                        nick,
                        ident,
                        realname,
                    }) => {
                        handle_identity_save(&state, nick, ident, realname).await;
                    }
                    Some(WorkerCommand::IgnoreAdd(mask)) => {
                        if let (Some(client), Some(token), Some(network)) =
                            (&state.client, &state.token, &state.settings_network)
                        {
                            let _ = client.add_ignore(token, network, &mask).await;
                        }
                        handle_settings_network_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::IgnoreRemove(mask)) => {
                        if let (Some(client), Some(token), Some(network)) =
                            (&state.client, &state.token, &state.settings_network)
                        {
                            let _ = client.remove_ignore(token, network, &mask).await;
                        }
                        handle_settings_network_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::PerformSave(text)) => {
                        if let (Some(client), Some(token), Some(network)) =
                            (&state.client, &state.token, &state.settings_network)
                        {
                            let request = cordiale_core::profile::PerformUpdateRequest {
                                perform_list: Some(text),
                                oper_pass: None,
                            };
                            let _ = client.update_perform(token, network, &request).await;
                        }
                    }
                    Some(WorkerCommand::AliasAdd { command, expansion }) => {
                        handle_alias_upsert(&state, &ui, Some((command, expansion))).await;
                    }
                    Some(WorkerCommand::AliasRemove(command)) => {
                        handle_alias_remove(&state, &ui, command).await;
                    }
                    Some(WorkerCommand::VhostToggle(address)) => {
                        handle_vhost_toggle(&state, &ui, address).await;
                    }
                    Some(WorkerCommand::NotifyAdd(nick)) => {
                        if let (Some(client), Some(token), Some(network)) =
                            (&state.client, &state.token, &state.settings_network)
                        {
                            if client
                                .add_notify_nicks(token, network, vec![nick.clone()])
                                .await
                                .is_ok()
                                && !state.notify_nicks.contains(&nick)
                            {
                                state.notify_nicks.push(nick);
                            }
                        }
                        push_notify_nicks(&state, &ui);
                    }
                    Some(WorkerCommand::NotifyRemove(nick)) => {
                        if let (Some(client), Some(token), Some(network)) =
                            (&state.client, &state.token, &state.settings_network)
                        {
                            if client.remove_notify_nick(token, network, &nick).await.is_ok() {
                                state.notify_nicks.retain(|existing| existing != &nick);
                            }
                        }
                        push_notify_nicks(&state, &ui);
                    }
                    Some(WorkerCommand::WatchPatternAdd(pattern)) => {
                        if let (Some(session), Some(identifier)) =
                            (&state.session, &state.identifier)
                        {
                            session.send_command(
                                format!("grappa:user:{identifier}"),
                                "watchlist",
                                serde_json::json!({"action": "add", "pattern": pattern}),
                            );
                        }
                        if !state.watch_patterns.contains(&pattern) {
                            state.watch_patterns.push(pattern);
                        }
                        push_watch_patterns(&state, &ui);
                    }
                    Some(WorkerCommand::WatchPatternRemove(pattern)) => {
                        if let (Some(session), Some(identifier)) =
                            (&state.session, &state.identifier)
                        {
                            session.send_command(
                                format!("grappa:user:{identifier}"),
                                "watchlist",
                                serde_json::json!({"action": "del", "pattern": pattern}),
                            );
                        }
                        state.watch_patterns.retain(|existing| existing != &pattern);
                        push_watch_patterns(&state, &ui);
                    }
                    Some(WorkerCommand::Disconnect) => {
                        persistence::log_line("disconnect requested");
                        if let Some(handle) = state.session.take() {
                            handle.shutdown();
                        }
                        session_events = None;
                        state = WorkerState::new();
                    }
                }
            }

            event = next_event => {
                match event {
                    Some(SessionEvent::Connected { protocol_version }) => {
                        persistence::log_line(&format!(
                            "session connected, protocol_version={protocol_version:?}"
                        ));
                    }
                    Some(SessionEvent::Frame(frame)) => {
                        handle_frame(&mut state, &ui, frame);
                    }
                    Some(SessionEvent::Disconnected { reason }) => {
                        persistence::log_line(&format!("session disconnected: {reason}"));
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_status_kind("disconnected".into());
                        });
                    }
                    Some(SessionEvent::Reconnecting { reason }) => {
                        persistence::log_line(&format!("session reconnecting: {reason}"));
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_status_kind("reconnecting".into());
                        });
                    }
                    None => {
                        session_events = None;
                    }
                }
            }
        }
    }
}

async fn handle_connect(
    state: &mut WorkerState,
    session_events: &mut Option<mpsc::UnboundedReceiver<SessionEvent>>,
    ui: &slint::Weak<AppWindow>,
    server_url: String,
    identifier: String,
    password: String,
) {
    let server_url = normalize_server_url(&server_url);

    // No password typed → guest/visitor login instead of sending an
    // empty credential the server will just 400 on. `identifier: "guest",
    // password: "guest"` is the one combination confirmed to work against
    // a real server (see docs/protocol-notes.md §5) — the identifier the
    // user typed, if any, is ignored for this attempt since the guest
    // mechanism isn't known to accept an arbitrary one.
    let is_guest_attempt = password.is_empty();
    let (login_identifier, login_password) = if is_guest_attempt {
        ("guest".to_string(), "guest".to_string())
    } else {
        (identifier.clone(), password.clone())
    };

    // Never log a real password: it may be a real password or a
    // per-client token, and either way it's a secret — see MEMORY.md
    // §3.6. "guest" isn't a secret, so the guest case can log it plainly.
    persistence::log_line(&format!(
        "connect attempt: server={server_url} identifier={login_identifier} \
         guest={is_guest_attempt}"
    ));
    remember_server_url(&server_url);

    let client = GrappaClient::new(server_url.clone());
    let request = LoginRequest {
        identifier: login_identifier.clone(),
        password: login_password,
    };
    let result = bootstrap(&client, &request).await;

    match result {
        Ok(outcome) => {
            persistence::log_line(&format!("connect succeeded: server={server_url}"));
            if !is_guest_attempt {
                remember_profile(&server_url, &identifier, &password);
            }

            let entries = channel_entries_from_boot(&outcome);
            state.channel_entries = entries.clone();
            state.topics = topics_from_boot(&outcome);
            state.messages = messages_from_boot(&outcome);
            state.network_ids = network_ids_from_boot(&outcome);
            let is_admin = outcome
                .subject
                .get("is_admin")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let token = outcome.token.clone();

            let ws_url = to_ws_url(&server_url);
            let (handle, events) = spawn_session(ws_url, token.clone(), identifier.clone());
            for entry in &entries {
                handle.join_topic(channel_topic(&identifier, &entry.0, &entry.1), true);
            }
            *session_events = Some(events);

            state.client = Some(client);
            state.token = Some(token.clone());
            state.identifier = Some(identifier.clone());
            state.session = Some(handle);
            state.joined_topics = entries
                .iter()
                .map(|(network, channel, _)| channel_topic(&identifier, network, channel))
                .collect();

            let prefs_client = GrappaClient::new(server_url.clone());
            let prefs_token = token.clone();
            let ui_for_prefs = ui.clone();
            tokio::spawn(async move {
                if let Ok(prefs) = prefs_client.fetch_display_prefs(&prefs_token).await {
                    let _ = ui_for_prefs.upgrade_in_event_loop(move |ui| {
                        apply_display_prefs(&ui, &prefs);
                    });
                }
            });

            let ui = ui.clone();
            let mut distinct_networks: Vec<String> = entries
                .iter()
                .map(|(network, _, _)| network.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            distinct_networks.sort();
            state.settings_network = distinct_networks.first().cloned();
            let network_count = distinct_networks.len();
            let channel_count = entries.len();
            let groups_data = network_groups_data(&entries, &state.expanded_networks);
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_connecting(false);
                ui.set_is_admin(is_admin);
                ui.set_known_servers(known_servers_model());
                ui.set_screen("connected".into());
                ui.set_status_kind("signed-in".into());
                ui.set_status_network_count(network_count as i32);
                ui.set_status_channel_count(channel_count as i32);
                let networks: Vec<slint::SharedString> =
                    distinct_networks.into_iter().map(Into::into).collect();
                ui.set_known_networks(Rc::new(slint::VecModel::from(networks)).into());
                let groups = network_groups_model(groups_data);
                ui.set_network_groups(Rc::new(slint::VecModel::from(groups)).into());
            });
        }
        Err(err) => {
            persistence::log_line(&format!("connect failed: server={server_url} {err:?}"));
            let ui = ui.clone();
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_connecting(false);
                apply_bootstrap_error(&ui, &err);
            });
        }
    }
}

async fn handle_select_channel(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    channel: String,
) {
    let Some(identifier) = state.identifier.clone() else {
        return;
    };
    let topic = channel_topic(&identifier, &network, &channel);
    if let Some(handle) = &state.session {
        if state.joined_topics.insert(topic.clone()) {
            handle.join_topic(topic, true);
        }
    }

    let key = (network.clone(), channel.clone());
    state.current_channel = Some(key.clone());
    let lines = state.messages.get(&key).cloned().unwrap_or_default();
    let draft = state.drafts.get(&key).cloned().unwrap_or_default();
    let irc_topic = state.topics.get(&key).cloned().unwrap_or_default();

    let label = format!("{network} — {channel}");
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_channel_label(label.into());
        ui.set_current_topic(irc_topic.into());
        ui.set_has_selected_channel(true);
        ui.set_compose_text(draft.into());
        let model = chat_lines_model(&lines);
        ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
    });
}

async fn handle_send_message(state: &WorkerState, ui: &slint::Weak<AppWindow>, body: String) {
    let (Some(client), Some(token), Some((network, channel))) =
        (&state.client, &state.token, &state.current_channel)
    else {
        return;
    };

    let request = SendMessageRequest::plain(body);
    if client
        .send_message(token, network, channel, &request)
        .await
        .is_err()
    {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_status_kind("send-failed".into());
        });
    }
}

fn handle_toggle_theme(ui: &slint::Weak<AppWindow>) {
    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.theme = match settings.theme {
        Theme::Light => Theme::Dark,
        Theme::Dark => Theme::Light,
    };
    let _ = persistence::save_settings(&settings);

    let new_theme = settings.theme;
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_theme(theme_to_slint(new_theme));
    });
}

async fn handle_save_display_prefs(state: &WorkerState, prefs: DisplayPrefs) {
    if let (Some(client), Some(token)) = (&state.client, &state.token) {
        let _ = client.update_display_prefs(token, &prefs).await;
    }
}

/// Fetches `/admin/overview` and `/admin/sessions` and pushes them to the
/// UI. Only meaningful for an `is_admin` account with a full web session —
/// a per-client token gets `403` here, surfaced as an empty refresh
/// (see `docs/protocol-notes.md` §4ter).
async fn handle_admin_refresh(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };

    let ui_for_loading = ui.clone();
    let _ = ui_for_loading.upgrade_in_event_loop(|ui| ui.set_admin_loading(true));

    let overview = client.fetch_admin_overview(token).await.ok();
    let sessions = client.fetch_admin_sessions(token).await.unwrap_or_default();
    let users = client.fetch_admin_users(token).await.unwrap_or_default();
    let networks = client.fetch_admin_networks(token).await.unwrap_or_default();
    let visitors = client.fetch_admin_visitors(token).await.unwrap_or_default();
    let session_log = client
        .fetch_admin_session_log(token, 50)
        .await
        .unwrap_or_default();

    let overview_text = overview.map(|overview| {
        format!(
            "{} session(s) · {}/{} visitors live · {} · v{}",
            overview.sessions,
            overview.visitors.live,
            overview.visitors.total,
            overview.hostname,
            overview.version
        )
    });

    let session_rows: Vec<AdminSessionRow> = sessions
        .iter()
        .map(|entry| AdminSessionRow {
            label: cordiale_core::admin::admin_session_label(entry).into(),
            alive: cordiale_core::admin::admin_session_is_alive(entry),
            session_id: cordiale_core::admin::admin_session_id(entry)
                .unwrap_or_default()
                .into(),
        })
        .collect();

    let user_rows: Vec<AdminUserRow> = users
        .iter()
        .map(|entry| AdminUserRow {
            label: cordiale_core::admin::admin_user_label(entry).into(),
            is_admin: cordiale_core::admin::admin_user_is_admin(entry),
            user_id: cordiale_core::admin::admin_user_id(entry)
                .unwrap_or_default()
                .into(),
        })
        .collect();

    let network_rows: Vec<AdminNetworkRow> = networks
        .iter()
        .map(|entry| {
            let label = format!(
                "{}{}",
                cordiale_core::admin::admin_network_label(entry),
                cordiale_core::admin::admin_network_status(entry)
            );
            let network_id = cordiale_core::admin::admin_network_id(entry).unwrap_or_default();
            AdminNetworkRow {
                label: label.into(),
                network_id: network_id.into(),
            }
        })
        .collect();

    let visitor_rows: Vec<AdminVisitorRow> = visitors
        .iter()
        .map(|entry| AdminVisitorRow {
            label: cordiale_core::admin::admin_visitor_label(entry).into(),
            visitor_id: cordiale_core::admin::admin_visitor_id(entry)
                .unwrap_or_default()
                .into(),
        })
        .collect();

    let session_log_lines: Vec<slint::SharedString> = session_log
        .iter()
        .map(|entry| cordiale_core::admin::admin_session_log_line(entry).into())
        .collect();

    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_admin_loading(false);
        ui.set_admin_overview_text(overview_text.unwrap_or_default().into());
        ui.set_admin_sessions(Rc::new(slint::VecModel::from(session_rows)).into());
        ui.set_admin_users(Rc::new(slint::VecModel::from(user_rows)).into());
        ui.set_admin_networks(Rc::new(slint::VecModel::from(network_rows)).into());
        ui.set_admin_visitors(Rc::new(slint::VecModel::from(visitor_rows)).into());
        ui.set_admin_session_log(Rc::new(slint::VecModel::from(session_log_lines)).into());
    });
}

async fn handle_admin_disconnect_session(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    session_id: String,
) {
    if let (Some(client), Some(token)) = (&state.client, &state.token) {
        let _ = client.disconnect_admin_session(token, &session_id).await;
    }
    handle_admin_refresh(state, ui).await;
}

/// Refreshes every self-service settings section: Ignores/Perform for
/// `state.settings_network` (empty if none picked yet), plus the
/// account-scoped Aliases/Vhost — see `docs/protocol-notes.md` §4quater.
async fn handle_settings_network_refresh(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };

    let ignores = match &state.settings_network {
        Some(network) => client
            .fetch_ignores(token, network)
            .await
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let perform_text = match &state.settings_network {
        Some(network) => client
            .fetch_perform(token, network)
            .await
            .ok()
            .and_then(|view| view.perform_list)
            .unwrap_or_default(),
        None => String::new(),
    };
    let aliases = client.fetch_aliases(token).await.unwrap_or_default();
    let vhost = client.fetch_vhost_settings(token).await.ok();

    let alias_rows: Vec<AliasRow> = aliases
        .into_iter()
        .map(|(command, expansion)| AliasRow {
            command: command.into(),
            expansion: expansion.into(),
        })
        .collect();

    let vhost_rows: Vec<VhostOptionRow> = match vhost {
        Some(view) => {
            let selection = view.selection;
            view.available
                .into_iter()
                .map(|option| {
                    let selected = selection.contains(&option.address);
                    let label = option
                        .name
                        .clone()
                        .unwrap_or_else(|| option.address.clone());
                    VhostOptionRow {
                        address: option.address.into(),
                        label: label.into(),
                        selected,
                    }
                })
                .collect()
        }
        None => Vec::new(),
    };

    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let ignores_model: Vec<slint::SharedString> = ignores.into_iter().map(Into::into).collect();
        ui.set_settings_ignores(Rc::new(slint::VecModel::from(ignores_model)).into());
        ui.set_perform_text(perform_text.into());
        ui.set_settings_aliases(Rc::new(slint::VecModel::from(alias_rows)).into());
        ui.set_settings_vhost_options(Rc::new(slint::VecModel::from(vhost_rows)).into());
    });
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

async fn handle_identity_save(state: &WorkerState, nick: String, ident: String, realname: String) {
    let (Some(client), Some(token), Some(network)) =
        (&state.client, &state.token, &state.settings_network)
    else {
        return;
    };
    let request = cordiale_core::profile::NetworkIdentityRequest {
        nick: non_empty(nick),
        ident: non_empty(ident),
        realname: non_empty(realname),
    };
    let _ = client
        .update_network_identity(token, network, &request)
        .await;
}

/// Adds/edits one alias — Grappa's `PUT /me/settings/aliases` replaces
/// the whole map, so this fetches the current one, applies the change,
/// and writes the whole thing back (no diff/patch endpoint exists).
async fn handle_alias_upsert(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    new_entry: Option<(String, String)>,
) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };
    let mut aliases = client.fetch_aliases(token).await.unwrap_or_default();
    if let Some((command, expansion)) = new_entry {
        if !command.is_empty() {
            aliases.insert(command, expansion);
        }
    }
    let _ = client.update_aliases(token, aliases).await;
    handle_settings_network_refresh(state, ui).await;
}

async fn handle_alias_remove(state: &WorkerState, ui: &slint::Weak<AppWindow>, command: String) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };
    let mut aliases = client.fetch_aliases(token).await.unwrap_or_default();
    aliases.remove(&command);
    let _ = client.update_aliases(token, aliases).await;
    handle_settings_network_refresh(state, ui).await;
}

/// Toggles one address in the vhost selection — `PUT /me/settings/vhost`
/// also replaces the whole selection, so this reads the current one,
/// flips the one address, and writes it back.
async fn handle_vhost_toggle(state: &WorkerState, ui: &slint::Weak<AppWindow>, address: String) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };
    let Ok(current) = client.fetch_vhost_settings(token).await else {
        return;
    };
    let mut selection = current.selection;
    if let Some(index) = selection.iter().position(|existing| existing == &address) {
        selection.remove(index);
    } else {
        selection.push(address);
    }
    let _ = client.update_vhost_selection(token, selection).await;
    handle_settings_network_refresh(state, ui).await;
}

/// Pushes the session-local presence-watchlist nicks to the UI — see
/// `WorkerState::notify_nicks`'s doc comment for why this is
/// session-local rather than server-refetched.
fn push_notify_nicks(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let nicks: Vec<slint::SharedString> =
        state.notify_nicks.iter().cloned().map(Into::into).collect();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_settings_notify_nicks(Rc::new(slint::VecModel::from(nicks)).into());
    });
}

/// Pushes the session-local keyword-watchlist patterns to the UI — same
/// session-local caveat as `push_notify_nicks`.
fn push_watch_patterns(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let patterns: Vec<slint::SharedString> = state
        .watch_patterns
        .iter()
        .cloned()
        .map(Into::into)
        .collect();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_settings_watch_patterns(Rc::new(slint::VecModel::from(patterns)).into());
    });
}

/// Sends a `/links` request on the user topic — see
/// `docs/protocol-notes.md` §4ter for why the user topic rather than a
/// network topic Cordiale doesn't currently join. The result arrives
/// later as a `links_bundle` frame, handled in `handle_frame`.
fn handle_request_links(state: &WorkerState, network: String) {
    let (Some(session), Some(identifier)) = (&state.session, &state.identifier) else {
        return;
    };
    // Grappa hard-rejects a non-integer `network_id` (`is_integer/1`
    // guard server-side, no slug fallback) — see
    // `docs/protocol-notes.md` §4ter. Silently do nothing rather than
    // send a request guaranteed to be rejected if the id isn't known.
    let Some(&network_id) = state.network_ids.get(&network) else {
        return;
    };
    let topic = format!("grappa:user:{identifier}");
    session.send_command(
        topic,
        "links",
        serde_json::json!({ "network_id": network_id }),
    );
}

/// Appends an incoming realtime frame to the channel it belongs to (if any)
/// and, if that channel is currently open, pushes the update to the UI.
///
/// The exact shape of a channel-message push isn't confirmed by
/// `docs/protocol-notes.md` (see its §7 open points), so this reads the
/// plausible fields defensively and always falls back to a raw
/// `event: payload` line rather than dropping the frame silently.
fn handle_frame(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    frame: cordiale_core::phoenix::PhoenixMessage,
) {
    // The `kind:` field is the real discriminator for these server-push
    // "bundle" replies per `docs/protocol-notes.md` §4ter — the Phoenix
    // `event` name itself isn't confirmed to equal the bundle name, so
    // this checks both rather than betting on one interpretation.
    let payload_kind = frame.payload.get("kind").and_then(Value::as_str);
    if frame.event == "links_bundle" || payload_kind == Some("links_bundle") {
        handle_links_bundle(ui, &frame.payload);
        return;
    }

    let Some((network, channel)) = channel_from_topic(&frame.topic) else {
        return;
    };
    if frame.event == "phx_reply" {
        return;
    }

    let key = (network.clone(), channel.clone());

    // Any frame that happens to carry a `topic` field is treated as a
    // topic update for its channel — no confirmed `topic_changed`-style
    // event name in `docs/protocol-notes.md`, so this doesn't bet on one.
    if let Some(new_topic) = frame.payload.get("topic").and_then(Value::as_str) {
        if !new_topic.is_empty() {
            state.topics.insert(key.clone(), new_topic.to_string());
            if state.current_channel.as_ref() == Some(&key) {
                let new_topic = new_topic.to_string();
                let ui = ui.clone();
                let _ = ui.upgrade_in_event_loop(move |ui| {
                    ui.set_current_topic(new_topic.into());
                });
            }
        }
    }

    let line = render_frame(&frame);
    state.messages.entry(key.clone()).or_default().push(line);

    if state.current_channel.as_ref() == Some(&key) {
        let lines = state.messages[&key].clone();
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            let model = chat_lines_model(&lines);
            ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        });
    }
}

/// Parses a `links_bundle` payload, reconstructs the tree (see
/// `cordiale_core::links`), and pushes an indented rendering to the
/// `"links"` screen. Never crashes on an unexpected shape: an
/// unparseable `entries` array just shows nothing rather than erroring.
fn handle_links_bundle(ui: &slint::Weak<AppWindow>, payload: &Value) {
    let entries: Vec<cordiale_core::links::LinksEntry> = payload
        .get("entries")
        .and_then(|entries| serde_json::from_value(entries.clone()).ok())
        .unwrap_or_default();
    let network_label = payload
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let tree = cordiale_core::links::build_links_tree(&entries);

    let mut children_of: HashMap<Option<String>, Vec<&cordiale_core::links::LinksNode>> =
        HashMap::new();
    let mut by_server: HashMap<&str, &cordiale_core::links::LinksNode> = HashMap::new();
    for node in &tree {
        children_of
            .entry(node.parent.clone())
            .or_default()
            .push(node);
        by_server.insert(node.server.as_str(), node);
    }
    for children in children_of.values_mut() {
        children.sort_by(|a, b| a.server.cmp(&b.server));
    }

    let mut ordered: Vec<&cordiale_core::links::LinksNode> = Vec::with_capacity(tree.len());
    let mut stack: Vec<&str> = tree
        .iter()
        .filter(|node| node.is_root)
        .map(|node| node.server.as_str())
        .collect();
    while let Some(server) = stack.pop() {
        let Some(node) = by_server.get(server) else {
            continue;
        };
        ordered.push(node);
        if let Some(children) = children_of.get(&Some(server.to_string())) {
            for child in children.iter().rev() {
                stack.push(child.server.as_str());
            }
        }
    }

    let rows: Vec<LinksRow> = ordered
        .into_iter()
        .map(|node| {
            let indent = "  ".repeat(node.depth as usize);
            let hops = node
                .hopcount
                .map(|hops| format!(" (hops: {hops})"))
                .unwrap_or_default();
            let description = node
                .description
                .as_deref()
                .map(|description| format!(" — {description}"))
                .unwrap_or_default();
            LinksRow {
                display: format!("{indent}{}{hops}{description}", node.server).into(),
            }
        })
        .collect();

    // Radial layout for the optional graph window ("Show graph" on the
    // list screen) — computed here too so it's ready the moment the user
    // asks for it, rather than recomputed on click.
    const CANVAS_CENTER: f64 = 380.0;
    const RING_GAP: f64 = 64.0;
    let layout = cordiale_core::links::radial_layout(&tree, RING_GAP);
    let edges_commands = cordiale_core::links::links_graph_edges_svg_path(
        &layout.edges,
        CANVAS_CENTER,
        CANVAS_CENTER,
    );
    let graph_nodes: Vec<LinksGraphNode> = layout
        .nodes
        .into_iter()
        .map(|node| LinksGraphNode {
            server: node.server.into(),
            x: (node.x + CANVAS_CENTER).round() as i32,
            y: (node.y + CANVAS_CENTER).round() as i32,
        })
        .collect();

    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_links_network_label(network_label.into());
        ui.set_links_rows(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_links_graph_edges_commands(edges_commands.into());
        ui.set_links_graph_nodes(Rc::new(slint::VecModel::from(graph_nodes)).into());
        ui.set_screen("links".into());
    });
}

/// Shared `from`/`nick` + `body`/`message` extraction for both live frames
/// (`render_frame`) and REST history rows (`render_history_entry`) — per
/// `docs/protocol-notes.md` §4, scrollback rows and push events are the
/// same "message" entity, so both shapes use the same field names.
fn render_message_body(payload: &Value) -> Option<String> {
    let nick = payload
        .get("from")
        .or_else(|| payload.get("nick"))
        .and_then(|v| v.as_str());
    let body = payload
        .get("body")
        .or_else(|| payload.get("message"))
        .and_then(|v| v.as_str());

    match (nick, body) {
        (Some(nick), Some(body)) => Some(format!("<{nick}> {body}")),
        (None, Some(body)) => Some(body.to_string()),
        _ => None,
    }
}

fn render_frame(frame: &cordiale_core::phoenix::PhoenixMessage) -> String {
    render_message_body(&frame.payload)
        .unwrap_or_else(|| format!("{}: {}", frame.event, frame.payload))
}

/// Renders one `boot.heads` scrollback row the same way a live frame would
/// be, minus the `event`/`topic` envelope a bootstrap history row doesn't
/// have — falls back to the raw JSON rather than guessing a shape.
fn render_history_entry(value: &Value) -> String {
    render_message_body(value).unwrap_or_else(|| value.to_string())
}

fn apply_display_prefs(ui: &AppWindow, prefs: &DisplayPrefs) {
    ui.set_display_prefs_loaded(true);
    if let Some(value) = prefs.colored_nicklist {
        ui.set_pref_colored_nicklist(value);
    }
    if let Some(value) = prefs.show_bottom_bar {
        ui.set_pref_show_bottom_bar(value);
    }
    if let Some(value) = prefs.strip_formatting {
        ui.set_pref_strip_formatting(value);
    }
    if let Some(value) = prefs.show_event_badge {
        ui.set_pref_show_event_badge(value);
    }
    if let Some(value) = prefs.bold_mentions {
        ui.set_pref_bold_mentions(value);
    }
}

/// `grappa:user:{user}/network:{network}/channel:{channel}`, per
/// `docs/protocol-notes.md` §2.
fn channel_topic(user: &str, network: &str, channel: &str) -> String {
    format!("grappa:user:{user}/network:{network}/channel:{channel}")
}

/// Parses `(network, channel)` back out of a channel-level topic string;
/// `None` for the user topic, a network-level topic, or the heartbeat
/// topic.
fn channel_from_topic(topic: &str) -> Option<(String, String)> {
    let after_network = topic.split_once("/network:")?.1;
    let (network, after_channel) = after_network.split_once("/channel:")?;
    Some((network.to_string(), after_channel.to_string()))
}

/// Strips surrounding whitespace and any trailing slash(es) from a
/// server URL the user typed, and defaults a missing scheme to
/// `https://` (typing just `"irc.example.com"` is easy to do and would
/// otherwise make `reqwest`/`Url::parse` reject every request outright).
fn normalize_server_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    let with_scheme = if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    with_scheme.trim_end_matches('/').to_string()
}

/// Turns an `https://`/`http://` base URL into the matching `wss://`/`ws://`
/// Phoenix socket URL, per `docs/protocol-notes.md` §2.
fn to_ws_url(base_url: &str) -> String {
    let with_scheme = if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("wss://{base_url}")
    };
    format!(
        "{}/socket/websocket?vsn=2.0.0",
        with_scheme.trim_end_matches('/')
    )
}

/// Reads `(network, channel, label)` triples out of `boot.channels`. Field
/// names aren't fully confirmed (see `docs/protocol-notes.md` §4), so this
/// tries the plausible candidates and falls back to a positional
/// placeholder rather than guessing further. `label` is just the channel
/// name — the sidebar groups by network already, so repeating it per row
/// would be redundant (that's what the old flat "network — channel" list
/// did).
fn channel_entries_from_boot(outcome: &BootstrapOutcome) -> Vec<(String, String, String)> {
    let mut entries = Vec::new();
    for (network, channels) in &outcome.boot.channels {
        for (index, value) in channels.iter().enumerate() {
            let channel = value
                .get("name")
                .or_else(|| value.get("channel"))
                .and_then(|field| field.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("channel #{}", index + 1));
            let label = channel.clone();
            entries.push((network.clone(), channel, label));
        }
    }
    entries
}

/// Reads `(network, channel) -> topic` out of `boot.channels`, for entries
/// that actually carry a non-empty `topic` field — inferred, not confirmed
/// by `docs/protocol-notes.md` §4 ("Ha: membri, topic, modes, ..."; no
/// JSON schema given). Channels without one are simply absent from the
/// map; the UI falls back to the plain channel label in that case.
fn topics_from_boot(outcome: &BootstrapOutcome) -> HashMap<(String, String), String> {
    let mut topics = HashMap::new();
    for (network, channels) in &outcome.boot.channels {
        for value in channels {
            let channel = value
                .get("name")
                .or_else(|| value.get("channel"))
                .and_then(|field| field.as_str());
            let topic = value.get("topic").and_then(|field| field.as_str());
            if let (Some(channel), Some(topic)) = (channel, topic) {
                if !topic.is_empty() {
                    topics.insert((network.clone(), channel.to_string()), topic.to_string());
                }
            }
        }
    }
    topics
}

/// Reads initial scrollback out of `boot.heads` (network -> channel ->
/// message rows), rendered the same way a live frame would be.
/// `boot.heads` "is only present for a channel that actually has history"
/// (confirmed in an earlier research pass, see MEMORY.md) — a channel with
/// none simply has no key here and starts empty, same as before this was
/// wired in.
fn messages_from_boot(outcome: &BootstrapOutcome) -> HashMap<(String, String), Vec<String>> {
    let mut messages = HashMap::new();
    for (network, channels) in &outcome.boot.heads {
        for (channel, rows) in channels {
            let lines: Vec<String> = rows.iter().map(render_history_entry).collect();
            if !lines.is_empty() {
                messages.insert((network.clone(), channel.clone()), lines);
            }
        }
    }
    messages
}

/// One sidebar network group as plain data: network slug, expand state,
/// and its `(channel, label)` pairs.
type NetworkGroupData = (String, bool, Vec<(String, String)>);

/// Groups flat `(network, channel, label)` entries by network, sorted by
/// network then channel (`boot.channels` is a `HashMap`, so iteration
/// order isn't stable without this), with each group's expand state from
/// `expanded` — a network missing from that map defaults to expanded, so
/// the sidebar starts fully open without having to pre-populate it.
///
/// Returns plain data, not yet a Slint model: this runs on the worker
/// thread, and `NetworkGroup`/`ChannelEntry` need a `ModelRc` (backed by
/// `Rc`, not `Send`) for the nested channel list — building that here
/// would make the plain data un-`Send`, and it has to cross into an
/// `upgrade_in_event_loop` closure to reach the UI thread. Pass this to
/// `network_groups_model` only from inside that closure.
fn network_groups_data(
    entries: &[(String, String, String)],
    expanded: &HashMap<String, bool>,
) -> Vec<NetworkGroupData> {
    let mut by_network: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for (network, channel, label) in entries {
        by_network
            .entry(network.clone())
            .or_default()
            .push((channel.clone(), label.clone()));
    }
    by_network
        .into_iter()
        .map(|(network, mut channels)| {
            channels.sort();
            let is_expanded = expanded.get(&network).copied().unwrap_or(true);
            (network, is_expanded, channels)
        })
        .collect()
}

/// Builds the actual sidebar `NetworkGroup` Slint model out of
/// `network_groups_data`'s plain grouping — must run on the UI thread,
/// see that function's doc comment for why.
fn network_groups_model(data: Vec<NetworkGroupData>) -> Vec<NetworkGroup> {
    data.into_iter()
        .map(|(network, expanded, channels)| {
            let channel_entries: Vec<ChannelEntry> = channels
                .into_iter()
                .map(|(channel, label)| ChannelEntry {
                    network: network.clone().into(),
                    channel: channel.into(),
                    label: label.into(),
                })
                .collect();
            NetworkGroup {
                network: network.into(),
                expanded,
                channels: Rc::new(slint::VecModel::from(channel_entries)).into(),
            }
        })
        .collect()
}

/// Pushes `state.channel_entries` + `state.expanded_networks` to the
/// sidebar as a fresh `network-groups` model — called after anything that
/// changes either (a network's expand toggle, a fresh connect).
fn refresh_network_groups(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let data = network_groups_data(&state.channel_entries, &state.expanded_networks);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let groups = network_groups_model(data);
        ui.set_network_groups(Rc::new(slint::VecModel::from(groups)).into());
    });
}

/// Converts one already mIRC-parsed line into the Slint `ChatLine` model,
/// mapping `cordiale_core::formatting::ColorSegment`'s abstract `(u8, u8,
/// u8)` into a real `slint::Color` only here — the core crate stays free
/// of any Slint dependency.
fn chat_line_from_raw(raw: &str) -> ChatLine {
    let segments: Vec<MessageSegment> = cordiale_core::formatting::parse_mirc_text(raw)
        .into_iter()
        .map(|segment| {
            let (has_color, color) = match segment.color {
                Some((r, g, b)) => (true, slint::Color::from_rgb_u8(r, g, b)),
                None => (false, slint::Color::from_rgb_u8(0, 0, 0)),
            };
            MessageSegment {
                text: segment.text.into(),
                has_color,
                color,
                bold: segment.bold,
            }
        })
        .collect();
    ChatLine {
        segments: Rc::new(slint::VecModel::from(segments)).into(),
    }
}

fn chat_lines_model(raw_lines: &[String]) -> Vec<ChatLine> {
    raw_lines
        .iter()
        .map(|line| chat_line_from_raw(line))
        .collect()
}

/// Reads a `slug -> id` map out of `boot.networks`, for WS commands that
/// need Grappa's integer `network_id` rather than the slug Cordiale uses
/// everywhere else (confirmed required — see `docs/protocol-notes.md`
/// §4ter). A network entry missing either field is skipped rather than
/// guessed: callers treat a missing id as "can't send this command for
/// that network" instead of sending a wrong one.
fn network_ids_from_boot(outcome: &BootstrapOutcome) -> HashMap<String, i64> {
    outcome
        .boot
        .networks
        .iter()
        .filter_map(|value| {
            let slug = value.get("slug").and_then(Value::as_str)?;
            let id = value.get("id").and_then(Value::as_i64)?;
            Some((slug.to_string(), id))
        })
        .collect()
}

fn load_remembered_server_url() -> String {
    persistence::load_servers_file()
        .ok()
        .and_then(|file| {
            file.selected_server_base_url
                .or_else(|| file.servers.first().map(|server| server.base_url.clone()))
        })
        .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string())
}

/// Remembers the last server URL the user tried, regardless of whether the
/// connection attempt succeeds — so it's pre-filled again next launch.
fn remember_server_url(server_url: &str) {
    let mut file = persistence::load_servers_file().unwrap_or_default();
    file.selected_server_base_url = Some(server_url.to_string());
    let _ = persistence::save_servers_file(&file);
}

/// Called only after a successful login: remembers the profile (never the
/// secret itself) in `servers.json`, and puts the secret in the
/// `CredentialStore` — never in the JSON file, see MEMORY.md §3.6. Also
/// remembers the server itself in `ServersFile.servers` — the quick-switch
/// list on the connect screen reads from there (see MEMORY.md §0sexies:
/// this field existed on disk already, nothing populated it until now).
///
/// Doesn't yet distinguish a password from a per-client token (the form
/// doesn't ask): always recorded as `AuthMethod::Password` for now.
fn remember_profile(server_url: &str, identifier: &str, secret: &str) {
    if let Ok(store) = resolve_credential_store() {
        let _ = store.set_secret(server_url, identifier, secret);
    }

    let mut file = persistence::load_servers_file().unwrap_or_default();

    if !file
        .servers
        .iter()
        .any(|server| server.base_url == server_url)
    {
        file.servers.push(cordiale_core::domain::Server {
            base_url: server_url.to_string(),
            label: server_url.to_string(),
        });
    }

    let already_known = file
        .profiles
        .iter()
        .any(|profile| profile.server_base_url == server_url && profile.identifier == identifier);
    if !already_known {
        file.profiles.push(Profile {
            server_base_url: server_url.to_string(),
            identifier: identifier.to_string(),
            auth_method: AuthMethod::Password,
            remembered: true,
        });
    }
    file.selected_profile_identifier = Some(identifier.to_string());
    let _ = persistence::save_servers_file(&file);
}

/// The base URLs of every server previously connected to successfully, for
/// the connect screen's quick-switch list.
fn known_servers_model() -> slint::ModelRc<slint::SharedString> {
    let file = persistence::load_servers_file().unwrap_or_default();
    let urls: Vec<slint::SharedString> = file
        .servers
        .into_iter()
        .map(|server| server.base_url.into())
        .collect();
    Rc::new(slint::VecModel::from(urls)).into()
}

/// Pre-fills the identifier and, if the `CredentialStore` has it, the
/// secret for the last remembered profile on `server_url` — a convenience
/// auto-fill, not an auto-connect.
fn prefill_remembered_profile(ui: &AppWindow, server_url: &str) {
    let file = persistence::load_servers_file().unwrap_or_default();
    let Some(profile) = file
        .profiles
        .iter()
        .find(|profile| profile.server_base_url == server_url && profile.remembered)
    else {
        return;
    };

    ui.set_identifier(profile.identifier.clone().into());

    if let Ok(store) = resolve_credential_store() {
        if let Ok(Some(secret)) = store.get_secret(server_url, &profile.identifier) {
            ui.set_password(secret.into());
        }
    }
}

fn language_from_code(code: &str) -> Option<persistence::Language> {
    match code {
        "en" => Some(persistence::Language::En),
        "it" => Some(persistence::Language::It),
        "fr" => Some(persistence::Language::Fr),
        "de" => Some(persistence::Language::De),
        "es" => Some(persistence::Language::Es),
        _ => None,
    }
}

/// The bundled-translation directory name for a language — matches the
/// `crates/cordiale-ui/lang/<code>/LC_MESSAGES/cordiale-ui.po` layout.
/// English has no `.po` file: it's the untranslated source text, and
/// `select_bundled_translation` is simply never called for it.
fn language_code(language: persistence::Language) -> &'static str {
    match language {
        persistence::Language::En => "en",
        persistence::Language::It => "it",
        persistence::Language::Fr => "fr",
        persistence::Language::De => "de",
        persistence::Language::Es => "es",
    }
}

fn theme_to_slint(theme: Theme) -> slint::SharedString {
    match theme {
        Theme::Light => "light".into(),
        Theme::Dark => "dark".into(),
    }
}

/// The current calendar year, for Settings > Credits' copyright line.
/// Approximated from the Unix clock using the average Gregorian year
/// length — no `chrono` dependency needed for a value only ever shown to
/// a human, and the average-year approximation can be off by at most a
/// fraction of a day around a year boundary, never a whole year.
fn current_year() -> i32 {
    const SECONDS_PER_YEAR: f64 = 365.2425 * 86_400.0;
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    1970 + (seconds as f64 / SECONDS_PER_YEAR) as i32
}

/// Sets `status-kind` (and `status-protocol-version` where needed) so
/// `appwindow.slint`'s `status-text()` can render a translated message —
/// this function never produces English text itself, only a machine-
/// readable key, per MEMORY.md §0septies.
fn apply_bootstrap_error(ui: &AppWindow, err: &BootstrapError) {
    match err {
        BootstrapError::IncompatibleServer(compat) => {
            ui.set_status_kind("protocol-too-old".into());
            ui.set_status_protocol_version(compat.protocol_version as i32);
        }
        BootstrapError::Config(_) => {
            ui.set_status_kind("unreachable".into());
        }
        BootstrapError::Login(LoginError::InvalidCredentials) => {
            ui.set_status_kind("wrong-credentials".into());
        }
        BootstrapError::Login(LoginError::TwoFactorRequired) => {
            ui.set_status_kind("two-factor-required".into());
        }
        BootstrapError::Login(LoginError::TooManyAttempts) => {
            ui.set_status_kind("too-many-attempts".into());
        }
        BootstrapError::Login(_) => {
            ui.set_status_kind("login-failed".into());
        }
        BootstrapError::Boot(_) | BootstrapError::Me(_) => {
            ui.set_status_kind("boot-me-failed".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_year_is_in_a_sane_range() {
        // Not pinned to an exact year (the test suite outlives any single
        // year): just guards against a unit mixup collapsing everything
        // to 1970 or overflowing wildly.
        let year = current_year();
        assert!((2020..2100).contains(&year));
    }

    #[test]
    fn channel_topic_has_the_documented_shape() {
        assert_eq!(
            channel_topic("vjt", "libera", "#rust"),
            "grappa:user:vjt/network:libera/channel:#rust"
        );
    }

    #[test]
    fn channel_from_topic_round_trips_a_channel_topic() {
        let topic = channel_topic("vjt", "libera", "#rust");
        assert_eq!(
            channel_from_topic(&topic),
            Some(("libera".to_string(), "#rust".to_string()))
        );
    }

    #[test]
    fn channel_from_topic_rejects_the_user_topic() {
        assert_eq!(channel_from_topic("grappa:user:vjt"), None);
    }

    #[test]
    fn normalize_server_url_strips_a_trailing_slash() {
        assert_eq!(
            normalize_server_url("https://irc.sythos.dev/"),
            "https://irc.sythos.dev"
        );
    }

    #[test]
    fn normalize_server_url_strips_whitespace_and_multiple_slashes() {
        assert_eq!(
            normalize_server_url("  https://irc.sythos.dev//  "),
            "https://irc.sythos.dev"
        );
    }

    #[test]
    fn normalize_server_url_leaves_a_clean_url_untouched() {
        assert_eq!(
            normalize_server_url("https://irc.sindro.me"),
            "https://irc.sindro.me"
        );
    }

    #[test]
    fn normalize_server_url_adds_a_missing_https_scheme() {
        assert_eq!(
            normalize_server_url("irc.sythos.dev"),
            "https://irc.sythos.dev"
        );
    }

    #[test]
    fn normalize_server_url_leaves_an_explicit_http_scheme_alone() {
        assert_eq!(
            normalize_server_url("http://irc.sythos.dev"),
            "http://irc.sythos.dev"
        );
    }

    #[test]
    fn to_ws_url_upgrades_https_to_wss() {
        assert_eq!(
            to_ws_url("https://irc.sindro.me"),
            "wss://irc.sindro.me/socket/websocket?vsn=2.0.0"
        );
    }

    #[test]
    fn to_ws_url_upgrades_http_to_ws() {
        assert_eq!(
            to_ws_url("http://localhost:4000"),
            "ws://localhost:4000/socket/websocket?vsn=2.0.0"
        );
    }
}
