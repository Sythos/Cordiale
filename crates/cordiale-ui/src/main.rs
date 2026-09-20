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

use serde_json::{Number, Value};
use tokio::sync::mpsc;

use cordiale_core::bootstrap::{
    bootstrap, bootstrap_with_bearer, BootstrapError, BootstrapOutcome,
};
use cordiale_core::client::{GrappaClient, LoginError};
use cordiale_core::credentials::resolve_credential_store;
use cordiale_core::domain::{AuthMethod, Profile};
use cordiale_core::persistence::{self, Theme};
use cordiale_core::rest::{DisplayPrefs, LoginRequest, SendMessageRequest};
use cordiale_core::session::{spawn_session, SessionEvent, SessionHandle};
use cordiale_core::wire_event::ClientEventKind;

/// The default server offered on first launch.
const DEFAULT_SERVER_URL: &str = "https://irc.sindro.me";

/// Everything the UI thread can ask the background worker to do. Sent over
/// a plain `tokio::sync::mpsc` channel whose sender is a normal, non-async
/// value — callbacks fire on the UI thread and just call `.send()`.
enum WorkerCommand {
    Connect {
        server_url: String,
        identifier: String,
        credential: ConnectCredential,
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
    GoHome,
    MemberModeAction {
        verb: String,
        nick: String,
    },
    MemberKick(String),
    MemberBan(String),
    MemberWhois(String),
    MemberCtcp {
        nick: String,
        verb: String,
    },
    MemberQuery(String),
}

/// The authentication action the user explicitly chose on the connect
/// screen. An empty form value is always the guest path; saved bearers are
/// used only through the separate saved-profile action.
enum ConnectCredential {
    FormValue(String),
    SavedProfile,
}

impl ConnectCredential {
    fn is_guest_attempt(&self) -> bool {
        matches!(self, Self::FormValue(value) if value.is_empty())
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

    // Settings > Credits: Cordiale's own info only, never a list of
    // Grappa/Cicchetto's contributors — explicit project-owner
    // requirement.
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
    ui.invoke_apply_color_scheme();
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
            ui.set_saved_profile_identifier("".into());
            ui.set_saved_profile_server_url("".into());
            prefill_remembered_profile(&ui, &server_url);
        }
    });

    let tx_for_connect = worker_tx.clone();
    let weak_for_connect = ui.as_weak();
    ui.on_connect_requested(move |server_url, identifier, password| {
        let server_url = normalize_server_url(&server_url);
        if let Some(ui) = weak_for_connect.upgrade() {
            ui.set_server_url(server_url.clone().into());
            ui.set_connecting(true);
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
        }
        let _ = tx_for_connect.send(WorkerCommand::Connect {
            server_url: server_url.to_string(),
            identifier: identifier.to_string(),
            credential: ConnectCredential::FormValue(password.to_string()),
        });
    });

    let tx_for_saved_profile = worker_tx.clone();
    let weak_for_saved_profile = ui.as_weak();
    ui.on_saved_profile_connect_requested(move |server_url, identifier| {
        let server_url = normalize_server_url(&server_url);
        if let Some(ui) = weak_for_saved_profile.upgrade() {
            ui.set_server_url(server_url.clone().into());
            ui.set_connecting(true);
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
        }
        let _ = tx_for_saved_profile.send(WorkerCommand::Connect {
            server_url: server_url.to_string(),
            identifier: identifier.to_string(),
            credential: ConnectCredential::SavedProfile,
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
            let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
            ui.set_channel_members(empty_members.into());
            ui.set_current_topic("".into());
            ui.set_current_window_is_joined(false);
            ui.set_has_selected_channel(false);
            ui.set_can_moderate_members(false);
        }
    });

    let tx_for_home = worker_tx.clone();
    let weak_for_home = ui.as_weak();
    ui.on_home_requested(move || {
        let _ = tx_for_home.send(WorkerCommand::GoHome);
        if let Some(ui) = weak_for_home.upgrade() {
            ui.set_screen("connected".into());
            let empty_lines = Rc::new(slint::VecModel::from(Vec::<ChatLine>::new()));
            ui.set_chat_lines(empty_lines.into());
            let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
            ui.set_channel_members(empty_members.into());
            ui.set_current_topic("".into());
            ui.set_current_channel_label("".into());
            ui.set_current_window_is_joined(false);
            ui.set_has_selected_channel(false);
            ui.set_can_moderate_members(false);
        }
    });

    let tx_for_mode_action = worker_tx.clone();
    ui.on_member_mode_action_requested(move |verb, nick| {
        let _ = tx_for_mode_action.send(WorkerCommand::MemberModeAction {
            verb: verb.to_string(),
            nick: nick.to_string(),
        });
    });

    let tx_for_kick = worker_tx.clone();
    ui.on_member_kick_requested(move |nick| {
        let _ = tx_for_kick.send(WorkerCommand::MemberKick(nick.to_string()));
    });

    let tx_for_ban = worker_tx.clone();
    ui.on_member_ban_requested(move |nick| {
        let _ = tx_for_ban.send(WorkerCommand::MemberBan(nick.to_string()));
    });

    let tx_for_whois = worker_tx.clone();
    ui.on_member_whois_requested(move |nick| {
        let _ = tx_for_whois.send(WorkerCommand::MemberWhois(nick.to_string()));
    });

    let tx_for_ctcp = worker_tx.clone();
    ui.on_member_ctcp_requested(move |nick, verb| {
        let _ = tx_for_ctcp.send(WorkerCommand::MemberCtcp {
            nick: nick.to_string(),
            verb: verb.to_string(),
        });
    });

    let tx_for_query = worker_tx.clone();
    ui.on_member_query_requested(move |nick| {
        let _ = tx_for_query.send(WorkerCommand::MemberQuery(nick.to_string()));
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChannelWindowState {
    Joined,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowFailure {
    reason: Option<String>,
    numeric: Option<Number>,
}

struct WorkerState {
    client: Option<GrappaClient>,
    token: Option<String>,
    identifier: Option<String>,
    session: Option<SessionHandle>,
    joined_topics: std::collections::HashSet<String>,
    /// Cicchetto's `windowStateByChannel` projection for supported lifecycle
    /// transitions.
    window_states: HashMap<(String, String), ChannelWindowState>,
    /// Nullable failure metadata is retained like Cicchetto but not shown in
    /// the channel row.
    window_failures: HashMap<(String, String), WindowFailure>,
    /// Invitation markers are cleared by terminal window transitions. The
    /// invitation event itself remains unsupported until its own parity step.
    invited_by: HashMap<(String, String), String>,
    /// Keyed by `(network, channel)`; holds messages already rendered for
    /// that channel so switching channels doesn't lose history.
    messages: MessagesByChannel,
    /// Keyed by `(network, channel)`; an unsent compose draft per channel,
    /// mirroring Cicchetto's own per-channel drafts (confirmed by the
    /// Grappa/Cicchetto maintainer) so switching channels doesn't lose or
    /// leak what's half-typed.
    drafts: HashMap<(String, String), String>,
    /// Keyed by `(network, channel)`; the channel topic, if the server sent
    /// one — see `topics_from_boot` and `handle_frame`.
    topics: HashMap<(String, String), String>,
    /// Keyed by `(network, channel)`; the member list from `boot`, if any
    /// was found — see `members_from_boot`. Snapshot only: unlike
    /// messages/topic, this doesn't update live on join/part yet (a known
    /// gap, see README).
    members: MembersByChannel,
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
    /// Current app theme, kept here too (not just in Slint's `theme`
    /// property) so message-rendering helpers running on this thread can
    /// pick a legible color without an extra hop to the UI thread.
    theme: Theme,
}

impl WorkerState {
    fn new() -> Self {
        WorkerState {
            client: None,
            token: None,
            identifier: None,
            session: None,
            joined_topics: std::collections::HashSet::new(),
            window_states: HashMap::new(),
            window_failures: HashMap::new(),
            invited_by: HashMap::new(),
            messages: HashMap::new(),
            drafts: HashMap::new(),
            topics: HashMap::new(),
            members: HashMap::new(),
            expanded_networks: HashMap::new(),
            channel_entries: Vec::new(),
            current_channel: None,
            network_ids: HashMap::new(),
            settings_network: None,
            notify_nicks: Vec::new(),
            watch_patterns: Vec::new(),
            theme: persistence::load_settings().unwrap_or_default().theme,
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
                    Some(WorkerCommand::Connect { server_url, identifier, credential }) => {
                        handle_connect(
                            &mut state,
                            &mut session_events,
                            &ui,
                            server_url,
                            identifier,
                            credential,
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
                        handle_toggle_theme(&mut state, &ui);
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
                    Some(WorkerCommand::GoHome) => {
                        state.current_channel = None;
                    }
                    Some(WorkerCommand::MemberModeAction { verb, nick }) => {
                        send_member_mode_action(&state, &verb, &nick);
                    }
                    Some(WorkerCommand::MemberKick(nick)) => {
                        send_member_kick(&state, &nick);
                    }
                    Some(WorkerCommand::MemberBan(nick)) => {
                        send_member_ban(&state, &nick);
                    }
                    Some(WorkerCommand::MemberWhois(nick)) => {
                        send_member_whois(&state, &nick);
                    }
                    Some(WorkerCommand::MemberCtcp { nick, verb }) => {
                        handle_member_ctcp(&state, &ui, nick, verb).await;
                    }
                    Some(WorkerCommand::MemberQuery(nick)) => {
                        send_member_query(&state, &nick);
                    }
                }
            }

            event = next_event => {
                match event {
                    Some(SessionEvent::Connected { protocol_version }) => {
                        persistence::log_line(&format!(
                            "session connected, protocol_version={protocol_version:?}"
                        ));
                        // Without this, a status set to "disconnected" or
                        // "reconnecting" by an earlier drop just sits
                        // there forever once the session actually comes
                        // back — nothing else ever clears it.
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_status_kind("signed-in".into());
                            ui.set_status_message("".into());
                        });
                    }
                    Some(SessionEvent::Frame(frame)) => {
                        handle_frame(&mut state, &ui, frame);
                    }
                    Some(SessionEvent::Disconnected { reason }) => {
                        persistence::log_line(&format!("session disconnected: {reason}"));
                        let _ = ui.upgrade_in_event_loop(move |ui| {
                            ui.set_status_kind("disconnected".into());
                            ui.set_status_message(reason.into());
                        });
                    }
                    Some(SessionEvent::Reconnecting { reason }) => {
                        persistence::log_line(&format!("session reconnecting: {reason}"));
                        let _ = ui.upgrade_in_event_loop(move |ui| {
                            ui.set_status_kind("reconnecting".into());
                            ui.set_status_message(reason.into());
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
    credential: ConnectCredential,
) {
    let server_url = normalize_server_url(&server_url);
    remember_server_url(&server_url);

    let client = GrappaClient::new(server_url.clone());
    let is_guest_attempt = credential.is_guest_attempt();
    let result = match credential {
        ConnectCredential::FormValue(password) => {
            // Older releases stored the entered password/client token in
            // the credential store. Drop that legacy value; only a bearer
            // returned by a successful login may be persisted now.
            discard_legacy_profile_secret(&server_url, &identifier);

            let (login_identifier, login_password) = if is_guest_attempt {
                // A blank Connect action is unconditionally guest, even if
                // the username field is prefilled with a remembered profile.
                ("guest".to_string(), "guest".to_string())
            } else {
                (identifier.clone(), password)
            };
            persistence::log_line(&format!(
                "connect attempt: server={server_url} identifier={login_identifier} \
                 guest={is_guest_attempt} auth=password_or_guest"
            ));
            let request = LoginRequest {
                identifier: login_identifier,
                password: login_password,
            };
            bootstrap(&client, &request).await
        }
        ConnectCredential::SavedProfile => {
            let bearer = match remembered_profile_credential(&server_url, &identifier) {
                RememberedProfileCredential::Bearer(bearer) => bearer,
                RememberedProfileCredential::None
                | RememberedProfileCredential::NeedsReauthentication => {
                    persistence::log_line(&format!(
                        "saved profile unavailable: server={server_url} identifier={identifier}"
                    ));
                    show_reauthentication_required(ui);
                    return;
                }
            };

            persistence::log_line(&format!(
                "connect attempt: server={server_url} identifier={identifier} \
                 guest=false auth=saved_bearer"
            ));
            let result = bootstrap_with_bearer(&client, &bearer).await;
            if matches!(&result, Err(BootstrapError::BearerRejected)) {
                forget_remembered_bearer(&server_url, &identifier);
                persistence::log_line(&format!(
                    "saved bearer rejected: server={server_url} identifier={identifier}"
                ));
                show_reauthentication_required(ui);
                return;
            }
            result
        }
    };

    match result {
        Ok(outcome) => {
            persistence::log_line(&format!("connect succeeded: server={server_url}"));
            if !is_guest_attempt {
                remember_profile(&server_url, &identifier, &outcome.token);
            }
            let saved_profile = if is_guest_attempt {
                // Guest sign-in does not alter any remembered profile.
                None
            } else if matches!(
                remembered_profile_credential(&server_url, &identifier),
                RememberedProfileCredential::Bearer(_)
            ) {
                Some((identifier.clone(), server_url.clone()))
            } else {
                Some((String::new(), String::new()))
            };

            let entries = channel_entries_from_boot(&outcome);
            state.channel_entries = entries.clone();
            state.window_states = joined_window_states_from_boot_channels(&outcome.boot.channels);
            state.window_failures.clear();
            state.invited_by.clear();
            state.topics = topics_from_boot(&outcome);
            state.members = members_from_boot(&outcome);
            state.messages = messages_from_boot(&outcome);
            state.network_ids = network_ids_from_boot(&outcome);
            // The Grappa login `subject` is opaque (and absent when reusing
            // a bearer); admin status comes only from the separate `/me`
            // response, where it is a top-level field.
            let is_admin = outcome.me.is_admin;
            let token = outcome.token.clone();
            // Guest login always sends the fixed server-confirmed identifier
            // "guest"; never derive its user-topic name from arbitrary text
            // left in the username field.
            let session_identifier = if is_guest_attempt {
                "guest".to_string()
            } else {
                identifier.clone()
            };

            let ws_url = to_ws_url(&server_url);
            let (handle, events) = spawn_session(ws_url, token.clone(), session_identifier.clone());
            for entry in &entries {
                handle.join_topic(channel_topic(&session_identifier, &entry.0, &entry.1), true);
            }
            *session_events = Some(events);

            state.client = Some(client);
            state.token = Some(token.clone());
            state.identifier = Some(session_identifier.clone());
            state.session = Some(handle);
            state.joined_topics = entries
                .iter()
                .map(|(network, channel, _)| channel_topic(&session_identifier, network, channel))
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
            let window_states = state.window_states.clone();
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_connecting(false);
                ui.set_is_admin(is_admin);
                if let Some((saved_identifier, saved_server_url)) = saved_profile {
                    ui.set_saved_profile_identifier(saved_identifier.into());
                    ui.set_saved_profile_server_url(saved_server_url.into());
                }
                ui.set_known_servers(known_servers_model());
                ui.set_screen("connected".into());
                ui.set_status_kind("signed-in".into());
                ui.set_status_network_count(network_count as i32);
                ui.set_status_channel_count(channel_count as i32);
                let networks: Vec<slint::SharedString> =
                    distinct_networks.into_iter().map(Into::into).collect();
                ui.set_known_networks(Rc::new(slint::VecModel::from(networks)).into());
                let groups = network_groups_model(groups_data, window_states);
                ui.set_network_groups(Rc::new(slint::VecModel::from(groups)).into());
            });

            // Drops the user back on the bare network overview after
            // every reconnect otherwise, even mid-conversation — only
            // restores a channel still actually joined this session
            // (`entries`), never a stale one from a since-parted channel.
            let restore_channel = persistence::load_settings()
                .unwrap_or_default()
                .last_channel
                .filter(|(network, channel)| {
                    entries.iter().any(|(n, c, _)| n == network && c == channel)
                });
            if let Some((network, channel)) = restore_channel {
                handle_select_channel(state, &ui, network, channel).await;
            }
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

    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.last_channel = Some(key.clone());
    let _ = persistence::save_settings(&settings);

    let lines = state.messages.get(&key).cloned().unwrap_or_default();
    let draft = state.drafts.get(&key).cloned().unwrap_or_default();
    let irc_topic = state.topics.get(&key).cloned().unwrap_or_default();
    let members = state.members.get(&key).cloned().unwrap_or_default();
    let window_is_joined = state
        .window_states
        .get(&window_state_key(&network, &channel))
        == Some(&ChannelWindowState::Joined);
    let can_moderate = is_own_nick_an_op(&members, &identifier);
    let dark_theme = state.theme == Theme::Dark;

    let label = format!("{network} — {channel}");
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_channel_label(label.into());
        ui.set_current_topic(irc_topic.into());
        ui.set_current_window_is_joined(window_is_joined);
        ui.set_has_selected_channel(true);
        ui.set_compose_text(draft.into());
        ui.set_can_moderate_members(can_moderate);
        let model = chat_lines_model(&lines, dark_theme);
        ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        let member_rows = members_model(&members, dark_theme);
        ui.set_channel_members(Rc::new(slint::VecModel::from(member_rows)).into());
    });
}

/// Whether `identifier` appears in `members` with the `@` (op) prefix —
/// gates `MemberContextMenu`'s Op/Deop/Voice/Devoice/Kick/Ban items. Only
/// ever as accurate as `members` itself, which doesn't track role
/// (mode) changes yet — see README's Known gaps.
fn is_own_nick_an_op(members: &[MemberEntry], identifier: &str) -> bool {
    members
        .iter()
        .any(|(name, prefix)| name == identifier && prefix == "@")
}

async fn handle_send_message(state: &WorkerState, ui: &slint::Weak<AppWindow>, body: String) {
    let (Some(client), Some(token), Some((network, channel))) =
        (&state.client, &state.token, &state.current_channel)
    else {
        return;
    };

    // `/links` isn't a chat message: it asks for the active server's
    // topology graph, same request the old per-network sidebar button
    // used to send — moved here since a button per connected network
    // doesn't scale (the user may have a dozen networks joined at once).
    if body.trim() == "/links" {
        handle_request_links(state, network.clone());
        return;
    }

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

fn handle_toggle_theme(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.theme = match settings.theme {
        Theme::Light => Theme::Dark,
        Theme::Dark => Theme::Light,
    };
    let _ = persistence::save_settings(&settings);

    let new_theme = settings.theme;
    state.theme = new_theme;

    // Re-render the currently open channel's history too: an mIRC-colored
    // message that was legible a moment ago (see `ensure_legible`) can
    // stop being legible the instant the background flips, and shouldn't
    // have to wait for a channel reselect to catch up.
    let current_lines = state
        .current_channel
        .as_ref()
        .and_then(|key| state.messages.get(key))
        .cloned();

    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_theme(theme_to_slint(new_theme));
        ui.invoke_apply_color_scheme();
        if let Some(lines) = current_lines {
            let model = chat_lines_model(&lines, new_theme == Theme::Dark);
            ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        }
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

/// Shared setup for every `MemberContextMenu` action below: the session,
/// the user topic to send on (every one of these actions is a push on
/// `grappa:user:{user}`, never the channel topic — confirmed against
/// Cicchetto's own `lib/socket.ts`/`UserContextMenu.tsx`, not guessed),
/// the currently-open channel's Grappa `network_id`, and its slug. `None`
/// whenever any piece is missing (no session, no channel open, or the
/// network's id hasn't been resolved yet) — every caller just does
/// nothing in that case, same as `handle_request_links` already does.
fn user_topic_channel_network(state: &WorkerState) -> Option<(&SessionHandle, String, i64, &str)> {
    let session = state.session.as_ref()?;
    let identifier = state.identifier.as_ref()?;
    let (network, channel) = state.current_channel.as_ref()?;
    let network_id = *state.network_ids.get(network)?;
    Some((
        session,
        format!("grappa:user:{identifier}"),
        network_id,
        channel.as_str(),
    ))
}

/// Op/Deop/Voice/Devoice — `verb` is one of those four, sent verbatim as
/// the Phoenix event name. Wire shape confirmed from Cicchetto's
/// `pushChannelOp`/`pushChannelDeop`/`pushChannelVoice`/
/// `pushChannelDevoice`, which all funnel through the same
/// `pushUserChannelVerb` helper: `nicks` is an array even for a single
/// target.
fn send_member_mode_action(state: &WorkerState, verb: &str, nick: &str) {
    let Some((session, topic, network_id, channel)) = user_topic_channel_network(state) else {
        return;
    };
    session.send_command(
        topic,
        verb,
        serde_json::json!({ "network_id": network_id, "channel": channel, "nicks": [nick] }),
    );
}

/// No reason prompt yet — Cicchetto's own UserContextMenu doesn't collect
/// one either (`pushChannelKick(networkId, channel, nick, reason)` is
/// called with an empty string from that same menu).
fn send_member_kick(state: &WorkerState, nick: &str) {
    let Some((session, topic, network_id, channel)) = user_topic_channel_network(state) else {
        return;
    };
    session.send_command(
        topic,
        "kick",
        serde_json::json!({
            "network_id": network_id,
            "channel": channel,
            "nick": nick,
            "reason": "",
        }),
    );
}

/// `{nick}!*@*` matches Cicchetto's own fallback mask (it prefers a
/// WHOIS-derived host mask when available, a gap it documents itself —
/// Cordiale doesn't have a WHOIS-derived mask to prefer either, so this
/// only ever sends the fallback shape).
fn send_member_ban(state: &WorkerState, nick: &str) {
    let Some((session, topic, network_id, channel)) = user_topic_channel_network(state) else {
        return;
    };
    let mask = format!("{nick}!*@*");
    session.send_command(
        topic,
        "ban",
        serde_json::json!({ "network_id": network_id, "channel": channel, "mask": mask }),
    );
}

/// `source: "user"` matches Cicchetto's own default (the alternative,
/// `"rail"`, isn't something Cordiale has a UI path to trigger from).
fn send_member_whois(state: &WorkerState, nick: &str) {
    let Some((session, topic, network_id, _channel)) = user_topic_channel_network(state) else {
        return;
    };
    session.send_command(
        topic,
        "whois",
        serde_json::json!({
            "network_id": network_id,
            "nick": nick,
            "server": Value::Null,
            "source": "user",
        }),
    );
}

/// Asks Grappa to open a DM window with `nick` — the server owns that
/// state (broadcasts `query_windows_list` back per Cicchetto's source);
/// Cordiale doesn't have a query-window UI to react to that yet, so this
/// is currently fire-and-forget rather than switching to one.
fn send_member_query(state: &WorkerState, nick: &str) {
    let Some((session, topic, network_id, _channel)) = user_topic_channel_network(state) else {
        return;
    };
    session.send_command(
        topic,
        "open_query_window",
        serde_json::json!({ "network_id": network_id, "target_nick": nick }),
    );
}

/// The one action here that isn't a WS push: Cicchetto sends CTCP
/// queries as a normal REST message post with `ctcp_target` set, not a
/// Phoenix event (confirmed from `lib/ctcpQuery.ts` + `lib/api.ts`).
async fn handle_member_ctcp(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    nick: String,
    verb: String,
) {
    let (Some(client), Some(token), Some((network, channel))) =
        (&state.client, &state.token, &state.current_channel)
    else {
        return;
    };
    let request = SendMessageRequest::ctcp(nick, &verb, None);
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

/// Real kinds Grappa pushes to a regular (non-admin) user that Cordiale
/// has no UI for yet — window-state transitions, ISUPPORT/umode/identity
/// bookkeeping, DCC offers, WHOIS/WHOWAS/LUSERS/banlist/directory bundles,
/// network-attach lifecycle, MONITOR/WATCH presence, the notify list,
/// per-server settings, and more. Exhaustive as of this date: audited
/// directly from the real server source (`session/wire.ex`'s
/// `@type wire_event_kind` union — the authoritative closed set — plus
/// every other non-admin `*/wire.ex` module in vjt/grappa-irc), not
/// grepped or guessed. Per `docs/CLIENT_PROTOCOL.md` §4's own policy
/// ("treat unknown `kind` values as ignorable"), these are dropped
/// silently rather than shown as a raw dump. Deliberately excludes
/// `"parted"`: two comments in the real
/// server source (`session/server.ex`, `session/window_state.ex`) state
/// there is intentionally no such broadcast — a self-part is signaled by
/// the window disappearing from window-state, not a push, so listening
/// for it here would be dead code matching nothing.
const IGNORED_KINDS: &[&str] = &[
    // Known from vjt/grappa-irc#2260 or the wire union (joined, join_failed,
    // topic_changed, and members_seeded/names_reply are handled above).
    "channel_modes_changed",
    "read_cursor_set",
    "window_counts",
    "away_confirmed",
    "bundle_hash",
    "query_windows_list",
    // session/wire.ex's wire_event_kind union.
    "channels_changed",
    "own_nick_changed",
    "isupport_changed",
    "umode_changed",
    "session_identity_changed",
    "supported_umodes_changed",
    "channel_created",
    "who_reply",
    "server_reply",
    "window_pending",
    "window_invited",
    "window_invite_declined",
    "dcc_offer",
    "dcc_offer_resolved",
    "kicked",
    "mentions_bundle",
    "whois_bundle",
    "whois_avatar_ready",
    "peer_away",
    "invite_ack",
    "lusers_bundle",
    "whowas_bundle",
    "banlist_bundle",
    "directory_progress",
    "directory_complete",
    "directory_failed",
    "connection_progress",
    "recover_progress",
    "recover_result",
    "presence_changed",
    "presence_error",
    "presence_snapshot",
    // scrollback/wire.ex.
    "archive_changed",
    "archive_purged",
    // networks/wire.ex.
    "network_detached",
    "network_attached",
    "connection_state_changed",
    // user_settings/wire.ex.
    "auto_away_debounce_changed",
    "quit_part_reason_changed",
    "auto_away_reason_changed",
    // rate_limit/wire.ex.
    "web_session_severed",
    // notify/wire.ex.
    "notify_list",
    // server_settings/wire.ex.
    "server_settings_changed",
];

/// Appends an incoming realtime frame to the channel it belongs to (if any)
/// and, if that channel is currently open, pushes the update to the UI.
///
/// Kinds Grappa's own `docs/CLIENT_PROTOCOL.md` documents as real but
/// Cordiale has no use for yet (window-state/administrative pushes) are
/// dropped without rendering anything, per that doc's own policy on
/// unrecognized kinds (§4). A kind genuinely unknown to both the doc and
/// this function still falls back to a raw `event: payload` line — the
/// mechanism that caught the ones now handled by name below, via real user
/// screenshots.
fn handle_frame(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    frame: cordiale_core::phoenix::PhoenixMessage,
) {
    // The `kind:` field is the real discriminator for these server-push
    // "bundle" replies per `docs/protocol-notes.md` §4ter — the Phoenix
    // `event` name itself isn't confirmed to equal the bundle name, so
    // this checks both rather than betting on one interpretation.
    let Some(event_kind) = ClientEventKind::from_payload(&frame.payload) else {
        // Grappa explicitly requires unknown event kinds to be ignored for
        // forward compatibility. Never turn an unrecognized event payload
        // into a raw JSON chat line.
        return;
    };
    let payload_kind = event_kind.as_wire_name();
    if frame.event == "links_bundle" || payload_kind == "links_bundle" {
        handle_links_bundle(ui, &frame.payload);
        return;
    }

    // Grappa doesn't use Phoenix Presence (`presence_state`/`presence_diff`)
    // — confirmed by reading Cicchetto's actual source
    // (`cicchetto/src/lib/subscribe.ts`). The full initial roster instead
    // arrives as this one-shot event, fired after a channel join and on
    // every real `366 RPL_ENDOFNAMES`; carries its own `network`/`channel`
    // fields so it's handled here rather than through `channel_from_topic`,
    // matching `links_bundle` above (may not even arrive on a channel
    // topic). Without this, the member list only ever grows through
    // incremental join/part/nick_change frames and starts empty for every
    // channel that already had people in it before Cordiale connected.
    if payload_kind == "members_seeded" {
        match apply_members_seeded(state, &frame.payload) {
            Some(key) => {
                let count = state.members.get(&key).map(Vec::len).unwrap_or(0);
                persistence::log_line(&format!(
                    "members_seeded applied: {}/{} -> {count} member(s)",
                    key.0, key.1
                ));
                if state.current_channel.as_ref() == Some(&key) {
                    push_members_update(state, ui, &key);
                }
            }
            // Confirms the event arrives but this server's actual field
            // names differ from Cicchetto's (`network`/`channel`/`members`
            // with each member `{nick, modes}`) — logged instead of
            // guessed again; the payload is safe to log verbatim, it never
            // carries credentials.
            None => {
                persistence::log_line(&format!(
                    "members_seeded frame didn't match the expected shape: {}",
                    frame.payload
                ));
            }
        }
        return;
    }

    // Confirmed real (not a guess): a chat row doesn't arrive as a flat
    // `kind: "privmsg"`/`"notice"` object the way a `boot.heads` history
    // row does — it's nested one level deeper, under a `kind: "message"`
    // envelope (`{"kind": "message", "message": {"kind": "privmsg", ...}}`).
    // Every frame this session before now was read straight off
    // `frame.payload`, so every live chat message fell through to the raw
    // dump fallback (`sender`/`body` both absent at the top level) — the
    // WebSocket connection itself never even succeeding until now meant
    // this had no chance to be noticed until a real user screenshot
    // showed the literal envelope shape.
    let effective_payload: &Value = if payload_kind == "message" {
        match frame.payload.get("message") {
            Some(inner) => inner,
            None => return,
        }
    } else {
        &frame.payload
    };

    if payload_kind == "topic_changed" {
        handle_topic_changed(state, ui, &frame.payload);
        return;
    }

    // `names_reply` carries the exact same shape as `members_seeded`
    // (`{network, channel, members: [{nick, modes}]}`) — another real
    // source for the initial roster, confirmed by reading
    // `session/wire.ex` directly (not the same code path as
    // `members_seeded`, but the payload contract matches byte for byte).
    if payload_kind == "names_reply" {
        if let Some(key) = apply_members_seeded(state, &frame.payload) {
            if state.current_channel.as_ref() == Some(&key) {
                push_members_update(state, ui, &key);
            }
        }
        return;
    }

    // A successful join is broadcast on the user topic and replayed as a
    // cold snapshot on a subscribed channel topic. Both paths carry the
    // same typed payload; accepting only the matching topic keeps a stale or
    // unrelated frame from adding another channel, while the upsert below
    // makes dual delivery idempotent (Cicchetto's setJoined semantics).
    if payload_kind == "joined" {
        let Some(identifier) = state.identifier.as_deref() else {
            return;
        };
        let Some((network, channel)) = parse_joined_event(&frame.payload, &frame.topic, identifier)
        else {
            return;
        };
        let state_changed = set_joined_window_state(
            &mut state.window_states,
            &mut state.window_failures,
            &mut state.invited_by,
            &network,
            &channel,
        );
        let selected_window_joined =
            state
                .current_channel
                .as_ref()
                .is_some_and(|(current_network, current_channel)| {
                    window_state_key(current_network, current_channel)
                        == window_state_key(&network, &channel)
                });
        let sidebar_changed =
            upsert_channel_entry(&mut state.channel_entries, network.clone(), channel.clone());
        if selected_window_joined {
            let ui = ui.clone();
            let _ = ui.upgrade_in_event_loop(|ui| ui.set_current_window_is_joined(true));
        }
        if state_changed || sidebar_changed {
            refresh_network_groups(state, ui);
        }
        return;
    }

    // A rejected join is also a window-state transition: Cicchetto applies
    // it on the user topic and as a channel-topic reconnect snapshot. Keep a
    // faded pseudo-row, but never show a roster for a failed window. The
    // nullable reason/numeric stay in the session store only.
    if payload_kind == "join_failed" {
        let Some(identifier) = state.identifier.as_deref() else {
            return;
        };
        let Some((network, channel, failure)) =
            parse_join_failed_event(&frame.payload, &frame.topic, identifier)
        else {
            return;
        };

        let state_changed = set_failed_window_state(
            &mut state.window_states,
            &mut state.window_failures,
            &mut state.invited_by,
            &network,
            &channel,
            failure,
        );
        let sidebar_changed =
            upsert_channel_entry(&mut state.channel_entries, network.clone(), channel.clone());
        let selected_window_failed = state
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_channel)| {
                window_state_key(current_network, current_channel)
                    == window_state_key(&network, &channel)
            });

        if selected_window_failed {
            let ui = ui.clone();
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_current_window_is_joined(false);
                ui.set_can_moderate_members(false);
            });
        }
        if state_changed || sidebar_changed {
            refresh_network_groups(state, ui);
        }
        return;
    }

    if IGNORED_KINDS.contains(&payload_kind) {
        return;
    }

    let Some((network, channel)) = channel_from_topic(&frame.topic) else {
        return;
    };
    if frame.event == "phx_reply" {
        return;
    }

    let key = (network.clone(), channel.clone());

    let line = render_message(effective_payload, Some(&frame.event));
    state.messages.entry(key.clone()).or_default().push(line);

    if state.current_channel.as_ref() == Some(&key) {
        let lines = state.messages[&key].clone();
        let dark_theme = state.theme == Theme::Dark;
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            let model = chat_lines_model(&lines, dark_theme);
            ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        });
    }

    let members_changed = update_members_from_frame(state, &key, effective_payload);
    if members_changed && state.current_channel.as_ref() == Some(&key) {
        push_members_update(state, ui, &key);
    }
}

/// Applies a `topic_changed` push — real shape confirmed via a live user
/// frame and `github.com/vjt/grappa-irc/issues/2260`:
/// `{"channel", "kind": "topic_changed", "network", "topic": {"set_at",
/// "set_by", "text"}}`. `topic` is an object here, not the plain string
/// the old ad-hoc extraction assumed (dead code against real traffic —
/// removed, this replaces it), so only `.topic.text` is used; `set_by`/
/// `set_at` aren't surfaced yet.
fn handle_topic_changed(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, payload: &Value) {
    let Some((key, text)) = parse_topic_changed(payload) else {
        return;
    };

    state.topics.insert(key.clone(), text.clone());
    if state.current_channel.as_ref() == Some(&key) {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            ui.set_current_topic(text.into());
        });
    }
}

/// Pulls `(network, channel)` and the new topic text out of a
/// `topic_changed` payload — `{"channel", "network", "topic": {"text", ...}}`.
fn parse_topic_changed(payload: &Value) -> Option<((String, String), String)> {
    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    let text = payload
        .get("topic")
        .and_then(|topic| topic.get("text"))
        .and_then(Value::as_str)?;
    Some(((network.to_string(), channel.to_string()), text.to_string()))
}

/// Parses Cicchetto's typed `joined` payload from either supported delivery
/// path: the current user's live topic or the matching channel's reconnect
/// snapshot. Cicchetto's shared wire narrower requires `network`, `channel`,
/// and the exact `state: "joined"` discriminant.
fn parse_joined_event(payload: &Value, topic: &str, identifier: &str) -> Option<(String, String)> {
    if payload.get("kind").and_then(Value::as_str) != Some("joined")
        || payload.get("state").and_then(Value::as_str) != Some("joined")
    {
        return None;
    }

    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    let user_topic = format!("grappa:user:{identifier}");
    if topic != user_topic && !channel_topic_matches(identifier, topic, network, channel) {
        return None;
    }

    Some((network.to_string(), channel.to_string()))
}

/// Parses Cicchetto's required `join_failed` payload from either the live
/// user topic or the matching per-channel reconnect snapshot. Nullable fields
/// must be present, but unknown additive fields are deliberately ignored.
fn parse_join_failed_event(
    payload: &Value,
    topic: &str,
    identifier: &str,
) -> Option<(String, String, WindowFailure)> {
    let object = payload.as_object()?;
    if object.get("kind").and_then(Value::as_str) != Some("join_failed")
        || object.get("state").and_then(Value::as_str) != Some("failed")
    {
        return None;
    }

    let network = object.get("network")?.as_str()?;
    let channel = object.get("channel")?.as_str()?;
    let reason = match object.get("reason")? {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        _ => return None,
    };
    let numeric = match object.get("numeric")? {
        Value::Null => None,
        Value::Number(value) => Some(value.clone()),
        _ => return None,
    };

    let user_topic = format!("grappa:user:{identifier}");
    if topic != user_topic && !channel_topic_matches(identifier, topic, network, channel) {
        return None;
    }

    Some((
        network.to_string(),
        channel.to_string(),
        WindowFailure { reason, numeric },
    ))
}

/// Matches the server's channel topic with the same identifier key used by
/// Cicchetto: exact user and network, ASCII-folded channel only.
fn channel_topic_matches(identifier: &str, topic: &str, network: &str, channel: &str) -> bool {
    let prefix = channel_topic(identifier, network, "");
    topic.strip_prefix(&prefix).is_some_and(|topic_channel| {
        ascii_fold_channel(topic_channel) == ascii_fold_channel(channel)
    })
}

/// Cicchetto's `channelKey` uses `asciiFold` (`A-Z` only) for the channel
/// segment. Keep display names untouched and leave all non-ASCII characters
/// unchanged, matching its current key equivalence exactly.
fn ascii_fold_channel(channel: &str) -> String {
    channel
        .chars()
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

/// The Rust tuple is Cordiale's equivalent of Cicchetto's composite
/// `channelKey`: preserve the network slug and ASCII-fold only the channel.
fn window_state_key(network: &str, channel: &str) -> (String, String) {
    (network.to_string(), ascii_fold_channel(channel))
}

fn window_is_failed(
    window_states: &HashMap<(String, String), ChannelWindowState>,
    network: &str,
    channel: &str,
) -> bool {
    window_states.get(&window_state_key(network, channel)) == Some(&ChannelWindowState::Failed)
}

/// Adds a channel window to the session's sidebar source of truth after a
/// server-reported join or join failure. The return value lets callers avoid
/// rebuilding Slint models for duplicate live/snapshot delivery.
fn upsert_channel_entry(
    entries: &mut Vec<(String, String, String)>,
    network: String,
    channel: String,
) -> bool {
    if entries.iter().any(|(known_network, known_channel, _)| {
        window_state_key(known_network, known_channel) == window_state_key(&network, &channel)
    }) {
        return false;
    }

    entries.push((network, channel.clone(), channel));
    true
}

/// Mirrors Cicchetto's `setJoined`: assignment overwrites the prior
/// window-state value and clears stale invite/failure metadata. Repeated
/// delivery on the live user topic and channel reconnect snapshot is
/// idempotent.
fn set_joined_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Joined)
        != Some(ChannelWindowState::Joined);
    let failure_cleared = window_failures.remove(&key).is_some();
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_cleared || invite_cleared
}

/// Mirrors Cicchetto's `setFailed`: failure replaces the current window
/// status, retains its nullable wire metadata, and clears any invite marker.
/// Replayed snapshots are idempotent.
fn set_failed_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
    failure: WindowFailure,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Failed)
        != Some(ChannelWindowState::Failed);
    let failure_changed = window_failures.insert(key.clone(), failure.clone()) != Some(failure);
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_changed || invite_cleared
}

/// Parses a `members_seeded` payload (`{kind, network, channel, members}`,
/// each member `{nick, modes: [...]}`) and replaces the stored roster for
/// that channel outright — it's a full snapshot, not a delta.
fn apply_members_seeded(state: &mut WorkerState, payload: &Value) -> Option<(String, String)> {
    let network = payload.get("network").and_then(Value::as_str)?.to_string();
    let channel = payload.get("channel").and_then(Value::as_str)?.to_string();
    let list = payload.get("members").and_then(Value::as_array)?;
    let mut members: Vec<MemberEntry> = list.iter().filter_map(member_from_entry).collect();
    sort_members_by_rank(&mut members);
    let key = (network, channel);
    state.members.insert(key.clone(), members);
    Some(key)
}

/// Pushes `state.members[key]` (and the derived op-gating flag) to the UI
/// — shared by every member-list mutation path (`members_seeded`,
/// incremental join/part/nick_change, channel selection).
fn push_members_update(state: &WorkerState, ui: &slint::Weak<AppWindow>, key: &(String, String)) {
    let members = state.members.get(key).cloned().unwrap_or_default();
    let can_moderate = state
        .identifier
        .as_deref()
        .is_some_and(|identifier| is_own_nick_an_op(&members, identifier));
    let dark_theme = state.theme == Theme::Dark;
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_can_moderate_members(can_moderate);
        let member_rows = members_model(&members, dark_theme);
        ui.set_channel_members(Rc::new(slint::VecModel::from(member_rows)).into());
    });
}

/// Maintains `state.members` from live join/part/quit/nick_change frames
/// — the boot-time snapshot (`members_from_boot`) may come back empty if
/// its field-name guesses don't match this server, so this is the only
/// reliable way members ever show up in practice. Returns whether the
/// member list for `key` actually changed (callers use this to decide
/// whether to push an update to the UI).
fn update_members_from_frame(
    state: &mut WorkerState,
    key: &(String, String),
    payload: &Value,
) -> bool {
    let kind = payload.get("kind").and_then(Value::as_str);
    let nick = payload
        .get("from")
        .or_else(|| payload.get("nick"))
        .or_else(|| payload.get("sender"))
        .and_then(Value::as_str);

    match kind {
        Some("join") => {
            let Some(nick) = nick else { return false };
            let members = state.members.entry(key.clone()).or_default();
            if members.iter().any(|(name, _)| name == nick) {
                return false;
            }
            members.push((nick.to_string(), String::new()));
            sort_members_by_rank(members);
            true
        }
        Some("part") | Some("quit") => {
            let Some(nick) = nick else { return false };
            let Some(members) = state.members.get_mut(key) else {
                return false;
            };
            let before = members.len();
            members.retain(|(name, _)| name != nick);
            before != members.len()
        }
        Some("nick_change") => {
            let (Some(old_nick), Some(new_nick)) = (
                nick,
                payload
                    .get("meta")
                    .and_then(|meta| meta.get("new_nick"))
                    .and_then(Value::as_str),
            ) else {
                return false;
            };
            let Some(members) = state.members.get_mut(key) else {
                return false;
            };
            let Some(entry) = members.iter_mut().find(|(name, _)| name == old_nick) else {
                return false;
            };
            entry.0 = new_nick.to_string();
            sort_members_by_rank(members);
            true
        }
        // Real, observed shape (a screenshot caught this leaking as raw
        // JSON before this was handled): `meta.modes` like `"+o"`/`"-o"`,
        // `meta.args` the targets in order for whichever letters take one.
        // Cordiale only tracks the three prefix-bearing modes it renders
        // (`@`/`%`/`+`) — any other letter in the string (ban masks, keys,
        // limits, ...) is skipped without consuming an `args` entry, since
        // Cordiale has no ISUPPORT CHANMODES table to know which of those
        // take one; a combined string mixing a skipped letter with a
        // prefix letter (e.g. `"+ob"`) would misalign, but no such case
        // has been observed yet — see README's Known gaps.
        Some("mode") => {
            let modes = payload
                .get("meta")
                .and_then(|meta| meta.get("modes"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let targets = mode_args(payload);
            let Some(members) = state.members.get_mut(key) else {
                return false;
            };
            let mut sign = '+';
            let mut targets = targets.into_iter();
            let mut changed = false;
            for ch in modes.chars() {
                match ch {
                    '+' | '-' => sign = ch,
                    'o' | 'h' | 'v' => {
                        let Some(target) = targets.next() else {
                            continue;
                        };
                        let Some(entry) = members.iter_mut().find(|(name, _)| *name == target)
                        else {
                            continue;
                        };
                        let symbol = match ch {
                            'o' => "@",
                            'h' => "%",
                            _ => "+",
                        };
                        entry.1 = if sign == '+' {
                            symbol.to_string()
                        } else {
                            String::new()
                        };
                        changed = true;
                    }
                    _ => {}
                }
            }
            if changed {
                sort_members_by_rank(members);
            }
            changed
        }
        _ => false,
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

/// One message/event ready for display: local timestamp already resolved
/// (see `local_timestamp`), split into an ordinary chat line (`nick`
/// `Some`, shown as `<nick> text` with a per-nick hash color) or a
/// synthesized system line (`nick: None` — join/part/quit/notice/mode/
/// server_event), always `italic`.
#[derive(Clone)]
struct RenderedMessage {
    timestamp: String,
    nick: Option<String>,
    text: String,
    italic: bool,
}

/// Shared `from`/`nick`/`sender` + `body`/`message` extraction for both
/// live frames (called from `handle_frame`, after unwrapping the
/// `kind: "message"` envelope a chat row arrives under) and REST history
/// rows (`render_history_entry`) — per `docs/protocol-notes.md` §4, scrollback
/// rows and push events are the same "message" entity, so both shapes use
/// the same field names. `sender` is real, observed field on a live
/// `kind: "join"` payload (`{"sender":"LAS3r","kind":"join","body":null,
/// ...}`) that neither `from` nor `nick` cover — docs don't list it.
fn render_message(payload: &Value, event_fallback: Option<&str>) -> RenderedMessage {
    let timestamp = local_timestamp(payload);
    let nick = payload
        .get("from")
        .or_else(|| payload.get("nick"))
        .or_else(|| payload.get("sender"))
        .and_then(Value::as_str);
    let body = payload
        .get("body")
        .or_else(|| payload.get("message"))
        .and_then(Value::as_str);
    let kind = payload.get("kind").and_then(Value::as_str);
    let reason = payload.get("reason").and_then(Value::as_str);

    let event_text = match kind {
        Some("join") => Some(format!("→ {} joined", nick.unwrap_or("someone"))),
        Some("part") => Some(match reason {
            Some(reason) => format!("← {} left ({reason})", nick.unwrap_or("someone")),
            None => format!("← {} left", nick.unwrap_or("someone")),
        }),
        Some("quit") => Some(match reason {
            Some(reason) => format!("⇐ {} quit ({reason})", nick.unwrap_or("someone")),
            None => format!("⇐ {} quit", nick.unwrap_or("someone")),
        }),
        // Real, observed shape (`docs/protocol-notes.md` doesn't mention
        // this kind at all): old nick in `sender` (already captured
        // above), new one in `meta.new_nick`.
        Some("nick_change") => {
            let new_nick = payload
                .get("meta")
                .and_then(|meta| meta.get("new_nick"))
                .and_then(Value::as_str)
                .unwrap_or("someone else");
            Some(format!(
                "* {} is now known as {new_nick}",
                nick.unwrap_or("someone")
            ))
        }
        // Real, observed shape: `meta.modes` is the mode-change string
        // (e.g. `"+o"`, `"+ov"`, `"-o"`) and `meta.args` the targets that
        // take one, in order — same alignment `update_members_from_frame`
        // uses to actually apply the change.
        Some("mode") => {
            let modes = payload
                .get("meta")
                .and_then(|meta| meta.get("modes"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let targets = mode_args(payload);
            let suffix = if targets.is_empty() {
                String::new()
            } else {
                format!(" {}", targets.join(" "))
            };
            Some(format!(
                "* {} sets {modes}{suffix}",
                nick.unwrap_or("someone")
            ))
        }
        // CTCP ACTION (`/me`) — the inner kind riding under a `message`
        // envelope, confirmed real by auditing `scrollback/message.ex`
        // directly. The body is the plain action text,
        // not the raw `\x01ACTION ... \x01` wire form (that framing is
        // stripped server-side, matching how `notice` is already a clean
        // kind rather than needing CTCP unwrapping itself).
        Some("action") => Some(format!(
            "* {} {}",
            nick.unwrap_or("someone"),
            body.unwrap_or("")
        )),
        _ => None,
    };
    if let Some(text) = event_text {
        return RenderedMessage {
            timestamp,
            nick: None,
            text,
            italic: true,
        };
    }

    // A `notice` (the IRC convention services like NickServ/ChanServ use)
    // keeps the normal `<nick> text` shape but renders italic, same as
    // join/part/quit — distinguishing it from an ordinary privmsg without
    // hiding its content the way a synthesized sentence would.
    let italic = kind == Some("notice");

    match (nick, body) {
        (Some(nick), Some(body)) => RenderedMessage {
            timestamp,
            nick: Some(nick.to_string()),
            text: body.to_string(),
            italic,
        },
        (None, Some(body)) => RenderedMessage {
            timestamp,
            nick: None,
            text: body.to_string(),
            italic,
        },
        _ => RenderedMessage {
            timestamp,
            nick: None,
            text: event_fallback
                .map(|event| format!("{event}: {payload}"))
                .unwrap_or_else(|| payload.to_string()),
            italic: true,
        },
    }
}

/// `meta.args` on a `kind: "mode"` payload — the targets a mode change's
/// letters that take one line up with, in order (same list `render_message`
/// and `update_members_from_frame` both read).
fn mode_args(payload: &Value) -> Vec<String> {
    payload
        .get("meta")
        .and_then(|meta| meta.get("args"))
        .and_then(Value::as_array)
        .map(|args| {
            args.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Renders one `boot.heads` scrollback row the same way a live frame would
/// be, minus the `event`/`topic` envelope a bootstrap history row doesn't
/// have.
fn render_history_entry(value: &Value) -> RenderedMessage {
    render_message(value, None)
}

/// Local `HH:MM:SS` for a message. `server_time` (epoch milliseconds) is
/// the real, observed field — confirmed from a live `kind: "nick_change"`
/// payload during field testing (`docs/protocol-notes.md` never named
/// it). The RFC-3339-string field names below are kept as a fallback in
/// case some other event shape uses a different convention; "now" is the
/// last resort — correct for a live push, best-effort for scrollback
/// history whose field turns out to be neither.
fn local_timestamp(payload: &Value) -> String {
    if let Some(millis) = payload.get("server_time").and_then(Value::as_i64) {
        if let Some(parsed) = chrono::DateTime::from_timestamp_millis(millis) {
            return parsed
                .with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string();
        }
    }
    for field in ["server_timestamp", "timestamp", "inserted_at", "created_at"] {
        if let Some(raw) = payload.get(field).and_then(Value::as_str) {
            if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(raw) {
                return parsed
                    .with_timezone(&chrono::Local)
                    .format("%H:%M:%S")
                    .to_string();
            }
        }
    }
    chrono::Local::now().format("%H:%M:%S").to_string()
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

/// Seeds the runtime joined map only from Grappa's explicit `/boot` flag.
/// The channel tree also contains persisted autojoin intentions that can be
/// disconnected, so mere presence in `boot.channels` is not enough.
fn joined_window_states_from_boot_channels(
    channels: &HashMap<String, Vec<Value>>,
) -> HashMap<(String, String), ChannelWindowState> {
    let mut window_states = HashMap::new();
    for (network, entries) in channels {
        for entry in entries {
            if entry.get("joined").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let Some(channel) = entry
                .get("name")
                .or_else(|| entry.get("channel"))
                .and_then(Value::as_str)
                .filter(|channel| !channel.is_empty())
            else {
                continue;
            };
            window_states.insert(
                window_state_key(network, channel),
                ChannelWindowState::Joined,
            );
        }
    }
    window_states
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

/// `(name, prefix)` — `prefix` is the single highest-ranked IRC role
/// marker (`@` op, `%` halfop, `+` voice, empty for a plain member).
type MemberEntry = (String, String);
type MembersByChannel = HashMap<(String, String), Vec<MemberEntry>>;

/// Reads `(network, channel) -> members` out of `boot.channels`. The
/// exact field/shape isn't confirmed by `docs/protocol-notes.md` (only
/// "channel... ha: membri" is mentioned, no schema) — tries the plausible
/// field names and both a flat `["@nick", "+other", "plain"]` shape and an
/// object-per-member shape (`{"nick"/"name", "prefix"}` or `{"modes":
/// [...]}`) defensively. An unrecognized shape just yields no members for
/// that channel rather than guessing further; see README's Known gaps.
fn members_from_boot(outcome: &BootstrapOutcome) -> MembersByChannel {
    const FIELD_NAMES: &[&str] = &["members", "nicks", "names", "userlist", "who"];

    let mut members_by_channel = HashMap::new();
    for (network, channels) in &outcome.boot.channels {
        for value in channels {
            let channel = value
                .get("name")
                .or_else(|| value.get("channel"))
                .and_then(Value::as_str);
            let Some(channel) = channel else { continue };

            let Some(list) = FIELD_NAMES
                .iter()
                .find_map(|field| value.get(field))
                .and_then(Value::as_array)
            else {
                continue;
            };

            let mut members: Vec<MemberEntry> = list.iter().filter_map(member_from_entry).collect();
            if members.is_empty() {
                continue;
            }
            sort_members_by_rank(&mut members);
            members_by_channel.insert((network.clone(), channel.to_string()), members);
        }
    }
    members_by_channel
}

/// Parses one member list entry: either a plain string with an optional
/// leading role-prefix character (`"@nick"`, `"+nick"`, `"nick"`), or an
/// object carrying a `nick`/`name` field plus either an explicit `prefix`
/// string or a `modes` array of mode letters (`o`/`h`/`v`) to derive one
/// from.
fn member_from_entry(entry: &Value) -> Option<MemberEntry> {
    if let Some(raw) = entry.as_str() {
        let prefix_char = raw.chars().next().filter(|c| "@%+&~".contains(*c));
        return Some(match prefix_char {
            Some(c) => (raw[c.len_utf8()..].to_string(), c.to_string()),
            None => (raw.to_string(), String::new()),
        });
    }

    let obj = entry.as_object()?;
    let name = obj
        .get("nick")
        .or_else(|| obj.get("name"))
        .and_then(Value::as_str)?
        .to_string();
    let prefix = obj
        .get("prefix")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            obj.get("modes")
                .and_then(Value::as_array)
                .and_then(|modes| {
                    modes.iter().find_map(|mode| match mode.as_str() {
                        Some("o") => Some("@".to_string()),
                        Some("h") => Some("%".to_string()),
                        Some("v") => Some("+".to_string()),
                        _ => None,
                    })
                })
        })
        .unwrap_or_default();
    Some((name, prefix))
}

/// Ops first, then halfops, then voice, then everyone else — each group
/// alphabetical (case-insensitive) within itself.
fn sort_members_by_rank(members: &mut [MemberEntry]) {
    const RANK_ORDER: &str = "@%+";
    let rank = |prefix: &str| {
        prefix
            .chars()
            .next()
            .and_then(|c| RANK_ORDER.find(c))
            .unwrap_or(RANK_ORDER.len())
    };
    members.sort_by(|(name_a, prefix_a), (name_b, prefix_b)| {
        rank(prefix_a)
            .cmp(&rank(prefix_b))
            .then_with(|| name_a.to_lowercase().cmp(&name_b.to_lowercase()))
    });
}

/// Reads initial scrollback out of `boot.heads` (network -> channel ->
/// message rows), rendered the same way a live frame would be.
/// `boot.heads` "is only present for a channel that actually has history"
/// (confirmed in an earlier research pass) — a channel with none simply
/// has no key here and starts empty, same as before this was wired in.
type MessagesByChannel = HashMap<(String, String), Vec<RenderedMessage>>;

fn messages_from_boot(outcome: &BootstrapOutcome) -> MessagesByChannel {
    let mut messages = HashMap::new();
    for (network, channels) in &outcome.boot.heads {
        for (channel, rows) in channels {
            let lines: Vec<RenderedMessage> = rows.iter().map(render_history_entry).collect();
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
fn network_groups_model(
    data: Vec<NetworkGroupData>,
    window_states: HashMap<(String, String), ChannelWindowState>,
) -> Vec<NetworkGroup> {
    data.into_iter()
        .map(|(network, expanded, channels)| {
            let channel_entries: Vec<ChannelEntry> = channels
                .into_iter()
                .map(|(channel, label)| {
                    let failed = window_is_failed(&window_states, &network, &channel);
                    ChannelEntry {
                        network: network.clone().into(),
                        channel: channel.into(),
                        label: label.into(),
                        failed,
                    }
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
    let window_states = state.window_states.clone();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let groups = network_groups_model(data, window_states);
        ui.set_network_groups(Rc::new(slint::VecModel::from(groups)).into());
    });
}

/// Converts one already-rendered message into the Slint `ChatLine` model.
/// `timestamp` and `nick` are their own fields rather than folded into
/// `segments` (as they briefly were) so the markup can style/wrap the
/// timestamp as muted text and put just the nick inside a
/// right-click-for-context-menu area, without either catching the mIRC
/// body `Text` elements around them. Every body segment is forced
/// `italic` when the message itself is (join/part/quit/notice/fallback),
/// and every explicit mIRC color run passed through `ensure_legible` for
/// `dark_theme`. Maps `cordiale_core::formatting::ColorSegment`'s
/// abstract `(u8, u8, u8)` into a real `slint::Color` only here — the
/// core crate stays free of any Slint dependency.
fn chat_line_from_message(message: &RenderedMessage, dark_theme: bool) -> ChatLine {
    let (nick, nick_color_value) = match &message.nick {
        Some(nick) => {
            let (r, g, b) = nick_color(nick, dark_theme);
            (nick.clone(), slint::Color::from_rgb_u8(r, g, b))
        }
        None => (String::new(), slint::Color::from_rgb_u8(0, 0, 0)),
    };

    let mut segments = Vec::new();
    for segment in cordiale_core::formatting::parse_mirc_text(&message.text) {
        let (has_color, color) = match segment.color {
            Some(rgb) => {
                let (r, g, b) = ensure_legible(rgb, dark_theme);
                (true, slint::Color::from_rgb_u8(r, g, b))
            }
            None => (false, slint::Color::from_rgb_u8(0, 0, 0)),
        };
        segments.push(MessageSegment {
            text: segment.text.into(),
            has_color,
            color,
            bold: segment.bold,
            italic: message.italic,
        });
    }

    ChatLine {
        timestamp: message.timestamp.clone().into(),
        timestamp_color: muted_color(dark_theme),
        nick: nick.into(),
        nick_color: nick_color_value,
        italic: message.italic,
        segments: Rc::new(slint::VecModel::from(segments)).into(),
    }
}

fn chat_lines_model(messages: &[RenderedMessage], dark_theme: bool) -> Vec<ChatLine> {
    messages
        .iter()
        .map(|message| chat_line_from_message(message, dark_theme))
        .collect()
}

fn members_model(members: &[MemberEntry], dark_theme: bool) -> Vec<MemberRow> {
    members
        .iter()
        .map(|(name, prefix)| {
            let (r, g, b) = nick_color(name, dark_theme);
            MemberRow {
                name: name.clone().into(),
                prefix: prefix.clone().into(),
                color: slint::Color::from_rgb_u8(r, g, b),
            }
        })
        .collect()
}

/// Timestamp-prefix color: readable but visually secondary against either
/// theme's default text color.
fn muted_color(dark_theme: bool) -> slint::Color {
    if dark_theme {
        slint::Color::from_rgb_u8(150, 150, 150)
    } else {
        slint::Color::from_rgb_u8(110, 110, 110)
    }
}

/// Deterministic, good-contrast color for a nick — the same nick always
/// gets the same hue on a given theme, distinguishing speakers without
/// needing any per-server nick metadata. Saturation/lightness are
/// theme-tuned so every hue stays legible on that theme's background.
fn nick_color(nick: &str, dark_theme: bool) -> (u8, u8, u8) {
    let hue = (fnv1a_hash(nick.as_bytes()) % 360) as f32;
    let (saturation, lightness) = if dark_theme {
        (0.65, 0.68)
    } else {
        (0.65, 0.35)
    };
    hsl_to_rgb(hue, saturation, lightness)
}

/// Raises (dark theme) or lowers (light theme) `color`'s perceived
/// brightness to a legibility floor/ceiling, blending toward white/black
/// proportionally to how far past the threshold it is — a message using
/// an explicit mIRC color that happens to be near-black shouldn't become
/// unreadable just because the theme flipped underneath it.
fn ensure_legible(color: (u8, u8, u8), dark_theme: bool) -> (u8, u8, u8) {
    let (r, g, b) = color;
    let luminance = 0.299 * r as f32 + 0.587 * g as f32 + 0.114 * b as f32;
    const DARK_FLOOR: f32 = 140.0;
    const LIGHT_CEILING: f32 = 180.0;
    if dark_theme && luminance < DARK_FLOOR {
        blend_toward(
            color,
            (255, 255, 255),
            (DARK_FLOOR - luminance) / DARK_FLOOR,
        )
    } else if !dark_theme && luminance > LIGHT_CEILING {
        blend_toward(
            color,
            (0, 0, 0),
            (luminance - LIGHT_CEILING) / (255.0 - LIGHT_CEILING),
        )
    } else {
        color
    }
}

fn blend_toward(from: (u8, u8, u8), to: (u8, u8, u8), amount: f32) -> (u8, u8, u8) {
    let amount = amount.clamp(0.0, 1.0);
    let mix = |c: u8, t: u8| (c as f32 + (t as f32 - c as f32) * amount).round() as u8;
    (mix(from.0, to.0), mix(from.1, to.1), mix(from.2, to.2))
}

/// FNV-1a — simple, fully deterministic (no dependency on Rust's own
/// `DefaultHasher`, which the standard library doesn't promise stability
/// for across versions), good enough to scatter nicks across the hue
/// wheel without visible clustering.
fn fnv1a_hash(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for &byte in bytes {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

/// Standard HSL -> RGB conversion; `h` in degrees, `s`/`l` in `0.0..=1.0`.
fn hsl_to_rgb(h: f32, s: f32, l: f32) -> (u8, u8, u8) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r1, g1, b1) = match h as u32 {
        0..=59 => (c, x, 0.0),
        60..=119 => (x, c, 0.0),
        120..=179 => (0.0, c, x),
        180..=239 => (0.0, x, c),
        240..=299 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    (
        ((r1 + m) * 255.0).round() as u8,
        ((g1 + m) * 255.0).round() as u8,
        ((b1 + m) * 255.0).round() as u8,
    )
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

/// Called only after a successful non-guest bootstrap. The entered password
/// or per-client token is never persisted: only Grappa's returned bearer is
/// written to the CredentialStore, while `servers.json` records its kind.
fn remember_profile(server_url: &str, identifier: &str, bearer: &str) {
    if let Ok(store) = resolve_credential_store() {
        let _ = store.set_secret(server_url, identifier, bearer);
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

    let profile = file
        .profiles
        .iter_mut()
        .find(|profile| profile.server_base_url == server_url && profile.identifier == identifier);
    if let Some(profile) = profile {
        profile.auth_method = AuthMethod::BearerToken;
        profile.remembered = true;
    } else {
        file.profiles.push(Profile {
            server_base_url: server_url.to_string(),
            identifier: identifier.to_string(),
            auth_method: AuthMethod::BearerToken,
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

/// Pre-fills only the identifier for the last remembered profile on
/// `server_url`. Credentials are never copied into the password field; a
/// returned bearer is loaded privately only when the user explicitly chooses
/// the saved-profile sign-in action.
fn prefill_remembered_profile(ui: &AppWindow, server_url: &str) {
    ui.set_saved_profile_identifier("".into());
    ui.set_saved_profile_server_url("".into());
    let file = persistence::load_servers_file().unwrap_or_default();
    let Some(profile) = file
        .profiles
        .iter()
        .find(|profile| profile.server_base_url == server_url && profile.remembered)
    else {
        return;
    };

    ui.set_identifier(profile.identifier.clone().into());
    if matches!(
        remembered_profile_credential(server_url, &profile.identifier),
        RememberedProfileCredential::Bearer(_)
    ) {
        ui.set_saved_profile_identifier(profile.identifier.clone().into());
        ui.set_saved_profile_server_url(server_url.into());
    }
}

enum RememberedProfileCredential {
    None,
    NeedsReauthentication,
    Bearer(String),
}

/// Returns a saved Grappa bearer only when `servers.json` marks the value as
/// a bearer written by the current persistence flow. Older releases stored
/// the entered password/client token under the same key; those values are
/// never reused as bearer credentials and are removed on a form Connect.
fn remembered_profile_credential(
    server_url: &str,
    identifier: &str,
) -> RememberedProfileCredential {
    if identifier.is_empty() {
        return RememberedProfileCredential::None;
    }

    let file = persistence::load_servers_file().unwrap_or_default();
    let Some(profile) = file.profiles.iter().find(|profile| {
        profile.server_base_url == server_url
            && profile.identifier == identifier
            && profile.remembered
    }) else {
        return RememberedProfileCredential::None;
    };

    if profile.auth_method != AuthMethod::BearerToken {
        return RememberedProfileCredential::NeedsReauthentication;
    }

    let Ok(store) = resolve_credential_store() else {
        return RememberedProfileCredential::NeedsReauthentication;
    };
    match store.get_secret(server_url, identifier) {
        Ok(Some(bearer)) if !bearer.is_empty() => RememberedProfileCredential::Bearer(bearer),
        _ => RememberedProfileCredential::NeedsReauthentication,
    }
}

/// Removes a value written by the old implementation, which persisted the
/// form's password/client-token input under the same key now used for the
/// returned bearer. The profile metadata lets us distinguish it safely.
fn discard_legacy_profile_secret(server_url: &str, identifier: &str) {
    if identifier.is_empty() {
        return;
    }

    let file = persistence::load_servers_file().unwrap_or_default();
    let is_legacy_profile = file.profiles.iter().any(|profile| {
        profile.server_base_url == server_url
            && profile.identifier == identifier
            && profile.auth_method != AuthMethod::BearerToken
    });
    if is_legacy_profile {
        if let Ok(store) = resolve_credential_store() {
            let _ = store.delete_secret(server_url, identifier);
        }
    }
}

/// Best-effort removal of a bearer that Grappa has rejected. The profile's
/// marker remains so a later explicit saved-profile attempt requests fresh
/// credentials instead of interpreting it as a password or guest choice.
fn forget_remembered_bearer(server_url: &str, identifier: &str) {
    let file = persistence::load_servers_file().unwrap_or_default();
    let is_bearer_profile = file.profiles.iter().any(|profile| {
        profile.server_base_url == server_url
            && profile.identifier == identifier
            && profile.remembered
            && profile.auth_method == AuthMethod::BearerToken
    });
    if is_bearer_profile {
        if let Ok(store) = resolve_credential_store() {
            let _ = store.delete_secret(server_url, identifier);
        }
    }
}

fn show_reauthentication_required(ui: &slint::Weak<AppWindow>) {
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_connecting(false);
        ui.set_saved_profile_identifier("".into());
        ui.set_saved_profile_server_url("".into());
        ui.set_status_kind("reauthentication-required".into());
        ui.set_status_message("".into());
    });
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
/// this function never produces English text itself, only a
/// machine-readable key.
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
        BootstrapError::BearerRejected => {
            ui.set_status_kind("reauthentication-required".into());
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
    fn blank_connect_form_is_guest_but_saved_profile_is_explicit() {
        assert!(ConnectCredential::FormValue(String::new()).is_guest_attempt());
        assert!(!ConnectCredential::FormValue("new-password".into()).is_guest_attempt());
        assert!(!ConnectCredential::SavedProfile.is_guest_attempt());
    }

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
    fn parse_topic_changed_reads_the_nested_text_field() {
        // Real shape, confirmed via a live frame and
        // github.com/vjt/grappa-irc/issues/2260 — `topic` is an object,
        // not the plain string an earlier version of this code assumed.
        let payload = serde_json::json!({
            "channel": "#grappa",
            "kind": "topic_changed",
            "network": "azzurra",
            "topic": {
                "set_at": "2026-09-14T21:42:44Z",
                "set_by": "vjt",
                "text": "Welcome to #grappa"
            }
        });
        assert_eq!(
            parse_topic_changed(&payload),
            Some((
                ("azzurra".to_string(), "#grappa".to_string()),
                "Welcome to #grappa".to_string()
            ))
        );
    }

    #[test]
    fn parse_topic_changed_rejects_a_plain_string_topic() {
        let payload = serde_json::json!({
            "channel": "#grappa",
            "network": "azzurra",
            "topic": "not an object"
        });
        assert_eq!(parse_topic_changed(&payload), None);
    }

    #[test]
    fn parse_joined_event_accepts_live_and_channel_snapshot_topics() {
        let payload = serde_json::json!({
            "kind": "joined",
            "network": "libera",
            "channel": "#cordiale",
            "state": "joined",
            "future_field": true
        });
        let expected = Some(("libera".to_string(), "#cordiale".to_string()));

        assert_eq!(
            parse_joined_event(&payload, "grappa:user:sythos", "sythos"),
            expected
        );
        assert_eq!(
            parse_joined_event(
                &payload,
                &channel_topic("sythos", "libera", "#CoRdIaLe"),
                "sythos"
            ),
            expected
        );
        assert_eq!(ascii_fold_channel("#CAFÉ[1]"), "#cafÉ[1]");
    }

    #[test]
    fn boot_seeds_only_channels_with_an_explicit_true_joined_flag() {
        let channels = HashMap::from([(
            "libera".to_string(),
            vec![
                serde_json::json!({"name": "#ACTIVE-AUTOJOIN", "joined": true, "source": "autojoin"}),
                serde_json::json!({"name": "#active-dynamic", "joined": true, "source": "joined"}),
                serde_json::json!({"name": "#configured-only", "joined": false, "source": "autojoin"}),
                serde_json::json!({"name": "#missing-joined", "source": "joined"}),
                serde_json::json!({"name": "#malformed-joined", "joined": "true"}),
                serde_json::json!({"joined": true, "source": "joined"}),
            ],
        )]);

        let states = joined_window_states_from_boot_channels(&channels);
        let expected = HashMap::from([
            (
                ("libera".to_string(), "#active-autojoin".to_string()),
                ChannelWindowState::Joined,
            ),
            (
                ("libera".to_string(), "#active-dynamic".to_string()),
                ChannelWindowState::Joined,
            ),
        ]);

        assert_eq!(states, expected);
    }

    #[test]
    fn parse_joined_event_rejects_malformed_state_and_unrelated_topics() {
        let valid = serde_json::json!({
            "kind": "joined",
            "network": "libera",
            "channel": "#cordiale",
            "state": "joined"
        });
        assert_eq!(
            parse_joined_event(&valid, "grappa:user:someone-else", "sythos"),
            None
        );
        assert_eq!(
            parse_joined_event(
                &valid,
                &channel_topic("sythos", "libera", "#other"),
                "sythos"
            ),
            None
        );

        let wrong_state = serde_json::json!({
            "kind": "joined",
            "network": "libera",
            "channel": "#cordiale",
            "state": "pending"
        });
        assert_eq!(
            parse_joined_event(&wrong_state, "grappa:user:sythos", "sythos"),
            None
        );

        let missing_channel = serde_json::json!({
            "kind": "joined",
            "network": "libera",
            "state": "joined"
        });
        assert_eq!(
            parse_joined_event(&missing_channel, "grappa:user:sythos", "sythos"),
            None
        );
    }

    #[test]
    fn parse_join_failed_accepts_live_and_matching_channel_snapshot_topics() {
        let payload = serde_json::json!({
            "kind": "join_failed",
            "network": "libera",
            "channel": "#cordiale",
            "state": "failed",
            "reason": "invite only",
            "numeric": 473,
            "future_field": true
        });
        let expected = Some((
            "libera".to_string(),
            "#cordiale".to_string(),
            WindowFailure {
                reason: Some("invite only".to_string()),
                numeric: Some(Number::from(473)),
            },
        ));

        assert_eq!(
            parse_join_failed_event(&payload, "grappa:user:sythos", "sythos"),
            expected
        );
        assert_eq!(
            parse_join_failed_event(
                &payload,
                &channel_topic("sythos", "libera", "#CoRdIaLe"),
                "sythos"
            ),
            expected
        );
    }

    #[test]
    fn parse_join_failed_preserves_required_nullable_fields_and_rejects_bad_payloads() {
        let nullable = serde_json::json!({
            "kind": "join_failed",
            "network": "libera",
            "channel": "#cordiale",
            "state": "failed",
            "reason": null,
            "numeric": null
        });
        assert_eq!(
            parse_join_failed_event(&nullable, "grappa:user:sythos", "sythos"),
            Some((
                "libera".to_string(),
                "#cordiale".to_string(),
                WindowFailure {
                    reason: None,
                    numeric: None,
                },
            ))
        );

        let wrong_state = serde_json::json!({
            "kind": "join_failed",
            "network": "libera",
            "channel": "#cordiale",
            "state": "joined",
            "reason": null,
            "numeric": null
        });
        assert_eq!(
            parse_join_failed_event(&wrong_state, "grappa:user:sythos", "sythos"),
            None
        );

        let missing_reason = serde_json::json!({
            "kind": "join_failed",
            "network": "libera",
            "channel": "#cordiale",
            "state": "failed",
            "numeric": null
        });
        assert_eq!(
            parse_join_failed_event(&missing_reason, "grappa:user:sythos", "sythos"),
            None
        );

        let malformed_numeric = serde_json::json!({
            "kind": "join_failed",
            "network": "libera",
            "channel": "#cordiale",
            "state": "failed",
            "reason": null,
            "numeric": "473"
        });
        assert_eq!(
            parse_join_failed_event(&malformed_numeric, "grappa:user:sythos", "sythos"),
            None
        );

        assert_eq!(
            parse_join_failed_event(&nullable, "grappa:user:other", "sythos"),
            None
        );
        assert_eq!(
            parse_join_failed_event(
                &nullable,
                &channel_topic("sythos", "libera", "#other"),
                "sythos"
            ),
            None
        );
        assert_eq!(
            parse_join_failed_event(
                &nullable,
                "grappa:user:sythos/network:libera/query:friend",
                "sythos"
            ),
            None
        );
    }

    #[test]
    fn upsert_channel_entry_is_idempotent_for_live_and_snapshot_delivery() {
        let mut entries = vec![(
            "libera".to_string(),
            "#cordiale".to_string(),
            "#cordiale".to_string(),
        )];

        assert!(!upsert_channel_entry(
            &mut entries,
            "libera".to_string(),
            "#CoRdIaLe".to_string()
        ));
        assert!(upsert_channel_entry(
            &mut entries,
            "libera".to_string(),
            "#rust".to_string()
        ));
        assert!(!upsert_channel_entry(
            &mut entries,
            "libera".to_string(),
            "#rust".to_string()
        ));
        assert_eq!(
            entries,
            vec![
                (
                    "libera".to_string(),
                    "#cordiale".to_string(),
                    "#cordiale".to_string()
                ),
                (
                    "libera".to_string(),
                    "#rust".to_string(),
                    "#rust".to_string()
                )
            ]
        );
    }

    #[test]
    fn set_joined_window_state_records_transition_and_deduplicates_delivery() {
        let key = window_state_key("libera", "#cordiale");
        let mut states = HashMap::new();
        let mut failures = HashMap::from([(
            key.clone(),
            WindowFailure {
                reason: Some("old failure".to_string()),
                numeric: Some(Number::from(473)),
            },
        )]);
        let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);

        assert!(set_joined_window_state(
            &mut states,
            &mut failures,
            &mut invited_by,
            &key.0,
            "#CoRdIaLe"
        ));
        assert_eq!(states.get(&key), Some(&ChannelWindowState::Joined));
        assert!(!failures.contains_key(&key));
        assert!(!invited_by.contains_key(&key));

        assert!(!set_joined_window_state(
            &mut states,
            &mut failures,
            &mut invited_by,
            &key.0,
            &key.1
        ));
        assert_eq!(states.len(), 1);
        assert_eq!(states.get(&key), Some(&ChannelWindowState::Joined));
    }

    #[test]
    fn set_failed_window_state_keeps_metadata_clears_invite_and_is_idempotent() {
        let key = window_state_key("libera", "#cordiale");
        let failure = WindowFailure {
            reason: Some("invite only".to_string()),
            numeric: Some(Number::from(473)),
        };
        let mut states = HashMap::from([(key.clone(), ChannelWindowState::Joined)]);
        let mut failures = HashMap::new();
        let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);

        assert!(set_failed_window_state(
            &mut states,
            &mut failures,
            &mut invited_by,
            "libera",
            "#CoRdIaLe",
            failure.clone()
        ));
        assert_eq!(states.get(&key), Some(&ChannelWindowState::Failed));
        assert!(window_is_failed(&states, "libera", "#CoRdIaLe"));
        assert_eq!(failures.get(&key), Some(&failure));
        assert!(!invited_by.contains_key(&key));

        assert!(!set_failed_window_state(
            &mut states,
            &mut failures,
            &mut invited_by,
            "libera",
            "#cordiale",
            failure
        ));
    }

    #[test]
    fn render_message_reads_the_message_envelopes_inner_row() {
        // `handle_frame` unwraps `payload.message` before calling this —
        // this test locks in what that inner row looks like, confirmed
        // via a real live frame: {"kind": "message", "message": {"kind":
        // "privmsg", "sender", "body", ...}}.
        let inner = serde_json::json!({
            "kind": "privmsg",
            "sender": "vjt",
            "body": "hello from the real channel",
            "channel": "#grappa",
            "network": "azzurra",
            "id": 40172,
        });
        let rendered = render_message(&inner, None);
        assert_eq!(rendered.nick.as_deref(), Some("vjt"));
        assert_eq!(rendered.text, "hello from the real channel");
        assert!(!rendered.italic);
    }

    #[test]
    fn render_message_formats_a_ctcp_action_as_a_sentence() {
        let inner = serde_json::json!({
            "kind": "action",
            "sender": "vjt",
            "body": "waves hello",
        });
        let rendered = render_message(&inner, None);
        assert_eq!(rendered.nick, None);
        assert_eq!(rendered.text, "* vjt waves hello");
        assert!(rendered.italic);
    }

    #[test]
    fn ignored_kinds_covers_the_ones_this_session_actually_saw() {
        // The kinds caught leaking as raw JSON in chat before being fixed
        // this session — a regression here means one of them is no longer
        // ignored and would start dumping raw JSON again.
        for kind in [
            "channel_modes_changed",
            "read_cursor_set",
            "window_counts",
            "away_confirmed",
            "bundle_hash",
            "query_windows_list",
        ] {
            assert!(
                IGNORED_KINDS.contains(&kind),
                "{kind} should be in IGNORED_KINDS"
            );
        }
        // members_seeded/names_reply/topic_changed are handled, not
        // ignored, so they must NOT be in this list — that would silently
        // drop real state instead of applying it.
        assert!(!IGNORED_KINDS.contains(&"members_seeded"));
        assert!(!IGNORED_KINDS.contains(&"names_reply"));
        assert!(!IGNORED_KINDS.contains(&"topic_changed"));
        assert!(!IGNORED_KINDS.contains(&"joined"));
        assert!(!IGNORED_KINDS.contains(&"join_failed"));
        // "parted" is confirmed to never actually be sent by the server
        // — listing it here would be harmless but wrong documentation,
        // so it must stay absent.
        assert!(!IGNORED_KINDS.contains(&"parted"));
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
