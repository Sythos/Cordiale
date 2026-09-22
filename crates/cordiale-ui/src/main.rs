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
use std::collections::{HashMap, VecDeque};
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
use cordiale_core::isupport::{parse_isupport_changed, IsupportState};
use cordiale_core::persistence::{self, Theme};
use cordiale_core::rest::{
    BootResponse, DisplayPrefs, LoginRequest, MeResponse, SendMessageRequest,
};
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
    SelectQuery {
        network: String,
        nick: String,
    },
    DismissKickedChannel {
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
            ui.set_current_channel_modes("".into());
            ui.set_current_window_is_joined(false);
            ui.set_has_selected_channel(false);
            ui.set_current_query(false);
            ui.set_current_query_ready(false);
            ui.set_can_moderate_members(false);
            ui.set_window_invite_banner("".into());
            ui.set_window_invite_network("".into());
            ui.set_window_invite_channel("".into());
            ui.set_window_invite_inviter("".into());
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
            ui.set_current_channel_modes("".into());
            ui.set_current_channel_label("".into());
            ui.set_current_window_is_joined(false);
            ui.set_has_selected_channel(false);
            ui.set_current_query(false);
            ui.set_current_query_ready(false);
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

    let tx_for_query_window = worker_tx.clone();
    ui.on_query_selected(move |network, nick| {
        let _ = tx_for_query_window.send(WorkerCommand::SelectQuery {
            network: network.to_string(),
            nick: nick.to_string(),
        });
    });

    // The invitation banner deliberately does not auto-focus a window. Its
    // explicit Join action only opens the invited row; the server remains the
    // authority for the subsequent pending/joined transition.
    let tx_for_window_invite = worker_tx.clone();
    ui.on_window_invite_join_requested(move |network, channel| {
        let _ = tx_for_window_invite.send(WorkerCommand::SelectChannel {
            network: network.to_string(),
            channel: channel.to_string(),
        });
    });

    let tx_for_dismiss_kicked_channel = worker_tx.clone();
    ui.on_kicked_channel_dismiss_requested(move |network, channel| {
        let _ = tx_for_dismiss_kicked_channel.send(WorkerCommand::DismissKickedChannel {
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
    Pending,
    Invited,
    Joined,
    Failed,
    Kicked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowFailure {
    reason: Option<String>,
    numeric: Option<Number>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WindowKick {
    by: Option<String>,
    reason: Option<String>,
}

/// Last complete `channel_modes_changed` snapshot for a network/channel.
/// `params` is retained even though the initial UI only renders the compact
/// mode letters; Cicchetto treats this event as a full replacement snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ChannelModes {
    modes: Vec<String>,
    params: HashMap<String, Option<String>>,
}

/// One open Grappa query window. `opened_at` is retained from the server's
/// full snapshot so a unique stable opening can be matched across a nick
/// rename without guessing from list position.
#[derive(Clone, Debug, PartialEq, Eq)]
struct QueryWindow {
    network: String,
    target_nick: String,
    opened_at: String,
}

/// Stable per-window key used for server-provided unread counts. Channel
/// identity follows Cicchetto's ASCII-folded channel key; the network slug
/// remains exact.
type WindowCountsKey = (String, String);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct WindowCountSnapshot {
    messages: u64,
    mentions: u64,
}

#[derive(Clone, Debug)]
struct PendingOwnNickDm {
    network: String,
    sender: String,
    payload: Value,
    event_fallback: String,
}

const MAX_PENDING_OWN_NICK_DMS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
enum OwnNickListenerAction {
    Leave(String),
    Join(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnNickListenerJoinReply {
    Untracked,
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ChannelTopicAction {
    Leave(String),
    Join(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AwayStatus {
    Present,
    Away,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionIdentity {
    /// Authoritative NickServ/services verdict. This must not be inferred
    /// from `account`, which is descriptive and may be absent even here.
    identified: bool,
    account: Option<String>,
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
    /// Nullable kick metadata is retained like Cicchetto but not shown in
    /// the channel row.
    window_kicks: HashMap<(String, String), WindowKick>,
    /// Invitation markers are cleared by terminal window transitions. The
    /// marker is kept separately from the state enum so the banner can retain
    /// the server-provided inviter while the sidebar only needs the state.
    invited_by: HashMap<(String, String), String>,
    /// Server-authoritative counts from `window_counts` and `/me.unread_counts`.
    /// Mentions remain separate so the existing highlight badge is preserved.
    window_mentions: HashMap<WindowCountsKey, u64>,
    window_messages: HashMap<WindowCountsKey, u64>,
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
    /// Keyed by `(network, channel)`; the last complete channel-mode
    /// snapshot received on the Phoenix channel topic.
    channel_modes: HashMap<(String, String), ChannelModes>,
    /// Last server-confirmed read message ID per canonical channel-shaped
    /// window key. The network is preserved and only the channel segment is
    /// ASCII-folded, matching Cicchetto's channel key.
    read_cursors: HashMap<(String, String), i64>,
    /// Account-wide unread badge from `/me` or the latest read-cursor push.
    badge_count: u64,
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
    /// Channel topics owned by the latest authoritative `/boot` snapshot.
    /// This stays separate because `joined_topics` also includes query and
    /// own-nick listeners that may share the same channel-shaped topic.
    channel_topics: std::collections::HashSet<String>,
    /// Full replacement from `query_windows_list`; query rows live beside
    /// channel rows while retaining their own window identity.
    query_windows: Vec<QueryWindow>,
    /// Own-nick DMs can precede the authoritative query snapshot that Grappa
    /// emits after opening a sender's query. Hold only a small FIFO until that
    /// snapshot either confirms the query or proves it should be discarded.
    pending_own_nick_dms: VecDeque<PendingOwnNickDm>,
    /// Query topics whose Phoenix join was acknowledged successfully. Keys
    /// use the same network + ASCII-folded target identity as the snapshot.
    query_joined: std::collections::HashSet<(String, String)>,
    /// Query topics whose join and initial/refresh history load both
    /// completed; only these are ready for sending, like Cicchetto.
    query_ready: std::collections::HashSet<(String, String)>,
    /// Queries that received a buffered first DM before their initial history
    /// fetch; the join-ACK path must load the full tail, not just `after` the
    /// buffered message ID.
    query_full_history_required: std::collections::HashSet<(String, String)>,
    /// Query keys removed/renamed by a later full snapshot. Since Grappa
    /// shares the channel-shaped Phoenix topic for channels and queries,
    /// remember these identities so their late frames are ignored without
    /// swallowing ordinary channel traffic.
    stale_query_topics: std::collections::HashSet<(String, String)>,
    /// Channel-selection MRU, used when a dismissed pseudo-window was open.
    recent_channels: Vec<(String, String)>,
    /// `current_channel` is the active window's `(network, target)` key;
    /// this flag disambiguates query topics from channel topics.
    current_query: bool,
    current_query_ready: bool,
    current_channel: Option<(String, String)>,
    /// Network slug -> Grappa's own integer `network_id`, read from
    /// `boot.networks`. WS commands like `/links` need the integer id,
    /// never the slug — see `docs/protocol-notes.md` §4ter for why this
    /// isn't just string-vs-int bikeshedding: the server hard-rejects a
    /// non-integer `network_id` (`is_integer/1` guard), no slug fallback.
    network_ids: HashMap<String, i64>,
    /// Current IRC nick for each network, seeded from `/boot.networks` and
    /// replaced by `own_nick_changed` on the matching network only.
    own_nicks: HashMap<String, String>,
    /// Last server-confirmed self away state, kept independently per network
    /// so a late away ACK cannot reset other per-network or message state.
    away_states: HashMap<String, AwayStatus>,
    /// Last server-confirmed services identity for each network. Snapshot and
    /// live `session_identity_changed` events share this same replacement
    /// path; `identified` remains authoritative when `account` is `None`.
    session_identities: HashMap<String, SessionIdentity>,
    /// Last complete IRC ISUPPORT snapshot for each known network. Live and
    /// replayed `isupport_changed` events replace only their own network.
    isupport_by_network: HashMap<String, IsupportState>,
    /// Ordered set of active IRC user modes for each known network. Live and
    /// replayed `umode_changed` snapshots replace only their own network.
    user_modes_by_network: HashMap<String, Vec<String>>,
    /// Ordered set of IRC user modes advertised as supported by each known
    /// network. This is intentionally separate from the active modes above;
    /// live and replayed `supported_umodes_changed` snapshots replace only
    /// their own network.
    supported_user_modes_by_network: HashMap<String, Vec<String>>,
    /// Own-nick listener topics become usable only after a successful
    /// Phoenix join reply. Keys are canonical topic strings.
    own_listener_ready: std::collections::HashSet<String>,
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
            window_kicks: HashMap::new(),
            invited_by: HashMap::new(),
            window_mentions: HashMap::new(),
            window_messages: HashMap::new(),
            messages: HashMap::new(),
            drafts: HashMap::new(),
            topics: HashMap::new(),
            channel_modes: HashMap::new(),
            read_cursors: HashMap::new(),
            badge_count: 0,
            members: HashMap::new(),
            expanded_networks: HashMap::new(),
            channel_entries: Vec::new(),
            channel_topics: std::collections::HashSet::new(),
            query_windows: Vec::new(),
            pending_own_nick_dms: VecDeque::new(),
            query_joined: std::collections::HashSet::new(),
            query_ready: std::collections::HashSet::new(),
            query_full_history_required: std::collections::HashSet::new(),
            stale_query_topics: std::collections::HashSet::new(),
            recent_channels: Vec::new(),
            current_query: false,
            current_query_ready: false,
            current_channel: None,
            network_ids: HashMap::new(),
            own_nicks: HashMap::new(),
            away_states: HashMap::new(),
            session_identities: HashMap::new(),
            isupport_by_network: HashMap::new(),
            user_modes_by_network: HashMap::new(),
            supported_user_modes_by_network: HashMap::new(),
            own_listener_ready: std::collections::HashSet::new(),
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
                    Some(WorkerCommand::SelectQuery { network, nick }) => {
                        handle_select_query(&mut state, &ui, network, nick).await;
                    }
                    Some(WorkerCommand::DismissKickedChannel { network, channel }) => {
                        handle_dismiss_kicked_channel(&mut state, &ui, network, channel).await;
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
                        state.current_query = false;
                        state.current_query_ready = false;
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
                        handle_frame(&mut state, &ui, frame).await;
                    }
                    Some(SessionEvent::Disconnected { reason }) => {
                        persistence::log_line(&format!("session disconnected: {reason}"));
                        reset_query_session_readiness(&mut state);
                        state.own_listener_ready.clear();
                        state.supported_user_modes_by_network.clear();
                        let _ = ui.upgrade_in_event_loop(move |ui| {
                            ui.set_status_kind("disconnected".into());
                            ui.set_status_message(reason.into());
                            ui.set_current_query_ready(false);
                        });
                    }
                    Some(SessionEvent::Reconnecting { reason }) => {
                        persistence::log_line(&format!("session reconnecting: {reason}"));
                        reset_query_session_readiness(&mut state);
                        state.own_listener_ready.clear();
                        state.supported_user_modes_by_network.clear();
                        let _ = ui.upgrade_in_event_loop(move |ui| {
                            ui.set_status_kind("reconnecting".into());
                            ui.set_status_message(reason.into());
                            ui.set_current_query_ready(false);
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
            state.query_windows.clear();
            state.pending_own_nick_dms.clear();
            state.query_joined.clear();
            state.query_ready.clear();
            state.query_full_history_required.clear();
            state.stale_query_topics.clear();
            state.window_states = joined_window_states_from_boot_channels(&outcome.boot.channels);
            state.window_failures.clear();
            state.window_kicks.clear();
            state.invited_by.clear();
            state.window_mentions = window_mentions_from_me(&outcome.me.unread_counts);
            state.window_messages = window_messages_from_me(&outcome.me.unread_counts);
            state.recent_channels.clear();
            state.topics = topics_from_boot(&outcome);
            // Mode snapshots are replayed on each subscribed channel topic,
            // not included in `/boot`; never carry them across identities.
            state.channel_modes.clear();
            // `/me` is the cold seed for the server-authoritative read cursor
            // and account-wide badge; replace prior identity state before
            // opening the new Phoenix session.
            state.read_cursors = read_cursors_from_me(&outcome.me.read_cursors);
            state.badge_count = normalize_badge_count(Some(&outcome.me.badge_count));
            state.members = members_from_boot(&outcome);
            state.messages = messages_from_boot(&outcome);
            state.network_ids = network_ids_from_boot(&outcome);
            state.own_nicks = network_nicks_from_boot(&outcome);
            state.away_states.clear();
            state.session_identities.clear();
            state.isupport_by_network.clear();
            state.user_modes_by_network.clear();
            state.supported_user_modes_by_network.clear();
            state.own_listener_ready.clear();
            state.current_query = false;
            state.current_query_ready = false;
            state.current_channel = None;
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
            for (network, nick) in &state.own_nicks {
                handle.join_topic(
                    own_nick_listener_topic(&session_identifier, network, nick),
                    false,
                );
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
            state.channel_topics = channel_topics_for_entries(&session_identifier, &entries);
            for (network, nick) in &state.own_nicks {
                state.joined_topics.insert(own_nick_listener_topic(
                    &session_identifier,
                    network,
                    nick,
                ));
            }

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
            let groups_data =
                network_groups_data(&entries, &state.query_windows, &state.expanded_networks);
            let window_states = state.window_states.clone();
            let window_mentions = state.window_mentions.clone();
            let window_messages = state.window_messages.clone();
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
                ui.set_window_invite_banner("".into());
                ui.set_window_invite_network("".into());
                ui.set_window_invite_channel("".into());
                ui.set_window_invite_inviter("".into());
                ui.set_current_query(false);
                ui.set_current_query_ready(false);
                let networks: Vec<slint::SharedString> =
                    distinct_networks.into_iter().map(Into::into).collect();
                ui.set_known_networks(Rc::new(slint::VecModel::from(networks)).into());
                let groups = network_groups_model(
                    groups_data,
                    window_states,
                    window_mentions,
                    window_messages,
                );
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
    state
        .recent_channels
        .retain(|(known_network, known_channel)| {
            window_state_key(known_network, known_channel) != window_state_key(&network, &channel)
        });
    state.recent_channels.insert(0, key.clone());
    state.current_query = false;
    state.current_query_ready = false;
    state.current_channel = Some(key.clone());

    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.last_channel = Some(key.clone());
    let _ = persistence::save_settings(&settings);

    let lines = state.messages.get(&key).cloned().unwrap_or_default();
    let draft = state.drafts.get(&key).cloned().unwrap_or_default();
    let irc_topic = state.topics.get(&key).cloned().unwrap_or_default();
    let channel_modes = state
        .channel_modes
        .get(&key)
        .map(|snapshot| format_channel_modes(&snapshot.modes))
        .unwrap_or_default();
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
        ui.set_current_channel_modes(channel_modes.into());
        ui.set_current_window_is_joined(window_is_joined);
        ui.set_has_selected_channel(true);
        ui.set_current_query(false);
        ui.set_current_query_ready(false);
        ui.set_compose_text(draft.into());
        ui.set_can_moderate_members(can_moderate);
        let model = chat_lines_model(&lines, dark_theme);
        ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        let member_rows = members_model(&members, dark_theme);
        ui.set_channel_members(Rc::new(slint::VecModel::from(member_rows)).into());
    });
}

/// Selects a query row already present in the server-owned snapshot. Joining
/// the query topic only subscribes to its realtime stream; it never sends an
/// IRC JOIN. The server's snapshot is the authority for whether the window is
/// currently open.
async fn handle_select_query(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    nick: String,
) {
    let Some(query) = find_query_window(&state.query_windows, &network, &nick).cloned() else {
        return;
    };
    let Some(identifier) = state.identifier.clone() else {
        return;
    };

    let topic = query_topic(&identifier, &query.network, &query.target_nick);
    if let Some(handle) = &state.session {
        if state.joined_topics.insert(topic.clone()) {
            handle.join_topic(topic, false);
        }
    }

    let key = (query.network.clone(), query.target_nick.clone());
    let identity = query_window_key(&query.network, &query.target_nick);
    state.current_query = true;
    state.current_query_ready = state.query_ready.contains(&identity);
    state.current_channel = Some(key.clone());
    show_query_window(state, ui, &query, &key);

    // Cicchetto loads the latest page when a query is selected, independently
    // of the history refresh that follows the Phoenix join ACK. The endpoint's
    // default page is newest-first, so merge_query_history restores chronological
    // display order and deduplicates any messages received live in the meantime.
    if fetch_query_history(state, &query, None, None).await {
        state.query_full_history_required.remove(&identity);
        mark_query_ready_after_history(state, &identity);
        show_query_window(state, ui, &query, &key);
    }
}

fn show_query_window(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    query: &QueryWindow,
    key: &(String, String),
) {
    let lines = state.messages.get(key).cloned().unwrap_or_default();
    let draft = state.drafts.get(key).cloned().unwrap_or_default();
    let dark_theme = state.theme == Theme::Dark;
    let query_ready = state.current_query_ready;
    let label = format!("{} — {}", query.network, query.target_nick);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_channel_label(label.into());
        ui.set_current_topic("".into());
        ui.set_current_channel_modes("".into());
        ui.set_current_window_is_joined(false);
        ui.set_has_selected_channel(true);
        ui.set_current_query(true);
        ui.set_current_query_ready(query_ready);
        ui.set_compose_text(draft.into());
        ui.set_can_moderate_members(false);
        let model = chat_lines_model(&lines, dark_theme);
        ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
        ui.set_channel_members(empty_members.into());
    });
}

async fn fetch_query_history(
    state: &mut WorkerState,
    query: &QueryWindow,
    after_id: Option<i64>,
    limit: Option<usize>,
) -> bool {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return false;
    };
    let rows = match client
        .fetch_messages(&token, &query.network, &query.target_nick, after_id, limit)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            persistence::log_line(&format!(
                "query history fetch failed for {}/{}: {error:?}",
                query.network, query.target_nick
            ));
            return false;
        }
    };

    // A newer full snapshot can close/rename this query while the request is
    // in flight. The worker serializes awaits today, but retain the guard so a
    // later async refactor cannot resurrect a stale conversation.
    if find_query_window(&state.query_windows, &query.network, &query.target_nick).is_none() {
        return false;
    }
    let key = (query.network.clone(), query.target_nick.clone());
    merge_query_history(state, &key, &rows);
    true
}

fn mark_query_ready_after_history(state: &mut WorkerState, identity: &(String, String)) {
    if !state.query_joined.contains(identity) {
        return;
    }
    state.query_ready.insert(identity.clone());
    if state.current_query
        && state
            .current_channel
            .as_ref()
            .is_some_and(|(network, nick)| &query_window_key(network, nick) == identity)
    {
        state.current_query_ready = true;
    }
}

/// Dismisses a kicked pseudo-window with the same optimistic semantics as
/// Cicchetto: authenticated REST PART in the background, then local window
/// removal immediately. If the dismissed window was selected, return to the
/// most-recent remaining channel or the server/home view.
async fn handle_dismiss_kicked_channel(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    channel: String,
) {
    if !window_is_kicked(&state.window_states, &network, &channel) {
        return;
    }
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };

    let part_network = network.clone();
    let part_channel = channel.clone();
    tokio::spawn(async move {
        if let Err(err) = client
            .part_channel(&token, &part_network, &part_channel, None)
            .await
        {
            persistence::log_line(&format!("kicked channel part failed: {err:?}"));
        }
    });

    let Some(selected) = dismiss_kicked_window_locally(state, &network, &channel) else {
        return;
    };
    refresh_network_groups(state, ui);

    if !selected {
        return;
    }

    let next_channel = state
        .recent_channels
        .iter()
        .find(|(recent_network, recent_channel)| {
            state
                .channel_entries
                .iter()
                .any(|(entry_network, entry_channel, _)| {
                    window_state_key(recent_network, recent_channel)
                        == window_state_key(entry_network, entry_channel)
                })
        })
        .cloned();
    if let Some((next_network, next_channel)) = next_channel {
        handle_select_channel(state, ui, next_network, next_channel).await;
        return;
    }

    state.current_channel = None;
    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.last_channel = None;
    let _ = persistence::save_settings(&settings);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let empty_lines = Rc::new(slint::VecModel::from(Vec::<ChatLine>::new()));
        let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
        ui.set_has_selected_channel(false);
        ui.set_current_channel_label("".into());
        ui.set_current_topic("".into());
        ui.set_current_channel_modes("".into());
        ui.set_current_window_is_joined(false);
        ui.set_can_moderate_members(false);
        ui.set_compose_text("".into());
        ui.set_chat_lines(empty_lines.into());
        ui.set_channel_members(empty_members.into());
    });
}

/// Cicchetto's `forceParted` projection for a kicked channel: remove its
/// lifecycle metadata and cached modes immediately after REST PART. The
/// sidebar channel list is maintained separately by Cordiale.
fn force_parted_kicked_window(state: &mut WorkerState, network: &str, channel: &str) -> bool {
    if !window_is_kicked(&state.window_states, network, channel) {
        return false;
    }

    let key = window_state_key(network, channel);
    state.window_states.remove(&key);
    state.window_failures.remove(&key);
    state.window_kicks.remove(&key);
    state.invited_by.remove(&key);
    state
        .channel_modes
        .retain(|(known_network, known_channel), _| {
            window_state_key(known_network, known_channel) != key
        });
    true
}

/// Applies the kicked-row portion of Cicchetto's close action locally and
/// reports whether that pseudo-window was selected, without changing the
/// current selection or its MRU ordering.
fn dismiss_kicked_window_locally(
    state: &mut WorkerState,
    network: &str,
    channel: &str,
) -> Option<bool> {
    let key = window_state_key(network, channel);
    let selected =
        state
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_channel)| {
                window_state_key(current_network, current_channel) == key
            });
    if !force_parted_kicked_window(state, network, channel) {
        return None;
    }
    remove_sidebar_channel_entry(&mut state.channel_entries, network, channel);
    Some(selected)
}

/// Removes a dismissed channel from Cordiale's current sidebar projection.
fn remove_sidebar_channel_entry(
    entries: &mut Vec<(String, String, String)>,
    network: &str,
    channel: &str,
) -> bool {
    let key = window_state_key(network, channel);
    let previous_len = entries.len();
    entries.retain(|(entry_network, entry_channel, _)| {
        window_state_key(entry_network, entry_channel) != key
    });
    entries.len() != previous_len
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
    if state.current_query && !state.current_query_ready {
        return;
    }
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
    if state.current_query {
        return None;
    }
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

/// Asks Grappa to open a DM window with `nick`; the resulting
/// `query_windows_list` snapshot drives Cordiale's query rows and topic
/// subscriptions.
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
    // kicked, topic_changed, channel_modes_changed, and members_seeded/names_reply
    // are handled above.
    "bundle_hash",
    // session/wire.ex's wire_event_kind union.
    "channel_created",
    "who_reply",
    "server_reply",
    "dcc_offer",
    "dcc_offer_resolved",
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

fn reset_query_session_readiness(state: &mut WorkerState) {
    state.query_joined.clear();
    state.query_ready.clear();
    state.current_query_ready = false;
}

fn record_query_join_success(state: &mut WorkerState, identity: &(String, String)) {
    state.query_joined.insert(identity.clone());
}

fn reset_query_join_failure(
    state: &mut WorkerState,
    identity: &(String, String),
    topic: &str,
) -> bool {
    state.query_joined.remove(identity);
    state.query_ready.remove(identity);
    state.joined_topics.remove(topic);
    let selected = state.current_query
        && state
            .current_channel
            .as_ref()
            .is_some_and(|(network, nick)| &query_window_key(network, nick) == identity);
    if selected {
        state.current_query_ready = false;
    }
    selected
}

async fn handle_query_join_reply(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    topic: &str,
    status: Option<&str>,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network, nick)) = query_from_topic(identifier, topic) else {
        return;
    };
    let (identity, query) = match resolve_query_topic(
        &state.query_windows,
        &state.stale_query_topics,
        &network,
        &nick,
    ) {
        QueryTopicResolution::Active(query) => (
            query_window_key(&query.network, &query.target_nick),
            Some(query.clone()),
        ),
        QueryTopicResolution::Stale => (query_window_key(&network, &nick), None),
        QueryTopicResolution::Untracked => return,
    };

    if status != Some("ok") {
        let selected = reset_query_join_failure(state, &identity, topic);
        if selected {
            let ui = ui.clone();
            let _ = ui.upgrade_in_event_loop(|ui| ui.set_current_query_ready(false));
        }
        persistence::log_line(&format!(
            "query topic join was not acknowledged: {network}/{nick}"
        ));
        return;
    }

    record_query_join_success(state, &identity);
    let Some(query) = query else {
        // Cicchetto leaves old query topics joined for the session lifetime.
        // Remember the ACK so a later close→reopen can reuse that topic; the
        // selected query will load its latest tail before becoming ready.
        return;
    };
    let key = (query.network.clone(), query.target_nick.clone());
    let (high_water, limit) = query_history_fetch_window(state, &identity, &key);

    // Phoenix's join reply is only the window/cursor seed; it carries no
    // message rows. Fetch the after-page from Grappa, using a known local
    // message ID as a high-water mark when available, and fall back to the
    // normal tail page rather than treating read_cursor as a message ID.
    if !fetch_query_history(state, &query, high_water, limit).await {
        return;
    }
    state.query_full_history_required.remove(&identity);
    mark_query_ready_after_history(state, &identity);

    let selected = state.current_query
        && state
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_nick)| {
                query_window_key(current_network, current_nick) == identity
            });
    if selected {
        show_query_window(state, ui, &query, &key);
    }
}

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
async fn handle_frame(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    frame: cordiale_core::phoenix::PhoenixMessage,
) {
    if frame.event == "phx_reply" {
        let status = frame.payload.get("status").and_then(Value::as_str);
        if apply_window_counts_join_reply(state, &frame.topic, &frame.payload, status) {
            refresh_network_groups(state, ui);
        }
        if handle_own_nick_listener_join_reply(state, &frame.topic, status)
            == OwnNickListenerJoinReply::Rejected
        {
            persistence::log_line(&format!(
                "own-nick listener join was not acknowledged: {}",
                frame.topic
            ));
        }
        handle_query_join_reply(state, ui, &frame.topic, status).await;
        return;
    }

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
    if payload_kind == "channels_changed" {
        handle_channels_changed(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "network_detached" {
        handle_network_detached(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "network_attached" {
        handle_network_attached(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "own_nick_changed" {
        handle_own_nick_changed(state, &frame.topic, &frame.payload);
        return;
    }
    // `read_cursor_set` omits both network and target from its payload; the
    // Phoenix channel topic is its window identity. Cicchetto applies these
    // authoritative pushes last-write-wins, including a lower cursor from a
    // later-arriving frame, and treats the account-wide badge separately.
    if payload_kind == "read_cursor_set" {
        if let Some(identifier) = state.identifier.clone() {
            apply_read_cursor_set(state, &identifier, &frame.topic, &frame.payload);
        }
        return;
    }
    if payload_kind == "away_confirmed" {
        handle_away_confirmed(state, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "session_identity_changed" {
        handle_session_identity_changed(state, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "isupport_changed" {
        handle_isupport_changed(state, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "umode_changed" {
        handle_umode_changed(state, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "supported_umodes_changed" {
        handle_supported_umodes_changed(state, &frame.topic, &frame.payload);
        return;
    }
    if frame.event == "links_bundle" || payload_kind == "links_bundle" {
        handle_links_bundle(ui, &frame.payload);
        return;
    }

    if payload_kind == "query_windows_list" {
        handle_query_windows_list(state, ui, &frame.topic, &frame.payload);
        return;
    }

    // A JOIN accepted by Grappa first creates a transient window on the user
    // topic. Subscribe immediately to the channel-shaped topic so the
    // subsequent `joined` or `join_failed` transition cannot race past this
    // client. Unlike those terminal states, `window_pending` is live-only and
    // must never be accepted from a channel reconnect snapshot.
    if payload_kind == "window_pending" {
        handle_window_pending(state, ui, &frame.topic, &frame.payload);
        return;
    }

    // An invitation is replayable on the user topic, unlike the live-only
    // pending transition. Store it immediately and join the matching channel
    // topic so the eventual `joined`/`join_failed` event cannot race us.
    if payload_kind == "window_invited" {
        handle_window_invited(state, ui, &frame.topic, &frame.payload);
        return;
    }

    // A declined invitation is a terminal removal broadcast on the user
    // topic. The server has already removed the invited window, so there is
    // no client-side IRC DECLINE command and no replacement `declined` state.
    if payload_kind == "window_invite_declined" {
        handle_window_invite_declined(state, ui, &frame.topic, &frame.payload);
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

    if let Some(network) = own_nick_listener_network_for_topic(state, &frame.topic) {
        if payload_kind == "window_counts" {
            handle_window_counts(state, ui, &frame.topic, &frame.payload);
            return;
        }
        if payload_kind == "message"
            && state.own_listener_ready.contains(&frame.topic)
            && own_nick_listener_accepts_inbound_dm(effective_payload)
        {
            if let Some(key) = own_nick_dm_query_key(state, &network, effective_payload) {
                require_query_full_history_if_unready(state, &key);
                if append_query_live_message(state, &key, effective_payload, Some(&frame.event))
                    && state.current_query
                    && state.current_channel.as_ref() == Some(&key)
                {
                    let lines = state.messages[&key].clone();
                    let dark_theme = state.theme == Theme::Dark;
                    let ui = ui.clone();
                    let _ = ui.upgrade_in_event_loop(move |ui| {
                        let model = chat_lines_model(&lines, dark_theme);
                        ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
                    });
                }
            } else {
                buffer_pending_own_nick_dm(state, &network, effective_payload, &frame.event);
            }
        }
        return;
    }

    if payload_kind == "topic_changed" {
        handle_topic_changed(state, ui, &frame.payload);
        return;
    }

    if payload_kind == "channel_modes_changed" {
        handle_channel_modes_changed(state, ui, &frame.topic, &frame.payload);
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
            &mut state.window_kicks,
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
        refresh_invite_banner(state, ui);
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
            &mut state.window_kicks,
            &mut state.invited_by,
            &network,
            &channel,
            failure,
        );
        let sidebar_changed =
            upsert_channel_entry(&mut state.channel_entries, network.clone(), channel.clone());
        let selected_window_failed =
            state
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
        refresh_invite_banner(state, ui);
        if state_changed || sidebar_changed {
            refresh_network_groups(state, ui);
        }
        return;
    }

    // A kick becomes a retained, muted pseudo-window just like Cicchetto's
    // UI state. The server sends it live on the user topic and as a cold
    // snapshot on the matching channel topic; query/DM topics are rejected
    // by the parser. Keep the by/reason metadata in session state only.
    if payload_kind == "kicked" {
        let Some(identifier) = state.identifier.as_deref() else {
            return;
        };
        let Some((network, channel, kick)) =
            parse_kicked_event(&frame.payload, &frame.topic, identifier)
        else {
            return;
        };

        let state_changed = set_kicked_window_state(
            &mut state.window_states,
            &mut state.window_failures,
            &mut state.window_kicks,
            &mut state.invited_by,
            &network,
            &channel,
            kick,
        );
        let sidebar_changed =
            upsert_channel_entry(&mut state.channel_entries, network.clone(), channel.clone());
        let key = window_state_key(&network, &channel);
        state.members.retain(|(known_network, known_channel), _| {
            window_state_key(known_network, known_channel) != key
        });
        let selected_window_kicked =
            state
                .current_channel
                .as_ref()
                .is_some_and(|(current_network, current_channel)| {
                    window_state_key(current_network, current_channel) == key
                });

        if selected_window_kicked {
            let ui = ui.clone();
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_current_window_is_joined(false);
                ui.set_can_moderate_members(false);
                let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
                ui.set_channel_members(empty_members.into());
            });
        }
        refresh_invite_banner(state, ui);
        if state_changed || sidebar_changed {
            refresh_network_groups(state, ui);
        }
        return;
    }

    if payload_kind == "window_counts" {
        handle_window_counts(state, ui, &frame.topic, &frame.payload);
        return;
    }

    if IGNORED_KINDS.contains(&payload_kind) {
        return;
    }

    if let Some((network, topic_nick)) = state
        .identifier
        .as_deref()
        .and_then(|identifier| query_from_topic(identifier, &frame.topic))
    {
        match resolve_query_topic(
            &state.query_windows,
            &state.stale_query_topics,
            &network,
            &topic_nick,
        ) {
            QueryTopicResolution::Active(query) => {
                let key = (query.network.clone(), query.target_nick.clone());
                append_query_live_message(state, &key, effective_payload, Some(&frame.event));

                if state.current_query && state.current_channel.as_ref() == Some(&key) {
                    let lines = state.messages[&key].clone();
                    let dark_theme = state.theme == Theme::Dark;
                    let ui = ui.clone();
                    let _ = ui.upgrade_in_event_loop(move |ui| {
                        let model = chat_lines_model(&lines, dark_theme);
                        ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
                    });
                }
                return;
            }
            QueryTopicResolution::Stale => {
                // The topic can remain joined after its query row disappears;
                // the full snapshot is authoritative, so don't render late
                // data from the obsolete conversation.
                return;
            }
            QueryTopicResolution::Untracked => {
                // The query parser starts from the common `/channel:` form.
                // A channel that isn't in the query snapshot must continue
                // into the normal channel message path below.
            }
        }
    }

    let Some((network, channel)) = channel_from_topic(&frame.topic) else {
        return;
    };

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

/// Applies a complete `channel_modes_changed` snapshot. This event replaces,
/// rather than incrementally mutates, the cached modes for its channel.
fn handle_channel_modes_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    topic: &str,
    payload: &Value,
) {
    let Some((key, label)) = apply_channel_modes_changed(state, topic, payload) else {
        return;
    };
    if state.current_channel.as_ref() == Some(&key) {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            ui.set_current_channel_modes(label.into());
        });
    }
}

/// Stores one full mode snapshot and returns its `(network, channel)` key and
/// compact display label when the payload satisfies the wire contract.
fn apply_channel_modes_changed(
    state: &mut WorkerState,
    topic: &str,
    payload: &Value,
) -> Option<((String, String), String)> {
    let (key, snapshot) = parse_channel_modes_changed(payload)?;
    // Cicchetto consumes this kind only on its per-channel Phoenix topic;
    // require the payload identity to agree with that topic as well.
    if channel_from_topic(topic).as_ref() != Some(&key) {
        return None;
    }
    let label = format_channel_modes(&snapshot.modes);
    state.channel_modes.insert(key.clone(), snapshot);
    Some((key, label))
}

/// Parses `{ network, channel, modes: { modes: string[], params:
/// Record<string, string | null> } }`. Unknown fields are ignored, while
/// malformed values are rejected instead of corrupting the cached snapshot.
fn parse_channel_modes_changed(payload: &Value) -> Option<((String, String), ChannelModes)> {
    let network = payload.get("network")?.as_str()?.to_owned();
    let channel = payload.get("channel")?.as_str()?.to_owned();
    let mode_state = payload.get("modes")?.as_object()?;
    let modes = mode_state
        .get("modes")?
        .as_array()?
        .iter()
        .map(|mode| mode.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let params = mode_state
        .get("params")?
        .as_object()?
        .iter()
        .map(|(name, value)| {
            let value = if value.is_null() {
                None
            } else {
                Some(value.as_str()?.to_owned())
            };
            Some((name.clone(), value))
        })
        .collect::<Option<HashMap<_, _>>>()?;

    Some(((network, channel), ChannelModes { modes, params }))
}

/// Uses the same network-exact, ASCII-folded window identity as Cicchetto.
fn window_counts_key(network: &str, channel: &str) -> WindowCountsKey {
    (network.to_string(), ascii_fold_channel(channel))
}

/// Produces a compact visible suffix plus a descriptive accessible suffix.
fn mention_count_labels(count: u64) -> (String, String) {
    if count == 0 {
        (String::new(), String::new())
    } else {
        (format!(" ({count})"), format!(" — {count} mentions"))
    }
}

/// Keeps the unread-count column visually quiet at zero while retaining an
/// accessible description for an authoritative zero. Missing data is not a
/// zero and therefore produces no description.
fn unread_message_count_labels(count: Option<u64>) -> (String, String) {
    match count {
        None => (String::new(), String::new()),
        Some(0) => (String::new(), "0 unread messages".to_string()),
        Some(count) => (count.to_string(), format!("{count} unread messages")),
    }
}

/// Validates the complete counts object used by `/me`, join replies, and live
/// `window_counts` pushes. Severity is informational: as in the existing
/// mainline behavior, a missing or future string value is accepted while a
/// present non-string value is malformed. Extra fields remain additive.
fn parse_window_count_snapshot(snapshot: &Value) -> Option<WindowCountSnapshot> {
    let messages = snapshot.get("messages")?.as_u64()?;
    let mentions = snapshot.get("mentions")?.as_u64()?;
    let _events = snapshot.get("events")?.as_u64()?;
    if let Some(severity) = snapshot.get("severity") {
        let _severity = severity.as_str()?;
    }
    Some(WindowCountSnapshot { messages, mentions })
}

/// Validates a complete counts object, while returning only `mentions`.
/// Missing or unknown string severity values normalize to `none`; severity
/// does not affect the count. Extra fields are ignored for forward compatibility.
fn parse_window_count_mentions(snapshot: &Value) -> Option<u64> {
    parse_window_count_snapshot(snapshot).map(|counts| counts.mentions)
}

fn parse_window_count_messages(snapshot: &Value) -> Option<u64> {
    parse_window_count_snapshot(snapshot).map(|counts| counts.messages)
}

/// `/me.unread_counts` is a nested `network_slug -> target -> snapshot` map.
/// Invalid rows are omitted, never synthesized as zeroes.
fn window_count_field_from_me(
    value: &Value,
    count_field: impl Fn(&Value) -> Option<u64>,
) -> HashMap<WindowCountsKey, u64> {
    let mut counts = HashMap::new();
    let Some(networks) = value.as_object() else {
        return counts;
    };

    for (network, windows) in networks {
        if network.trim().is_empty() {
            continue;
        }
        let Some(windows) = windows.as_object() else {
            continue;
        };
        for (target, snapshot) in windows {
            if target.trim().is_empty() {
                continue;
            }
            if let Some(count) = count_field(snapshot) {
                counts.insert(window_counts_key(network, target), count);
            }
        }
    }
    counts
}

fn window_mentions_from_me(value: &Value) -> HashMap<WindowCountsKey, u64> {
    window_count_field_from_me(value, parse_window_count_mentions)
}

fn window_messages_from_me(value: &Value) -> HashMap<WindowCountsKey, u64> {
    window_count_field_from_me(value, parse_window_count_messages)
}

/// Validates a live snapshot against the channel-shaped topic that carried
/// it. The server-owned `channel` must agree with the topic under Cicchetto's
/// ASCII-folded channel equivalence.
fn parse_window_counts(
    payload: &Value,
    topic: &str,
    identifier: &str,
) -> Option<(WindowCountsKey, WindowCountSnapshot)> {
    if payload.get("kind")?.as_str()? != "window_counts" {
        return None;
    }
    let channel = payload.get("channel")?.as_str()?;
    if channel.trim().is_empty() {
        return None;
    }
    let counts = parse_window_count_snapshot(payload)?;

    let (network, _) = channel_from_topic(topic)?;
    if !channel_topic_matches(identifier, topic, &network, channel) {
        return None;
    }
    Some((window_counts_key(&network, channel), counts))
}

/// Cicchetto routes the own-nick listener's count to the self-message window,
/// keyed by the current own nick. Peer-DM counts arrive on each peer query's
/// own channel topic, not on this listener.
fn parse_own_nick_window_counts(
    state: &WorkerState,
    topic: &str,
    payload: &Value,
) -> Option<(WindowCountsKey, WindowCountSnapshot)> {
    if payload.get("kind")?.as_str()? != "window_counts" {
        return None;
    }
    let channel = payload.get("channel")?.as_str()?;
    if channel.trim().is_empty() {
        return None;
    }
    let counts = parse_window_count_snapshot(payload)?;
    let network = own_nick_listener_network_for_topic(state, topic)?;
    let own_nick = state.own_nicks.get(&network)?;
    if ascii_fold_channel(channel) != ascii_fold_channel(own_nick) {
        return None;
    }
    Some((window_counts_key(&network, own_nick), counts))
}

/// Applies one authoritative unread snapshot only to an existing channel or
/// query row. The own-nick listener is an exception: Cicchetto tracks its
/// self-message window even though it is not a peer query row.
fn apply_window_counts(state: &mut WorkerState, topic: &str, payload: &Value) -> bool {
    let own_nick_listener = own_nick_listener_network_for_topic(state, topic).is_some();
    let parsed = if own_nick_listener {
        parse_own_nick_window_counts(state, topic, payload)
    } else {
        state
            .identifier
            .as_deref()
            .and_then(|identifier| parse_window_counts(payload, topic, identifier))
    };
    let Some((key, counts)) = parsed else {
        return false;
    };
    let known_window = state
        .channel_entries
        .iter()
        .any(|(network, channel, _)| window_counts_key(network, channel) == key)
        || state
            .query_windows
            .iter()
            .any(|query| window_counts_key(&query.network, &query.target_nick) == key);
    if !known_window && !own_nick_listener {
        return false;
    }
    apply_window_count_snapshot(state, key, counts)
}

/// Reads the server-authoritative unread seed from a successful Phoenix join
/// reply. Missing or malformed counts default to zero, matching the join-reply
/// narrowing used by Cicchetto.
fn parse_window_counts_join_reply(
    identifier: &str,
    topic: &str,
    payload: &Value,
    status: Option<&str>,
) -> Option<(WindowCountsKey, WindowCountSnapshot)> {
    if status != Some("ok") {
        return None;
    }
    let (network, channel) = channel_from_topic(topic)?;
    if network.is_empty()
        || channel.is_empty()
        || !channel_topic_matches(identifier, topic, &network, &channel)
    {
        return None;
    }

    let counts = payload
        .get("response")
        .and_then(|response| response.get("window_counts"))
        .and_then(Value::as_object);
    let messages = counts
        .and_then(|counts| counts.get("messages"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let mentions = counts
        .and_then(|counts| counts.get("mentions"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    Some((
        window_counts_key(&network, &channel),
        WindowCountSnapshot { messages, mentions },
    ))
}

fn apply_window_counts_join_reply(
    state: &mut WorkerState,
    topic: &str,
    payload: &Value,
    status: Option<&str>,
) -> bool {
    let Some(identifier) = state.identifier.as_deref() else {
        return false;
    };
    let Some((key, counts)) = parse_window_counts_join_reply(identifier, topic, payload, status)
    else {
        return false;
    };
    apply_window_count_snapshot(state, key, counts)
}

fn apply_window_count_snapshot(
    state: &mut WorkerState,
    key: WindowCountsKey,
    counts: WindowCountSnapshot,
) -> bool {
    let mentions_changed = apply_window_mention_count(state, key.clone(), counts.mentions);
    let messages_changed = state.window_messages.get(&key) != Some(&counts.messages);
    if messages_changed {
        state.window_messages.insert(key, counts.messages);
    }
    mentions_changed || messages_changed
}

fn apply_window_mention_count(
    state: &mut WorkerState,
    key: WindowCountsKey,
    mentions: u64,
) -> bool {
    if mentions == 0 {
        return state.window_mentions.remove(&key).is_some();
    }
    if state.window_mentions.get(&key) == Some(&mentions) {
        return false;
    }
    state.window_mentions.insert(key, mentions);
    true
}

fn handle_window_counts(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    topic: &str,
    payload: &Value,
) {
    if apply_window_counts(state, topic, payload) {
        refresh_network_groups(state, ui);
    }
}

/// Drops counts for query rows that the latest full snapshot closed. Channel
/// counts and the own-nick self-message window remain until connection reset.
fn retain_window_counts_for_open_windows(state: &mut WorkerState) {
    let mut retained = std::collections::HashSet::new();
    retained.extend(
        state
            .channel_entries
            .iter()
            .map(|(network, channel, _)| window_counts_key(network, channel)),
    );
    retained.extend(
        state
            .query_windows
            .iter()
            .map(|query| window_counts_key(&query.network, &query.target_nick)),
    );
    retained.extend(
        state
            .own_nicks
            .iter()
            .map(|(network, nick)| window_counts_key(network, nick)),
    );
    state
        .window_mentions
        .retain(|key, _| retained.contains(key));
    state
        .window_messages
        .retain(|key, _| retained.contains(key));
}

/// Cicchetto's compact `+nt` form; empty-but-known modes remain distinguishable
/// from an unknown snapshot in `WorkerState::channel_modes`.
fn format_channel_modes(modes: &[String]) -> String {
    if modes.is_empty() {
        String::new()
    } else {
        format!("+{}", modes.join(""))
    }
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

/// Parses Cicchetto's required `kicked` payload from either the live user
/// topic or the matching per-channel cold snapshot. Nullable fields must be
/// present, but unknown additive fields are deliberately ignored.
fn parse_kicked_event(
    payload: &Value,
    topic: &str,
    identifier: &str,
) -> Option<(String, String, WindowKick)> {
    let object = payload.as_object()?;
    if object.get("kind").and_then(Value::as_str) != Some("kicked")
        || object.get("state").and_then(Value::as_str) != Some("kicked")
    {
        return None;
    }

    let network = object.get("network")?.as_str()?;
    let channel = object.get("channel")?.as_str()?;
    let by = match object.get("by")? {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        _ => return None,
    };
    let reason = match object.get("reason")? {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        _ => return None,
    };

    let user_topic = format!("grappa:user:{identifier}");
    if topic != user_topic && !channel_topic_matches(identifier, topic, network, channel) {
        return None;
    }

    Some((
        network.to_string(),
        channel.to_string(),
        WindowKick { by, reason },
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

/// Parses `/me.read_cursors`, keyed by network slug and target, into the same
/// `(network, ASCII-folded target)` key used for channel/query windows.
/// Absent, null, or malformed cursor entries are not fabricated.
fn read_cursors_from_me(value: &Value) -> HashMap<(String, String), i64> {
    let mut cursors = HashMap::new();
    let Some(networks) = value.as_object() else {
        return cursors;
    };

    for (network, windows) in networks {
        if network.is_empty() {
            continue;
        }
        let Some(windows) = windows.as_object() else {
            continue;
        };
        for (target, cursor) in windows {
            if target.is_empty() {
                continue;
            }
            if let Some(message_id) = cursor.as_i64() {
                cursors.insert(window_state_key(network, target), message_id);
            }
        }
    }

    cursors
}

/// Mirrors Cicchetto's account-wide badge normalization: invalid/non-positive
/// values become zero, positive fractions are floored, and the visible badge
/// is capped at 99.
fn normalize_badge_count(value: Option<&Value>) -> u64 {
    let Some(count) = value.and_then(Value::as_f64) else {
        return 0;
    };
    if !count.is_finite() || count <= 0.0 {
        return 0;
    }
    count.floor().min(99.0) as u64
}

/// Parses one channel-topic cursor push. The kind is checked again here so
/// the helper is safe to exercise independently in tests; an unrelated user
/// topic, foreign identity, empty window, or malformed cursor is rejected.
fn parse_read_cursor_set_event(
    identifier: &str,
    topic: &str,
    payload: &Value,
) -> Option<((String, String), i64, u64)> {
    if payload.get("kind").and_then(Value::as_str) != Some("read_cursor_set") {
        return None;
    }
    let (network, channel) = channel_from_topic(topic)?;
    if network.is_empty()
        || channel.is_empty()
        || !channel_topic_matches(identifier, topic, &network, &channel)
    {
        return None;
    }
    let last_read_message_id = payload.get("last_read_message_id")?.as_i64()?;
    let badge_count = normalize_badge_count(payload.get("badge_count"));
    Some((
        window_state_key(&network, &channel),
        last_read_message_id,
        badge_count,
    ))
}

/// Applies a server-authoritative cursor/badge update. A malformed required
/// cursor leaves both values unchanged; an omitted or malformed badge is
/// normalized to zero, as Cicchetto's badge setter does.
fn apply_read_cursor_set(
    state: &mut WorkerState,
    identifier: &str,
    topic: &str,
    payload: &Value,
) -> bool {
    let Some((key, last_read_message_id, badge_count)) =
        parse_read_cursor_set_event(identifier, topic, payload)
    else {
        return false;
    };

    let cursor_changed = state.read_cursors.get(&key).copied() != Some(last_read_message_id);
    let badge_changed = state.badge_count != badge_count;
    state.read_cursors.insert(key, last_read_message_id);
    state.badge_count = badge_count;
    cursor_changed || badge_changed
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

/// Parses the live-only `window_pending` transition. Grappa emits this on the
/// authenticated user topic before the channel subscription exists; accepting
/// it anywhere else would accidentally turn a channel snapshot into a seed.
/// Unknown additive fields are deliberately ignored for forward compatibility.
fn parse_window_pending_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String)> {
    if carrier_topic != format!("grappa:user:{identifier}")
        || payload.get("kind").and_then(Value::as_str) != Some("window_pending")
        || payload.get("state").and_then(Value::as_str) != Some("pending")
    {
        return None;
    }

    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    if network.is_empty() || channel.is_empty() {
        return None;
    }

    Some((network.to_string(), channel.to_string()))
}

/// Mirrors Cicchetto's pending-window reducer: replace any stale terminal
/// state and metadata without manufacturing history or a channel snapshot.
fn set_pending_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Pending)
        != Some(ChannelWindowState::Pending);
    let failure_cleared = window_failures.remove(&key).is_some();
    let kick_cleared = window_kicks.remove(&key).is_some();
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_cleared || kick_cleared || invite_cleared
}

fn register_pending_channel_topic(
    joined_topics: &mut std::collections::HashSet<String>,
    channel_topics: &mut std::collections::HashSet<String>,
    topic: String,
) -> bool {
    channel_topics.insert(topic.clone());
    joined_topics.insert(topic)
}

fn handle_window_pending(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.clone() else {
        return;
    };
    let Some((network, channel)) = parse_window_pending_event(payload, carrier_topic, &identifier)
    else {
        return;
    };
    // The event identifies a window on an already bootstrapped network. Do
    // not invent a new network from an unsolicited or stale payload.
    if !state.network_ids.contains_key(&network) {
        return;
    }

    let state_changed = set_pending_window_state(
        &mut state.window_states,
        &mut state.window_failures,
        &mut state.window_kicks,
        &mut state.invited_by,
        &network,
        &channel,
    );
    let sidebar_changed =
        upsert_channel_entry(&mut state.channel_entries, network.clone(), channel.clone());

    let topic = channel_topic(&identifier, &network, &channel);
    let subscription_added = register_pending_channel_topic(
        &mut state.joined_topics,
        &mut state.channel_topics,
        topic.clone(),
    );
    if let (true, Some(handle)) = (subscription_added, state.session.as_ref()) {
        handle.join_topic(topic, true);
    }

    let selected_window_pending =
        state
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_channel)| {
                window_state_key(current_network, current_channel)
                    == window_state_key(&network, &channel)
            });
    if selected_window_pending {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_current_window_is_joined(false);
            ui.set_can_moderate_members(false);
        });
    }
    refresh_invite_banner(state, ui);
    if state_changed || sidebar_changed {
        refresh_network_groups(state, ui);
    }
}

/// Parses the replayable `window_invited` transition. Grappa sends this only
/// on the authenticated user topic; accepting a matching channel-topic frame
/// would incorrectly seed invitation state from a channel snapshot.
/// Unknown additive fields remain tolerated, while the required `inviter`
/// field must be a JSON string (the server uses `"*"` when no prefix exists).
fn parse_window_invited_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String, String)> {
    if identifier.is_empty()
        || carrier_topic != format!("grappa:user:{identifier}")
        || payload.get("kind").and_then(Value::as_str) != Some("window_invited")
        || payload.get("state").and_then(Value::as_str) != Some("invited")
    {
        return None;
    }

    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    let inviter = payload.get("inviter").and_then(Value::as_str)?;
    if network.is_empty() || channel.is_empty() || inviter.is_empty() {
        return None;
    }

    Some((
        network.to_string(),
        channel.to_string(),
        inviter.to_string(),
    ))
}

/// Mirrors Cicchetto's invited-window reducer: replace any stale terminal
/// state, retain the required inviter for the Join banner, and make repeated
/// live/replay delivery idempotent.
fn set_invited_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
    inviter: String,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Invited)
        != Some(ChannelWindowState::Invited);
    let failure_cleared = window_failures.remove(&key).is_some();
    let kick_cleared = window_kicks.remove(&key).is_some();
    let inviter_changed = invited_by.get(&key) != Some(&inviter);
    invited_by.insert(key, inviter);
    state_changed || failure_cleared || kick_cleared || inviter_changed
}

/// Projects the most stable invited entry into the native banner. The
/// invitation itself must not change `current_channel`, so receiving a live
/// event never steals focus from the user's current window.
fn refresh_invite_banner(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let banner = state
        .invited_by
        .iter()
        .min_by(|(left, _), (right, _)| left.cmp(right))
        .map(|((network, channel), inviter)| {
            (
                format!("{network} {channel}"),
                network.clone(),
                channel.clone(),
                inviter.clone(),
            )
        });
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        if let Some((label, network, channel, inviter)) = banner {
            ui.set_window_invite_banner(
                format!("Invited to {label} by {inviter}. Select Join to open it.").into(),
            );
            ui.set_window_invite_network(network.into());
            ui.set_window_invite_channel(channel.into());
            ui.set_window_invite_inviter(inviter.into());
        } else {
            ui.set_window_invite_banner("".into());
            ui.set_window_invite_network("".into());
            ui.set_window_invite_channel("".into());
            ui.set_window_invite_inviter("".into());
        }
    });
}

fn handle_window_invited(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.clone() else {
        return;
    };
    let Some((network, channel, inviter)) =
        parse_window_invited_event(payload, carrier_topic, &identifier)
    else {
        return;
    };
    // Do not manufacture a sidebar/network entry from an invite for a stale
    // or unknown network; the bootstrap snapshot remains authoritative.
    if !state.network_ids.contains_key(&network) {
        return;
    }

    let state_changed = set_invited_window_state(
        &mut state.window_states,
        &mut state.window_failures,
        &mut state.window_kicks,
        &mut state.invited_by,
        &network,
        &channel,
        inviter,
    );
    let sidebar_changed =
        upsert_channel_entry(&mut state.channel_entries, network.clone(), channel.clone());

    let topic = channel_topic(&identifier, &network, &channel);
    let subscription_added = register_pending_channel_topic(
        &mut state.joined_topics,
        &mut state.channel_topics,
        topic.clone(),
    );
    if let (true, Some(handle)) = (subscription_added, state.session.as_ref()) {
        handle.join_topic(topic, true);
    }

    // The event is deliberately not an auto-focus request. If the invited
    // window is already selected, keep the roster hidden until `joined`.
    let selected_window_invited =
        state
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_channel)| {
                window_state_key(current_network, current_channel)
                    == window_state_key(&network, &channel)
            });
    if selected_window_invited {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_current_window_is_joined(false);
            ui.set_can_moderate_members(false);
        });
    }
    refresh_invite_banner(state, ui);
    if state_changed || sidebar_changed {
        refresh_network_groups(state, ui);
    }
}

/// Parses the terminal `window_invite_declined` transition. Grappa sends it
/// only on the authenticated user topic and intentionally omits `state`: the
/// server has already removed the invited window. Unknown additive fields are
/// tolerated for forward compatibility.
fn parse_window_invite_declined_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String)> {
    if identifier.is_empty()
        || carrier_topic != format!("grappa:user:{identifier}")
        || payload.get("kind").and_then(Value::as_str) != Some("window_invite_declined")
    {
        return None;
    }

    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    if network.trim().is_empty() || channel.trim().is_empty() {
        return None;
    }

    Some((network.to_string(), channel.to_string()))
}

/// Removes all lifecycle metadata for a declined invitation. In particular,
/// this also clears `Pending`, so a decline racing with the transient JOIN
/// state cannot leave a stale pseudo-row behind. No `declined` state is
/// created, and cached messages/drafts/topics remain untouched like
/// Cicchetto's `forceParted` projection.
fn clear_declined_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
) -> bool {
    let key = window_state_key(network, channel);
    let state_removed = window_states.remove(&key).is_some();
    let failure_removed = window_failures.remove(&key).is_some();
    let kick_removed = window_kicks.remove(&key).is_some();
    let invite_removed = invited_by.remove(&key).is_some();
    state_removed || failure_removed || kick_removed || invite_removed
}

/// Applies the server-authoritative removal to both lifecycle state and the
/// native sidebar projection. Repeated delivery is therefore a no-op.
fn remove_declined_window(state: &mut WorkerState, network: &str, channel: &str) -> bool {
    let lifecycle_changed = clear_declined_window_state(
        &mut state.window_states,
        &mut state.window_failures,
        &mut state.window_kicks,
        &mut state.invited_by,
        network,
        channel,
    );
    let sidebar_changed =
        remove_sidebar_channel_entry(&mut state.channel_entries, network, channel);
    lifecycle_changed || sidebar_changed
}

/// Removes the channel-topic subscription that was created for the invited
/// window, while preserving a topic still owned by an open query or the
/// own-nick listener (all three use the same Phoenix topic shape).
fn remove_declined_channel_subscription(
    state: &mut WorkerState,
    identifier: &str,
    network: &str,
    channel: &str,
) -> bool {
    let canonical_topic = channel_topic(identifier, network, &ascii_fold_channel(channel));
    let topic_is_owned_elsewhere =
        channel_topic_is_owned_elsewhere(state, identifier, &canonical_topic);
    let matching_channel_topics: Vec<String> = state
        .channel_topics
        .iter()
        .filter(|topic| channel_topic_matches(identifier, topic, network, channel))
        .cloned()
        .collect();
    let channel_topic_removed = !matching_channel_topics.is_empty();
    for topic in matching_channel_topics {
        state.channel_topics.remove(&topic);
    }

    let matching_joined_topics: Vec<String> = if topic_is_owned_elsewhere {
        Vec::new()
    } else {
        state
            .joined_topics
            .iter()
            .filter(|topic| channel_topic_matches(identifier, topic, network, channel))
            .cloned()
            .collect()
    };
    let joined_topic_removed = !matching_joined_topics.is_empty();
    for topic in matching_joined_topics {
        state.joined_topics.remove(&topic);
        if let Some(handle) = state.session.as_ref() {
            handle.leave_topic(topic);
        }
    }
    channel_topic_removed || joined_topic_removed
}

fn handle_window_invite_declined(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.clone() else {
        return;
    };
    let Some((network, channel)) =
        parse_window_invite_declined_event(payload, carrier_topic, &identifier)
    else {
        return;
    };
    // Bootstrap remains authoritative for known networks; malformed or stale
    // network names must not remove an unrelated row or lifecycle entry.
    if !state.network_ids.contains_key(&network) {
        return;
    }

    let window_changed = remove_declined_window(state, &network, &channel);
    let subscription_changed =
        remove_declined_channel_subscription(state, &identifier, &network, &channel);
    if window_changed || subscription_changed {
        refresh_invite_banner(state, ui);
        refresh_network_groups(state, ui);
    }
}

fn window_is_failed(
    window_states: &HashMap<(String, String), ChannelWindowState>,
    network: &str,
    channel: &str,
) -> bool {
    window_states.get(&window_state_key(network, channel)) == Some(&ChannelWindowState::Failed)
}

fn window_is_kicked(
    window_states: &HashMap<(String, String), ChannelWindowState>,
    network: &str,
    channel: &str,
) -> bool {
    window_states.get(&window_state_key(network, channel)) == Some(&ChannelWindowState::Kicked)
}

fn window_is_invited(
    window_states: &HashMap<(String, String), ChannelWindowState>,
    network: &str,
    channel: &str,
) -> bool {
    window_states.get(&window_state_key(network, channel)) == Some(&ChannelWindowState::Invited)
}

/// Adds a channel window to the session's sidebar source of truth after a
/// server-reported join, invitation, join failure, or kick. The return value
/// lets callers avoid rebuilding Slint models for duplicate delivery.
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
/// window-state value and clears stale invite/failure/kick metadata. Repeated
/// delivery on the live user topic and channel reconnect snapshot is
/// idempotent.
fn set_joined_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Joined)
        != Some(ChannelWindowState::Joined);
    let failure_cleared = window_failures.remove(&key).is_some();
    let kick_cleared = window_kicks.remove(&key).is_some();
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_cleared || kick_cleared || invite_cleared
}

/// Mirrors Cicchetto's `setFailed`: failure replaces the current window
/// status, retains its nullable wire metadata, and clears any invite marker.
/// Replayed snapshots are idempotent.
fn set_failed_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
    failure: WindowFailure,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Failed)
        != Some(ChannelWindowState::Failed);
    let failure_changed = window_failures.insert(key.clone(), failure.clone()) != Some(failure);
    let kick_cleared = window_kicks.remove(&key).is_some();
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_changed || kick_cleared || invite_cleared
}

/// Mirrors Cicchetto's `setKicked`: replaces the current window status,
/// retains nullable actor/reason metadata, and clears stale failure/invite
/// data. Replayed user-topic and channel-topic deliveries are idempotent.
fn set_kicked_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
    kick: WindowKick,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Kicked)
        != Some(ChannelWindowState::Kicked);
    let failure_cleared = window_failures.remove(&key).is_some();
    let kick_changed = window_kicks.insert(key.clone(), kick.clone()) != Some(kick);
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_cleared || kick_changed || invite_cleared
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
    message_id: Option<i64>,
    server_time: Option<i64>,
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
            message_id: message_id(payload),
            server_time: server_time(payload),
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
            message_id: message_id(payload),
            server_time: server_time(payload),
        },
        (None, Some(body)) => RenderedMessage {
            timestamp,
            nick: None,
            text: body.to_string(),
            italic,
            message_id: message_id(payload),
            server_time: server_time(payload),
        },
        _ => RenderedMessage {
            timestamp,
            nick: None,
            text: event_fallback
                .map(|event| format!("{event}: {payload}"))
                .unwrap_or_else(|| payload.to_string()),
            italic: true,
            message_id: message_id(payload),
            server_time: server_time(payload),
        },
    }
}

fn message_id(payload: &Value) -> Option<i64> {
    payload.get("id").and_then(Value::as_i64)
}

fn server_time(payload: &Value) -> Option<i64> {
    payload.get("server_time").and_then(Value::as_i64)
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

fn compare_rendered_message_order(
    left: &RenderedMessage,
    right: &RenderedMessage,
) -> std::cmp::Ordering {
    left.server_time
        .cmp(&right.server_time)
        .then_with(|| left.message_id.cmp(&right.message_id))
}

fn query_high_water_id(state: &WorkerState, key: &(String, String)) -> Option<i64> {
    state
        .messages
        .get(key)?
        .iter()
        .filter_map(|message| message.message_id)
        .max()
}

fn query_history_fetch_window(
    state: &WorkerState,
    identity: &(String, String),
    key: &(String, String),
) -> (Option<i64>, Option<usize>) {
    if state.query_full_history_required.contains(identity) {
        // The highest local ID may be the just-buffered inbound DM, not a
        // history checkpoint. Fetch the default tail and merge it by ID.
        return (None, None);
    }
    let high_water = query_high_water_id(state, key);
    (high_water, high_water.map(|_| 200))
}

fn require_query_full_history_if_unready(state: &mut WorkerState, key: &(String, String)) {
    let identity = query_window_key(&key.0, &key.1);
    if !state.query_ready.contains(&identity) {
        state.query_full_history_required.insert(identity);
    }
}

/// Merges a query history page into the local conversation by the server's
/// stable message ID, then restores Cicchetto's chronological
/// `(server_time, id)` ordering. This makes the default newest-first tail and
/// the post-join `after` page converge without duplicate echoes.
fn merge_query_history(state: &mut WorkerState, key: &(String, String), rows: &[Value]) {
    let messages = state.messages.entry(key.clone()).or_default();
    merge_rendered_messages(messages, rows.iter().map(render_history_entry));
}

fn merge_rendered_messages(
    messages: &mut Vec<RenderedMessage>,
    incoming: impl IntoIterator<Item = RenderedMessage>,
) {
    let mut known_ids: std::collections::HashSet<i64> = messages
        .iter()
        .filter_map(|message| message.message_id)
        .collect();
    for message in incoming {
        if let Some(id) = message.message_id {
            if !known_ids.insert(id) {
                continue;
            }
        }
        messages.push(message);
    }
    messages.sort_by(compare_rendered_message_order);
}

fn append_query_live_message(
    state: &mut WorkerState,
    key: &(String, String),
    payload: &Value,
    event_fallback: Option<&str>,
) -> bool {
    let message = render_message(payload, event_fallback);
    let messages = state.messages.entry(key.clone()).or_default();
    if message.message_id.is_some_and(|id| {
        messages
            .iter()
            .any(|existing| existing.message_id == Some(id))
    }) {
        return false;
    }
    messages.push(message);
    messages.sort_by(compare_rendered_message_order);
    true
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

/// Cicchetto uses the existing channel-shaped Phoenix topic for a private
/// query, with the target nick ASCII-folded into the channel segment.
fn query_topic(user: &str, network: &str, nick: &str) -> String {
    channel_topic(user, network, &ascii_fold_channel(nick))
}

fn own_nick_listener_topic(user: &str, network: &str, nick: &str) -> String {
    query_topic(user, network, nick)
}

/// Parses a channel-shaped query topic only when it belongs to the active
/// user. It intentionally accepts the same `channel:` topic contract as
/// Grappa; callers must additionally confirm the target is in the current
/// `query_windows_list` snapshot before treating it as a DM.
fn query_from_topic(user: &str, topic: &str) -> Option<(String, String)> {
    let prefix = format!("grappa:user:{user}/network:");
    let rest = topic.strip_prefix(&prefix)?;
    let (network, nick) = rest.split_once("/channel:")?;
    if network.is_empty() || nick.is_empty() || network.contains('/') || nick.contains('/') {
        return None;
    }
    Some((network.to_string(), nick.to_string()))
}

fn own_nick_listener_network_for_topic(state: &WorkerState, topic: &str) -> Option<String> {
    let user = state.identifier.as_deref()?;
    state.own_nicks.iter().find_map(|(network, nick)| {
        (own_nick_listener_topic(user, network, nick) == topic).then(|| network.clone())
    })
}

fn own_nick_listener_accepts_inbound_dm(payload: &Value) -> bool {
    matches!(
        payload.get("kind").and_then(Value::as_str),
        Some("privmsg" | "action")
    )
}

fn own_nick_dm_query_key(
    state: &WorkerState,
    network: &str,
    payload: &Value,
) -> Option<(String, String)> {
    let sender = own_nick_dm_sender(payload)?;
    let query = find_query_window(&state.query_windows, network, sender)?;
    Some((query.network.clone(), query.target_nick.clone()))
}

fn own_nick_dm_sender(payload: &Value) -> Option<&str> {
    let sender = ["from", "nick", "sender"]
        .iter()
        .find_map(|field| payload.get(*field).and_then(Value::as_str))?;
    if sender.trim().is_empty()
        || payload
            .get("body")
            .or_else(|| payload.get("message"))
            .and_then(Value::as_str)
            .is_none()
    {
        return None;
    }
    Some(sender)
}

fn buffer_pending_own_nick_dm(
    state: &mut WorkerState,
    network: &str,
    payload: &Value,
    event_fallback: &str,
) {
    let Some(sender) = own_nick_dm_sender(payload) else {
        return;
    };
    if find_query_window(&state.query_windows, network, sender).is_some() {
        return;
    }
    if state.pending_own_nick_dms.len() >= MAX_PENDING_OWN_NICK_DMS {
        state.pending_own_nick_dms.pop_front();
    }
    state.pending_own_nick_dms.push_back(PendingOwnNickDm {
        network: network.to_string(),
        sender: sender.to_string(),
        payload: payload.clone(),
        event_fallback: event_fallback.to_string(),
    });
}

fn drain_pending_own_nick_dms(state: &mut WorkerState) {
    let pending = std::mem::take(&mut state.pending_own_nick_dms);
    for dm in pending {
        let Some(query) = find_query_window(&state.query_windows, &dm.network, &dm.sender).cloned()
        else {
            // A valid full snapshot is authoritative: if it didn't open the
            // sender's query, don't invent a client-side window or retain the
            // message until some unrelated later snapshot.
            continue;
        };
        let key = (query.network.clone(), query.target_nick.clone());
        require_query_full_history_if_unready(state, &key);
        append_query_live_message(state, &key, &dm.payload, Some(&dm.event_fallback));
    }
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
    channel_entries_from_channels(&outcome.boot.channels)
}

fn channel_entries_from_channels(
    channels_by_network: &HashMap<String, Vec<Value>>,
) -> Vec<(String, String, String)> {
    let mut entries = Vec::new();
    for (network, channels) in channels_by_network {
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

fn channel_topics_for_entries(
    user: &str,
    entries: &[(String, String, String)],
) -> std::collections::HashSet<String> {
    entries
        .iter()
        .map(|(network, channel, _)| channel_topic(user, network, channel))
        .collect()
}

fn channel_topic_is_owned_elsewhere(state: &WorkerState, user: &str, topic: &str) -> bool {
    state
        .query_windows
        .iter()
        .any(|query| query_topic(user, &query.network, &query.target_nick) == topic)
        || state
            .stale_query_topics
            .iter()
            .any(|(network, nick)| query_topic(user, network, nick) == topic)
        || state
            .own_nicks
            .iter()
            .any(|(network, nick)| own_nick_listener_topic(user, network, nick) == topic)
}

/// Replaces only the server-owned channel projection. Message history,
/// cursors, query windows, and listener ownership remain untouched.
fn reconcile_channel_entries(
    state: &mut WorkerState,
    user: &str,
    entries: Vec<(String, String, String)>,
) -> Vec<ChannelTopicAction> {
    let next_topics = channel_topics_for_entries(user, &entries);
    let previous_topics = std::mem::replace(&mut state.channel_topics, next_topics.clone());
    let mut actions = Vec::new();

    let mut removed_topics: Vec<String> =
        previous_topics.difference(&next_topics).cloned().collect();
    removed_topics.sort();
    for topic in removed_topics {
        if channel_topic_is_owned_elsewhere(state, user, &topic) {
            continue;
        }
        if state.joined_topics.remove(&topic) {
            actions.push(ChannelTopicAction::Leave(topic));
        }
    }

    let mut desired_topics: Vec<String> = next_topics.into_iter().collect();
    desired_topics.sort();
    for topic in desired_topics {
        if state.joined_topics.insert(topic.clone()) {
            actions.push(ChannelTopicAction::Join(topic));
        }
    }

    state.channel_entries = entries;
    actions
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
    topics_from_boot_response(&outcome.boot)
}

fn topics_from_boot_response(boot: &BootResponse) -> HashMap<(String, String), String> {
    let mut topics = HashMap::new();
    for (network, channels) in &boot.channels {
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
    members_from_boot_response(&outcome.boot)
}

fn members_from_boot_response(boot: &BootResponse) -> MembersByChannel {
    const FIELD_NAMES: &[&str] = &["members", "nicks", "names", "userlist", "who"];

    let mut members_by_channel = HashMap::new();
    for (network, channels) in &boot.channels {
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
    messages_from_boot_response(&outcome.boot)
}

fn messages_from_boot_response(boot: &BootResponse) -> MessagesByChannel {
    let mut messages = HashMap::new();
    for (network, channels) in &boot.heads {
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
type NetworkGroupData = (String, bool, Vec<(String, String)>, Vec<(String, String)>);
type NetworkEntries = (Vec<(String, String)>, Vec<(String, String)>);

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
    query_windows: &[QueryWindow],
    expanded: &HashMap<String, bool>,
) -> Vec<NetworkGroupData> {
    let mut by_network: std::collections::BTreeMap<String, NetworkEntries> =
        std::collections::BTreeMap::new();
    for (network, channel, label) in entries {
        by_network
            .entry(network.clone())
            .or_default()
            .0
            .push((channel.clone(), label.clone()));
    }
    for query in query_windows {
        by_network
            .entry(query.network.clone())
            .or_default()
            .1
            .push((query.target_nick.clone(), query.target_nick.clone()));
    }
    by_network
        .into_iter()
        .map(|(network, (mut channels, queries))| {
            channels.sort();
            let is_expanded = expanded.get(&network).copied().unwrap_or(true);
            (network, is_expanded, channels, queries)
        })
        .collect()
}

/// Builds the actual sidebar `NetworkGroup` Slint model out of
/// `network_groups_data`'s plain grouping — must run on the UI thread,
/// see that function's doc comment for why.
fn network_groups_model(
    data: Vec<NetworkGroupData>,
    window_states: HashMap<(String, String), ChannelWindowState>,
    window_mentions: HashMap<WindowCountsKey, u64>,
    window_messages: HashMap<WindowCountsKey, u64>,
) -> Vec<NetworkGroup> {
    data.into_iter()
        .enumerate()
        .map(|(index, (network, expanded, channels, queries))| {
            let channel_entries: Vec<ChannelEntry> = channels
                .into_iter()
                .map(|(channel, label)| {
                    let failed = window_is_failed(&window_states, &network, &channel);
                    let kicked = window_is_kicked(&window_states, &network, &channel);
                    let invited = window_is_invited(&window_states, &network, &channel);
                    let mention_count = window_mentions
                        .get(&window_counts_key(&network, &channel))
                        .copied()
                        .unwrap_or_default();
                    let (mention_badge, mentions_description) = mention_count_labels(mention_count);
                    let (unread_count, unread_description) = unread_message_count_labels(
                        window_messages
                            .get(&window_counts_key(&network, &channel))
                            .copied(),
                    );
                    ChannelEntry {
                        network: network.clone().into(),
                        channel: channel.into(),
                        label: label.into(),
                        mention_badge: mention_badge.into(),
                        mentions_description: mentions_description.into(),
                        unread_count: unread_count.into(),
                        unread_description: unread_description.into(),
                        failed,
                        kicked,
                        invited,
                    }
                })
                .collect();
            let query_entries: Vec<QueryEntry> = queries
                .into_iter()
                .map(|(nick, label)| {
                    let (mention_badge, mentions_description) = window_mentions
                        .get(&window_counts_key(&network, &nick))
                        .copied()
                        .map(mention_count_labels)
                        .unwrap_or_default();
                    QueryEntry {
                        network: network.clone().into(),
                        nick: nick.into(),
                        label: label.into(),
                        mention_badge: mention_badge.into(),
                        mentions_description: mentions_description.into(),
                    }
                })
                .collect();
            NetworkGroup {
                network: network.into(),
                separator_before: index > 0,
                expanded,
                channels: Rc::new(slint::VecModel::from(channel_entries)).into(),
                queries: Rc::new(slint::VecModel::from(query_entries)).into(),
            }
        })
        .collect()
}

/// Pushes `state.channel_entries` + `state.expanded_networks` to the
/// sidebar as a fresh `network-groups` model — called after anything that
/// changes either (a network's expand toggle, a fresh connect).
fn refresh_network_groups(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let data = network_groups_data(
        &state.channel_entries,
        &state.query_windows,
        &state.expanded_networks,
    );
    let window_states = state.window_states.clone();
    let window_mentions = state.window_mentions.clone();
    let window_messages = state.window_messages.clone();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let groups = network_groups_model(data, window_states, window_mentions, window_messages);
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
    network_ids_from_entries(&outcome.boot.networks)
}

fn network_ids_from_entries(networks: &[Value]) -> HashMap<String, i64> {
    networks
        .iter()
        .filter_map(|value| {
            let slug = value.get("slug").and_then(Value::as_str)?;
            let id = value.get("id").and_then(Value::as_i64)?;
            Some((slug.to_string(), id))
        })
        .collect()
}

fn network_nicks_from_boot(outcome: &BootstrapOutcome) -> HashMap<String, String> {
    network_nicks_from_entries(&outcome.boot.networks)
}

fn network_nicks_from_entries(networks: &[Value]) -> HashMap<String, String> {
    networks
        .iter()
        .filter_map(|value| {
            let slug = value.get("slug").and_then(Value::as_str)?;
            let nick = value.get("nick").and_then(Value::as_str)?;
            if nick.trim().is_empty() {
                return None;
            }
            Some((slug.to_string(), nick.to_string()))
        })
        .collect()
}

/// Reverses `/boot`'s slug-to-id map. Duplicate IDs are rejected rather than
/// allowing an event row to be attached to an arbitrary network.
fn network_slugs_by_id(network_ids: &HashMap<String, i64>) -> Option<HashMap<i64, String>> {
    let mut slugs = HashMap::new();
    for (slug, id) in network_ids {
        if *id <= 0 {
            return None;
        }
        if let Some(previous) = slugs.insert(*id, slug.clone()) {
            if previous != *slug {
                return None;
            }
        }
    }
    Some(slugs)
}

fn parse_own_nick_changed(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<(String, String)> {
    if payload.get("kind")?.as_str()? != "own_nick_changed" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    if network_id <= 0 {
        return None;
    }
    let network = network_slugs.get(&network_id)?;
    let nick = payload.get("nick")?.as_str()?;
    if nick.trim().is_empty() {
        return None;
    }
    Some((network.clone(), nick.to_string()))
}

fn parse_away_confirmed(
    payload: &Value,
    known_networks: &HashMap<String, i64>,
) -> Option<(String, AwayStatus)> {
    if payload.get("kind")?.as_str()? != "away_confirmed" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() || !known_networks.contains_key(network) {
        return None;
    }
    let status = match payload.get("state")?.as_str()? {
        "present" => AwayStatus::Present,
        "away" => AwayStatus::Away,
        _ => return None,
    };
    Some((network.to_string(), status))
}

fn apply_away_confirmed(
    away_states: &mut HashMap<String, AwayStatus>,
    network: &str,
    status: AwayStatus,
) -> bool {
    if away_states.get(network) == Some(&status) {
        return false;
    }
    away_states.insert(network.to_string(), status);
    true
}

fn handle_away_confirmed(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(user) = state.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some((network, status)) = parse_away_confirmed(payload, &state.network_ids) else {
        persistence::log_line("away_confirmed rejected: invalid state or unknown network");
        return;
    };
    if apply_away_confirmed(&mut state.away_states, &network, status) {
        persistence::log_line(&format!("away_confirmed applied: {network}={status:?}"));
    }
}

fn parse_session_identity_changed(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<(String, SessionIdentity)> {
    if payload.get("kind")?.as_str()? != "session_identity_changed" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    let network = network_slugs.get(&network_id)?;
    let identified = payload.get("identified")?.as_bool()?;
    let account = match payload.get("account")? {
        Value::Null => None,
        Value::String(account) => Some(account.clone()),
        _ => return None,
    };
    Some((
        network.clone(),
        SessionIdentity {
            identified,
            account,
        },
    ))
}

fn handle_session_identity_changed(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(user) = state.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.network_ids) else {
        persistence::log_line("session_identity_changed rejected: invalid network map");
        return;
    };
    let Some((network, identity)) = parse_session_identity_changed(payload, &network_slugs) else {
        persistence::log_line(
            "session_identity_changed rejected: invalid payload or unknown network",
        );
        return;
    };
    state.session_identities.insert(network, identity);
}

fn handle_isupport_changed(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(user) = state.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(event) = parse_isupport_changed(payload) else {
        persistence::log_line("isupport_changed rejected: invalid payload");
        return;
    };
    let Some(network_slugs) = network_slugs_by_id(&state.network_ids) else {
        persistence::log_line("isupport_changed rejected: invalid network map");
        return;
    };
    let Some(network) = network_slugs.get(&event.network_id) else {
        persistence::log_line("isupport_changed rejected: unknown network");
        return;
    };
    state
        .isupport_by_network
        .insert(network.clone(), event.state);
}

fn parse_umode_changed(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<(String, Vec<String>)> {
    if payload.get("kind")?.as_str()? != "umode_changed" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    if network_id <= 0 {
        return None;
    }
    let network = network_slugs.get(&network_id)?;
    let raw_modes = payload.get("modes")?.as_array()?;
    let mut seen = std::collections::HashSet::with_capacity(raw_modes.len());
    let mut modes = Vec::with_capacity(raw_modes.len());
    for value in raw_modes {
        let mode = value.as_str()?;
        if mode.is_empty() || mode.starts_with('+') || mode.starts_with('-') || !seen.insert(mode) {
            return None;
        }
        modes.push(mode.to_string());
    }
    Some((network.clone(), modes))
}

fn handle_umode_changed(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(user) = state.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.network_ids) else {
        persistence::log_line("umode_changed rejected: invalid network map");
        return;
    };
    let Some((network, modes)) = parse_umode_changed(payload, &network_slugs) else {
        persistence::log_line("umode_changed rejected: invalid payload or unknown network");
        return;
    };
    state.user_modes_by_network.insert(network, modes);
}

fn parse_supported_umodes_changed(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<(String, Vec<String>)> {
    if payload.get("kind")?.as_str()? != "supported_umodes_changed" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    if network_id <= 0 {
        return None;
    }
    let network = network_slugs.get(&network_id)?;
    let raw_modes = payload.get("modes")?.as_array()?;
    let mut seen = std::collections::HashSet::with_capacity(raw_modes.len());
    let mut modes = Vec::with_capacity(raw_modes.len());
    for value in raw_modes {
        let mode = value.as_str()?;
        if mode.is_empty() || mode.starts_with('+') || mode.starts_with('-') || !seen.insert(mode) {
            return None;
        }
        modes.push(mode.to_string());
    }
    Some((network.clone(), modes))
}

fn handle_supported_umodes_changed(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(user) = state.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.network_ids) else {
        persistence::log_line("supported_umodes_changed rejected: invalid network map");
        return;
    };
    let Some((network, modes)) = parse_supported_umodes_changed(payload, &network_slugs) else {
        persistence::log_line(
            "supported_umodes_changed rejected: invalid payload or unknown network",
        );
        return;
    };
    state.supported_user_modes_by_network.insert(network, modes);
}

fn apply_own_nick_change(
    state: &mut WorkerState,
    user: &str,
    network: &str,
    nick: &str,
) -> Vec<OwnNickListenerAction> {
    let previous = state
        .own_nicks
        .insert(network.to_string(), nick.to_string());
    let new_topic = own_nick_listener_topic(user, network, nick);
    if previous
        .as_deref()
        .is_some_and(|old_nick| ascii_fold_channel(old_nick) == ascii_fold_channel(nick))
    {
        return Vec::new();
    }

    let mut actions = Vec::with_capacity(2);
    if let Some(old_nick) = previous {
        let old_topic = own_nick_listener_topic(user, network, &old_nick);
        state.own_listener_ready.remove(&old_topic);
        if find_query_window(&state.query_windows, network, &old_nick).is_none() {
            state.joined_topics.remove(&old_topic);
            actions.push(OwnNickListenerAction::Leave(old_topic));
        }
    }

    if state.joined_topics.insert(new_topic.clone()) {
        state.own_listener_ready.remove(&new_topic);
        actions.push(OwnNickListenerAction::Join(new_topic));
    } else if state
        .query_joined
        .contains(&query_window_key(network, nick))
    {
        // The canonical topic may already have been joined as a listed query.
        // Its successful query ACK is also sufficient for this listener.
        state.own_listener_ready.insert(new_topic);
    }

    actions
}

fn handle_own_nick_listener_join_reply(
    state: &mut WorkerState,
    topic: &str,
    status: Option<&str>,
) -> OwnNickListenerJoinReply {
    if !state.joined_topics.contains(topic)
        || own_nick_listener_network_for_topic(state, topic).is_none()
    {
        return OwnNickListenerJoinReply::Untracked;
    }
    if status == Some("ok") {
        state.own_listener_ready.insert(topic.to_string());
        OwnNickListenerJoinReply::Accepted
    } else {
        state.own_listener_ready.remove(topic);
        OwnNickListenerJoinReply::Rejected
    }
}

fn handle_own_nick_changed(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(user) = state.identifier.clone() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.network_ids) else {
        persistence::log_line("own_nick_changed rejected: ambiguous network ID map");
        return;
    };
    let Some((network, nick)) = parse_own_nick_changed(payload, &network_slugs) else {
        persistence::log_line("own_nick_changed rejected: invalid or unknown network");
        return;
    };

    let actions = apply_own_nick_change(state, &user, &network, &nick);
    if let Some(session) = state.session.as_ref() {
        for action in actions {
            match action {
                OwnNickListenerAction::Leave(topic) => session.leave_topic(topic),
                OwnNickListenerAction::Join(topic) => session.join_topic(topic, false),
            }
        }
    }
}

fn is_channels_changed_signal(user: &str, carrier_topic: &str, payload: &Value) -> bool {
    carrier_topic == format!("grappa:user:{user}")
        && payload.get("kind").and_then(Value::as_str) == Some("channels_changed")
}

async fn handle_channels_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.clone() else {
        return;
    };
    if !is_channels_changed_signal(&identifier, carrier_topic, payload) {
        return;
    }
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };

    let mut networks: Vec<String> = state.network_ids.keys().cloned().collect();
    networks.sort();
    let mut requests = tokio::task::JoinSet::new();
    for network in networks {
        let client = client.clone();
        let token = token.clone();
        requests.spawn(async move {
            let channels = client.fetch_channels(&token, &network).await;
            (network, channels)
        });
    }

    let mut channels_by_network = HashMap::new();
    while let Some(result) = requests.join_next().await {
        match result {
            Ok((network, Ok(channels))) => {
                channels_by_network.insert(network, channels);
            }
            Ok((_, Err(_))) | Err(_) => {
                persistence::log_line(
                    "channels_changed refresh failed; keeping existing channel state",
                );
                return;
            }
        }
    }

    if state.session.is_none() {
        persistence::log_line(
            "channels_changed refresh skipped without an active realtime session",
        );
        return;
    }
    let entries = channel_entries_from_channels(&channels_by_network);
    let actions = reconcile_channel_entries(state, &identifier, entries);
    let Some(session) = state.session.as_ref() else {
        // Checked immediately before reconciliation; keep this defensive in
        // case the state container changes independently in the future.
        return;
    };
    for action in actions {
        match action {
            ChannelTopicAction::Leave(topic) => session.leave_topic(topic),
            ChannelTopicAction::Join(topic) => session.join_topic(topic, true),
        }
    }
    refresh_network_groups(state, ui);
}

/// Parses an authoritative network lifecycle signal. The event is carried
/// only by the authenticated user topic and identifies the network by both
/// its stable integer id and its display slug. Additive fields are ignored,
/// but the two identity fields are required so a stale or malformed push can
/// never make Cordiale mutate an unrelated network locally.
fn parse_network_lifecycle_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
    expected_kind: &str,
) -> Option<(i64, String)> {
    if identifier.is_empty()
        || carrier_topic != format!("grappa:user:{identifier}")
        || payload.get("kind").and_then(Value::as_str) != Some(expected_kind)
    {
        return None;
    }

    let network_id = payload.get("network_id").and_then(Value::as_i64)?;
    if network_id <= 0 {
        return None;
    }
    let network_slug = payload.get("network_slug").and_then(Value::as_str)?;
    if network_slug.trim().is_empty() {
        return None;
    }
    Some((network_id, network_slug.to_string()))
}

fn parse_network_detached_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(i64, String)> {
    parse_network_lifecycle_event(payload, carrier_topic, identifier, "network_detached")
}

fn parse_network_attached_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(i64, String)> {
    parse_network_lifecycle_event(payload, carrier_topic, identifier, "network_attached")
}

/// Reconciles the self-message listener topics after an authoritative
/// `/boot` refresh.  Channel-shaped topics are shared with query windows, so
/// an old listener is left only when no open query still owns that topic.
fn reconcile_own_nick_listener_topics(
    state: &mut WorkerState,
    user: &str,
    next_own_nicks: HashMap<String, String>,
) -> Vec<OwnNickListenerAction> {
    let previous = std::mem::replace(&mut state.own_nicks, next_own_nicks.clone());
    let mut actions = Vec::new();

    for (network, old_nick) in previous {
        let same_topic = next_own_nicks
            .get(&network)
            .is_some_and(|new_nick| ascii_fold_channel(new_nick) == ascii_fold_channel(&old_nick));
        if same_topic {
            continue;
        }

        let old_topic = own_nick_listener_topic(user, &network, &old_nick);
        state.own_listener_ready.remove(&old_topic);
        if find_query_window(&state.query_windows, &network, &old_nick).is_none()
            && state.joined_topics.remove(&old_topic)
        {
            actions.push(OwnNickListenerAction::Leave(old_topic));
        }
    }

    for (network, nick) in next_own_nicks {
        let topic = own_nick_listener_topic(user, &network, &nick);
        if state.joined_topics.insert(topic.clone()) {
            state.own_listener_ready.remove(&topic);
            actions.push(OwnNickListenerAction::Join(topic));
        }
    }

    actions
}

/// Applies the two REST snapshots that Cicchetto refreshes after a network
/// attach or detach. The REST responses are fetched before any mutation, so a
/// failed refresh leaves the existing projection intact. The WebSocket session
/// is preserved; only the state owned by `/boot` and `/me` is replaced and the
/// resulting topic differences are sent to the existing session.
fn apply_network_rest_refresh(
    state: &mut WorkerState,
    identifier: &str,
    boot: &BootResponse,
    me: &MeResponse,
) -> Vec<ChannelTopicAction> {
    let entries = channel_entries_from_channels(&boot.channels);
    let channel_actions = reconcile_channel_entries(state, identifier, entries);

    state.window_states = joined_window_states_from_boot_channels(&boot.channels);
    state.window_failures.clear();
    state.window_kicks.clear();
    state.invited_by.clear();
    state.window_mentions = window_mentions_from_me(&me.unread_counts);
    state.window_messages = window_messages_from_me(&me.unread_counts);
    state.topics = topics_from_boot_response(boot);
    state.members = members_from_boot_response(boot);
    state.messages = messages_from_boot_response(boot);
    state.read_cursors = read_cursors_from_me(&me.read_cursors);
    state.badge_count = normalize_badge_count(Some(&me.badge_count));
    state.network_ids = network_ids_from_entries(&boot.networks);

    let listener_actions = reconcile_own_nick_listener_topics(
        state,
        identifier,
        network_nicks_from_entries(&boot.networks),
    );

    // The refresh is authoritative for per-network transient snapshots too;
    // discard entries for networks no longer present while preserving the
    // latest values for networks that remain attached/parked.
    let known_networks: std::collections::HashSet<&str> =
        state.network_ids.keys().map(String::as_str).collect();
    state
        .away_states
        .retain(|network, _| known_networks.contains(network.as_str()));
    state
        .session_identities
        .retain(|network, _| known_networks.contains(network.as_str()));
    state
        .isupport_by_network
        .retain(|network, _| known_networks.contains(network.as_str()));
    state
        .user_modes_by_network
        .retain(|network, _| known_networks.contains(network.as_str()));
    state
        .supported_user_modes_by_network
        .retain(|network, _| known_networks.contains(network.as_str()));

    let mut actions = channel_actions;
    for action in listener_actions {
        actions.push(match action {
            OwnNickListenerAction::Leave(topic) => ChannelTopicAction::Leave(topic),
            OwnNickListenerAction::Join(topic) => ChannelTopicAction::Join(topic),
        });
    }
    actions
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkLifecycleKind {
    Attached,
    Detached,
}

impl NetworkLifecycleKind {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Attached => "network_attached",
            Self::Detached => "network_detached",
        }
    }

    fn parse(
        self,
        payload: &Value,
        carrier_topic: &str,
        identifier: &str,
    ) -> Option<(i64, String)> {
        parse_network_lifecycle_event(payload, carrier_topic, identifier, self.wire_name())
    }
}

async fn handle_network_lifecycle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
    lifecycle: NetworkLifecycleKind,
) {
    let Some(identifier) = state.identifier.clone() else {
        return;
    };
    let Some((network_id, network_slug)) = lifecycle.parse(payload, carrier_topic, &identifier)
    else {
        return;
    };

    // A detach must refer to the current projection before the refresh. An
    // attach is allowed to introduce a network that is not known locally yet;
    // its identity is checked against the refreshed authoritative snapshot
    // below instead.
    if lifecycle == NetworkLifecycleKind::Detached
        && state.network_ids.get(&network_slug) != Some(&network_id)
    {
        persistence::log_line(&format!(
            "{} rejected: unknown or stale network",
            lifecycle.wire_name()
        ));
        return;
    }
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };

    let boot = match client.fetch_boot(&token).await {
        Ok(boot) => boot,
        Err(error) => {
            persistence::log_line(&format!(
                "{} boot refresh failed; keeping existing state: {error:?}",
                lifecycle.wire_name()
            ));
            return;
        }
    };
    let me = match client.fetch_me(&token).await {
        Ok(me) => me,
        Err(error) => {
            persistence::log_line(&format!(
                "{} me refresh failed; keeping existing state: {error:?}",
                lifecycle.wire_name()
            ));
            return;
        }
    };

    // An attach may be the first local indication of a newly attached
    // network, but a replayed/stale signal must not cause a projection change
    // if the authoritative snapshot does not contain the same id/slug.
    if lifecycle == NetworkLifecycleKind::Attached
        && network_ids_from_entries(&boot.networks).get(&network_slug) != Some(&network_id)
    {
        persistence::log_line("network_attached rejected: unknown or stale network");
        return;
    }

    let actions = apply_network_rest_refresh(state, &identifier, &boot, &me);
    if let Some(session) = state.session.as_ref() {
        for action in actions {
            match action {
                ChannelTopicAction::Leave(topic) => session.leave_topic(topic),
                ChannelTopicAction::Join(topic) => {
                    let is_own_listener =
                        own_nick_listener_network_for_topic(state, &topic).is_some();
                    session.join_topic(topic, !is_own_listener);
                }
            }
        }
    }

    if let Some((current_network, _)) = state.current_channel.as_ref() {
        if !state.network_ids.contains_key(current_network) {
            state.current_channel = None;
            state.current_query = false;
            state.current_query_ready = false;
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_has_selected_channel(false);
                ui.set_current_channel_label("".into());
                ui.set_current_topic("".into());
                ui.set_current_channel_modes("".into());
                ui.set_current_window_is_joined(false);
                ui.set_can_moderate_members(false);
                ui.set_compose_text("".into());
                ui.set_chat_lines(Rc::new(slint::VecModel::from(Vec::<ChatLine>::new())).into());
                ui.set_channel_members(
                    Rc::new(slint::VecModel::from(Vec::<MemberRow>::new())).into(),
                );
            });
        }
    }

    refresh_network_groups(state, ui);
    persistence::log_line(&format!(
        "{} refreshed authoritative state for {network_slug}",
        lifecycle.wire_name()
    ));
}

async fn handle_network_detached(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    handle_network_lifecycle(
        state,
        ui,
        carrier_topic,
        payload,
        NetworkLifecycleKind::Detached,
    )
    .await;
}

async fn handle_network_attached(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    handle_network_lifecycle(
        state,
        ui,
        carrier_topic,
        payload,
        NetworkLifecycleKind::Attached,
    )
    .await;
}

/// Parses the authoritative `query_windows_list` full snapshot. If any row
/// is malformed, has an unknown/mismatched network ID, duplicates another
/// query identity, or carries a non-RFC3339 `opened_at`, reject the whole
/// snapshot so a partial payload cannot erase known windows.
fn parse_query_windows_list(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<Vec<QueryWindow>> {
    if payload.get("kind")?.as_str()? != "query_windows_list" {
        return None;
    }
    let windows = payload.get("windows")?.as_object()?;
    let mut parsed = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (raw_network_id, entries) in windows {
        let network_id = raw_network_id.parse::<i64>().ok()?;
        if network_id <= 0 {
            return None;
        }
        let network = network_slugs.get(&network_id)?;
        for entry in entries.as_array()? {
            if entry.get("network_id").and_then(Value::as_i64) != Some(network_id) {
                return None;
            }
            let target_nick = entry.get("target_nick")?.as_str()?;
            if target_nick.trim().is_empty() {
                return None;
            }
            let opened_at = entry.get("opened_at")?.as_str()?;
            chrono::DateTime::parse_from_rfc3339(opened_at).ok()?;

            let query = QueryWindow {
                network: network.clone(),
                target_nick: target_nick.to_string(),
                opened_at: opened_at.to_string(),
            };
            if !seen.insert(query_window_key(&query.network, &query.target_nick)) {
                return None;
            }
            parsed.push(query);
        }
    }

    // The server's per-network list is already oldest-first; preserve it for
    // the sidebar instead of replacing the user's established ordering.
    Some(parsed)
}

fn query_window_key(network: &str, nick: &str) -> (String, String) {
    (network.to_string(), ascii_fold_channel(nick))
}

fn find_query_window<'a>(
    windows: &'a [QueryWindow],
    network: &str,
    nick: &str,
) -> Option<&'a QueryWindow> {
    let key = query_window_key(network, nick);
    windows
        .iter()
        .find(|window| query_window_key(&window.network, &window.target_nick) == key)
}

enum QueryTopicResolution<'a> {
    Active(&'a QueryWindow),
    Stale,
    Untracked,
}

fn resolve_query_topic<'a>(
    windows: &'a [QueryWindow],
    stale_topics: &std::collections::HashSet<(String, String)>,
    network: &str,
    target: &str,
) -> QueryTopicResolution<'a> {
    if let Some(query) = find_query_window(windows, network, target) {
        QueryTopicResolution::Active(query)
    } else if stale_topics.contains(&query_window_key(network, target)) {
        QueryTopicResolution::Stale
    } else {
        QueryTopicResolution::Untracked
    }
}

fn same_rfc3339_instant(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (
        chrono::DateTime::parse_from_rfc3339(left),
        chrono::DateTime::parse_from_rfc3339(right),
    ) else {
        return false;
    };
    left.timestamp() == right.timestamp()
        && left.timestamp_subsec_nanos() == right.timestamp_subsec_nanos()
}

/// Infers only unambiguous renames: exactly one disappeared and one appeared
/// on the same network with the same validated opening instant. No list
/// ordering or nickname similarity is treated as identity.
fn query_window_renames(
    previous: &[QueryWindow],
    next: &[QueryWindow],
) -> Vec<(QueryWindow, QueryWindow)> {
    let removed: Vec<&QueryWindow> = previous
        .iter()
        .filter(|old| find_query_window(next, &old.network, &old.target_nick).is_none())
        .collect();
    let added: Vec<&QueryWindow> = next
        .iter()
        .filter(|new| find_query_window(previous, &new.network, &new.target_nick).is_none())
        .collect();

    let mut renames = Vec::new();
    for old in removed.iter().copied() {
        let candidates: Vec<&QueryWindow> = added
            .iter()
            .copied()
            .filter(|new| {
                old.network == new.network && same_rfc3339_instant(&old.opened_at, &new.opened_at)
            })
            .collect();
        if candidates.len() != 1 {
            continue;
        }
        let new = candidates[0];
        let reverse_matches = removed
            .iter()
            .copied()
            .filter(|other| {
                other.network == new.network
                    && same_rfc3339_instant(&other.opened_at, &new.opened_at)
            })
            .count();
        if reverse_matches == 1 {
            renames.push((old.clone(), new.clone()));
        }
    }
    renames
}

fn move_query_window_cache(state: &mut WorkerState, old: &QueryWindow, new: &QueryWindow) {
    let from = (old.network.clone(), old.target_nick.clone());
    let to = (new.network.clone(), new.target_nick.clone());
    if from == to {
        return;
    }
    if let Some(lines) = state.messages.remove(&from) {
        merge_rendered_messages(state.messages.entry(to.clone()).or_default(), lines);
    }
    if !state.drafts.contains_key(&to) {
        if let Some(draft) = state.drafts.remove(&from) {
            state.drafts.insert(to, draft);
        }
    }
    // A rename changes the canonical Phoenix topic. Keep old join/readiness
    // tracking because Cicchetto keeps obsolete topics joined for the session;
    // the new identity starts unready until its own join/history cycle.
}

/// Replaces local query state from a complete server snapshot. Returns true
/// only when the currently selected query was closed rather than retained or
/// unambiguously renamed.
fn apply_query_windows_snapshot(state: &mut WorkerState, snapshot: Vec<QueryWindow>) -> bool {
    let previous = state.query_windows.clone();
    // A case-only nick change retains the same query identity and topic, but
    // the rendered-message and draft maps use the displayed nick verbatim.
    // Move those exact-key caches before normal rename detection, which
    // deliberately treats this as the same identity.
    for new in &snapshot {
        if let Some(old) = find_query_window(&previous, &new.network, &new.target_nick) {
            if old.network != new.network || old.target_nick != new.target_nick {
                move_query_window_cache(state, old, new);
            }
        }
    }
    let renames = query_window_renames(&previous, &snapshot);
    for (old, new) in &renames {
        move_query_window_cache(state, old, new);
    }

    let mut selected_closed = false;
    if state.current_query {
        if let Some((network, nick)) = state.current_channel.clone() {
            let selected = find_query_window(&snapshot, &network, &nick)
                .cloned()
                .or_else(|| {
                    renames
                        .iter()
                        .find(|(old, _)| {
                            query_window_key(&old.network, &old.target_nick)
                                == query_window_key(&network, &nick)
                        })
                        .map(|(_, new)| new.clone())
                });
            if let Some(query) = selected {
                if let Some(old) = find_query_window(&previous, &network, &nick) {
                    move_query_window_cache(state, old, &query);
                }
                state.current_channel = Some((query.network, query.target_nick));
            } else {
                state.current_channel = None;
                state.current_query = false;
                selected_closed = true;
            }
        } else {
            state.current_query = false;
            selected_closed = true;
        }
    }

    state.query_windows = snapshot;
    selected_closed
}

/// Keeps the worker's query/topic lifecycle aligned with the latest complete
/// snapshot while retaining acknowledgements for topics Grappa/Cicchetto keep
/// joined after a query closes. Those acknowledgements allow a same-session
/// reopen to reuse the existing topic and load a fresh tail without a second
/// join.
fn reconcile_query_topic_tracking(state: &mut WorkerState, previous: &[QueryWindow]) {
    let active_queries: std::collections::HashSet<(String, String)> = state
        .query_windows
        .iter()
        .map(|query| query_window_key(&query.network, &query.target_nick))
        .collect();
    state
        .query_full_history_required
        .retain(|identity| active_queries.contains(identity));
    for query in previous {
        let identity = query_window_key(&query.network, &query.target_nick);
        if !active_queries.contains(&identity) {
            state.stale_query_topics.insert(identity);
            // The topic remains joined, but reopening must load its latest
            // tail before the composer is enabled again.
            state
                .query_ready
                .remove(&query_window_key(&query.network, &query.target_nick));
        }
    }
    for query in &state.query_windows {
        state
            .stale_query_topics
            .remove(&query_window_key(&query.network, &query.target_nick));
    }
    state.current_query_ready = state.current_query
        && state
            .current_channel
            .as_ref()
            .is_some_and(|(network, nick)| {
                state.query_ready.contains(&query_window_key(network, nick))
            });
}

fn handle_query_windows_list(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.clone() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{identifier}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.network_ids) else {
        persistence::log_line("query_windows_list rejected: ambiguous network ID map");
        return;
    };
    let Some(snapshot) = parse_query_windows_list(payload, &network_slugs) else {
        persistence::log_line("query_windows_list rejected: invalid full snapshot");
        return;
    };

    let previous_queries = state.query_windows.clone();
    let selected_closed = apply_query_windows_snapshot(state, snapshot);
    retain_window_counts_for_open_windows(state);
    reconcile_query_topic_tracking(state, &previous_queries);
    drain_pending_own_nick_dms(state);
    if let Some(session) = state.session.as_ref() {
        for query in &state.query_windows {
            let topic = query_topic(&identifier, &query.network, &query.target_nick);
            if state.joined_topics.insert(topic.clone()) {
                // Query topics carry scrollback/messages, not the channel
                // presence stream used to populate the roster.
                session.join_topic(topic, false);
            }
        }
    }

    refresh_network_groups(state, ui);
    if state.current_query {
        if let Some((network, nick)) = state.current_channel.as_ref() {
            if let Some(query) = find_query_window(&state.query_windows, network, nick).cloned() {
                let key = (query.network.clone(), query.target_nick.clone());
                show_query_window(state, ui, &query, &key);
            }
        }
    } else if selected_closed {
        clear_closed_query_view(ui);
    }
}

fn clear_closed_query_view(ui: &slint::Weak<AppWindow>) {
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let empty_lines = Rc::new(slint::VecModel::from(Vec::<ChatLine>::new()));
        let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
        ui.set_current_channel_label("".into());
        ui.set_current_topic("".into());
        ui.set_current_channel_modes("".into());
        ui.set_current_window_is_joined(false);
        ui.set_has_selected_channel(false);
        ui.set_current_query(false);
        ui.set_current_query_ready(false);
        ui.set_can_moderate_members(false);
        ui.set_compose_text("".into());
        ui.set_chat_lines(empty_lines.into());
        ui.set_channel_members(empty_members.into());
    });
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
    fn query_topic_uses_the_channel_segment_and_ascii_folded_nick() {
        assert_eq!(
            query_topic("vjt", "libera", "FrIeNd"),
            "grappa:user:vjt/network:libera/channel:friend"
        );
        assert_eq!(
            query_from_topic("vjt", "grappa:user:vjt/network:libera/channel:friend"),
            Some(("libera".to_string(), "friend".to_string()))
        );
        assert_eq!(
            query_from_topic("other", "grappa:user:vjt/network:libera/channel:friend"),
            None
        );
        assert_eq!(
            query_from_topic("vjt", "grappa:user:vjt/network:libera/channel:#rust"),
            Some(("libera".to_string(), "#rust".to_string()))
        );
        assert_eq!(
            query_from_topic("vjt", "grappa:user:vjt/network:libera/channel:"),
            None
        );
        assert_eq!(
            query_from_topic("vjt", "grappa:user:vjt/network:libera/channel:friend/extra"),
            None
        );
    }

    #[test]
    fn boot_seeds_current_nicks_per_network_and_skips_missing_or_blank_values() {
        let nicks = network_nicks_from_entries(&[
            serde_json::json!({"slug": "libera", "nick": "OldNick"}),
            serde_json::json!({"slug": "azzurra", "nick": "  "}),
            serde_json::json!({"slug": "oftc"}),
            serde_json::json!({"nick": "orphan"}),
        ]);

        let expected: HashMap<String, String> = [("libera".to_string(), "OldNick".to_string())]
            .into_iter()
            .collect();
        assert_eq!(nicks, expected);
    }

    #[test]
    fn own_nick_changed_maps_only_known_positive_network_ids() {
        let network_slugs: HashMap<i64, String> =
            [(7, "libera".to_string()), (9, "azzurra".to_string())]
                .into_iter()
                .collect();
        let valid = serde_json::json!({
            "kind": "own_nick_changed",
            "network_id": 7,
            "nick": "NewNick",
            "future_field": true
        });
        assert_eq!(
            parse_own_nick_changed(&valid, &network_slugs),
            Some(("libera".to_string(), "NewNick".to_string()))
        );

        for invalid in [
            serde_json::json!({"kind": "own_nick_changed", "network_id": 77, "nick": "NewNick"}),
            serde_json::json!({"kind": "own_nick_changed", "network_id": 0, "nick": "NewNick"}),
            serde_json::json!({"kind": "own_nick_changed", "network_id": 7, "nick": "  "}),
            serde_json::json!({"kind": "other_kind", "network_id": 7, "nick": "NewNick"}),
        ] {
            assert_eq!(parse_own_nick_changed(&invalid, &network_slugs), None);
        }
    }

    #[test]
    fn away_confirmed_maps_present_and_away_for_known_networks() {
        let known_networks: HashMap<String, i64> =
            [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
                .into_iter()
                .collect();

        for (state, expected) in [("present", AwayStatus::Present), ("away", AwayStatus::Away)] {
            let payload = serde_json::json!({
                "kind": "away_confirmed",
                "network": "libera",
                "state": state,
                "future_field": true
            });
            assert_eq!(
                parse_away_confirmed(&payload, &known_networks),
                Some(("libera".to_string(), expected))
            );
        }
    }

    #[test]
    fn away_confirmed_rejects_unknown_network_and_invalid_state() {
        let known_networks: HashMap<String, i64> =
            [("libera".to_string(), 7)].into_iter().collect();

        for invalid in [
            serde_json::json!({
                "kind": "away_confirmed",
                "network": "unknown",
                "state": "away"
            }),
            serde_json::json!({
                "kind": "away_confirmed",
                "network": "libera",
                "state": "unknown"
            }),
            serde_json::json!({
                "kind": "away_confirmed",
                "network": "libera",
                "state": "awayish"
            }),
            serde_json::json!({
                "kind": "other_kind",
                "network": "libera",
                "state": "away"
            }),
            serde_json::json!({
                "kind": "away_confirmed",
                "network": "   ",
                "state": "present"
            }),
        ] {
            assert_eq!(parse_away_confirmed(&invalid, &known_networks), None);
        }
    }

    #[test]
    fn session_identity_changed_preserves_true_with_null_account() {
        let network_slugs: HashMap<i64, String> = [(7, "libera".to_string())].into_iter().collect();
        let payload = serde_json::json!({
            "kind": "session_identity_changed",
            "network_id": 7,
            "identified": true,
            "account": null,
            "future_field": {"is_ignored": true}
        });

        assert_eq!(
            parse_session_identity_changed(&payload, &network_slugs),
            Some((
                "libera".to_string(),
                SessionIdentity {
                    identified: true,
                    account: None,
                }
            ))
        );
    }

    #[test]
    fn session_identity_changed_rejects_unknown_network_and_invalid_fields() {
        let network_slugs: HashMap<i64, String> = [(7, "libera".to_string())].into_iter().collect();

        for invalid in [
            serde_json::json!({
                "kind": "session_identity_changed",
                "network_id": 8,
                "identified": true,
                "account": "vjt"
            }),
            serde_json::json!({
                "kind": "session_identity_changed",
                "network_id": "7",
                "identified": true,
                "account": "vjt"
            }),
            serde_json::json!({
                "kind": "session_identity_changed",
                "network_id": 7,
                "identified": "true",
                "account": "vjt"
            }),
            serde_json::json!({
                "kind": "session_identity_changed",
                "network_id": 7,
                "identified": true
            }),
            serde_json::json!({
                "kind": "session_identity_changed",
                "network_id": 7,
                "identified": true,
                "account": 42
            }),
            serde_json::json!({
                "kind": "other_kind",
                "network_id": 7,
                "identified": true,
                "account": null
            }),
        ] {
            assert_eq!(
                parse_session_identity_changed(&invalid, &network_slugs),
                None
            );
        }
    }

    #[test]
    fn session_identity_changed_is_user_carrier_scoped_and_per_network() {
        let mut state = WorkerState::new();
        state.identifier = Some("vjt".to_string());
        state.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
            .into_iter()
            .collect();
        let message_key = ("libera".to_string(), "#rust".to_string());
        state.messages.insert(
            message_key.clone(),
            vec![render_message(
                &serde_json::json!({"kind": "privmsg", "sender": "Alice", "body": "hello"}),
                None,
            )],
        );
        let identified_without_account = serde_json::json!({
            "kind": "session_identity_changed",
            "network_id": 7,
            "identified": true,
            "account": null
        });

        handle_session_identity_changed(
            &mut state,
            "grappa:user:vjt/network:libera/channel:#rust",
            &identified_without_account,
        );
        assert!(state.session_identities.is_empty());

        handle_session_identity_changed(
            &mut state,
            "grappa:user:vjt",
            &serde_json::json!({
                "kind": "session_identity_changed",
                "network_id": 99,
                "identified": true,
                "account": "unknown"
            }),
        );
        assert!(state.session_identities.is_empty());

        handle_session_identity_changed(&mut state, "grappa:user:vjt", &identified_without_account);
        handle_session_identity_changed(
            &mut state,
            "grappa:user:vjt",
            &serde_json::json!({
                "kind": "session_identity_changed",
                "network_id": 9,
                "identified": false,
                "account": "descriptive-account"
            }),
        );

        assert_eq!(
            state.session_identities.get("libera"),
            Some(&SessionIdentity {
                identified: true,
                account: None,
            })
        );
        assert_eq!(
            state.session_identities.get("azzurra"),
            Some(&SessionIdentity {
                identified: false,
                account: Some("descriptive-account".to_string()),
            })
        );
        assert_eq!(state.messages.get(&message_key).map(Vec::len), Some(1));
    }

    fn isupport_payload(network_id: i64, casemapping: &str, frame_budget_base: u64) -> Value {
        serde_json::json!({
            "kind": "isupport_changed",
            "network_id": network_id,
            "chanmodes_a": ["b"],
            "chanmodes_b": ["k"],
            "chanmodes_c": ["l"],
            "chanmodes_d": ["i", "m"],
            "list_modes_queryable": ["b"],
            "prefix": {"o": "@", "v": "+"},
            "prefix_order": ["o", "v"],
            "chantypes": ["#"],
            "casemapping": casemapping,
            "maxlist": {"b": 100},
            "nicklen": 30,
            "channellen": null,
            "topiclen": 390,
            "frame_budget_base": frame_budget_base,
            "future_field": ["ignored"]
        })
    }

    #[test]
    fn isupport_changed_is_user_carrier_scoped_and_replaces_only_its_network() {
        let mut state = WorkerState::new();
        state.identifier = Some("vjt".to_string());
        state.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
            .into_iter()
            .collect();

        handle_isupport_changed(
            &mut state,
            "grappa:user:vjt",
            &isupport_payload(7, "rfc1459", 4096),
        );
        handle_isupport_changed(
            &mut state,
            "grappa:user:vjt",
            &isupport_payload(9, "ascii", 2048),
        );
        let azzurra = state
            .isupport_by_network
            .get("azzurra")
            .expect("second network snapshot")
            .clone();

        handle_isupport_changed(
            &mut state,
            "grappa:user:vjt",
            &isupport_payload(7, "rfc1459_strict", 8192),
        );

        assert_eq!(
            state
                .isupport_by_network
                .get("libera")
                .map(|state| state.frame_budget_base),
            Some(8192)
        );
        assert_eq!(state.isupport_by_network.get("azzurra"), Some(&azzurra));
    }

    #[test]
    fn isupport_changed_rejects_bad_carrier_network_and_payload_without_mutation() {
        let mut state = WorkerState::new();
        state.identifier = Some("vjt".to_string());
        state.network_ids = [("libera".to_string(), 7)].into_iter().collect();

        handle_isupport_changed(
            &mut state,
            "grappa:user:vjt/network:libera/channel:#rust",
            &isupport_payload(7, "rfc1459", 4096),
        );
        handle_isupport_changed(
            &mut state,
            "grappa:user:vjt",
            &isupport_payload(99, "rfc1459", 4096),
        );
        handle_isupport_changed(
            &mut state,
            "grappa:user:vjt",
            &isupport_payload(7, "unicode", 4096),
        );

        assert!(state.isupport_by_network.is_empty());

        handle_isupport_changed(
            &mut state,
            "grappa:user:vjt",
            &isupport_payload(7, "rfc1459", 4096),
        );
        let accepted = state.isupport_by_network.clone();
        let mut invalid = isupport_payload(7, "rfc1459", 4096);
        invalid["maxlist"] = serde_json::json!({"b": 0});
        handle_isupport_changed(&mut state, "grappa:user:vjt", &invalid);

        assert_eq!(state.isupport_by_network, accepted);
    }

    #[test]
    fn umode_changed_preserves_ordered_set_and_replays_as_replacement() {
        let mut state = WorkerState::new();
        state.identifier = Some("vjt".to_string());
        state.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
            .into_iter()
            .collect();

        let libera = serde_json::json!({
            "kind": "umode_changed",
            "network_id": 7,
            "modes": ["i", "w", "s"],
            "future_field": true
        });
        handle_umode_changed(&mut state, "grappa:user:vjt", &libera);
        handle_umode_changed(&mut state, "grappa:user:vjt", &libera);
        handle_umode_changed(
            &mut state,
            "grappa:user:vjt",
            &serde_json::json!({
                "kind": "umode_changed",
                "network_id": 9,
                "modes": ["w", "i"]
            }),
        );

        assert_eq!(state.user_modes_by_network.len(), 2);
        assert_eq!(state.user_modes_by_network["libera"], ["i", "w", "s"]);
        assert_eq!(state.user_modes_by_network["azzurra"], ["w", "i"]);

        handle_umode_changed(
            &mut state,
            "grappa:user:vjt",
            &serde_json::json!({
                "kind": "umode_changed",
                "network_id": 7,
                "modes": []
            }),
        );
        assert!(state.user_modes_by_network["libera"].is_empty());
        assert_eq!(state.user_modes_by_network["azzurra"], ["w", "i"]);
    }

    #[test]
    fn umode_changed_rejects_bad_carrier_network_and_payload_without_mutation() {
        let mut state = WorkerState::new();
        state.identifier = Some("vjt".to_string());
        state.network_ids = [("libera".to_string(), 7)].into_iter().collect();
        let accepted = serde_json::json!({
            "kind": "umode_changed",
            "network_id": 7,
            "modes": ["i", "w"]
        });

        handle_umode_changed(
            &mut state,
            "grappa:user:vjt/network:libera/channel:#rust",
            &accepted,
        );
        assert!(state.user_modes_by_network.is_empty());

        handle_umode_changed(&mut state, "grappa:user:vjt", &accepted);
        let original = state.user_modes_by_network.clone();
        for invalid in [
            serde_json::json!({"kind": "umode_changed", "network_id": 99, "modes": ["i"]}),
            serde_json::json!({"kind": "umode_changed", "network_id": 0, "modes": ["i"]}),
            serde_json::json!({"kind": "umode_changed", "network_id": "7", "modes": ["i"]}),
            serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": "iw"}),
            serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": ["i", 1]}),
            serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": ["i", "i"]}),
            serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": ["+i"]}),
            serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": [""]}),
            serde_json::json!({"kind": "other_kind", "network_id": 7, "modes": ["s"]}),
        ] {
            handle_umode_changed(&mut state, "grappa:user:vjt", &invalid);
            assert_eq!(state.user_modes_by_network, original);
        }
    }

    #[test]
    fn supported_umodes_changed_is_separate_ordered_per_network_and_replays_as_replacement() {
        let mut state = WorkerState::new();
        state.identifier = Some("vjt".to_string());
        state.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
            .into_iter()
            .collect();

        handle_umode_changed(
            &mut state,
            "grappa:user:vjt",
            &serde_json::json!({
                "kind": "umode_changed",
                "network_id": 7,
                "modes": ["i"]
            }),
        );
        let libera = serde_json::json!({
            "kind": "supported_umodes_changed",
            "network_id": 7,
            "modes": ["i", "w", "s"],
            "future_field": true
        });
        handle_supported_umodes_changed(&mut state, "grappa:user:vjt", &libera);
        handle_supported_umodes_changed(&mut state, "grappa:user:vjt", &libera);
        handle_supported_umodes_changed(
            &mut state,
            "grappa:user:vjt",
            &serde_json::json!({
                "kind": "supported_umodes_changed",
                "network_id": 9,
                "modes": ["w", "i"]
            }),
        );

        assert_eq!(state.supported_user_modes_by_network.len(), 2);
        assert_eq!(
            state.supported_user_modes_by_network["libera"],
            ["i", "w", "s"]
        );
        assert_eq!(state.supported_user_modes_by_network["azzurra"], ["w", "i"]);
        assert_eq!(state.user_modes_by_network["libera"], ["i"]);

        handle_supported_umodes_changed(
            &mut state,
            "grappa:user:vjt",
            &serde_json::json!({
                "kind": "supported_umodes_changed",
                "network_id": 7,
                "modes": []
            }),
        );
        assert!(state.supported_user_modes_by_network["libera"].is_empty());
        assert_eq!(state.supported_user_modes_by_network["azzurra"], ["w", "i"]);
        assert_eq!(state.user_modes_by_network["libera"], ["i"]);
    }

    #[test]
    fn supported_umodes_changed_rejects_bad_carrier_network_and_payload_without_mutation() {
        let mut state = WorkerState::new();
        state.identifier = Some("vjt".to_string());
        state.network_ids = [("libera".to_string(), 7)].into_iter().collect();
        let accepted = serde_json::json!({
            "kind": "supported_umodes_changed",
            "network_id": 7,
            "modes": ["i", "w"]
        });

        handle_supported_umodes_changed(
            &mut state,
            "grappa:user:vjt/network:libera/channel:#rust",
            &accepted,
        );
        assert!(state.supported_user_modes_by_network.is_empty());

        handle_supported_umodes_changed(&mut state, "grappa:user:vjt", &accepted);
        let original = state.supported_user_modes_by_network.clone();
        for invalid in [
            serde_json::json!({"kind": "supported_umodes_changed", "network_id": 99, "modes": ["i"]}),
            serde_json::json!({"kind": "supported_umodes_changed", "network_id": 0, "modes": ["i"]}),
            serde_json::json!({"kind": "supported_umodes_changed", "network_id": "7", "modes": ["i"]}),
            serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": "iw"}),
            serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": ["i", 1]}),
            serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": ["i", "i"]}),
            serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": ["+i"]}),
            serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": ["-i"]}),
            serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": [""]}),
            serde_json::json!({"kind": "other_kind", "network_id": 7, "modes": ["s"]}),
        ] {
            handle_supported_umodes_changed(&mut state, "grappa:user:vjt", &invalid);
            assert_eq!(state.supported_user_modes_by_network, original);
        }
    }

    #[test]
    fn late_away_confirmation_updates_one_network_without_resetting_other_state() {
        let mut state = WorkerState::new();
        state.identifier = Some("vjt".to_string());
        state.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
            .into_iter()
            .collect();
        state
            .away_states
            .insert("azzurra".to_string(), AwayStatus::Present);

        // `mentions_bundle` remains an independent gap. This models existing
        // message state and ensures an away ACK can't clear broader UI state.
        let message_key = ("libera".to_string(), "#rust".to_string());
        let existing_messages = vec![render_message(
            &serde_json::json!({"kind": "privmsg", "sender": "Alice", "body": "hello"}),
            None,
        )];
        state
            .messages
            .insert(message_key.clone(), existing_messages.clone());

        let away_payload = serde_json::json!({
            "kind": "away_confirmed",
            "network": "libera",
            "state": "away"
        });
        handle_away_confirmed(
            &mut state,
            "grappa:user:vjt/network:libera/channel:#rust",
            &away_payload,
        );
        assert!(!state.away_states.contains_key("libera"));

        handle_away_confirmed(&mut state, "grappa:user:vjt", &away_payload);

        assert_eq!(state.away_states.get("libera"), Some(&AwayStatus::Away));
        assert_eq!(state.away_states.get("azzurra"), Some(&AwayStatus::Present));
        assert_eq!(
            state.messages.get(&message_key).map(Vec::len),
            Some(existing_messages.len())
        );
        assert_eq!(
            state
                .messages
                .get(&message_key)
                .and_then(|messages| messages.first())
                .map(|message| message.text.as_str()),
            Some("hello")
        );

        // A late repeat is idempotent; a later server-confirmed return to
        // present is a normal per-network state transition.
        assert!(!apply_away_confirmed(
            &mut state.away_states,
            "libera",
            AwayStatus::Away
        ));
        assert!(apply_away_confirmed(
            &mut state.away_states,
            "libera",
            AwayStatus::Present
        ));
        assert_eq!(state.away_states.get("libera"), Some(&AwayStatus::Present));
        assert_eq!(
            state.messages.get(&message_key).map(Vec::len),
            Some(existing_messages.len())
        );
        assert_eq!(
            state
                .messages
                .get(&message_key)
                .and_then(|messages| messages.first())
                .map(|message| message.text.as_str()),
            Some("hello")
        );
    }

    #[test]
    fn channels_changed_signal_requires_exact_kind_and_user_topic() {
        let payload = serde_json::json!({"kind": "channels_changed"});
        assert!(is_channels_changed_signal(
            "vjt",
            "grappa:user:vjt",
            &payload
        ));
        assert!(!is_channels_changed_signal(
            "vjt",
            "grappa:user:someone-else",
            &payload
        ));
        assert!(!is_channels_changed_signal(
            "vjt",
            "grappa:user:vjt/network:libera/channel:#rust",
            &payload
        ));
        assert!(!is_channels_changed_signal(
            "vjt",
            "grappa:user:vjt",
            &serde_json::json!({"kind": "message"})
        ));
    }

    #[test]
    fn channels_changed_reconciles_authoritative_topics_idempotently() {
        let entry = |channel: &str| {
            (
                "libera".to_string(),
                channel.to_string(),
                channel.to_string(),
            )
        };
        let user = "vjt";
        let mut state = WorkerState::new();
        let initial = vec![entry("#alpha"), entry("#beta")];

        assert_eq!(
            reconcile_channel_entries(&mut state, user, initial.clone()),
            vec![
                ChannelTopicAction::Join(channel_topic(user, "libera", "#alpha")),
                ChannelTopicAction::Join(channel_topic(user, "libera", "#beta")),
            ]
        );
        assert_eq!(state.channel_entries, initial);
        assert!(reconcile_channel_entries(&mut state, user, initial).is_empty());

        let updated = vec![entry("#beta"), entry("#gamma")];
        assert_eq!(
            reconcile_channel_entries(&mut state, user, updated.clone()),
            vec![
                ChannelTopicAction::Leave(channel_topic(user, "libera", "#alpha")),
                ChannelTopicAction::Join(channel_topic(user, "libera", "#gamma")),
            ]
        );
        assert_eq!(state.channel_entries, updated);
        assert_eq!(state.channel_topics.len(), 2);
        assert!(reconcile_channel_entries(&mut state, user, updated).is_empty());
    }

    #[test]
    fn channels_changed_keeps_topics_owned_by_queries_and_own_nick_listener() {
        let user = "vjt";
        let mut state = WorkerState::new();
        state.query_windows.push(QueryWindow {
            network: "libera".to_string(),
            target_nick: "Peer".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        });
        state
            .stale_query_topics
            .insert(query_window_key("libera", "FormerPeer"));
        state
            .own_nicks
            .insert("libera".to_string(), "OwnNick".to_string());

        let active_query_topic = query_topic(user, "libera", "Peer");
        let stale_query_topic = query_topic(user, "libera", "FormerPeer");
        let own_topic = own_nick_listener_topic(user, "libera", "OwnNick");
        let channel_only_topic = channel_topic(user, "libera", "orphan");
        state.channel_topics.extend([
            active_query_topic.clone(),
            stale_query_topic.clone(),
            own_topic.clone(),
            channel_only_topic.clone(),
        ]);
        state.joined_topics = state.channel_topics.clone();

        assert_eq!(
            reconcile_channel_entries(&mut state, user, Vec::new()),
            vec![ChannelTopicAction::Leave(channel_only_topic.clone())]
        );
        assert!(state.joined_topics.contains(&active_query_topic));
        assert!(state.joined_topics.contains(&stale_query_topic));
        assert!(state.joined_topics.contains(&own_topic));
        assert!(!state.joined_topics.contains(&channel_only_topic));
        assert!(state.channel_topics.is_empty());
    }

    #[test]
    fn own_nick_rename_leaves_old_topic_before_joining_new_topic() {
        let mut state = WorkerState::new();
        state
            .own_nicks
            .insert("libera".to_string(), "OldNick".to_string());
        state
            .own_nicks
            .insert("azzurra".to_string(), "AwayNick".to_string());
        let old_topic = own_nick_listener_topic("vjt", "libera", "OldNick");
        let new_topic = own_nick_listener_topic("vjt", "libera", "NewNick");
        let other_topic = own_nick_listener_topic("vjt", "azzurra", "AwayNick");
        state
            .joined_topics
            .extend([old_topic.clone(), other_topic.clone()]);
        state.own_listener_ready.insert(old_topic.clone());
        state.own_listener_ready.insert(other_topic.clone());

        let actions = apply_own_nick_change(&mut state, "vjt", "libera", "NewNick");

        assert_eq!(
            actions,
            vec![
                OwnNickListenerAction::Leave(old_topic.clone()),
                OwnNickListenerAction::Join(new_topic.clone()),
            ]
        );
        assert!(!state.joined_topics.contains(&old_topic));
        assert!(state.joined_topics.contains(&new_topic));
        assert!(!state.own_listener_ready.contains(&old_topic));
        assert!(!state.own_listener_ready.contains(&new_topic));
        assert!(state.joined_topics.contains(&other_topic));
        assert!(state.own_listener_ready.contains(&other_topic));
        assert_eq!(
            state.own_nicks.get("libera").map(String::as_str),
            Some("NewNick")
        );
        assert_eq!(
            state.own_nicks.get("azzurra").map(String::as_str),
            Some("AwayNick")
        );
    }

    #[test]
    fn own_nick_rename_keeps_old_topic_when_an_open_query_owns_it() {
        let mut state = WorkerState::new();
        state
            .own_nicks
            .insert("libera".to_string(), "OldNick".to_string());
        state.identifier = Some("vjt".to_string());
        state.query_windows.push(QueryWindow {
            network: "libera".to_string(),
            target_nick: "OldNick".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        });
        let old_topic = own_nick_listener_topic("vjt", "libera", "OldNick");
        let new_topic = own_nick_listener_topic("vjt", "libera", "NewNick");
        let old_query = query_window_key("libera", "OldNick");
        state.joined_topics.insert(old_topic.clone());
        state.own_listener_ready.insert(old_topic.clone());
        state.query_joined.insert(old_query.clone());
        state.query_ready.insert(old_query.clone());

        let actions = apply_own_nick_change(&mut state, "vjt", "libera", "NewNick");

        assert_eq!(
            actions,
            vec![OwnNickListenerAction::Join(new_topic.clone())]
        );
        assert!(state.joined_topics.contains(&old_topic));
        assert!(!state.own_listener_ready.contains(&old_topic));
        assert!(state.joined_topics.contains(&new_topic));
        assert!(!state.own_listener_ready.contains(&new_topic));
        assert!(state.query_joined.contains(&old_query));
        assert!(state.query_ready.contains(&old_query));
        assert_eq!(
            own_nick_listener_network_for_topic(&state, &old_topic),
            None
        );
        assert!(matches!(
            resolve_query_topic(
                &state.query_windows,
                &state.stale_query_topics,
                "libera",
                "OldNick"
            ),
            QueryTopicResolution::Active(_)
        ));
    }

    #[test]
    fn own_nick_case_only_change_updates_spelling_without_rejoining() {
        let mut state = WorkerState::new();
        state
            .own_nicks
            .insert("libera".to_string(), "Foo".to_string());
        let topic = own_nick_listener_topic("vjt", "libera", "Foo");
        state.joined_topics.insert(topic.clone());
        state.own_listener_ready.insert(topic.clone());

        let actions = apply_own_nick_change(&mut state, "vjt", "libera", "fOO");

        assert!(actions.is_empty());
        assert_eq!(
            state.own_nicks.get("libera").map(String::as_str),
            Some("fOO")
        );
        assert!(state.joined_topics.contains(&topic));
        assert!(state.own_listener_ready.contains(&topic));
    }

    #[test]
    fn own_nick_listener_readiness_requires_ack_and_fails_closed_without_it() {
        let mut state = WorkerState::new();
        state.identifier = Some("vjt".to_string());
        state
            .own_nicks
            .insert("libera".to_string(), "OldNick".to_string());
        let old_topic = own_nick_listener_topic("vjt", "libera", "OldNick");
        let new_topic = own_nick_listener_topic("vjt", "libera", "NewNick");
        state.joined_topics.insert(old_topic.clone());
        state.own_listener_ready.insert(old_topic.clone());

        assert_eq!(
            apply_own_nick_change(&mut state, "vjt", "libera", "NewNick"),
            vec![
                OwnNickListenerAction::Leave(old_topic.clone()),
                OwnNickListenerAction::Join(new_topic.clone()),
            ]
        );
        // A join with no reply (including a timeout) never reaches the
        // positive-ACK transition and must remain unusable for DM routing.
        assert!(!state.own_listener_ready.contains(&new_topic));
        assert_eq!(
            handle_own_nick_listener_join_reply(&mut state, &new_topic, Some("error")),
            OwnNickListenerJoinReply::Rejected
        );
        assert!(!state.own_listener_ready.contains(&new_topic));
        assert_eq!(
            handle_own_nick_listener_join_reply(&mut state, &new_topic, None),
            OwnNickListenerJoinReply::Rejected
        );
        assert!(!state.own_listener_ready.contains(&new_topic));
        assert_eq!(
            handle_own_nick_listener_join_reply(&mut state, &new_topic, Some("ok")),
            OwnNickListenerJoinReply::Accepted
        );
        assert!(state.own_listener_ready.contains(&new_topic));
        assert_eq!(
            handle_own_nick_listener_join_reply(&mut state, &old_topic, Some("ok")),
            OwnNickListenerJoinReply::Untracked
        );
        assert!(!state.own_listener_ready.contains(&old_topic));
    }

    #[test]
    fn own_nick_listener_accepts_privmsg_and_action() {
        assert!(own_nick_listener_accepts_inbound_dm(&serde_json::json!({
            "kind": "privmsg"
        })));
        assert!(own_nick_listener_accepts_inbound_dm(&serde_json::json!({
            "kind": "action"
        })));
    }

    #[test]
    fn own_nick_listener_rejects_non_dm_kinds() {
        assert!(!own_nick_listener_accepts_inbound_dm(&serde_json::json!({
            "kind": "notice"
        })));
    }

    #[test]
    fn own_nick_dm_is_appended_only_to_an_authoritative_existing_query() {
        let mut state = WorkerState::new();
        state.query_windows = vec![QueryWindow {
            network: "libera".to_string(),
            target_nick: "Peer".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        }];
        let inbound = serde_json::json!({
            "kind": "privmsg",
            "sender": "peer",
            "body": "inbound DM",
            "id": 41
        });

        let key = own_nick_dm_query_key(&state, "libera", &inbound).unwrap();
        assert_eq!(key, ("libera".to_string(), "Peer".to_string()));
        let identity = query_window_key(&key.0, &key.1);
        require_query_full_history_if_unready(&mut state, &key);
        assert!(append_query_live_message(
            &mut state,
            &key,
            &inbound,
            Some("message")
        ));
        assert_eq!(
            state.messages.get(&key).unwrap()[0].text.as_str(),
            "inbound DM"
        );
        assert_eq!(
            query_history_fetch_window(&state, &identity, &key),
            (None, None)
        );

        let unknown_sender = serde_json::json!({
            "kind": "privmsg",
            "sender": "not-listed",
            "body": "do not invent a query",
            "id": 42
        });
        assert_eq!(
            own_nick_dm_query_key(&state, "libera", &unknown_sender),
            None
        );
        assert_eq!(own_nick_dm_query_key(&state, "azzurra", &inbound), None);
        assert_eq!(state.query_windows.len(), 1);
        assert_eq!(state.messages.len(), 1);
    }

    #[test]
    fn own_nick_dm_fifo_waits_for_snapshot_then_merges_with_history_by_id() {
        let mut state = WorkerState::new();
        let first = serde_json::json!({
            "kind": "privmsg",
            "sender": "peer",
            "body": "first buffered",
            "id": 41,
            "server_time": 2_000
        });
        let second = serde_json::json!({
            "kind": "privmsg",
            "sender": "peer",
            "body": "second buffered",
            "id": 42,
            "server_time": 3_000
        });

        assert_eq!(own_nick_dm_query_key(&state, "libera", &first), None);
        buffer_pending_own_nick_dm(&mut state, "libera", &first, "message");
        buffer_pending_own_nick_dm(&mut state, "libera", &second, "message");
        assert_eq!(state.pending_own_nick_dms.len(), 2);
        assert!(state.messages.is_empty());

        let query = QueryWindow {
            network: "libera".to_string(),
            target_nick: "Peer".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        };
        assert!(!apply_query_windows_snapshot(&mut state, vec![query]));
        drain_pending_own_nick_dms(&mut state);

        let key = ("libera".to_string(), "Peer".to_string());
        let identity = query_window_key(&key.0, &key.1);
        assert!(state.pending_own_nick_dms.is_empty());
        assert!(state.query_full_history_required.contains(&identity));
        assert_eq!(
            query_history_fetch_window(&state, &identity, &key),
            (None, None)
        );
        assert_eq!(
            state.messages[&key]
                .iter()
                .filter_map(|message| message.message_id)
                .collect::<Vec<_>>(),
            vec![41, 42]
        );

        merge_query_history(
            &mut state,
            &key,
            &[
                serde_json::json!({
                    "kind": "privmsg",
                    "sender": "peer",
                    "body": "older history",
                    "id": 40,
                    "server_time": 1_000
                }),
                serde_json::json!({
                    "kind": "privmsg",
                    "sender": "peer",
                    "body": "duplicate history row",
                    "id": 41,
                    "server_time": 2_000
                }),
            ],
        );

        let messages = &state.messages[&key];
        assert_eq!(
            messages
                .iter()
                .filter_map(|message| message.message_id)
                .collect::<Vec<_>>(),
            vec![40, 41, 42]
        );
        assert_eq!(messages[1].text, "first buffered");
        state.query_full_history_required.remove(&identity);
        assert_eq!(
            query_history_fetch_window(&state, &identity, &key),
            (Some(42), Some(200))
        );
    }

    #[test]
    fn own_nick_dm_buffer_is_bounded_and_unconfirmed_queries_are_discarded() {
        let mut state = WorkerState::new();
        for id in 0..(MAX_PENDING_OWN_NICK_DMS + 2) {
            let payload = serde_json::json!({
                "kind": "privmsg",
                "sender": "unlisted",
                "body": format!("message {id}"),
                "id": id as i64,
                "server_time": id as i64
            });
            buffer_pending_own_nick_dm(&mut state, "libera", &payload, "message");
        }
        assert_eq!(state.pending_own_nick_dms.len(), MAX_PENDING_OWN_NICK_DMS);
        assert_eq!(
            state.pending_own_nick_dms.front().unwrap().payload["id"].as_i64(),
            Some(2)
        );

        assert!(!apply_query_windows_snapshot(&mut state, Vec::new()));
        drain_pending_own_nick_dms(&mut state);
        assert!(state.pending_own_nick_dms.is_empty());
        assert!(state.query_windows.is_empty());
        assert!(state.messages.is_empty());
    }

    #[test]
    fn channel_shaped_topics_distinguish_active_stale_and_normal_windows() {
        let active = QueryWindow {
            network: "libera".to_string(),
            target_nick: "peer".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        };
        let stale: std::collections::HashSet<(String, String)> =
            [query_window_key("libera", "oldpeer")]
                .into_iter()
                .collect();
        let windows = vec![active.clone()];

        assert!(matches!(
            resolve_query_topic(&windows, &stale, "libera", "PEER"),
            QueryTopicResolution::Active(query) if query == &active
        ));
        assert!(matches!(
            resolve_query_topic(&windows, &stale, "libera", "oldpeer"),
            QueryTopicResolution::Stale
        ));
        assert!(matches!(
            resolve_query_topic(&windows, &stale, "libera", "#rust"),
            QueryTopicResolution::Untracked
        ));
    }

    #[test]
    fn query_windows_snapshot_maps_ids_and_preserves_server_order() {
        let network_slugs: HashMap<i64, String> =
            [(1, "libera".to_string()), (2, "azzurra".to_string())]
                .into_iter()
                .collect();
        let payload = serde_json::json!({
            "kind": "query_windows_list",
            "windows": {
                "1": [
                    {"network_id": 1, "target_nick": "older", "opened_at": "2026-09-21T10:00:00Z"},
                    {"network_id": 1, "target_nick": "newer", "opened_at": "2026-09-21T11:00:00Z"}
                ],
                "2": [
                    {"network_id": 2, "target_nick": "peer", "opened_at": "2026-09-21T12:00:00+02:00"}
                ]
            },
            "future_field": true
        });

        let queries = parse_query_windows_list(&payload, &network_slugs).unwrap();
        assert_eq!(queries.len(), 3);
        assert_eq!(queries[0].network, "libera");
        assert_eq!(queries[0].target_nick, "older");
        assert_eq!(queries[1].target_nick, "newer");
        assert_eq!(queries[2].network, "azzurra");

        let grouped = network_groups_data(&[], &queries, &HashMap::new());
        let libera = grouped.iter().find(|group| group.0 == "libera").unwrap();
        assert_eq!(libera.3[0].0, "older");
        assert_eq!(libera.3[1].0, "newer");
    }

    #[test]
    fn query_windows_snapshot_accepts_empty_and_rejects_invalid_rows_atomically() {
        let network_slugs: HashMap<i64, String> = [(1, "libera".to_string())].into_iter().collect();
        let empty = serde_json::json!({"kind": "query_windows_list", "windows": {}});
        assert_eq!(
            parse_query_windows_list(&empty, &network_slugs),
            Some(Vec::new())
        );

        let bad_timestamp = serde_json::json!({
            "kind": "query_windows_list",
            "windows": {"1": [{
                "network_id": 1,
                "target_nick": "peer",
                "opened_at": "not-rfc3339"
            }]}
        });
        assert_eq!(
            parse_query_windows_list(&bad_timestamp, &network_slugs),
            None
        );

        let mismatched_id = serde_json::json!({
            "kind": "query_windows_list",
            "windows": {"1": [{
                "network_id": 2,
                "target_nick": "peer",
                "opened_at": "2026-09-21T10:00:00Z"
            }]}
        });
        assert_eq!(
            parse_query_windows_list(&mismatched_id, &network_slugs),
            None
        );

        let unknown_network = serde_json::json!({
            "kind": "query_windows_list",
            "windows": {"9": []}
        });
        assert_eq!(
            parse_query_windows_list(&unknown_network, &network_slugs),
            None
        );

        let duplicate_folded_nick = serde_json::json!({
            "kind": "query_windows_list",
            "windows": {"1": [
                {"network_id": 1, "target_nick": "Peer", "opened_at": "2026-09-21T10:00:00Z"},
                {"network_id": 1, "target_nick": "peer", "opened_at": "2026-09-21T11:00:00Z"}
            ]}
        });
        assert_eq!(
            parse_query_windows_list(&duplicate_folded_nick, &network_slugs),
            None
        );
    }

    #[test]
    fn query_windows_snapshot_replaces_state_and_migrates_unambiguous_rename() {
        let old = QueryWindow {
            network: "libera".to_string(),
            target_nick: "oldnick".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        };
        let renamed = QueryWindow {
            network: "libera".to_string(),
            target_nick: "newnick".to_string(),
            opened_at: "2026-09-21T12:00:00+02:00".to_string(),
        };
        let old_key = (old.network.clone(), old.target_nick.clone());
        let new_key = (renamed.network.clone(), renamed.target_nick.clone());
        let mut state = WorkerState::new();
        state.query_windows = vec![old.clone()];
        state
            .query_joined
            .insert(query_window_key(&old.network, &old.target_nick));
        state
            .query_ready
            .insert(query_window_key(&old.network, &old.target_nick));
        state.current_query = true;
        state.current_query_ready = true;
        state.current_channel = Some(old_key.clone());
        state.messages.insert(old_key.clone(), Vec::new());
        state
            .drafts
            .insert(old_key.clone(), "unsent draft".to_string());

        let previous = state.query_windows.clone();
        assert!(!apply_query_windows_snapshot(
            &mut state,
            vec![renamed.clone()]
        ));
        reconcile_query_topic_tracking(&mut state, &previous);
        assert_eq!(state.query_windows, vec![renamed]);
        assert_eq!(state.current_channel, Some(new_key.clone()));
        assert!(!state.current_query_ready);
        assert!(state
            .query_joined
            .contains(&query_window_key(&old.network, &old.target_nick)));
        assert!(!state
            .query_ready
            .contains(&query_window_key(&old.network, &old.target_nick)));
        assert!(state
            .stale_query_topics
            .contains(&query_window_key(&old.network, &old.target_nick)));
        assert!(state.messages.contains_key(&new_key));
        assert_eq!(
            state.drafts.get(&new_key).map(String::as_str),
            Some("unsent draft")
        );

        let previous = state.query_windows.clone();
        assert!(apply_query_windows_snapshot(&mut state, Vec::new()));
        reconcile_query_topic_tracking(&mut state, &previous);
        assert!(state.query_windows.is_empty());
        assert!(!state.current_query);
        assert_eq!(state.current_channel, None);
    }

    #[test]
    fn query_windows_snapshot_migrates_cache_on_case_only_nick_change() {
        let old = QueryWindow {
            network: "libera".to_string(),
            target_nick: "foo".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        };
        let recased = QueryWindow {
            network: "libera".to_string(),
            target_nick: "Foo".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        };
        let old_key = (old.network.clone(), old.target_nick.clone());
        let recased_key = (recased.network.clone(), recased.target_nick.clone());
        let identity = query_window_key(&old.network, &old.target_nick);
        let topic = query_topic("vjt", &old.network, &old.target_nick);
        let mut state = WorkerState::new();
        state.query_windows = vec![old.clone()];
        state.query_joined.insert(identity.clone());
        state.query_ready.insert(identity.clone());
        state.joined_topics.insert(topic.clone());
        state.messages.insert(
            old_key.clone(),
            vec![RenderedMessage {
                timestamp: "10:00".to_string(),
                nick: Some("foo".to_string()),
                text: "retained history".to_string(),
                italic: false,
                message_id: Some(1),
                server_time: Some(1),
            }],
        );
        state
            .drafts
            .insert(old_key.clone(), "unsent draft".to_string());

        let previous = state.query_windows.clone();
        assert!(!apply_query_windows_snapshot(
            &mut state,
            vec![recased.clone()]
        ));
        reconcile_query_topic_tracking(&mut state, &previous);

        assert_eq!(state.query_windows, vec![recased]);
        assert!(!state.messages.contains_key(&old_key));
        assert_eq!(state.messages[&recased_key][0].text, "retained history");
        assert!(!state.drafts.contains_key(&old_key));
        assert_eq!(
            state.drafts.get(&recased_key).map(String::as_str),
            Some("unsent draft")
        );
        assert!(state.query_joined.contains(&identity));
        assert!(state.query_ready.contains(&identity));
        assert!(state.joined_topics.contains(&topic));
        assert!(!state.stale_query_topics.contains(&identity));
    }

    #[test]
    fn query_window_rename_matching_refuses_ambiguous_open_times() {
        let old_one = QueryWindow {
            network: "libera".to_string(),
            target_nick: "old-one".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        };
        let old_two = QueryWindow {
            network: "libera".to_string(),
            target_nick: "old-two".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        };
        let new_one = QueryWindow {
            network: "libera".to_string(),
            target_nick: "new-one".to_string(),
            opened_at: "2026-09-21T12:00:00+02:00".to_string(),
        };
        let new_two = QueryWindow {
            network: "libera".to_string(),
            target_nick: "new-two".to_string(),
            opened_at: "2026-09-21T12:00:00+02:00".to_string(),
        };

        assert!(query_window_renames(&[old_one, old_two], &[new_one, new_two]).is_empty());
    }

    #[test]
    fn closing_and_reopening_query_reuses_join_but_reloads_tail_before_ready() {
        let query = QueryWindow {
            network: "libera".to_string(),
            target_nick: "peer".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        };
        let identity = query_window_key(&query.network, &query.target_nick);
        let topic = query_topic("vjt", &query.network, &query.target_nick);
        let mut state = WorkerState::new();
        state.query_windows = vec![query.clone()];
        state.joined_topics.insert(topic.clone());
        record_query_join_success(&mut state, &identity);
        state.query_ready.insert(identity.clone());

        let previous = state.query_windows.clone();
        assert!(!apply_query_windows_snapshot(&mut state, Vec::new()));
        reconcile_query_topic_tracking(&mut state, &previous);
        assert!(state.stale_query_topics.contains(&identity));
        assert!(state.joined_topics.contains(&topic));
        assert!(state.query_joined.contains(&identity));
        assert!(!state.query_ready.contains(&identity));

        let previous = state.query_windows.clone();
        assert!(!apply_query_windows_snapshot(
            &mut state,
            vec![query.clone()]
        ));
        reconcile_query_topic_tracking(&mut state, &previous);
        assert!(!state.stale_query_topics.contains(&identity));
        assert!(state.joined_topics.contains(&topic));
        assert!(state.query_joined.contains(&identity));
        assert!(!state.query_ready.contains(&identity));
        state.current_query = true;
        state.current_channel = Some(("libera".to_string(), "peer".to_string()));
        mark_query_ready_after_history(&mut state, &identity);
        assert!(state.query_ready.contains(&identity));
        assert!(state.current_query_ready);
    }

    #[test]
    fn reopening_query_after_reconnect_waits_for_ack_and_history_again() {
        let query = QueryWindow {
            network: "libera".to_string(),
            target_nick: "peer".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        };
        let identity = query_window_key(&query.network, &query.target_nick);
        let topic = query_topic("vjt", &query.network, &query.target_nick);
        let mut state = WorkerState::new();
        state.query_windows = vec![query.clone()];
        state.joined_topics.insert(topic);
        record_query_join_success(&mut state, &identity);
        state.query_ready.insert(identity.clone());

        let previous = state.query_windows.clone();
        assert!(!apply_query_windows_snapshot(&mut state, Vec::new()));
        reconcile_query_topic_tracking(&mut state, &previous);
        reset_query_session_readiness(&mut state);
        assert!(state.query_joined.is_empty());
        assert!(state.query_ready.is_empty());

        // The session rejoins the retained stale topic after reconnect; its
        // successful ACK is remembered even though the snapshot still omits it.
        record_query_join_success(&mut state, &identity);
        let previous = state.query_windows.clone();
        assert!(!apply_query_windows_snapshot(&mut state, vec![query]));
        reconcile_query_topic_tracking(&mut state, &previous);
        assert!(state.query_joined.contains(&identity));
        assert!(!state.query_ready.contains(&identity));

        state.current_query = true;
        state.current_channel = Some(("libera".to_string(), "peer".to_string()));
        mark_query_ready_after_history(&mut state, &identity);
        assert!(state.query_ready.contains(&identity));
        assert!(state.current_query_ready);
    }

    #[test]
    fn failed_query_join_clears_readiness_and_allows_a_retry() {
        let identity = query_window_key("libera", "peer");
        let topic = query_topic("vjt", "libera", "peer");
        let mut state = WorkerState::new();
        state.joined_topics.insert(topic.clone());
        state.query_joined.insert(identity.clone());
        state.query_ready.insert(identity.clone());
        state.current_query = true;
        state.current_query_ready = true;
        state.current_channel = Some(("libera".to_string(), "peer".to_string()));

        assert!(reset_query_join_failure(&mut state, &identity, &topic));
        assert!(!state.query_joined.contains(&identity));
        assert!(!state.query_ready.contains(&identity));
        assert!(!state.joined_topics.contains(&topic));
        assert!(!state.current_query_ready);
    }

    #[test]
    fn query_history_merges_tail_and_after_pages_by_time_then_id() {
        let key = ("libera".to_string(), "peer".to_string());
        let mut state = WorkerState::new();
        let tail = vec![
            serde_json::json!({
                "id": 12,
                "server_time": 200,
                "kind": "privmsg",
                "sender": "peer",
                "body": "second"
            }),
            serde_json::json!({
                "id": 10,
                "server_time": 100,
                "kind": "privmsg",
                "sender": "peer",
                "body": "first"
            }),
        ];
        merge_query_history(&mut state, &key, &tail);

        let live = serde_json::json!({
            "id": 13,
            "server_time": 300,
            "kind": "privmsg",
            "sender": "peer",
            "body": "third"
        });
        assert!(append_query_live_message(&mut state, &key, &live, None));
        let after = vec![
            live,
            serde_json::json!({
                "id": 14,
                "server_time": 300,
                "kind": "privmsg",
                "sender": "peer",
                "body": "fourth"
            }),
        ];
        merge_query_history(&mut state, &key, &after);

        let messages = &state.messages[&key];
        assert_eq!(
            messages
                .iter()
                .filter_map(|message| message.message_id)
                .collect::<Vec<_>>(),
            vec![10, 12, 13, 14]
        );
        assert_eq!(query_high_water_id(&state, &key), Some(14));
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
    fn channel_modes_changed_replaces_the_complete_channel_snapshot() {
        let mut state = WorkerState::new();
        let first = serde_json::json!({
            "kind": "channel_modes_changed",
            "network": "libera",
            "channel": "#cordiale",
            "modes": {"modes": ["n", "t", "k"], "params": {"k": "secret", "l": null}},
            "future_field": true
        });
        assert_eq!(
            apply_channel_modes_changed(
                &mut state,
                &channel_topic("sythos", "libera", "#cordiale"),
                &first
            ),
            Some((
                ("libera".to_string(), "#cordiale".to_string()),
                "+ntk".to_string(),
            ))
        );
        let key = ("libera".to_string(), "#cordiale".to_string());
        assert_eq!(
            state.channel_modes[&key].params.get("k"),
            Some(&Some("secret".to_string()))
        );
        assert_eq!(state.channel_modes[&key].params.get("l"), Some(&None));

        let replacement = serde_json::json!({
            "kind": "channel_modes_changed",
            "network": "libera",
            "channel": "#cordiale",
            "modes": {"modes": ["i"], "params": {}}
        });
        assert_eq!(
            apply_channel_modes_changed(
                &mut state,
                &channel_topic("sythos", "libera", "#cordiale"),
                &replacement
            ),
            Some((
                ("libera".to_string(), "#cordiale".to_string()),
                "+i".to_string(),
            ))
        );
        assert_eq!(state.channel_modes.len(), 1);
        assert_eq!(state.channel_modes[&key].modes, vec!["i".to_string()]);
        assert!(state.channel_modes[&key].params.is_empty());
    }

    #[test]
    fn channel_modes_changed_preserves_known_empty_and_rejects_bad_params() {
        let mut state = WorkerState::new();
        let empty = serde_json::json!({
            "network": "libera",
            "channel": "#empty",
            "modes": {"modes": [], "params": {}}
        });
        assert_eq!(
            apply_channel_modes_changed(
                &mut state,
                &channel_topic("sythos", "libera", "#empty"),
                &empty
            ),
            Some((("libera".to_string(), "#empty".to_string()), String::new(),))
        );
        assert!(state
            .channel_modes
            .contains_key(&("libera".to_string(), "#empty".to_string())));

        let malformed = serde_json::json!({
            "network": "libera",
            "channel": "#empty",
            "modes": {"modes": ["n"], "params": {"limit": 42}}
        });
        assert_eq!(
            apply_channel_modes_changed(
                &mut state,
                &channel_topic("sythos", "libera", "#empty"),
                &malformed
            ),
            None
        );
        assert!(
            state.channel_modes[&("libera".to_string(), "#empty".to_string())]
                .modes
                .is_empty()
        );
    }

    #[test]
    fn channel_modes_changed_requires_the_matching_channel_topic() {
        let payload = serde_json::json!({
            "network": "libera",
            "channel": "#cordiale",
            "modes": {"modes": ["n"], "params": {}}
        });
        let mut state = WorkerState::new();

        assert_eq!(
            apply_channel_modes_changed(&mut state, "grappa:user:sythos", &payload),
            None
        );
        assert_eq!(
            apply_channel_modes_changed(
                &mut state,
                &channel_topic("sythos", "libera", "#different"),
                &payload
            ),
            None
        );
        assert!(state.channel_modes.is_empty());
    }

    #[test]
    fn window_counts_updates_messages_and_mentions_for_each_known_window() {
        let mut state = WorkerState::new();
        state.identifier = Some("sythos".to_string());
        state.channel_entries = vec![(
            "libera".to_string(),
            "#Cordiale".to_string(),
            "#Cordiale".to_string(),
        )];
        state.query_windows = vec![QueryWindow {
            network: "libera".to_string(),
            target_nick: "Peer".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        }];

        let channel_payload = serde_json::json!({
            "kind": "window_counts",
            "channel": "#CORDIALE",
            "messages": 9,
            "mentions": 3,
            "events": 2,
            "severity": "mention",
            "future_field": "ignored"
        });
        assert!(apply_window_counts(
            &mut state,
            &channel_topic("sythos", "libera", "#cordiale"),
            &channel_payload
        ));
        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "#cordiale")),
            Some(&3)
        );
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "#cordiale")),
            Some(&9)
        );

        let query_payload = serde_json::json!({
            "kind": "window_counts",
            "channel": "peer",
            "messages": 4,
            "mentions": 1,
            "events": 0,
            "severity": "mention"
        });
        assert!(apply_window_counts(
            &mut state,
            &query_topic("sythos", "libera", "PEER"),
            &query_payload
        ));
        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "Peer")),
            Some(&1)
        );
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "Peer")),
            Some(&4)
        );
        assert_eq!(state.window_mentions.len(), 2);
        assert_eq!(state.window_messages.len(), 2);

        // Snapshots are absolute and last-arrival-wins, even when the count
        // decreases (for example, when an older queued snapshot arrives late).
        let lower_snapshot = serde_json::json!({
            "kind": "window_counts",
            "channel": "#cordiale",
            "messages": 2,
            "mentions": 2,
            "events": 1,
            "severity": "none"
        });
        assert!(apply_window_counts(
            &mut state,
            &channel_topic("sythos", "libera", "#cordiale"),
            &lower_snapshot
        ));
        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "#cordiale")),
            Some(&2)
        );
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "#cordiale")),
            Some(&2)
        );

        let cleared = serde_json::json!({
            "kind": "window_counts",
            "channel": "#cordiale",
            "messages": 0,
            "mentions": 0,
            "events": 0,
            "severity": "none"
        });
        assert!(apply_window_counts(
            &mut state,
            &channel_topic("sythos", "libera", "#cordiale"),
            &cleared
        ));
        assert!(!state
            .window_mentions
            .contains_key(&window_counts_key("libera", "#cordiale")));
        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "Peer")),
            Some(&1)
        );
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "#cordiale")),
            Some(&0)
        );
        assert_eq!(mention_count_labels(0), (String::new(), String::new()));
        assert_eq!(
            mention_count_labels(3),
            (" (3)".to_string(), " — 3 mentions".to_string())
        );
        assert_eq!(
            unread_message_count_labels(None),
            (String::new(), String::new())
        );
        assert_eq!(
            unread_message_count_labels(Some(0)),
            (String::new(), "0 unread messages".to_string())
        );
        assert_eq!(
            unread_message_count_labels(Some(12)),
            ("12".to_string(), "12 unread messages".to_string())
        );
    }

    #[test]
    fn window_counts_from_me_seeds_channel_and_query_counts() {
        let unread_counts = serde_json::json!({
            "libera": {
                "#Cordiale": {
                    "messages": 12,
                    "mentions": 4,
                    "events": 2,
                    "severity": "mention"
                },
                "Peer": {
                    "messages": 3,
                    "mentions": 1,
                    "events": 0,
                    "severity": "message"
                },
                "#invalid": {
                    "messages": 1,
                    "mentions": -1,
                    "events": 0,
                    "severity": "mention"
                }
            },
            "": {
                "#ignored": {
                    "messages": 1,
                    "mentions": 1,
                    "events": 0,
                    "severity": "mention"
                }
            }
        });

        let mentions = window_mentions_from_me(&unread_counts);
        assert_eq!(mentions.len(), 2);
        assert_eq!(
            mentions.get(&window_counts_key("libera", "#cordiale")),
            Some(&4)
        );
        assert_eq!(mentions.get(&window_counts_key("libera", "peer")), Some(&1));
        let messages = window_messages_from_me(&unread_counts);
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages.get(&window_counts_key("libera", "#cordiale")),
            Some(&12)
        );
        assert_eq!(messages.get(&window_counts_key("libera", "peer")), Some(&3));
    }

    #[test]
    fn window_counts_seed_from_channel_query_and_own_nick_join_replies() {
        let mut state = WorkerState::new();
        state.identifier = Some("sythos".to_string());
        state
            .own_nicks
            .insert("libera".to_string(), "Sythos".to_string());
        state
            .window_mentions
            .insert(window_counts_key("libera", "#cordiale"), 8);

        let reply = serde_json::json!({
            "status": "ok",
            "response": {
                "read_cursor": 17,
                "window_counts": {
                    "messages": 9,
                    "mentions": 3,
                    "events": 2,
                    "severity": "mention"
                }
            }
        });
        for topic in [
            channel_topic("sythos", "libera", "#Cordiale"),
            query_topic("sythos", "libera", "Peer"),
            own_nick_listener_topic("sythos", "libera", "Sythos"),
        ] {
            assert!(apply_window_counts_join_reply(
                &mut state,
                &topic,
                &reply,
                Some("ok")
            ));
        }

        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "#cordiale")),
            Some(&3)
        );
        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "Peer")),
            Some(&3)
        );
        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "Sythos")),
            Some(&3)
        );
        for target in ["#cordiale", "Peer", "Sythos"] {
            assert_eq!(
                state
                    .window_messages
                    .get(&window_counts_key("libera", target)),
                Some(&9)
            );
        }

        let no_counts = serde_json::json!({"status": "ok", "response": {}});
        assert!(apply_window_counts_join_reply(
            &mut state,
            &query_topic("sythos", "libera", "Peer"),
            &no_counts,
            Some("ok")
        ));
        assert!(!state
            .window_mentions
            .contains_key(&window_counts_key("libera", "Peer")));
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "Peer")),
            Some(&0)
        );

        assert!(!apply_window_counts_join_reply(
            &mut state,
            &channel_topic("someone-else", "libera", "#Cordiale"),
            &reply,
            Some("ok")
        ));
        assert!(!apply_window_counts_join_reply(
            &mut state,
            &channel_topic("sythos", "libera", "#Cordiale"),
            &reply,
            Some("error")
        ));
    }

    #[test]
    fn window_counts_on_own_nick_listener_updates_only_own_nick_window() {
        let mut state = WorkerState::new();
        state.identifier = Some("sythos".to_string());
        state
            .own_nicks
            .insert("libera".to_string(), "Sythos".to_string());
        state.query_windows = vec![QueryWindow {
            network: "libera".to_string(),
            target_nick: "Peer".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        }];
        state
            .window_mentions
            .insert(window_counts_key("libera", "Sythos"), 1);
        state
            .window_mentions
            .insert(window_counts_key("libera", "Peer"), 2);
        let payload = serde_json::json!({
            "kind": "window_counts",
            "channel": "sythos",
            "messages": 1,
            "mentions": 0,
            "events": 0,
            "severity": "message"
        });
        let own_nick_topic = own_nick_listener_topic("sythos", "libera", "Sythos");

        assert!(apply_window_counts(&mut state, &own_nick_topic, &payload));
        assert!(!state
            .window_mentions
            .contains_key(&window_counts_key("libera", "Sythos")));
        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "Peer")),
            Some(&2)
        );
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "Sythos")),
            Some(&1)
        );

        let unrelated = serde_json::json!({
            "kind": "window_counts",
            "channel": "Peer",
            "messages": 1,
            "mentions": 1,
            "events": 0,
            "severity": "mention"
        });
        assert!(!apply_window_counts(
            &mut state,
            &own_nick_topic,
            &unrelated
        ));
        assert_eq!(state.window_mentions.len(), 1);
    }

    #[test]
    fn window_counts_rejects_invalid_or_unrelated_snapshots() {
        let mut state = WorkerState::new();
        state.identifier = Some("sythos".to_string());
        state.channel_entries = vec![(
            "libera".to_string(),
            "#cordiale".to_string(),
            "#cordiale".to_string(),
        )];

        let valid = serde_json::json!({
            "kind": "window_counts",
            "channel": "#cordiale",
            "messages": 3,
            "mentions": 2,
            "events": 1,
            "severity": "mention"
        });
        for (topic, payload) in [
            (
                channel_topic("someone-else", "libera", "#cordiale"),
                valid.clone(),
            ),
            (
                channel_topic("sythos", "libera", "#different"),
                valid.clone(),
            ),
            (
                channel_topic("sythos", "libera", "#cordiale"),
                serde_json::json!({
                    "kind": "window_counts",
                    "channel": "#cordiale",
                    "messages": -1,
                    "mentions": 2,
                    "events": 1,
                    "severity": "mention"
                }),
            ),
            (
                channel_topic("sythos", "libera", "#cordiale"),
                serde_json::json!({
                    "kind": "window_counts",
                    "channel": "#cordiale",
                    "messages": 3,
                    "mentions": -1,
                    "events": 1,
                    "severity": "mention"
                }),
            ),
            (
                channel_topic("sythos", "libera", "#cordiale"),
                serde_json::json!({
                    "kind": "window_counts",
                    "channel": "#cordiale",
                    "messages": 3,
                    "mentions": 2,
                    "events": 1,
                    "severity": 42
                }),
            ),
            (
                channel_topic("sythos", "libera", "#cordiale"),
                serde_json::json!({
                    "kind": "window_counts",
                    "channel": "#cordiale",
                    "messages": 3,
                    "mentions": 2,
                    "severity": "mention"
                }),
            ),
            (
                channel_topic("sythos", "libera", "#not-open"),
                serde_json::json!({
                    "kind": "window_counts",
                    "channel": "#not-open",
                    "messages": 3,
                    "mentions": 2,
                    "events": 1,
                    "severity": "mention"
                }),
            ),
        ] {
            assert!(
                !apply_window_counts(&mut state, &topic, &payload),
                "unrelated or malformed window_counts payload must be ignored"
            );
        }
        assert!(state.window_mentions.is_empty());
        assert!(state.window_messages.is_empty());
    }

    #[test]
    fn window_counts_preserves_mentions_when_severity_is_missing_or_unknown() {
        let mut state = WorkerState::new();
        state.identifier = Some("sythos".to_string());
        state.channel_entries = vec![
            (
                "libera".to_string(),
                "#unknown-severity".to_string(),
                "#unknown-severity".to_string(),
            ),
            (
                "libera".to_string(),
                "#missing-severity".to_string(),
                "#missing-severity".to_string(),
            ),
        ];

        let unknown = serde_json::json!({
            "kind": "window_counts",
            "channel": "#unknown-severity",
            "messages": 3,
            "mentions": 2,
            "events": 1,
            "severity": "future-severity"
        });
        assert!(apply_window_counts(
            &mut state,
            &channel_topic("sythos", "libera", "#unknown-severity"),
            &unknown
        ));

        let missing = serde_json::json!({
            "kind": "window_counts",
            "channel": "#missing-severity",
            "messages": 5,
            "mentions": 4,
            "events": 2
        });
        assert!(apply_window_counts(
            &mut state,
            &channel_topic("sythos", "libera", "#missing-severity"),
            &missing
        ));

        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "#unknown-severity")),
            Some(&2)
        );
        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "#missing-severity")),
            Some(&4)
        );
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "#unknown-severity")),
            Some(&3)
        );
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "#missing-severity")),
            Some(&5)
        );
    }

    #[test]
    fn window_counts_removes_closed_query_counters_but_keeps_channels() {
        let mut state = WorkerState::new();
        state
            .own_nicks
            .insert("libera".to_string(), "Sythos".to_string());
        state.channel_entries = vec![(
            "libera".to_string(),
            "#cordiale".to_string(),
            "#cordiale".to_string(),
        )];
        state.query_windows = vec![QueryWindow {
            network: "libera".to_string(),
            target_nick: "Peer".to_string(),
            opened_at: "2026-09-21T10:00:00Z".to_string(),
        }];
        state
            .window_mentions
            .insert(window_counts_key("libera", "#cordiale"), 2);
        state
            .window_mentions
            .insert(window_counts_key("libera", "Peer"), 1);
        state
            .window_mentions
            .insert(window_counts_key("libera", "Sythos"), 2);
        state
            .window_messages
            .insert(window_counts_key("libera", "#cordiale"), 9);
        state
            .window_messages
            .insert(window_counts_key("libera", "Peer"), 3);
        state
            .window_messages
            .insert(window_counts_key("libera", "Sythos"), 4);

        state.query_windows.clear();
        retain_window_counts_for_open_windows(&mut state);

        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "#cordiale")),
            Some(&2)
        );
        assert!(!state
            .window_mentions
            .contains_key(&window_counts_key("libera", "Peer")));
        assert_eq!(
            state
                .window_mentions
                .get(&window_counts_key("libera", "Sythos")),
            Some(&2)
        );
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "#cordiale")),
            Some(&9)
        );
        assert!(!state
            .window_messages
            .contains_key(&window_counts_key("libera", "Peer")));
        assert_eq!(
            state
                .window_messages
                .get(&window_counts_key("libera", "Sythos")),
            Some(&4)
        );
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
    fn parse_window_pending_accepts_only_live_user_topic_and_exact_fields() {
        let payload = serde_json::json!({
            "kind": "window_pending",
            "network": "libera",
            "channel": "#cordiale",
            "state": "pending",
            "future_field": true
        });
        let expected = Some(("libera".to_string(), "#cordiale".to_string()));

        assert_eq!(
            parse_window_pending_event(&payload, "grappa:user:sythos", "sythos"),
            expected
        );
        assert_eq!(
            parse_window_pending_event(
                &payload,
                &channel_topic("sythos", "libera", "#cordiale"),
                "sythos"
            ),
            None
        );
        assert_eq!(
            parse_window_pending_event(&payload, "grappa:user:other", "sythos"),
            None
        );

        for malformed in [
            serde_json::json!({
                "kind": "window_pending",
                "network": "libera",
                "channel": "#cordiale",
                "state": "joined"
            }),
            serde_json::json!({
                "kind": "window_pending",
                "network": "libera",
                "state": "pending"
            }),
            serde_json::json!({
                "kind": "window_pending",
                "network": 7,
                "channel": "#cordiale",
                "state": "pending"
            }),
            serde_json::json!({
                "kind": "window_pending",
                "network": "libera",
                "channel": "",
                "state": "pending"
            }),
        ] {
            assert_eq!(
                parse_window_pending_event(&malformed, "grappa:user:sythos", "sythos"),
                None
            );
        }
    }

    #[test]
    fn parse_window_invited_accepts_only_the_user_topic_and_required_fields() {
        let payload = serde_json::json!({
            "kind": "window_invited",
            "network": "libera",
            "channel": "#cordiale",
            "state": "invited",
            "inviter": "*",
            "future_field": true
        });
        let expected = Some((
            "libera".to_string(),
            "#cordiale".to_string(),
            "*".to_string(),
        ));

        assert_eq!(
            parse_window_invited_event(&payload, "grappa:user:sythos", "sythos"),
            expected
        );
        assert_eq!(
            parse_window_invited_event(
                &payload,
                &channel_topic("sythos", "libera", "#cordiale"),
                "sythos"
            ),
            None
        );
        assert_eq!(
            parse_window_invited_event(&payload, "grappa:user:other", "sythos"),
            None
        );

        for malformed in [
            serde_json::json!({
                "kind": "window_invited",
                "network": "libera",
                "channel": "#cordiale",
                "state": "pending",
                "inviter": "ChanServ"
            }),
            serde_json::json!({
                "kind": "window_invited",
                "network": "libera",
                "channel": "#cordiale",
                "state": "invited"
            }),
            serde_json::json!({
                "kind": "window_invited",
                "network": "libera",
                "channel": "#cordiale",
                "state": "invited",
                "inviter": null
            }),
            serde_json::json!({
                "kind": "window_invited",
                "network": "",
                "channel": "#cordiale",
                "state": "invited",
                "inviter": "ChanServ"
            }),
            serde_json::json!({
                "kind": "window_invited",
                "network": "libera",
                "channel": "",
                "state": "invited",
                "inviter": "ChanServ"
            }),
            serde_json::json!({
                "kind": "window_invited",
                "network": "libera",
                "channel": "#cordiale",
                "state": "invited",
                "inviter": ""
            }),
            serde_json::json!({
                "kind": "window_invited",
                "network": 7,
                "channel": "#cordiale",
                "state": "invited",
                "inviter": "ChanServ"
            }),
        ] {
            assert_eq!(
                parse_window_invited_event(&malformed, "grappa:user:sythos", "sythos"),
                None
            );
        }
    }

    #[test]
    fn parse_window_invite_declined_accepts_only_the_user_topic_without_state() {
        let payload = serde_json::json!({
            "kind": "window_invite_declined",
            "network": "libera",
            "channel": "#cordiale",
            "future_field": true
        });
        let expected = Some(("libera".to_string(), "#cordiale".to_string()));

        assert_eq!(
            parse_window_invite_declined_event(&payload, "grappa:user:sythos", "sythos"),
            expected
        );
        assert_eq!(
            parse_window_invite_declined_event(
                &payload,
                &channel_topic("sythos", "libera", "#cordiale"),
                "sythos"
            ),
            None
        );
        assert_eq!(
            parse_window_invite_declined_event(&payload, "grappa:user:other", "sythos"),
            None
        );

        for malformed in [
            serde_json::json!({
                "kind": "window_invited",
                "network": "libera",
                "channel": "#cordiale"
            }),
            serde_json::json!({
                "kind": "window_invite_declined",
                "channel": "#cordiale"
            }),
            serde_json::json!({
                "kind": "window_invite_declined",
                "network": "libera"
            }),
            serde_json::json!({
                "kind": "window_invite_declined",
                "network": 7,
                "channel": "#cordiale"
            }),
            serde_json::json!({
                "kind": "window_invite_declined",
                "network": "   ",
                "channel": "#cordiale"
            }),
            serde_json::json!({
                "kind": "window_invite_declined",
                "network": "libera",
                "channel": ""
            }),
        ] {
            assert_eq!(
                parse_window_invite_declined_event(&malformed, "grappa:user:sythos", "sythos"),
                None
            );
        }
    }

    #[test]
    fn invited_window_is_idempotent_and_replaces_stale_state() {
        let key = window_state_key("libera", "#cordiale");
        let mut states = HashMap::from([(key.clone(), ChannelWindowState::Failed)]);
        let mut failures = HashMap::from([(
            key.clone(),
            WindowFailure {
                reason: Some("old failure".to_string()),
                numeric: Some(Number::from(473)),
            },
        )]);
        let mut kicks = HashMap::from([(
            key.clone(),
            WindowKick {
                by: Some("old actor".to_string()),
                reason: None,
            },
        )]);
        let mut invited_by = HashMap::new();
        let mut joined_topics = std::collections::HashSet::new();
        let mut channel_topics = std::collections::HashSet::new();
        let topic = channel_topic("sythos", "libera", "#cordiale");

        assert!(set_invited_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#CoRdIaLe",
            "ChanServ".to_string(),
        ));
        assert_eq!(states.get(&key), Some(&ChannelWindowState::Invited));
        assert!(failures.is_empty());
        assert!(kicks.is_empty());
        assert_eq!(invited_by.get(&key).map(String::as_str), Some("ChanServ"));
        assert!(register_pending_channel_topic(
            &mut joined_topics,
            &mut channel_topics,
            topic.clone()
        ));
        assert!(!register_pending_channel_topic(
            &mut joined_topics,
            &mut channel_topics,
            topic.clone()
        ));
        assert_eq!(
            joined_topics,
            std::collections::HashSet::from([topic.clone()])
        );
        assert_eq!(channel_topics, std::collections::HashSet::from([topic]));

        assert!(!set_invited_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#cordiale",
            "ChanServ".to_string(),
        ));
        assert_eq!(invited_by.get(&key).map(String::as_str), Some("ChanServ"));

        // A later inviter value is a real state replacement, not a duplicate;
        // the required banner metadata follows the latest server frame.
        assert!(set_invited_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#cordiale",
            "*".to_string(),
        ));
        assert_eq!(invited_by.get(&key).map(String::as_str), Some("*"));
    }

    #[test]
    fn declined_window_removes_invited_and_pending_state_and_sidebar_row() {
        let key = window_state_key("libera", "#cordiale");
        let mut state = WorkerState::new();
        state
            .window_states
            .insert(key.clone(), ChannelWindowState::Pending);
        state.window_failures.insert(
            key.clone(),
            WindowFailure {
                reason: Some("stale failure".to_string()),
                numeric: Some(Number::from(473)),
            },
        );
        state.window_kicks.insert(
            key.clone(),
            WindowKick {
                by: Some("stale actor".to_string()),
                reason: Some("stale reason".to_string()),
            },
        );
        state.invited_by.insert(key.clone(), "ChanServ".to_string());
        state.channel_entries.push((
            "libera".to_string(),
            "#cordiale".to_string(),
            "#cordiale".to_string(),
        ));
        state
            .members
            .insert(key.clone(), vec![("sythos".to_string(), "@".to_string())]);
        state.messages.insert(key.clone(), Vec::new());
        state.drafts.insert(key.clone(), "draft".to_string());
        state.topics.insert(key.clone(), "topic".to_string());
        let topic = channel_topic("sythos", "libera", "#cordiale");
        state.channel_topics.insert(topic.clone());
        state.joined_topics.insert(topic.clone());

        assert!(remove_declined_window(&mut state, "libera", "#CoRdIaLe"));
        assert!(!state.window_states.contains_key(&key));
        assert!(!state.window_failures.contains_key(&key));
        assert!(!state.window_kicks.contains_key(&key));
        assert!(!state.invited_by.contains_key(&key));
        assert!(state.channel_entries.is_empty());
        // Lifecycle cleanup does not discard cached content or topic data.
        assert!(state.members.contains_key(&key));
        assert!(state.messages.contains_key(&key));
        assert_eq!(state.drafts.get(&key).map(String::as_str), Some("draft"));
        assert_eq!(state.topics.get(&key).map(String::as_str), Some("topic"));
        assert!(remove_declined_channel_subscription(
            &mut state,
            "sythos",
            "libera",
            "#CoRdIaLe"
        ));
        assert!(state.channel_topics.is_empty());
        assert!(state.joined_topics.is_empty());

        assert!(!remove_declined_window(&mut state, "libera", "#cordiale"));
        assert!(!remove_declined_channel_subscription(
            &mut state,
            "sythos",
            "libera",
            "#cordiale"
        ));
    }

    #[test]
    fn pending_window_is_idempotent_subscribes_once_and_transitions_to_joined() {
        let key = window_state_key("libera", "#cordiale");
        let mut states = HashMap::from([(key.clone(), ChannelWindowState::Failed)]);
        let mut failures = HashMap::from([(
            key.clone(),
            WindowFailure {
                reason: Some("old failure".to_string()),
                numeric: Some(Number::from(473)),
            },
        )]);
        let mut kicks = HashMap::from([(
            key.clone(),
            WindowKick {
                by: Some("old actor".to_string()),
                reason: None,
            },
        )]);
        let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);
        let mut joined_topics = std::collections::HashSet::new();
        let mut channel_topics = std::collections::HashSet::new();
        let topic = channel_topic("sythos", "libera", "#cordiale");

        assert!(set_pending_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#CoRdIaLe"
        ));
        assert_eq!(states.get(&key), Some(&ChannelWindowState::Pending));
        assert!(failures.is_empty());
        assert!(kicks.is_empty());
        assert!(invited_by.is_empty());
        assert!(register_pending_channel_topic(
            &mut joined_topics,
            &mut channel_topics,
            topic.clone()
        ));

        assert!(!set_pending_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#cordiale"
        ));
        assert!(!register_pending_channel_topic(
            &mut joined_topics,
            &mut channel_topics,
            topic.clone()
        ));
        assert_eq!(
            joined_topics,
            std::collections::HashSet::from([topic.clone()])
        );
        assert_eq!(channel_topics, std::collections::HashSet::from([topic]));

        assert!(set_joined_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#cordiale"
        ));
        assert_eq!(states.get(&key), Some(&ChannelWindowState::Joined));
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
    fn parse_kicked_accepts_live_and_matching_channel_snapshot_topics() {
        let payload = serde_json::json!({
            "kind": "kicked",
            "network": "libera",
            "channel": "#cordiale",
            "state": "kicked",
            "by": "ChanServ",
            "reason": "policy",
            "future_field": true
        });
        let expected = Some((
            "libera".to_string(),
            "#cordiale".to_string(),
            WindowKick {
                by: Some("ChanServ".to_string()),
                reason: Some("policy".to_string()),
            },
        ));

        assert_eq!(
            parse_kicked_event(&payload, "grappa:user:sythos", "sythos"),
            expected
        );
        assert_eq!(
            parse_kicked_event(
                &payload,
                &channel_topic("sythos", "libera", "#CoRdIaLe"),
                "sythos"
            ),
            expected
        );
    }

    #[test]
    fn parse_kicked_preserves_required_nullable_fields_and_rejects_bad_payloads() {
        let nullable = serde_json::json!({
            "kind": "kicked",
            "network": "libera",
            "channel": "#cordiale",
            "state": "kicked",
            "by": null,
            "reason": null
        });
        assert_eq!(
            parse_kicked_event(&nullable, "grappa:user:sythos", "sythos"),
            Some((
                "libera".to_string(),
                "#cordiale".to_string(),
                WindowKick {
                    by: None,
                    reason: None,
                },
            ))
        );

        let wrong_state = serde_json::json!({
            "kind": "kicked",
            "network": "libera",
            "channel": "#cordiale",
            "state": "joined",
            "by": null,
            "reason": null
        });
        assert_eq!(
            parse_kicked_event(&wrong_state, "grappa:user:sythos", "sythos"),
            None
        );

        let missing_by = serde_json::json!({
            "kind": "kicked",
            "network": "libera",
            "channel": "#cordiale",
            "state": "kicked",
            "reason": null
        });
        assert_eq!(
            parse_kicked_event(&missing_by, "grappa:user:sythos", "sythos"),
            None
        );

        let missing_reason = serde_json::json!({
            "kind": "kicked",
            "network": "libera",
            "channel": "#cordiale",
            "state": "kicked",
            "by": null
        });
        assert_eq!(
            parse_kicked_event(&missing_reason, "grappa:user:sythos", "sythos"),
            None
        );

        let malformed_by = serde_json::json!({
            "kind": "kicked",
            "network": "libera",
            "channel": "#cordiale",
            "state": "kicked",
            "by": 7,
            "reason": null
        });
        assert_eq!(
            parse_kicked_event(&malformed_by, "grappa:user:sythos", "sythos"),
            None
        );

        let malformed_reason = serde_json::json!({
            "kind": "kicked",
            "network": "libera",
            "channel": "#cordiale",
            "state": "kicked",
            "by": null,
            "reason": false
        });
        assert_eq!(
            parse_kicked_event(&malformed_reason, "grappa:user:sythos", "sythos"),
            None
        );

        assert_eq!(
            parse_kicked_event(&nullable, "grappa:user:other", "sythos"),
            None
        );
        assert_eq!(
            parse_kicked_event(
                &nullable,
                &channel_topic("sythos", "libera", "#other"),
                "sythos"
            ),
            None
        );
        assert_eq!(
            parse_kicked_event(
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
        let mut kicks = HashMap::from([(
            key.clone(),
            WindowKick {
                by: Some("old actor".to_string()),
                reason: None,
            },
        )]);
        let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);

        assert!(set_joined_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            &key.0,
            "#CoRdIaLe"
        ));
        assert_eq!(states.get(&key), Some(&ChannelWindowState::Joined));
        assert!(!failures.contains_key(&key));
        assert!(!kicks.contains_key(&key));
        assert!(!invited_by.contains_key(&key));

        assert!(!set_joined_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
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
        let mut kicks = HashMap::from([(
            key.clone(),
            WindowKick {
                by: None,
                reason: Some("stale".to_string()),
            },
        )]);
        let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);

        assert!(set_failed_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#CoRdIaLe",
            failure.clone()
        ));
        assert_eq!(states.get(&key), Some(&ChannelWindowState::Failed));
        assert!(window_is_failed(&states, "libera", "#CoRdIaLe"));
        assert_eq!(failures.get(&key), Some(&failure));
        assert!(!kicks.contains_key(&key));
        assert!(!invited_by.contains_key(&key));

        assert!(!set_failed_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#cordiale",
            failure
        ));
    }

    #[test]
    fn set_kicked_window_state_keeps_metadata_clears_prior_state_and_is_idempotent() {
        let key = window_state_key("libera", "#cordiale");
        let kick = WindowKick {
            by: Some("ChanServ".to_string()),
            reason: Some("policy".to_string()),
        };
        let mut states = HashMap::from([(key.clone(), ChannelWindowState::Failed)]);
        let mut failures = HashMap::from([(
            key.clone(),
            WindowFailure {
                reason: Some("old failure".to_string()),
                numeric: Some(Number::from(473)),
            },
        )]);
        let mut kicks = HashMap::new();
        let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);

        assert!(set_kicked_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#CoRdIaLe",
            kick.clone(),
        ));
        assert_eq!(states.get(&key), Some(&ChannelWindowState::Kicked));
        assert!(window_is_kicked(&states, "libera", "#CoRdIaLe"));
        assert!(!failures.contains_key(&key));
        assert_eq!(kicks.get(&key), Some(&kick));
        assert!(!invited_by.contains_key(&key));

        assert!(!set_kicked_window_state(
            &mut states,
            &mut failures,
            &mut kicks,
            &mut invited_by,
            "libera",
            "#cordiale",
            kick,
        ));
    }

    #[test]
    fn force_parted_kicked_window_clears_only_lifecycle_metadata() {
        let key = window_state_key("libera", "#cordiale");
        let mut state = WorkerState::new();
        state
            .window_states
            .insert(key.clone(), ChannelWindowState::Kicked);
        state.window_failures.insert(
            key.clone(),
            WindowFailure {
                reason: Some("old failure".to_string()),
                numeric: Some(Number::from(473)),
            },
        );
        state.window_kicks.insert(
            key.clone(),
            WindowKick {
                by: Some("ChanServ".to_string()),
                reason: Some("policy".to_string()),
            },
        );
        state.invited_by.insert(key.clone(), "ChanServ".to_string());
        state.channel_entries.push((
            "libera".to_string(),
            "#cordiale".to_string(),
            "#cordiale".to_string(),
        ));
        state
            .members
            .insert(key.clone(), vec![("sythos".to_string(), "@".to_string())]);
        state.messages.insert(key.clone(), Vec::new());
        state.drafts.insert(key.clone(), "draft".to_string());
        state.topics.insert(key.clone(), "topic".to_string());
        state.channel_modes.insert(
            key.clone(),
            ChannelModes {
                modes: vec!["n".to_string()],
                params: HashMap::new(),
            },
        );
        state
            .recent_channels
            .push(("libera".to_string(), "#cordiale".to_string()));

        assert!(force_parted_kicked_window(
            &mut state,
            "libera",
            "#CoRdIaLe"
        ));
        assert!(!state.window_states.contains_key(&key));
        assert!(!state.window_failures.contains_key(&key));
        assert!(!state.window_kicks.contains_key(&key));
        assert!(!state.invited_by.contains_key(&key));
        assert!(!state.channel_modes.contains_key(&key));
        assert_eq!(state.channel_entries.len(), 1);
        assert!(state.members.contains_key(&key));
        assert!(state.messages.contains_key(&key));
        assert_eq!(state.drafts.get(&key).map(String::as_str), Some("draft"));
        assert_eq!(state.topics.get(&key).map(String::as_str), Some("topic"));
        assert_eq!(state.recent_channels.len(), 1);
    }

    #[test]
    fn force_parted_kicked_window_is_a_noop_for_other_window_states() {
        let key = window_state_key("libera", "#cordiale");
        let mut state = WorkerState::new();
        state
            .window_states
            .insert(key.clone(), ChannelWindowState::Failed);
        state.window_failures.insert(
            key.clone(),
            WindowFailure {
                reason: Some("invite only".to_string()),
                numeric: Some(Number::from(473)),
            },
        );
        state.window_kicks.insert(
            key.clone(),
            WindowKick {
                by: Some("ChanServ".to_string()),
                reason: Some("stale".to_string()),
            },
        );
        state.invited_by.insert(key.clone(), "ChanServ".to_string());
        let expected_states = state.window_states.clone();
        let expected_failures = state.window_failures.clone();
        let expected_kicks = state.window_kicks.clone();
        let expected_invites = state.invited_by.clone();

        assert!(!force_parted_kicked_window(
            &mut state,
            "libera",
            "#cordiale"
        ));
        assert_eq!(state.window_states, expected_states);
        assert_eq!(state.window_failures, expected_failures);
        assert_eq!(state.window_kicks, expected_kicks);
        assert_eq!(state.invited_by, expected_invites);
    }

    #[test]
    fn dismiss_kicked_window_locally_removes_row_and_preserves_selection_state() {
        let key = window_state_key("libera", "#cordiale");
        let mut state = WorkerState::new();
        state
            .window_states
            .insert(key.clone(), ChannelWindowState::Kicked);
        state.window_kicks.insert(
            key.clone(),
            WindowKick {
                by: Some("ChanServ".to_string()),
                reason: Some("policy".to_string()),
            },
        );
        state.invited_by.insert(key.clone(), "ChanServ".to_string());
        state.channel_entries.push((
            "libera".to_string(),
            "#cordiale".to_string(),
            "#cordiale".to_string(),
        ));
        state.current_channel = Some(key.clone());
        state.recent_channels.push(key.clone());
        state
            .members
            .insert(key.clone(), vec![("sythos".to_string(), "@".to_string())]);

        assert_eq!(
            dismiss_kicked_window_locally(&mut state, "libera", "#CoRdIaLe"),
            Some(true)
        );
        assert!(state.channel_entries.is_empty());
        assert!(!state.window_states.contains_key(&key));
        assert!(!state.window_failures.contains_key(&key));
        assert!(!state.window_kicks.contains_key(&key));
        assert!(!state.invited_by.contains_key(&key));
        assert_eq!(state.current_channel, Some(key.clone()));
        assert_eq!(state.recent_channels, vec![key.clone()]);
        assert!(state.members.contains_key(&key));
    }

    #[test]
    fn remove_sidebar_channel_entry_matches_only_network_and_ascii_folded_channel() {
        let mut entries = vec![
            (
                "libera".to_string(),
                "#cordiale".to_string(),
                "#cordiale".to_string(),
            ),
            (
                "other".to_string(),
                "#cordiale".to_string(),
                "#cordiale".to_string(),
            ),
            (
                "libera".to_string(),
                "#rust".to_string(),
                "#rust".to_string(),
            ),
        ];

        assert!(remove_sidebar_channel_entry(
            &mut entries,
            "libera",
            "#CoRdIaLe"
        ));
        assert_eq!(
            entries,
            vec![
                (
                    "other".to_string(),
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
        assert!(!remove_sidebar_channel_entry(
            &mut entries,
            "libera",
            "#cordiale"
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
        assert_eq!(IGNORED_KINDS.len(), 32);
        // The kinds caught leaking as raw JSON in chat before being fixed
        // this session — a regression here means one of them is no longer
        // ignored and would start dumping raw JSON again.
        for kind in ["bundle_hash", "mentions_bundle"] {
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
        assert!(!IGNORED_KINDS.contains(&"channel_modes_changed"));
        assert!(!IGNORED_KINDS.contains(&"read_cursor_set"));
        assert!(!IGNORED_KINDS.contains(&"query_windows_list"));
        assert!(!IGNORED_KINDS.contains(&"own_nick_changed"));
        assert!(!IGNORED_KINDS.contains(&"away_confirmed"));
        assert!(!IGNORED_KINDS.contains(&"window_counts"));
        assert!(!IGNORED_KINDS.contains(&"joined"));
        assert!(!IGNORED_KINDS.contains(&"channels_changed"));
        assert!(!IGNORED_KINDS.contains(&"session_identity_changed"));
        assert!(!IGNORED_KINDS.contains(&"isupport_changed"));
        assert!(!IGNORED_KINDS.contains(&"umode_changed"));
        assert!(!IGNORED_KINDS.contains(&"supported_umodes_changed"));
        assert!(!IGNORED_KINDS.contains(&"join_failed"));
        assert!(!IGNORED_KINDS.contains(&"kicked"));
        assert!(!IGNORED_KINDS.contains(&"window_pending"));
        assert!(!IGNORED_KINDS.contains(&"window_invited"));
        assert!(!IGNORED_KINDS.contains(&"window_invite_declined"));
        assert!(!IGNORED_KINDS.contains(&"network_detached"));
        assert!(!IGNORED_KINDS.contains(&"network_attached"));
        // "parted" is confirmed to never actually be sent by the server
        // — listing it here would be harmless but wrong documentation,
        // so it must stay absent.
        assert!(!IGNORED_KINDS.contains(&"parted"));
    }

    #[test]
    fn parse_network_detached_accepts_only_the_authenticated_user_topic() {
        let payload = serde_json::json!({
            "kind": "network_detached",
            "network_id": 7,
            "network_slug": "libera",
            "future_field": true
        });
        assert_eq!(
            parse_network_detached_event(&payload, "grappa:user:sythos", "sythos"),
            Some((7, "libera".to_string()))
        );
        assert_eq!(
            parse_network_detached_event(&payload, "grappa:user:other", "sythos"),
            None
        );
        assert_eq!(
            parse_network_detached_event(
                &payload,
                "grappa:user:sythos/network:libera/channel:#rust",
                "sythos"
            ),
            None
        );
    }

    #[test]
    fn parse_network_detached_rejects_invalid_identity_fields() {
        for payload in [
            serde_json::json!({"kind": "network_detached", "network_id": 0, "network_slug": "libera"}),
            serde_json::json!({"kind": "network_detached", "network_id": -1, "network_slug": "libera"}),
            serde_json::json!({"kind": "network_detached", "network_id": 7, "network_slug": "  "}),
            serde_json::json!({"kind": "network_attached", "network_id": 7, "network_slug": "libera"}),
            serde_json::json!({"kind": "network_detached", "network_id": "7", "network_slug": "libera"}),
        ] {
            assert_eq!(
                parse_network_detached_event(&payload, "grappa:user:sythos", "sythos"),
                None
            );
        }
    }

    #[test]
    fn parse_network_attached_accepts_only_the_authenticated_user_topic() {
        let payload = serde_json::json!({
            "kind": "network_attached",
            "network_id": 7,
            "network_slug": "libera",
            "future_field": true
        });
        assert_eq!(
            parse_network_attached_event(&payload, "grappa:user:sythos", "sythos"),
            Some((7, "libera".to_string()))
        );
        assert_eq!(
            parse_network_attached_event(&payload, "grappa:user:other", "sythos"),
            None
        );
        assert_eq!(
            parse_network_attached_event(
                &payload,
                "grappa:user:sythos/network:libera/channel:#rust",
                "sythos"
            ),
            None
        );
    }

    #[test]
    fn parse_network_attached_rejects_invalid_identity_fields() {
        for payload in [
            serde_json::json!({"kind": "network_attached", "network_id": 0, "network_slug": "libera"}),
            serde_json::json!({"kind": "network_attached", "network_id": -1, "network_slug": "libera"}),
            serde_json::json!({"kind": "network_attached", "network_id": 7, "network_slug": "  "}),
            serde_json::json!({"kind": "network_detached", "network_id": 7, "network_slug": "libera"}),
            serde_json::json!({"kind": "network_attached", "network_id": "7", "network_slug": "libera"}),
        ] {
            assert_eq!(
                parse_network_attached_event(&payload, "grappa:user:sythos", "sythos"),
                None
            );
        }
    }

    #[test]
    fn network_attached_rest_refresh_is_idempotent() {
        let boot = BootResponse {
            networks: vec![serde_json::json!({
                "id": 7,
                "slug": "libera",
                "nick": "sythos"
            })],
            channels: HashMap::from([(
                "libera".to_string(),
                vec![serde_json::json!({
                    "name": "#rust",
                    "joined": true,
                    "topic": "Rust chat",
                    "members": ["@alice", "+bob"]
                })],
            )]),
            heads: HashMap::from([(
                "libera".to_string(),
                HashMap::from([(
                    "#rust".to_string(),
                    vec![serde_json::json!({
                        "id": 11,
                        "server_time": 100,
                        "kind": "privmsg",
                        "sender": "alice",
                        "body": "hello"
                    })],
                )]),
            )]),
        };
        let me = MeResponse {
            read_cursors: serde_json::json!({"libera": {"#rust": 10}}),
            unread_counts: serde_json::json!({
                "libera": {"#rust": {"messages": 2, "mentions": 1}}
            }),
            badge_count: serde_json::json!(2),
            is_admin: false,
        };

        let mut state = WorkerState::new();
        state.identifier = Some("sythos".to_string());
        let first_actions = apply_network_rest_refresh(&mut state, "sythos", &boot, &me);
        let first_channel_entries = state.channel_entries.clone();
        let first_joined_topics = state.joined_topics.clone();
        let first_messages = state.messages.clone();
        let first_members = state.members.clone();
        let first_cursors = state.read_cursors.clone();
        let first_counts = (state.window_messages.clone(), state.window_mentions.clone());

        let second_actions = apply_network_rest_refresh(&mut state, "sythos", &boot, &me);

        assert_eq!(first_actions.len(), 2);
        assert!(second_actions.is_empty());
        assert_eq!(state.channel_entries, first_channel_entries);
        assert_eq!(state.joined_topics, first_joined_topics);
        assert_eq!(state.messages, first_messages);
        assert_eq!(state.members, first_members);
        assert_eq!(state.read_cursors, first_cursors);
        assert_eq!(
            (&state.window_messages, &state.window_mentions),
            (&first_counts.0, &first_counts.1)
        );
        assert_eq!(state.network_ids.get("libera"), Some(&7));
        assert_eq!(state.own_nicks.get("libera"), Some(&"sythos".to_string()));
    }

    #[test]
    fn read_cursor_set_is_scoped_to_its_channel_shaped_topic_and_clamps_badge() {
        let channel = channel_topic("sythos", "libera", "#Cordiale");
        let payload = serde_json::json!({
            "kind": "read_cursor_set",
            "last_read_message_id": 202,
            "badge_count": 120,
            "future_field": "ignored"
        });

        assert_eq!(
            parse_read_cursor_set_event("sythos", &channel, &payload),
            Some((window_state_key("libera", "#cordiale"), 202, 99))
        );

        // Cicchetto uses the same channel-shaped topic for a DM or own-nick
        // listener, so those windows use the same per-network keying rule.
        let query = query_topic("sythos", "libera", "FrIeNd");
        let query_payload = serde_json::json!({
            "kind": "read_cursor_set",
            "last_read_message_id": 303,
            "badge_count": 7
        });
        assert_eq!(
            parse_read_cursor_set_event("sythos", &query, &query_payload),
            Some((window_state_key("libera", "friend"), 303, 7))
        );
    }

    #[test]
    fn read_cursor_set_is_last_write_wins_even_when_cursor_moves_backward() {
        let topic = channel_topic("sythos", "libera", "#rust");
        let mut state = WorkerState::new();
        state.identifier = Some("sythos".to_string());

        let newer = serde_json::json!({
            "kind": "read_cursor_set",
            "last_read_message_id": 202,
            "badge_count": 4
        });
        let older = serde_json::json!({
            "kind": "read_cursor_set",
            "last_read_message_id": 101,
            "badge_count": 5
        });

        assert!(apply_read_cursor_set(&mut state, "sythos", &topic, &newer));
        assert!(!apply_read_cursor_set(&mut state, "sythos", &topic, &newer));
        assert!(apply_read_cursor_set(&mut state, "sythos", &topic, &older));
        assert_eq!(
            state.read_cursors.get(&window_state_key("libera", "#rust")),
            Some(&101)
        );
        assert_eq!(state.badge_count, 5);
    }

    #[test]
    fn read_cursors_are_seeded_from_me_without_fabricating_invalid_entries() {
        let payload = serde_json::json!({
            "libera": {
                "#Rust": 101,
                "Alice": 202,
                "#null": null,
                "#text": "203",
                "#fraction": 1.5
            },
            "invalid-network": 3,
            "empty-network": {}
        });
        let cursors = read_cursors_from_me(&payload);

        assert_eq!(cursors.len(), 2);
        assert_eq!(
            cursors.get(&window_state_key("libera", "#rust")),
            Some(&101)
        );
        assert_eq!(
            cursors.get(&window_state_key("libera", "alice")),
            Some(&202)
        );
        assert!(read_cursors_from_me(&Value::Null).is_empty());
    }

    #[test]
    fn malformed_or_foreign_read_cursor_events_leave_state_unchanged() {
        let topic = channel_topic("sythos", "libera", "#rust");
        let mut state = WorkerState::new();
        state.identifier = Some("sythos".to_string());
        state
            .read_cursors
            .insert(window_state_key("libera", "#rust"), 101);
        state.badge_count = 6;
        let before_cursors = state.read_cursors.clone();
        let before_badge = state.badge_count;

        for (identifier, event) in [
            (
                "someone-else",
                serde_json::json!({
                    "kind": "read_cursor_set",
                    "last_read_message_id": 202,
                    "badge_count": 1
                }),
            ),
            (
                "sythos",
                serde_json::json!({
                    "kind": "read_cursor_set",
                    "last_read_message_id": "202",
                    "badge_count": 1
                }),
            ),
            (
                "sythos",
                serde_json::json!({
                    "kind": "window_counts",
                    "last_read_message_id": 202,
                    "badge_count": 1
                }),
            ),
        ] {
            assert!(!apply_read_cursor_set(
                &mut state, identifier, &topic, &event
            ));
        }
        assert!(!apply_read_cursor_set(
            &mut state,
            "sythos",
            "grappa:user:sythos",
            &serde_json::json!({
                "kind": "read_cursor_set",
                "last_read_message_id": 202,
                "badge_count": 1
            })
        ));

        assert_eq!(state.read_cursors, before_cursors);
        assert_eq!(state.badge_count, before_badge);
    }

    #[test]
    fn read_cursor_badge_normalizes_values_like_cicchetto() {
        let cases = [
            (serde_json::json!(0), 0),
            (serde_json::json!(99), 99),
            (serde_json::json!(100), 99),
            (serde_json::json!(u64::MAX), 99),
            (serde_json::json!(-1), 0),
            (serde_json::json!(4.9), 4),
            (serde_json::json!(null), 0),
            (serde_json::json!("bad"), 0),
        ];

        for (value, expected) in cases {
            assert_eq!(normalize_badge_count(Some(&value)), expected);
        }
        assert_eq!(normalize_badge_count(None), 0);
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
