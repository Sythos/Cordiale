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
use cordiale_core::client::{GrappaClient, GrappaClientError, LoginError};
use cordiale_core::credentials::{
    resolve_credential_store, CredentialStore, KeyringCredentialStore,
};
use cordiale_core::domain::{AuthMethod, Profile};
use cordiale_core::isupport::{parse_isupport_changed, IsupportState};
use cordiale_core::persistence::{self, Theme};
use cordiale_core::rest::{
    ArchiveEntry, BootResponse, DirectoryPage, DisplayPrefs, LoginRequest, MeResponse,
    SendMessageRequest,
};
use cordiale_core::session::{spawn_session, SessionEvent, SessionHandle};
use cordiale_core::slash::{self, SlashCommand};
use cordiale_core::theme::{font_family_for, ThemePalette, BUILTIN_THEMES};
use cordiale_core::upload::{attachment_message, mime_for_filename, UploadCategory};
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
    PartChannel {
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
    DismissRecover,
    DirectoryRefresh,
    DirectoryLoadMore,
    DirectorySort(String),
    DirectorySearch(String),
    DirectoryClose,
    DccOfferAnswer {
        network: String,
        offer_id: String,
        accept: bool,
    },
    ArchiveDelete(String),
    ArchiveClose,
    DismissPeerAway,
    ToggleNetwork(String),
    SendMessage {
        body: String,
    },
    /// A picked file and the lifetime to request for it.
    AttachFile(std::path::PathBuf, Option<i64>),
    UploadPrefsChanged {
        ttl: Option<i64>,
        confirm: bool,
    },
    ComposeTextChanged(String),
    ToggleTheme,
    SelectColorTheme(String),
    SaveDisplayPrefs(DisplayPrefs),
    LoadNotificationPrefs,
    SaveNotificationPrefs(NotificationToggles),
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
    LoadOlderHistory,
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
    let auto_connect = settings.auto_connect && settings.language.is_some();
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
    // A built-in color theme applies from the first screen; a Grappa one
    // needs the session and is applied after sign-in.
    if let Some(choice) = settings
        .color_theme
        .as_deref()
        .and_then(|key| builtin_theme_choices().into_iter().find(|c| c.key == key))
    {
        set_active_palette(Some(choice.palette.clone()));
        push_palette(&ui, Some(&choice));
    }
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

    // Sign in at launch with the remembered profile (its bearer, or the
    // login password kept in the OS keyring), unless the last session ended
    // with a manual disconnect.
    if auto_connect {
        if let Some(identifier) = auto_connect_identifier(&remembered_server_url) {
            ui.set_connecting(true);
            let _ = worker_tx.send(WorkerCommand::Connect {
                server_url: remembered_server_url.clone(),
                identifier,
                credential: ConnectCredential::SavedProfile,
            });
        }
    }

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
            ui.set_recover_visible(false);
            ui.set_dcc_offers(slint::ModelRc::default());
            ui.set_server_pref_auto_away_debounce("".into());
            ui.set_server_pref_leave_message_known(false);
            ui.set_server_pref_auto_away_reason_known(false);
            ui.set_server_upload_limits_known(false);
        }
    });

    let tx_for_older_history = worker_tx.clone();
    ui.on_older_history_requested(move || {
        let _ = tx_for_older_history.send(WorkerCommand::LoadOlderHistory);
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

    let tx_for_part = worker_tx.clone();
    ui.on_channel_part_requested(move |network, channel| {
        let _ = tx_for_part.send(WorkerCommand::PartChannel {
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

    let tx_for_dismiss_recover = worker_tx.clone();
    ui.on_recover_dismiss_requested(move || {
        let _ = tx_for_dismiss_recover.send(WorkerCommand::DismissRecover);
    });

    let tx_for_directory_refresh = worker_tx.clone();
    ui.on_directory_refresh_requested(move || {
        let _ = tx_for_directory_refresh.send(WorkerCommand::DirectoryRefresh);
    });

    let tx_for_directory_load_more = worker_tx.clone();
    ui.on_directory_load_more_requested(move || {
        let _ = tx_for_directory_load_more.send(WorkerCommand::DirectoryLoadMore);
    });

    let tx_for_directory_sort = worker_tx.clone();
    ui.on_directory_sort_requested(move |sort| {
        let _ = tx_for_directory_sort.send(WorkerCommand::DirectorySort(sort.to_string()));
    });

    let tx_for_directory_search = worker_tx.clone();
    ui.on_directory_search_requested(move |query| {
        let _ = tx_for_directory_search.send(WorkerCommand::DirectorySearch(query.to_string()));
    });

    let tx_for_directory_close = worker_tx.clone();
    ui.on_directory_closed(move || {
        let _ = tx_for_directory_close.send(WorkerCommand::DirectoryClose);
    });

    let tx_for_dcc_accept = worker_tx.clone();
    ui.on_dcc_offer_accept_requested(move |network, offer_id| {
        let _ = tx_for_dcc_accept.send(WorkerCommand::DccOfferAnswer {
            network: network.to_string(),
            offer_id: offer_id.to_string(),
            accept: true,
        });
    });

    let tx_for_dcc_refuse = worker_tx.clone();
    ui.on_dcc_offer_refuse_requested(move |network, offer_id| {
        let _ = tx_for_dcc_refuse.send(WorkerCommand::DccOfferAnswer {
            network: network.to_string(),
            offer_id: offer_id.to_string(),
            accept: false,
        });
    });

    let tx_for_archive_delete = worker_tx.clone();
    ui.on_archive_delete_requested(move |target| {
        let _ = tx_for_archive_delete.send(WorkerCommand::ArchiveDelete(target.to_string()));
    });

    let tx_for_archive_close = worker_tx.clone();
    ui.on_archive_closed(move || {
        let _ = tx_for_archive_close.send(WorkerCommand::ArchiveClose);
    });

    let tx_for_peer_away_dismiss = worker_tx.clone();
    ui.on_peer_away_dismiss_requested(move || {
        let _ = tx_for_peer_away_dismiss.send(WorkerCommand::DismissPeerAway);
    });

    let tx_for_network_toggle = worker_tx.clone();
    ui.on_network_toggle_requested(move |network| {
        let _ = tx_for_network_toggle.send(WorkerCommand::ToggleNetwork(network.to_string()));
    });

    let tx_for_attach = worker_tx.clone();
    let weak_for_attach = ui.as_weak();
    ui.on_attach_file_requested(move || {
        let Some(ui) = weak_for_attach.upgrade() else {
            return;
        };
        // The native file picker and the confirmation are modal and must run
        // on the UI thread (a requirement on macOS); the upload itself
        // happens in the worker.
        let Some(path) = rfd::FileDialog::new().pick_file() else {
            return;
        };
        if ui.get_pref_upload_confirm() {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let answer = rfd::MessageDialog::new()
                .set_title(ui.get_upload_confirm_title().as_str())
                .set_description(format!("{}\n\n{name}", ui.get_upload_confirm_text()))
                .set_buttons(rfd::MessageButtons::YesNo)
                .show();
            if !matches!(answer, rfd::MessageDialogResult::Yes) {
                return;
            }
        }
        let expire = upload_ttl_for_index(ui.get_pref_upload_ttl_index());
        let _ = tx_for_attach.send(WorkerCommand::AttachFile(path, expire));
    });

    let tx_for_upload_prefs = worker_tx.clone();
    let weak_for_upload_prefs = ui.as_weak();
    ui.on_upload_prefs_changed(move || {
        if let Some(ui) = weak_for_upload_prefs.upgrade() {
            let _ = tx_for_upload_prefs.send(WorkerCommand::UploadPrefsChanged {
                ttl: upload_ttl_for_index(ui.get_pref_upload_ttl_index()),
                confirm: ui.get_pref_upload_confirm(),
            });
        }
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

    let tx_for_color_theme = worker_tx.clone();
    ui.on_color_theme_requested(move |key| {
        let _ = tx_for_color_theme.send(WorkerCommand::SelectColorTheme(key.to_string()));
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

    let tx_for_notify_load = worker_tx.clone();
    ui.on_notification_prefs_requested(move || {
        let _ = tx_for_notify_load.send(WorkerCommand::LoadNotificationPrefs);
    });

    let tx_for_notify_save = worker_tx.clone();
    let weak_for_notify = ui.as_weak();
    ui.on_notification_prefs_changed(move || {
        if let Some(ui) = weak_for_notify.upgrade() {
            let _ = tx_for_notify_save.send(WorkerCommand::SaveNotificationPrefs(
                NotificationToggles {
                    channel_mentions: ui.get_notify_channel_mentions(),
                    channel_messages_all: ui.get_notify_channel_all(),
                    private_messages_all: ui.get_notify_private_all(),
                    presence_online: ui.get_notify_presence_online(),
                    presence_offline: ui.get_notify_presence_offline(),
                },
            ));
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkConnectionStatus {
    Connected,
    Failing,
    Parked,
    Failed,
}

impl NetworkConnectionStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "connected" => Some(Self::Connected),
            "failing" => Some(Self::Failing),
            "parked" => Some(Self::Parked),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Failing => "failing",
            Self::Parked => "parked",
            Self::Failed => "failed",
        }
    }

    fn sidebar_label(self) -> &'static str {
        match self {
            Self::Connected => "",
            Self::Failing => "reconnecting",
            Self::Parked => "paused",
            Self::Failed => "connection failed",
        }
    }
}

/// Transient upstream-connect progress from `connection_progress`. It is a
/// live-only overlay, never replayed on join and never a substitute for the
/// durable `connection_state` read from `/networks`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionProgressState {
    Connecting,
    Connected,
}

impl ConnectionProgressState {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "connecting" => Some(Self::Connecting),
            "connected" => Some(Self::Connected),
            _ => None,
        }
    }
}

/// Closed step set of Grappa's guided identity recovery (`/recover`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoverStep {
    Identify,
    Register,
    Nick,
    Recover,
    Release,
}

impl RecoverStep {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "identify" => Some(Self::Identify),
            "register" => Some(Self::Register),
            "nick" => Some(Self::Nick),
            "recover" => Some(Self::Recover),
            "release" => Some(Self::Release),
            _ => None,
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::Identify => "identify",
            Self::Register => "register",
            Self::Nick => "nick",
            Self::Recover => "recover",
            Self::Release => "release",
        }
    }
}

/// Closed status set of one recovery step (`running | ok | failed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoverStepStatus {
    Running,
    Done,
    Failed,
}

impl RecoverStepStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "running" => Some(Self::Running),
            "ok" => Some(Self::Done),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Done => "ok",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoverStepEntry {
    step: RecoverStep,
    status: RecoverStepStatus,
    /// Open string: Grappa may add reason tokens, so an unknown one must
    /// never drop the step.
    reason: Option<String>,
}

/// Terminal outcome of an identity recovery (`succeeded | failed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoverOutcome {
    Succeeded,
    Failed,
}

impl RecoverOutcome {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

/// Cicchetto's `RecoverState`: opened only by the first `recover_progress`,
/// bound to that event's network, cleared only by an explicit dismiss.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoverPanel {
    network: String,
    steps: Vec<RecoverStepEntry>,
    /// Set by `recover_result`; `None` while the recovery is still running.
    outcome: Option<RecoverOutcome>,
    /// Open failure token from `recover_result` (`null` on success).
    outcome_reason: Option<String>,
}

/// The subject's auto-away delay as Grappa stores it: `null` defers to the
/// server's own default, `0` turns auto-away off, anything else is seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AutoAwayDebounce {
    ServerDefault,
    Disabled,
    Seconds(u64),
}

impl AutoAwayDebounce {
    /// The token the Settings screen translates: `default`, `off`, or seconds.
    fn display_token(self) -> String {
        match self {
            Self::ServerDefault => "default".to_string(),
            Self::Disabled => "off".to_string(),
            Self::Seconds(seconds) => seconds.to_string(),
        }
    }
}

/// The latest reply to a command this client issued (a requester event),
/// shown on the reply screen. Rows are `(label key, value)`; an empty key is
/// a plain line.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplyView {
    kind: &'static str,
    subject: String,
    network: String,
    rows: Vec<(String, String)>,
}

/// The archive of one network: windows with bouncer scrollback that are no
/// longer joined or open, as listed by `GET /networks/:slug/archive`.
struct ArchiveView {
    network: String,
    /// `None` until the first list arrives.
    entries: Option<Vec<ArchiveEntry>>,
    /// Translated error key for the last failed request, if any.
    error: Option<&'static str>,
}

/// A `DCC SEND` offer Grappa holds until this user accepts or refuses it.
/// `channel` is only where Cicchetto renders it (often `$server`); the
/// offer is identified by `offer_id`, an opaque server string.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DccOffer {
    network: String,
    channel: String,
    offer_id: String,
    from: String,
    filename: String,
    size: u64,
}

/// The channel directory for one network: a view over Grappa's last `LIST`
/// snapshot, fetched over REST. `directory_*` pushes are only signals to
/// fetch again; the rows always come from the server's page.
struct DirectoryView {
    network: String,
    /// `users` or `name`, the two sorts the server knows.
    sort: &'static str,
    query: String,
    /// Loaded rows (pages appended by "load more") plus the latest page's
    /// cursor, total, status and capture time; `None` before the first load.
    page: Option<DirectoryPage>,
    /// Translated error key for the last failed request, if any.
    error: Option<&'static str>,
    /// A refresh was asked for and no `directory_*` push has answered yet.
    refresh_pending: bool,
    /// `reason` of the last `directory_failed` (an open string, e.g.
    /// `timeout`); cleared by the next refresh or capture progress.
    failed_reason: Option<String>,
}

impl DirectoryView {
    fn new(network: String, query: String) -> Self {
        Self {
            network,
            sort: "users",
            query,
            page: None,
            error: None,
            refresh_pending: false,
            failed_reason: None,
        }
    }
}

/// One `who_reply` user row, all fields required by the wire contract.
#[derive(Clone, Debug, PartialEq, Eq)]
struct WhoUser {
    nick: String,
    user: String,
    host: String,
    server: String,
    modes: String,
    channel: String,
    hops: Option<i64>,
    realname: Option<String>,
}

/// `whois_bundle` as the wire declares it. Every key is required except
/// `source` (absent means `user`) and `avatar_url` (absent means `None`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct WhoisBundle {
    network: String,
    target: String,
    user: Option<String>,
    host: Option<String>,
    realname: Option<String>,
    server: Option<String>,
    server_info: Option<String>,
    is_operator: bool,
    oper_text: Option<String>,
    idle_seconds: Option<i64>,
    signon: Option<i64>,
    channels: Option<Vec<String>>,
    using_ssl: bool,
    is_registered: bool,
    is_admin: bool,
    is_services_admin: bool,
    is_helper: bool,
    is_chanop: bool,
    is_agent: bool,
    is_java: bool,
    umodes: Option<String>,
    away_message: Option<String>,
    actually_host: Option<String>,
    actually_ip: Option<String>,
    account: Option<String>,
    secure: bool,
    secure_cipher: Option<String>,
    certfp: Option<String>,
    /// `(numeric, text)` in wire order: 320 and numerics Grappa doesn't fold.
    extra_lines: Option<Vec<(i64, String)>>,
    /// Authenticated Grappa path to the cached peer avatar, not a third-party
    /// URL; may arrive later through `whois_avatar_ready`.
    avatar_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WhoReply {
    network: String,
    target: String,
    users: Vec<WhoUser>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NetworkConnectionSnapshot {
    status: NetworkConnectionStatus,
    reason: Option<String>,
    changed_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NetworkConnectionTransition {
    network_id: i64,
    network_slug: String,
    from: NetworkConnectionStatus,
    snapshot: NetworkConnectionSnapshot,
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
    /// Windows whose history was paged back to its very first message.
    history_start_reached: std::collections::HashSet<(String, String)>,
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
    /// Last server-confirmed IRC connection state per network. This is
    /// separate from the Phoenix socket's reconnect state and is refreshed
    /// from `/networks` after a `connection_state_changed` push.
    network_connection_states: HashMap<String, NetworkConnectionSnapshot>,
    /// Networks whose upstream IRC connect attempt is in flight, per the last
    /// live `connection_progress`. Shown as a transient sidebar badge only;
    /// cleared by `connected` and whenever the Phoenix socket drops, since
    /// the event is never replayed and a missed `connected` would otherwise
    /// leave the badge stuck.
    connecting_networks: std::collections::HashSet<String>,
    /// Identity-recovery panel driven entirely by server pushes; `None`
    /// until the first `recover_progress` and again after a dismiss.
    recover_panel: Option<RecoverPanel>,
    /// Latest requester reply shown on the reply screen; never persisted
    /// and never rendered into a chat window.
    reply_view: Option<ReplyView>,
    /// The WHOIS card currently shown, kept so a later `whois_avatar_ready`
    /// can patch exactly this card and no other.
    whois_card: Option<WhoisBundle>,
    /// Display copy of the account-wide auto-away delay; `None` until the
    /// server announces it. Grappa applies the value itself.
    auto_away_debounce: Option<AutoAwayDebounce>,
    /// Display copy of the remembered QUIT/PART text: outer `None` until
    /// announced, inner `None` for `null` (the server's own fallback).
    quit_part_reason: Option<Option<String>>,
    /// Display copy of the auto-away text, same shape as `quit_part_reason`
    /// (inner `None`: the server keeps its built-in text).
    auto_away_reason: Option<Option<String>>,
    /// Networks with a `/lusers` awaiting its bundle. The ircd also sends
    /// LUSERS unasked at registration; only a requested bundle is shown,
    /// and each request is consumed by the first matching bundle.
    lusers_requested: std::collections::HashSet<String>,
    /// The channel directory screen opened with `/list`, if any.
    directory: Option<DirectoryView>,
    /// DCC offers the server is holding for consent, in arrival order.
    dcc_offers: Vec<DccOffer>,
    /// The archive screen opened with `/archive`, if any.
    archive: Option<ArchiveView>,
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
    /// Presence watchlist nicks per network ID, replaced whole by every
    /// `notify_list` snapshot (sent after join and after each change).
    notify_lists: HashMap<i64, Vec<String>>,
    /// Watched-nick presence per network ID, keyed by ASCII-folded nick.
    /// A nick missing here reads as `unknown`.
    presence_by_network: HashMap<i64, HashMap<String, Presence>>,
    /// Last standalone away message (301) per `(network, folded peer)`,
    /// shown above that peer's private window until dismissed.
    peer_away: HashMap<(String, String), String>,
    /// Latest back-from-away mentions summary per network, kept apart from
    /// `reply_view` so a later reply can't lose it; `/mentions` reopens it.
    mentions_bundles: HashMap<String, ReplyView>,
    /// Upload limits from the latest `server_settings_changed`, shown read
    /// only in Settings (Cordiale doesn't upload files yet).
    upload_limits: Option<UploadLimits>,
    /// Last push-notification map read from Grappa; edits overlay the
    /// toggles Cordiale shows and send the whole map back.
    notification_prefs: Option<serde_json::Map<String, Value>>,
    /// Last announced web-client bundle `(hash, version)`, only to log a
    /// change once; it names Cicchetto's build, not this app.
    web_bundle: Option<(String, Option<String>)>,
    /// Session-local only: the keyword watchlist has no documented `list`
    /// reply shape (see `docs/protocol-notes.md` §4quater). It is cleared on
    /// disconnect or relaunch; an automatic reconnect keeps it as it was,
    /// possibly stale.
    watch_patterns: Vec<String>,
    /// Current app theme, kept here too (not just in Slint's `theme`
    /// property) so message-rendering helpers running on this thread can
    /// pick a legible color without an extra hop to the UI thread.
    theme: Theme,
    /// Color themes offered in Settings > Themes: Grappa's gallery when the
    /// server has one, the built-in copies otherwise.
    theme_choices: Vec<ThemeChoice>,
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
            history_start_reached: std::collections::HashSet::new(),
            stale_query_topics: std::collections::HashSet::new(),
            recent_channels: Vec::new(),
            current_query: false,
            current_query_ready: false,
            current_channel: None,
            network_ids: HashMap::new(),
            network_connection_states: HashMap::new(),
            connecting_networks: std::collections::HashSet::new(),
            recover_panel: None,
            reply_view: None,
            whois_card: None,
            auto_away_debounce: None,
            quit_part_reason: None,
            auto_away_reason: None,
            lusers_requested: std::collections::HashSet::new(),
            directory: None,
            dcc_offers: Vec::new(),
            archive: None,
            own_nicks: HashMap::new(),
            away_states: HashMap::new(),
            session_identities: HashMap::new(),
            isupport_by_network: HashMap::new(),
            user_modes_by_network: HashMap::new(),
            supported_user_modes_by_network: HashMap::new(),
            own_listener_ready: std::collections::HashSet::new(),
            settings_network: None,
            notify_lists: HashMap::new(),
            presence_by_network: HashMap::new(),
            peer_away: HashMap::new(),
            mentions_bundles: HashMap::new(),
            upload_limits: None,
            notification_prefs: None,
            web_bundle: None,
            watch_patterns: Vec::new(),
            theme: persistence::load_settings().unwrap_or_default().theme,
            theme_choices: builtin_theme_choices(),
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
                        write_back_read_cursor(&mut state);
                        handle_select_channel(&mut state, &ui, network, channel).await;
                    }
                    Some(WorkerCommand::PartChannel { network, channel }) => {
                        handle_part_channel(&mut state, &ui, network, channel, None).await;
                    }
                    Some(WorkerCommand::SelectQuery { network, nick }) => {
                        write_back_read_cursor(&mut state);
                        handle_select_query(&mut state, &ui, network, nick).await;
                    }
                    Some(WorkerCommand::DismissKickedChannel { network, channel }) => {
                        handle_dismiss_kicked_channel(&mut state, &ui, network, channel).await;
                    }
                    Some(WorkerCommand::DismissRecover) => {
                        state.recover_panel = None;
                        push_recover_panel(&state, &ui);
                    }
                    Some(WorkerCommand::DirectoryRefresh) => {
                        refresh_directory(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::DirectoryLoadMore) => {
                        load_more_directory(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::DirectorySort(sort)) => {
                        let sort = if sort == "name" { "name" } else { "users" };
                        if let Some(view) = state.directory.as_mut() {
                            view.sort = sort;
                        }
                        load_directory(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::DirectorySearch(query)) => {
                        if let Some(view) = state.directory.as_mut() {
                            view.query = query.trim().to_string();
                        }
                        load_directory(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::DirectoryClose) => {
                        state.directory = None;
                    }
                    Some(WorkerCommand::DccOfferAnswer {
                        network,
                        offer_id,
                        accept,
                    }) => {
                        answer_dcc_offer(&state, &ui, &network, &offer_id, accept).await;
                    }
                    Some(WorkerCommand::ArchiveDelete(target)) => {
                        delete_archive_target(&mut state, &ui, &target).await;
                    }
                    Some(WorkerCommand::ArchiveClose) => {
                        state.archive = None;
                    }
                    Some(WorkerCommand::DismissPeerAway) => {
                        if let Some(key) = current_peer_away_key(&state) {
                            state.peer_away.remove(&key);
                        }
                        push_peer_away_banner(&state, &ui);
                    }
                    Some(WorkerCommand::ToggleNetwork(network)) => {
                        let initially_expanded = !state.network_connection_states.get(&network).is_some_and(
                            |snapshot| matches!(snapshot.status, NetworkConnectionStatus::Parked),
                        );
                        let expanded = state.expanded_networks.entry(network).or_insert(initially_expanded);
                        *expanded = !*expanded;
                        refresh_network_groups(&state, &ui);
                    }
                    Some(WorkerCommand::AttachFile(path, expire)) => {
                        handle_attach_file(&mut state, &ui, path, expire).await;
                    }
                    Some(WorkerCommand::UploadPrefsChanged { ttl, confirm }) => {
                        if let (Some(client), Some(token)) = (&state.client, &state.token) {
                            if let Err(err) = client.set_upload_ttl(token, ttl).await {
                                persistence::log_line(&format!("upload ttl save failed: {err:?}"));
                            }
                            if let Err(err) = client.set_upload_confirm(token, confirm).await {
                                persistence::log_line(&format!(
                                    "upload confirm save failed: {err:?}"
                                ));
                            }
                        }
                    }
                    Some(WorkerCommand::SendMessage { body }) => {
                        handle_send_message(&mut state, &ui, body).await;
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
                    Some(WorkerCommand::SelectColorTheme(key)) => {
                        select_color_theme(&mut state, &ui, &key).await;
                    }
                    Some(WorkerCommand::LoadNotificationPrefs) => {
                        handle_load_notification_prefs(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::SaveNotificationPrefs(toggles)) => {
                        handle_save_notification_prefs(&mut state, &ui, toggles).await;
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
                        push_notify_nicks(&state, &ui);
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
                    // The server answers each change with a full `notify_list`
                    // snapshot; the local edit only avoids a stale row until
                    // it arrives.
                    Some(WorkerCommand::NotifyAdd(nick)) => {
                        if let (Some(client), Some(token), Some(network)) =
                            (&state.client, &state.token, &state.settings_network)
                        {
                            let network_id = state.network_ids.get(network).copied();
                            if client
                                .add_notify_nicks(token, network, vec![nick.clone()])
                                .await
                                .is_ok()
                            {
                                if let Some(network_id) = network_id {
                                    let nicks = state.notify_lists.entry(network_id).or_default();
                                    if !nicks.contains(&nick) {
                                        nicks.push(nick);
                                    }
                                }
                            }
                        }
                        push_notify_nicks(&state, &ui);
                    }
                    Some(WorkerCommand::NotifyRemove(nick)) => {
                        if let (Some(client), Some(token), Some(network)) =
                            (&state.client, &state.token, &state.settings_network)
                        {
                            let network_id = state.network_ids.get(network).copied();
                            if client.remove_notify_nick(token, network, &nick).await.is_ok() {
                                if let Some(nicks) =
                                    network_id.and_then(|id| state.notify_lists.get_mut(&id))
                                {
                                    nicks.retain(|existing| existing != &nick);
                                }
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
                        // A manual disconnect is how the user switches
                        // accounts: don't sign back in at the next launch.
                        set_auto_connect(false);
                        if let Some(handle) = state.session.take() {
                            handle.shutdown();
                        }
                        session_events = None;
                        state = WorkerState::new();
                    }
                    Some(WorkerCommand::LoadOlderHistory) => {
                        handle_load_older_history(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::GoHome) => {
                        write_back_read_cursor(&mut state);
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
                    Some(SessionEvent::Disconnected { reason }) if state.session.is_none() => {
                        // A deliberately ended session (sign-out, revoked
                        // bearer) still reports its final socket close; it
                        // must not overwrite the sign-in screen's status.
                        persistence::log_line(&format!("ended session closed: {reason}"));
                    }
                    Some(SessionEvent::Reconnecting { reason }) if state.session.is_none() => {
                        persistence::log_line(&format!("ended session not reconnecting: {reason}"));
                    }
                    Some(SessionEvent::Disconnected { reason }) => {
                        persistence::log_line(&format!("session disconnected: {reason}"));
                        reset_query_session_readiness(&mut state);
                        state.own_listener_ready.clear();
                        state.supported_user_modes_by_network.clear();
                        if !state.connecting_networks.is_empty() {
                            state.connecting_networks.clear();
                            refresh_network_groups(&state, &ui);
                        }
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
                        if !state.connecting_networks.is_empty() {
                            state.connecting_networks.clear();
                            refresh_network_groups(&state, &ui);
                        }
                        let _ = ui.upgrade_in_event_loop(move |ui| {
                            ui.set_status_kind("reconnecting".into());
                            ui.set_status_message(reason.into());
                            ui.set_current_query_ready(false);
                        });
                    }
                    Some(SessionEvent::AuthRejected { reason }) => {
                        // The session task has already stopped retrying; a
                        // lost `web_session_severed` push ends up here too.
                        persistence::log_line(&format!("session bearer rejected: {reason}"));
                        end_revoked_session(&mut state, &ui, false);
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
    // The typed password (or client token) of a successful sign-in is kept
    // in the OS keyring for the next launch.
    let typed_password = match &credential {
        ConnectCredential::FormValue(password) if !password.is_empty() => Some(password.clone()),
        _ => None,
    };
    let mut used_remembered_password = false;
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
            let with_bearer = match remembered_profile_credential(&server_url, &identifier) {
                RememberedProfileCredential::Bearer(bearer) => {
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
                        None
                    } else {
                        Some(result)
                    }
                }
                RememberedProfileCredential::None
                | RememberedProfileCredential::NeedsReauthentication => None,
            };
            match with_bearer {
                Some(result) => result,
                // No usable bearer: sign in again with the password kept in
                // the OS keyring, if there is one.
                None => match remembered_login_password(&server_url, &identifier) {
                    Some(password) => {
                        persistence::log_line(&format!(
                            "connect attempt: server={server_url} identifier={identifier} \
                             guest=false auth=remembered_password"
                        ));
                        used_remembered_password = true;
                        let request = LoginRequest {
                            identifier: identifier.clone(),
                            password,
                        };
                        bootstrap(&client, &request).await
                    }
                    None => {
                        persistence::log_line(&format!(
                            "saved profile unavailable: server={server_url} identifier={identifier}"
                        ));
                        show_reauthentication_required(ui);
                        return;
                    }
                },
            }
        }
    };

    match result {
        Ok(outcome) => {
            persistence::log_line(&format!("connect succeeded: server={server_url}"));
            let mut connection_states =
                network_connection_states_from_entries(&outcome.boot.networks);
            match client.fetch_networks(&outcome.token).await {
                Ok(networks) => {
                    connection_states.extend(network_connection_states_from_entries(&networks));
                }
                Err(error) => {
                    persistence::log_line(&format!(
                        "initial network-state refresh failed; using boot rows: {error:?}"
                    ));
                }
            }
            if !is_guest_attempt {
                remember_profile(&server_url, &identifier, &outcome.token);
                if let Some(password) = typed_password.as_deref() {
                    remember_login_password(&server_url, &identifier, password);
                }
                set_auto_connect(true);
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
            state.network_connection_states = connection_states;
            state.connecting_networks.clear();
            state.recover_panel = None;
            state.reply_view = None;
            state.whois_card = None;
            state.auto_away_debounce = None;
            state.quit_part_reason = None;
            state.auto_away_reason = None;
            state.lusers_requested.clear();
            state.directory = None;
            state.dcc_offers.clear();
            state.archive = None;
            state.notify_lists.clear();
            state.presence_by_network.clear();
            state.peer_away.clear();
            state.mentions_bundles.clear();
            state.upload_limits = None;
            state.web_bundle = None;
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
                let ttl = prefs_client.fetch_upload_ttl(&prefs_token).await;
                let confirm = prefs_client.fetch_upload_confirm(&prefs_token).await;
                if let (Ok(ttl), Ok(confirm)) = (ttl, confirm) {
                    let _ = ui_for_prefs.upgrade_in_event_loop(move |ui| {
                        ui.set_pref_upload_ttl_index(upload_ttl_index(ttl));
                        ui.set_pref_upload_confirm(confirm);
                        ui.set_upload_prefs_loaded(true);
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
            let groups_data = network_groups_data(
                &entries,
                &state.query_windows,
                &state.expanded_networks,
                &state.network_connection_states,
                &state.network_ids,
            );
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
                ui.set_recover_visible(false);
                ui.set_dcc_offers(slint::ModelRc::default());
                ui.set_server_pref_auto_away_debounce("".into());
                ui.set_server_pref_leave_message_known(false);
                ui.set_server_pref_auto_away_reason_known(false);
                ui.set_server_upload_limits_known(false);
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
                ui.set_sidebar_widest_label(widest_sidebar_label(&groups).into());
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
            load_color_themes(state, &ui).await;
            if let Some((network, channel)) = restore_channel {
                handle_select_channel(state, &ui, network, channel).await;
            }
        }
        Err(err) => {
            persistence::log_line(&format!("connect failed: server={server_url} {err:?}"));
            // A kept password the server now refuses (changed elsewhere) is
            // dropped, so the next launch asks for it instead of retrying.
            if used_remembered_password
                && matches!(err, BootstrapError::Login(LoginError::InvalidCredentials))
            {
                forget_login_password(&server_url, &identifier);
            }
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
    let casemapping = network_casemapping(state, &network);
    let history_start = state.history_start_reached.contains(&key);

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
        ui.set_history_start_reached(history_start);
        ui.set_history_loading(false);
        let model = chat_lines_model_with_roster(&lines, dark_theme, &members, casemapping);
        ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        let member_rows = members_model(&members, dark_theme);
        ui.set_members_average_nick(members_average_probe(&member_rows).into());
        ui.set_channel_members(Rc::new(slint::VecModel::from(member_rows)).into());
    });
}

/// A successful REST response is the server's acknowledgement of PART. Keep
/// the sidebar and current view intact on failure, then reconcile local topic
/// ownership only after that acknowledgement.
async fn handle_part_channel(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    channel: String,
    reason: Option<String>,
) {
    let key = window_state_key(&network, &channel);
    if state.window_states.get(&key) != Some(&ChannelWindowState::Joined)
        || !state
            .channel_entries
            .iter()
            .any(|(entry_network, entry_channel, _)| {
                window_state_key(entry_network, entry_channel) == key
            })
    {
        return;
    }
    let (Some(client), Some(token), Some(identifier)) = (
        state.client.clone(),
        state.token.clone(),
        state.identifier.clone(),
    ) else {
        return;
    };

    if let Err(error) = client
        .part_channel(&token, &network, &channel, reason.as_deref())
        .await
    {
        persistence::log_line(&format!("channel part failed: {error:?}"));
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(|ui| ui.set_status_kind("part-failed".into()));
        return;
    }

    let selected =
        state
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_channel)| {
                !state.current_query && window_state_key(current_network, current_channel) == key
            });
    let mut remaining_entries = state.channel_entries.clone();
    remove_sidebar_channel_entry(&mut remaining_entries, &network, &channel);
    let actions = reconcile_channel_entries(state, &identifier, remaining_entries);
    if let Some(session) = state.session.as_ref() {
        for action in actions {
            if let ChannelTopicAction::Leave(topic) = action {
                session.leave_topic(topic);
            }
        }
    }
    state.window_states.remove(&key);
    state.window_failures.remove(&key);
    state.window_kicks.remove(&key);
    state.invited_by.remove(&key);
    state.channel_modes.remove(&key);
    state.topics.remove(&(network.clone(), channel.clone()));
    state.members.remove(&(network.clone(), channel.clone()));
    state.messages.remove(&(network.clone(), channel.clone()));
    state.drafts.remove(&(network.clone(), channel.clone()));
    state
        .recent_channels
        .retain(|(recent_network, recent_channel)| {
            window_state_key(recent_network, recent_channel) != key
        });
    refresh_network_groups(state, ui);

    if selected {
        state.current_channel = None;
        state.current_query = false;
        state.current_query_ready = false;
        let mut settings = persistence::load_settings().unwrap_or_default();
        settings.last_channel = None;
        let _ = persistence::save_settings(&settings);
        clear_closed_query_view(ui);
    }
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(|ui| {
        if ui.get_status_kind().as_str() == "part-failed" {
            ui.set_status_kind("signed-in".into());
        }
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
    let history_start = state.history_start_reached.contains(key);
    let label = format!("{} — {}", query.network, query.target_nick);
    push_peer_away_banner(state, ui);
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
        ui.set_history_start_reached(history_start);
        ui.set_history_loading(false);
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

async fn handle_send_message(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, body: String) {
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
    // `/recover` starts Grappa's guided NickServ identity recovery on the
    // active network; progress arrives only as `recover_progress` pushes,
    // which open the panel — nothing is shown optimistically, like Cicchetto.
    if body.trim() == "/recover" {
        send_user_network_verb(state, network, "recover");
        return;
    }
    // `/mentions` reopens the last away summary of the active network.
    if body.trim().eq_ignore_ascii_case("/mentions") {
        let bundle = state.mentions_bundles.get(network.as_str()).cloned();
        match bundle {
            Some(view) => show_reply_view(state, ui, view),
            None => {
                let ui = ui.clone();
                let _ = ui.upgrade_in_event_loop(|ui| {
                    ui.set_status_kind("no-mentions".into());
                });
            }
        }
        return;
    }
    // `/archive` lists the active network's archived windows.
    if body.trim().eq_ignore_ascii_case("/archive") {
        let network = network.clone();
        open_archive(state, ui, network).await;
        return;
    }
    // `/list [search]` opens the channel directory of the active network.
    if let Some(query) = parse_list_command(&body) {
        let network = network.clone();
        open_directory(state, ui, network, query).await;
        return;
    }
    // Commands answered by a requester reply (shown on the reply screen,
    // never as a chat line) are pushed on the user topic, not sent as text.
    if let Some(command) = parse_reply_command(&body, channel) {
        match command {
            ReplyCommand::Request { verb, payload } => {
                if verb == "lusers" {
                    state.lusers_requested.insert(network.to_string());
                }
                send_user_verb(state, network, verb, payload);
            }
            ReplyCommand::Usage => {
                let ui = ui.clone();
                let _ = ui.upgrade_in_event_loop(|ui| {
                    ui.set_status_kind("command-usage".into());
                });
            }
        }
        return;
    }
    if let Some(command) = slash::parse(&body) {
        let label = body
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        let (network, channel) = (network.clone(), channel.clone());
        run_slash_command(state, ui, network, channel, command, label).await;
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

/// Uploads a picked file to Grappa (`POST /api/uploads`) and posts its link
/// in the open window, as Cicchetto does: attachments stay plain messages,
/// prefixed by the category emoji (`📸 <url>` for an image). Types the
/// server would refuse, and files over the advertised per-file cap, are
/// stopped before uploading.
async fn handle_attach_file(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    path: std::path::PathBuf,
    expire: Option<i64>,
) {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let set_status = |kind: &'static str, name: String| {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            ui.set_status_attach_name(name.into());
            ui.set_status_kind(kind.into());
        });
    };
    if state.current_channel.is_none() {
        set_status("attach-no-window", filename);
        return;
    }
    let Some((mime, category)) = mime_for_filename(&filename) else {
        set_status("attach-unsupported-type", filename);
        return;
    };
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            persistence::log_line(&format!("attachment read failed: {err}"));
            set_status("attach-read-failed", filename);
            return;
        }
    };
    let over_cap = state
        .upload_limits
        .as_ref()
        .is_some_and(|limits| bytes.len() as u64 > upload_cap(limits, category));
    if over_cap {
        set_status("attach-too-large", filename);
        return;
    }
    set_status("attach-uploading", filename.clone());
    match client
        .upload_file(&token, &filename, mime, bytes, expire)
        .await
    {
        Ok(uploaded) => {
            persistence::log_line(&format!("attachment uploaded: slug={}", uploaded.slug));
            // Set first, so a failed send that follows can replace it.
            set_status("attach-sent", filename);
            handle_send_message(state, ui, attachment_message(category, &uploaded.url)).await;
        }
        Err(err) => {
            persistence::log_line(&format!("attachment upload failed: {err:?}"));
            set_status(
                attachment_error_status(err.status().map(|status| status.as_u16())),
                filename,
            );
        }
    }
}

/// Upload lifetimes offered in Settings, in the order of its menu: the
/// server's default, then the `expire` values Grappa accepts (1 hour,
/// 12 hours, 1 day, 3 days).
const UPLOAD_TTL_CHOICES: [Option<i64>; 5] =
    [None, Some(3600), Some(43_200), Some(86_400), Some(259_200)];

fn upload_ttl_for_index(index: i32) -> Option<i64> {
    usize::try_from(index)
        .ok()
        .and_then(|index| UPLOAD_TTL_CHOICES.get(index).copied())
        .flatten()
}

/// Menu entry for a stored lifetime; one the menu doesn't offer shows as
/// the server default.
fn upload_ttl_index(ttl: Option<i64>) -> i32 {
    UPLOAD_TTL_CHOICES
        .iter()
        .position(|choice| *choice == ttl)
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(0)
}

/// The per-file cap Grappa advertises for a category.
fn upload_cap(limits: &UploadLimits, category: UploadCategory) -> u64 {
    match category {
        UploadCategory::Image => limits.image_bytes,
        UploadCategory::Video => limits.video_bytes,
        UploadCategory::Document => limits.document_bytes,
        UploadCategory::Audio => limits.audio_bytes,
    }
}

/// Status-bar key for a failed upload, by `POST /api/uploads` status.
fn attachment_error_status(status: Option<u16>) -> &'static str {
    match status {
        Some(413) => "attach-too-large",
        Some(415) => "attach-unsupported-type",
        Some(507) => "attach-no-space",
        _ => "attach-failed",
    }
}

/// Runs a compose-line slash command (see `cordiale_core::slash`) against
/// the open window's network. REST calls report failure in the status bar;
/// WS verbs are fire-and-forget like the member context menu's, their
/// outcome arriving as server pushes. `label` is the command as typed.
async fn run_slash_command(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    channel: String,
    command: SlashCommand,
    label: String,
) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    let in_channel = !state.current_query && slash::is_channel(&channel);
    let open_channel = || in_channel.then(|| channel.clone());
    let result: Result<(), GrappaClientError> = match command {
        SlashCommand::Say(text) => {
            let request = SendMessageRequest::plain(text);
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::Action(text) => {
            let request = SendMessageRequest::plain(format!("\u{1}ACTION {text}\u{1}"));
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::Msg { target, text } => {
            // Services answer in the window the command was typed in.
            if !slash::is_service_nick(&target) {
                send_user_verb(
                    state,
                    &network,
                    "open_query_window",
                    serde_json::json!({ "target_nick": target }),
                );
            }
            let request = SendMessageRequest::plain(text);
            post_message(&client, &token, &network, &target, request).await
        }
        SlashCommand::Notice { target, text } => {
            let mut request = SendMessageRequest::plain(text);
            request.notice_target = Some(target);
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::Query(Some(nick)) => {
            send_user_verb(
                state,
                &network,
                "open_query_window",
                serde_json::json!({ "target_nick": nick }),
            );
            Ok(())
        }
        SlashCommand::Query(None) if state.current_query => {
            send_user_verb(
                state,
                &network,
                "close_query_window",
                serde_json::json!({ "target_nick": channel }),
            );
            Ok(())
        }
        SlashCommand::Query(None) => {
            return set_command_status(ui, "command-usage-hint", "/query <nick>".to_string());
        }
        SlashCommand::Join { channels, key } => {
            client
                .join_channel(&token, &network, &channels, key.as_deref())
                .await
        }
        SlashCommand::Part {
            channel: target,
            reason,
        } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            handle_part_channel(state, ui, network, target, reason).await;
            return;
        }
        SlashCommand::Cycle {
            channel: target,
            reason,
        } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            match client
                .part_channel(&token, &network, &target, reason.as_deref())
                .await
            {
                Ok(()) => client.join_channel(&token, &network, &target, None).await,
                Err(err) => Err(err),
            }
        }
        SlashCommand::TopicSet {
            channel: target,
            text,
        } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            client.set_topic(&token, &network, &target, &text).await
        }
        SlashCommand::TopicClear { channel: target } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            send_user_verb(
                state,
                &network,
                "topic_clear",
                serde_json::json!({ "channel": target }),
            );
            Ok(())
        }
        SlashCommand::Nick(nick) => client.change_nick(&token, &network, &nick).await,
        // The one user-topic verb addressed by slug rather than `network_id`.
        SlashCommand::Away(reason) => {
            let payload = match reason {
                Some(reason) => {
                    serde_json::json!({ "action": "set", "network": network, "reason": reason })
                }
                None => serde_json::json!({ "action": "unset", "network": network }),
            };
            send_user_topic_verb(state, "away", payload);
            Ok(())
        }
        SlashCommand::Ctcp { target, verb, args } if verb == "ACTION" => {
            let text = args.unwrap_or_default();
            let request = SendMessageRequest::plain(format!("\u{1}ACTION {text}\u{1}"));
            post_message(&client, &token, &network, &target, request).await
        }
        SlashCommand::Ctcp { target, verb, args } => {
            let request = SendMessageRequest::ctcp(target, &verb, args.as_deref());
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::Ping(target) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis())
                .unwrap_or_default()
                .to_string();
            let request = SendMessageRequest::ctcp(target, "PING", Some(&now));
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::NickModes { verb, nicks } if in_channel => {
            send_user_verb(
                state,
                &network,
                verb,
                serde_json::json!({ "channel": channel, "nicks": nicks }),
            );
            Ok(())
        }
        SlashCommand::Kick { nick, reason } if in_channel => {
            send_user_verb(
                state,
                &network,
                "kick",
                serde_json::json!({ "channel": channel, "nick": nick, "reason": reason }),
            );
            Ok(())
        }
        SlashCommand::Ban(mask) if in_channel => {
            send_user_verb(
                state,
                &network,
                "ban",
                serde_json::json!({ "channel": channel, "mask": mask }),
            );
            Ok(())
        }
        SlashCommand::Unban(mask) if in_channel => {
            send_user_verb(
                state,
                &network,
                "unban",
                serde_json::json!({ "channel": channel, "mask": mask }),
            );
            Ok(())
        }
        SlashCommand::NickModes { .. }
        | SlashCommand::Kick { .. }
        | SlashCommand::Ban(_)
        | SlashCommand::Unban(_) => {
            return set_command_status(ui, "command-needs-channel", label);
        }
        SlashCommand::Mode {
            target,
            modes,
            params,
        } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            send_user_verb(
                state,
                &network,
                "mode",
                serde_json::json!({ "target": target, "modes": modes, "params": params }),
            );
            Ok(())
        }
        SlashCommand::Umode(modes) => {
            send_user_verb(
                state,
                &network,
                "umode",
                serde_json::json!({ "modes": modes }),
            );
            Ok(())
        }
        SlashCommand::Names(target) => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            send_user_verb(
                state,
                &network,
                "names",
                serde_json::json!({ "channel": target }),
            );
            Ok(())
        }
        SlashCommand::Raw(line) => {
            send_user_verb(state, &network, "raw", serde_json::json!({ "line": line }));
            Ok(())
        }
        SlashCommand::Oper { name, password } => {
            send_user_verb(
                state,
                &network,
                "oper",
                serde_json::json!({ "name": name, "password": password }),
            );
            Ok(())
        }
        SlashCommand::Connect(target) => {
            client
                .set_connection_state(&token, &target, "connected", None)
                .await
        }
        SlashCommand::Disconnect {
            network: target,
            reason,
        } => {
            let target = target.unwrap_or(network);
            client
                .set_connection_state(&token, &target, "parked", reason.as_deref())
                .await
        }
        SlashCommand::Reconnect {
            network: target,
            reason,
        } => {
            let target = target.unwrap_or(network);
            match client
                .set_connection_state(&token, &target, "parked", reason.as_deref())
                .await
            {
                Ok(()) => {
                    client
                        .set_connection_state(&token, &target, "connected", None)
                        .await
                }
                Err(err) => Err(err),
            }
        }
        // Parks every network (a failure on one doesn't stop the others,
        // as in Cicchetto), then signs out like the Disconnect button.
        SlashCommand::Quit(reason) => {
            let networks: Vec<String> = state.network_ids.keys().cloned().collect();
            for target in networks {
                if let Err(err) = client
                    .set_connection_state(&token, &target, "parked", reason.as_deref())
                    .await
                {
                    persistence::log_line(&format!("quit: park failed: {err:?}"));
                }
            }
            let _ = ui.upgrade_in_event_loop(|ui| ui.invoke_disconnect_requested());
            return;
        }
        SlashCommand::Highlight { add, pattern } => {
            let action = if add { "add" } else { "del" };
            send_user_topic_verb(
                state,
                "watchlist",
                serde_json::json!({ "action": action, "pattern": pattern }),
            );
            if !add {
                state.watch_patterns.retain(|existing| existing != &pattern);
            } else if !state.watch_patterns.contains(&pattern) {
                state.watch_patterns.push(pattern);
            }
            push_watch_patterns(state, ui);
            Ok(())
        }
        SlashCommand::Ignore { add: true, mask } => {
            client.add_ignore(&token, &network, &mask).await.map(|_| ())
        }
        SlashCommand::Ignore { add: false, mask } => client
            .remove_ignore(&token, &network, &mask)
            .await
            .map(|_| ()),
        SlashCommand::Notify(nicks) => client.add_notify_nicks(&token, &network, nicks).await,
        SlashCommand::Usage(hint) => {
            return set_command_status(ui, "command-usage-hint", hint.to_string());
        }
        SlashCommand::Unknown(name) => {
            return set_command_status(ui, "command-unknown", name);
        }
    };
    if let Err(err) = result {
        persistence::log_line(&format!("{label} failed: {err:?}"));
        set_command_status(ui, "command-failed", label);
    }
}

/// Posts to `/networks/:slug/channels/:target/messages`.
async fn post_message(
    client: &GrappaClient,
    token: &str,
    network: &str,
    target: &str,
    request: SendMessageRequest,
) -> Result<(), GrappaClientError> {
    client
        .send_message(token, network, target, &request)
        .await
        .map(|_| ())
}

/// Shows a slash-command outcome in the status bar; `hint` fills its `{}`.
fn set_command_status(ui: &slint::Weak<AppWindow>, kind: &'static str, hint: String) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_command_hint(hint.into());
        ui.set_status_kind(kind.into());
    });
}

/// Pushes `verb` on the user topic with `payload` as is (no `network_id`).
fn send_user_topic_verb(state: &WorkerState, verb: &str, payload: Value) {
    if let (Some(session), Some(identifier)) = (&state.session, &state.identifier) {
        session.send_command(format!("grappa:user:{identifier}"), verb, payload);
    }
}

fn handle_toggle_theme(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.theme = match settings.theme {
        Theme::Light => Theme::Dark,
        Theme::Dark => Theme::Light,
    };
    // The light/dark switch is the classic look: it leaves any color theme.
    settings.color_theme = None;
    let _ = persistence::save_settings(&settings);
    set_active_palette(None);
    push_theme_choices(state, ui, None);
    {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(|ui| push_palette(&ui, None));
    }

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
    let current_roster = state
        .current_channel
        .as_ref()
        .filter(|_| !state.current_query)
        .map(|key| {
            (
                state.members.get(key).cloned().unwrap_or_default(),
                network_casemapping(state, &key.0),
            )
        });

    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_theme(theme_to_slint(new_theme));
        ui.invoke_apply_color_scheme();
        if let Some(lines) = current_lines {
            let model = match current_roster {
                Some((members, casemapping)) => chat_lines_model_with_roster(
                    &lines,
                    new_theme == Theme::Dark,
                    &members,
                    casemapping,
                ),
                None => chat_lines_model(&lines, new_theme == Theme::Dark),
            };
            ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        }
    });
}

/// The push-notification switches shown in Settings > Notifications; the
/// rest of Grappa's map (per-target lists, mutes, sound) is kept as read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NotificationToggles {
    channel_mentions: bool,
    channel_messages_all: bool,
    private_messages_all: bool,
    presence_online: bool,
    presence_offline: bool,
}

impl NotificationToggles {
    fn from_prefs(prefs: &serde_json::Map<String, Value>) -> Self {
        let flag =
            |key: &str, default: bool| prefs.get(key).and_then(Value::as_bool).unwrap_or(default);
        // Defaults are Grappa's own (`default_notification_prefs/0`).
        Self {
            channel_mentions: flag("channel_mentions", true),
            channel_messages_all: flag("channel_messages_all", false),
            private_messages_all: flag("private_messages_all", true),
            presence_online: flag("presence_online", false),
            presence_offline: flag("presence_offline", false),
        }
    }

    fn apply_to(self, prefs: &mut serde_json::Map<String, Value>) {
        for (key, value) in [
            ("channel_mentions", self.channel_mentions),
            ("channel_messages_all", self.channel_messages_all),
            ("private_messages_all", self.private_messages_all),
            ("presence_online", self.presence_online),
            ("presence_offline", self.presence_offline),
        ] {
            prefs.insert(key.to_string(), Value::Bool(value));
        }
    }
}

fn push_notification_toggles(ui: &slint::Weak<AppWindow>, toggles: NotificationToggles) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_notify_channel_mentions(toggles.channel_mentions);
        ui.set_notify_channel_all(toggles.channel_messages_all);
        ui.set_notify_private_all(toggles.private_messages_all);
        ui.set_notify_presence_online(toggles.presence_online);
        ui.set_notify_presence_offline(toggles.presence_offline);
        ui.set_notify_prefs_loaded(true);
    });
}

async fn handle_load_notification_prefs(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    match client.fetch_notification_prefs(&token).await {
        Ok(prefs) => {
            push_notification_toggles(ui, NotificationToggles::from_prefs(&prefs));
            state.notification_prefs = Some(prefs);
        }
        Err(err) => persistence::log_line(&format!("notification prefs load failed: {err:?}")),
    }
}

/// Saves the switches over the last map read. Grappa refuses (422) a map
/// with no message trigger left on; the switches then go back to the
/// stored values.
async fn handle_save_notification_prefs(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    toggles: NotificationToggles,
) {
    let (Some(client), Some(token), Some(stored)) = (
        state.client.clone(),
        state.token.clone(),
        state.notification_prefs.clone(),
    ) else {
        return;
    };
    let mut prefs = stored.clone();
    toggles.apply_to(&mut prefs);
    match client.set_notification_prefs(&token, &prefs).await {
        Ok(()) => state.notification_prefs = Some(prefs),
        Err(err) => {
            persistence::log_line(&format!("notification prefs save failed: {err:?}"));
            let kind = if err.status().map(|status| status.as_u16()) == Some(422) {
                "notify-prefs-invalid"
            } else {
                "notify-prefs-failed"
            };
            push_notification_toggles(ui, NotificationToggles::from_prefs(&stored));
            let _ = ui.upgrade_in_event_loop(move |ui| ui.set_status_kind(kind.into()));
        }
    }
}

/// Rows fetched per "Load older messages" click.
const OLDER_HISTORY_PAGE: usize = 100;

/// Pages the open window's history back from its oldest known message
/// (`?before=`), like Cicchetto's scroll-to-top. A short page means the
/// first message was reached, which hides the button for that window.
async fn handle_load_older_history(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token), Some(key)) = (
        state.client.clone(),
        state.token.clone(),
        state.current_channel.clone(),
    ) else {
        return;
    };
    let oldest = state
        .messages
        .get(&key)
        .and_then(|lines| lines.iter().filter_map(|line| line.message_id).min());
    let Some(oldest) = oldest else {
        return;
    };
    {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(|ui| ui.set_history_loading(true));
    }
    let rows = client
        .fetch_messages_before(&token, &key.0, &key.1, oldest, OLDER_HISTORY_PAGE)
        .await;
    let start_reached = match &rows {
        Ok(rows) => rows.len() < OLDER_HISTORY_PAGE,
        Err(err) => {
            persistence::log_line(&format!("older history fetch failed: {err:?}"));
            false
        }
    };
    if let Ok(rows) = rows {
        let messages = state.messages.entry(key.clone()).or_default();
        merge_rendered_messages(messages, rows.iter().map(render_history_entry));
    }
    if start_reached {
        state.history_start_reached.insert(key.clone());
    }
    // The user may have switched window while the page was loading.
    if state.current_channel.as_ref() != Some(&key) {
        return;
    }
    let lines = state.messages.get(&key).cloned().unwrap_or_default();
    let dark_theme = state.theme == Theme::Dark;
    let roster = (!state.current_query).then(|| {
        (
            state.members.get(&key).cloned().unwrap_or_default(),
            network_casemapping(state, &key.0),
        )
    });
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let model = match roster {
            Some((members, casemapping)) => {
                chat_lines_model_with_roster(&lines, dark_theme, &members, casemapping)
            }
            None => chat_lines_model(&lines, dark_theme),
        };
        ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        ui.set_history_start_reached(start_reached);
        ui.set_history_loading(false);
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

/// Pushes the presence watchlist of the network selected in Settings, each
/// nick with its last known presence.
fn push_notify_nicks(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let network_id = state
        .settings_network
        .as_ref()
        .and_then(|network| state.network_ids.get(network))
        .copied();
    let presence = network_id.and_then(|id| state.presence_by_network.get(&id));
    let rows: Vec<(String, &'static str)> = network_id
        .and_then(|id| state.notify_lists.get(&id))
        .into_iter()
        .flatten()
        .map(|nick| {
            let known = presence
                .and_then(|nicks| nicks.get(&presence_key(nick)))
                .copied()
                .unwrap_or(Presence::Unknown);
            (nick.clone(), known.wire_name())
        })
        .collect();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<NotifyRow> = rows
            .into_iter()
            .map(|(nick, presence)| NotifyRow {
                nick: nick.into(),
                presence: presence.into(),
            })
            .collect();
        ui.set_settings_notify_nicks(Rc::new(slint::VecModel::from(rows)).into());
    });
}

/// Presence of a watched nick, as Grappa reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Presence {
    Online,
    Offline,
    /// No report yet, or no MONITOR/WATCH/ISON on this network.
    Unknown,
}

impl Presence {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "online" => Some(Self::Online),
            "offline" => Some(Self::Offline),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Unknown => "unknown",
        }
    }
}

/// Presence maps are keyed by ASCII-folded nick, like Grappa's snapshot.
fn presence_key(nick: &str) -> String {
    cordiale_core::isupport::CaseMapping::Ascii.fold(nick)
}

/// Pushes the session-local keyword-watchlist patterns to the UI — see
/// `WorkerState::watch_patterns` for why they are session-local.
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
    send_user_network_verb(state, &network, "links");
}

/// Pushes a `{network_id}`-only verb (`links`, `recover`) on the user topic.
fn send_user_network_verb(state: &WorkerState, network: &str, verb: &str) {
    send_user_verb(state, network, verb, serde_json::json!({}));
}

/// Pushes `verb` on the user topic with `payload` plus the network's integer
/// `network_id`. `payload` must be a JSON object.
fn send_user_verb(state: &WorkerState, network: &str, verb: &str, mut payload: Value) {
    let (Some(session), Some(identifier)) = (&state.session, &state.identifier) else {
        return;
    };
    // Grappa hard-rejects a non-integer `network_id` (`is_integer/1`
    // guard server-side, no slug fallback) — see
    // `docs/protocol-notes.md` §4ter. Silently do nothing rather than
    // send a request guaranteed to be rejected if the id isn't known.
    let Some(&network_id) = state.network_ids.get(network) else {
        return;
    };
    let Value::Object(fields) = &mut payload else {
        return;
    };
    fields.insert("network_id".to_string(), Value::from(network_id));
    let topic = format!("grappa:user:{identifier}");
    session.send_command(topic, verb, payload);
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

/// Whether a known event kind is rendered as a chat line. Only `message`
/// envelopes are: every other kind of the protocol's closed set has its own
/// handler (or explicit no-op) in `handle_frame`, and any kind that reaches
/// the rendering path without one is dropped instead of becoming a raw
/// chat line. `"parted"` is not a kind at all — a self-part shows up as the
/// window leaving window-state, never as a push.
fn renders_as_chat_line(kind: &str) -> bool {
    kind == "message"
}

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
/// Every kind of the protocol's closed set has its own handler (or an
/// explicit no-op) below; only `message` envelopes reach chat rendering
/// (`renders_as_chat_line`). A kind unknown to `ClientEventKind` is dropped
/// silently, per `docs/CLIENT_PROTOCOL.md`'s policy on unrecognized kinds
/// (§4).
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
    if payload_kind == "connection_state_changed" {
        handle_connection_state_changed(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "connection_progress" {
        handle_connection_progress(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "recover_progress" {
        handle_recover_progress(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "recover_result" {
        handle_recover_result(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "web_session_severed" {
        handle_web_session_severed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "auto_away_debounce_changed" {
        handle_auto_away_debounce_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "quit_part_reason_changed" {
        handle_quit_part_reason_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "auto_away_reason_changed" {
        handle_auto_away_reason_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "who_reply" {
        handle_who_reply(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "server_reply" {
        handle_server_reply(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "whois_bundle" {
        handle_whois_bundle(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "whois_avatar_ready" {
        handle_whois_avatar_ready(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "whowas_bundle" {
        handle_whowas_bundle(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "directory_progress" {
        handle_directory_progress(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "directory_complete" {
        handle_directory_complete(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "directory_failed" {
        handle_directory_failed(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "dcc_offer" {
        handle_dcc_offer(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "dcc_offer_resolved" {
        handle_dcc_offer_resolved(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "archive_changed" {
        handle_archive_changed(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "archive_purged" {
        handle_archive_purged(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "notify_list" {
        handle_notify_list(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "presence_snapshot" {
        handle_presence_snapshot(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "presence_changed" {
        handle_presence_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "presence_error" {
        handle_presence_error(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "peer_away" {
        handle_peer_away(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "mentions_bundle" {
        handle_mentions_bundle(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "server_settings_changed" {
        handle_server_settings_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "bundle_hash" {
        handle_bundle_hash(state, &frame.topic, &frame.payload);
        return;
    }
    // 329 RPL_CREATIONTIME changes no state: Cicchetto keeps the kind but
    // dropped its join banner, so it is consumed without any UI.
    if payload_kind == "channel_created" {
        return;
    }
    if payload_kind == "invite_ack" {
        handle_invite_ack(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "lusers_bundle" {
        handle_lusers_bundle(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "banlist_bundle" {
        handle_banlist_bundle(state, ui, &frame.topic, &frame.payload);
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
        if let Some(key) = state
            .current_channel
            .as_ref()
            .filter(|_| !state.current_query)
        {
            push_members_update(state, ui, key);
        }
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

    if !renders_as_chat_line(payload_kind) {
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
        let members = state.members.get(&key).cloned().unwrap_or_default();
        let casemapping = network_casemapping(state, &network);
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            let model = chat_lines_model_with_roster(&lines, dark_theme, &members, casemapping);
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

/// The read cursor to send when leaving the open window: its newest message,
/// if that is past the known cursor. The local cursor advances at once
/// (forward-only), as in Cicchetto; the `read_cursor_set` push confirms it.
fn read_cursor_to_write(state: &mut WorkerState) -> Option<(String, String, i64)> {
    let (network, target) = state.current_channel.clone()?;
    let newest = query_high_water_id(state, &(network.clone(), target.clone()))?;
    let key = window_state_key(&network, &target);
    if state
        .read_cursors
        .get(&key)
        .is_some_and(|&cursor| cursor >= newest)
    {
        return None;
    }
    state.read_cursors.insert(key, newest);
    Some((network, target, newest))
}

/// Marks the window being left as read on the server (Cicchetto does it on
/// focus-leave). Fire-and-forget: a failure only leaves the unread count as
/// the server has it.
fn write_back_read_cursor(state: &mut WorkerState) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    let Some((network, target, message_id)) = read_cursor_to_write(state) else {
        return;
    };
    tokio::spawn(async move {
        if let Err(err) = client
            .set_read_cursor(&token, &network, &target, message_id)
            .await
        {
            persistence::log_line(&format!("read cursor write-back failed: {err:?}"));
        }
    });
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
    if state.current_query {
        return;
    }
    let members = state.members.get(key).cloned().unwrap_or_default();
    let can_moderate = state
        .identifier
        .as_deref()
        .is_some_and(|identifier| is_own_nick_an_op(&members, identifier));
    let dark_theme = state.theme == Theme::Dark;
    let lines = state.messages.get(key).cloned().unwrap_or_default();
    let casemapping = network_casemapping(state, &key.0);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_can_moderate_members(can_moderate);
        let member_rows = members_model(&members, dark_theme);
        ui.set_members_average_nick(members_average_probe(&member_rows).into());
        ui.set_channel_members(Rc::new(slint::VecModel::from(member_rows)).into());
        let chat_lines = chat_lines_model_with_roster(&lines, dark_theme, &members, casemapping);
        ui.set_chat_lines(Rc::new(slint::VecModel::from(chat_lines)).into());
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
    // Grappa stores the PART/QUIT/KICK reason in `body`; a top-level
    // `reason` is still honoured for older rows. An empty reason is none.
    let reason = body
        .or_else(|| payload.get("reason").and_then(Value::as_str))
        .filter(|reason| !reason.is_empty());

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
        // KICK: the kicker is the sender, the kicked nick is `meta.target`
        // and the optional reason is the body.
        Some("kick") => {
            let target = payload
                .get("meta")
                .and_then(|meta| meta.get("target"))
                .and_then(Value::as_str)
                .unwrap_or("someone");
            let kicker = nick.unwrap_or("someone");
            Some(match reason {
                Some(reason) => format!("⊘ {target} was kicked by {kicker} ({reason})"),
                None => format!("⊘ {target} was kicked by {kicker}"),
            })
        }
        // TOPIC: the body is the new topic; an empty one clears it.
        Some("topic") => Some(match body.filter(|topic| !topic.is_empty()) {
            Some(topic) => format!(
                "* {} changed the topic to: {topic}",
                nick.unwrap_or("someone")
            ),
            None => format!("* {} cleared the topic", nick.unwrap_or("someone")),
        }),
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
    let italic = matches!(kind, Some("notice") | Some("server_event"));

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
type NetworkGroupData = (
    String,
    bool,
    Vec<(String, String)>,
    Vec<(String, String)>,
    String,
    bool,
);
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
    connection_states: &HashMap<String, NetworkConnectionSnapshot>,
    known_networks: &HashMap<String, i64>,
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
    for network in known_networks.keys() {
        by_network.entry(network.clone()).or_default();
    }
    by_network
        .into_iter()
        .map(|(network, (mut channels, queries))| {
            channels.sort();
            let parked = connection_states
                .get(&network)
                .is_some_and(|snapshot| matches!(snapshot.status, NetworkConnectionStatus::Parked));
            let is_expanded = expanded.get(&network).copied().unwrap_or(!parked);
            let connection_label = connection_states
                .get(&network)
                .map(|snapshot| snapshot.status.sidebar_label().to_string())
                .unwrap_or_default();
            (
                network,
                is_expanded,
                channels,
                queries,
                connection_label,
                parked,
            )
        })
        .collect()
}

/// An in-flight upstream connect attempt outranks the durable label: a
/// `failing`/`failed`/`parked` network that is connecting again shows that.
fn apply_connecting_labels(
    data: &mut [NetworkGroupData],
    connecting: &std::collections::HashSet<String>,
) {
    for group in data.iter_mut() {
        if connecting.contains(&group.0) {
            group.4 = "connecting".to_string();
        }
    }
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
        .map(
            |(index, (network, expanded, channels, queries, connection_label, parked))| {
                let channel_entries: Vec<ChannelEntry> = channels
                    .into_iter()
                    .map(|(channel, label)| {
                        let failed = window_is_failed(&window_states, &network, &channel);
                        let kicked = window_is_kicked(&window_states, &network, &channel);
                        let invited = window_is_invited(&window_states, &network, &channel);
                        let joined = window_states.get(&window_state_key(&network, &channel))
                            == Some(&ChannelWindowState::Joined);
                        let mention_count = window_mentions
                            .get(&window_counts_key(&network, &channel))
                            .copied()
                            .unwrap_or_default();
                        let (mention_badge, mentions_description) =
                            mention_count_labels(mention_count);
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
                            joined,
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
                    connection_label: connection_label.into(),
                    separator_before: index > 0,
                    expanded,
                    parked,
                    channels: Rc::new(slint::VecModel::from(channel_entries)).into(),
                    queries: Rc::new(slint::VecModel::from(query_entries)).into(),
                }
            },
        )
        .collect()
}

/// Pushes `state.channel_entries` + `state.expanded_networks` to the
/// sidebar as a fresh `network-groups` model — called after anything that
/// changes either (a network's expand toggle, a fresh connect).
fn refresh_network_groups(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let mut data = network_groups_data(
        &state.channel_entries,
        &state.query_windows,
        &state.expanded_networks,
        &state.network_connection_states,
        &state.network_ids,
    );
    apply_connecting_labels(&mut data, &state.connecting_networks);
    let window_states = state.window_states.clone();
    let window_mentions = state.window_mentions.clone();
    let window_messages = state.window_messages.clone();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let groups = network_groups_model(data, window_states, window_mentions, window_messages);
        ui.set_sidebar_widest_label(widest_sidebar_label(&groups).into());
        ui.set_network_groups(Rc::new(slint::VecModel::from(groups)).into());
    });
}

fn return_home_if_network_selected(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
) {
    let selected_network_matches = state
        .current_channel
        .as_ref()
        .is_some_and(|(selected_network, _)| selected_network == network);
    if !selected_network_matches {
        return;
    }

    state.current_channel = None;
    state.current_query = false;
    state.current_query_ready = false;
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_screen("connected".into());
        ui.set_has_selected_channel(false);
        ui.set_current_channel_label("".into());
        ui.set_current_topic("".into());
        ui.set_current_channel_modes("".into());
        ui.set_current_window_is_joined(false);
        ui.set_current_query(false);
        ui.set_current_query_ready(false);
        ui.set_can_moderate_members(false);
        ui.set_compose_text("".into());
        ui.set_chat_lines(Rc::new(slint::VecModel::from(Vec::<ChatLine>::new())).into());
        ui.set_channel_members(Rc::new(slint::VecModel::from(Vec::<MemberRow>::new())).into());
    });
}

fn collapse_if_parked(state: &mut WorkerState, network: &str) -> bool {
    if state
        .network_connection_states
        .get(network)
        .is_some_and(|snapshot| matches!(snapshot.status, NetworkConnectionStatus::Parked))
    {
        return state.expanded_networks.insert(network.to_string(), false) != Some(false);
    }
    false
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
fn chat_line_from_message(
    message: &RenderedMessage,
    dark_theme: bool,
    nick_prefix: &str,
) -> ChatLine {
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
        nick_prefix: nick_prefix.into(),
        nick_color: nick_color_value,
        italic: message.italic,
        segments: Rc::new(slint::VecModel::from(segments)).into(),
    }
}

fn chat_lines_model(messages: &[RenderedMessage], dark_theme: bool) -> Vec<ChatLine> {
    chat_lines_model_with_roster(
        messages,
        dark_theme,
        &[],
        cordiale_core::isupport::CaseMapping::Rfc1459,
    )
}

fn member_prefix_for_nick<'a>(
    members: &'a [MemberEntry],
    nick: &str,
    casemapping: cordiale_core::isupport::CaseMapping,
) -> &'a str {
    members
        .iter()
        .find(|(member_nick, _)| casemapping.nick_eq(member_nick, nick))
        .map(|(_, prefix)| prefix.as_str())
        .unwrap_or("")
}

fn chat_lines_model_with_roster(
    messages: &[RenderedMessage],
    dark_theme: bool,
    members: &[MemberEntry],
    casemapping: cordiale_core::isupport::CaseMapping,
) -> Vec<ChatLine> {
    messages
        .iter()
        .map(|message| {
            let prefix = message
                .nick
                .as_deref()
                .map(|nick| member_prefix_for_nick(members, nick, casemapping))
                .unwrap_or("");
            chat_line_from_message(message, dark_theme, prefix)
        })
        .collect()
}

fn network_casemapping(state: &WorkerState, network: &str) -> cordiale_core::isupport::CaseMapping {
    state
        .isupport_by_network
        .get(network)
        .map(|isupport| isupport.casemapping)
        .unwrap_or(cordiale_core::isupport::CaseMapping::Rfc1459)
}

/// The longest sidebar row label, as displayed, measured by the Slint probe
/// that sets the sidebar's minimum width. Lengths are compared in
/// characters; the probe then measures the real text.
fn widest_sidebar_label(groups: &[NetworkGroup]) -> String {
    use slint::Model as _;

    fn keep_longer(widest: &mut String, candidate: String) {
        if candidate.chars().count() > widest.chars().count() {
            *widest = candidate;
        }
    }

    let mut widest = String::new();
    for group in groups {
        let network_row = if group.parked {
            format!("▸ {} [PARKED]", group.network)
        } else if group.connection_label.is_empty() {
            format!("▾ 🔌 {}", group.network)
        } else {
            format!("▾ 🔌 {} · {}", group.network, group.connection_label)
        };
        keep_longer(&mut widest, network_row);
        for entry in group.channels.iter() {
            let invited = if entry.invited { "🔔 " } else { "" };
            keep_longer(
                &mut widest,
                format!("{invited}{}{}", entry.label, entry.mention_badge),
            );
        }
        for query in group.queries.iter() {
            keep_longer(
                &mut widest,
                format!("↳ {}{}", query.label, query.mention_badge),
            );
        }
    }
    widest
}

/// A run of `n` characters as long as the average member label as shown in
/// the member column (`[@] nick` when the member has a role), rounded up;
/// empty without members. The Slint probe measures it for the column's
/// minimum width.
fn members_average_probe(rows: &[MemberRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let total: usize = rows
        .iter()
        .map(|row| {
            let name = row.name.chars().count();
            if row.prefix.is_empty() {
                name
            } else {
                name + row.prefix.chars().count() + 3
            }
        })
        .sum();
    "n".repeat(total.div_ceil(rows.len()))
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

/// A color theme offered in Settings > Themes. `key` is `server:<id>` for a
/// Grappa theme or `builtin:<name>` for a built-in copy.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ThemeChoice {
    key: String,
    name: String,
    author: String,
    palette: ThemePalette,
    font_family: String,
}

/// The built-in color themes (copies of Grappa's irssi-derived gallery).
fn builtin_theme_choices() -> Vec<ThemeChoice> {
    BUILTIN_THEMES
        .iter()
        .map(|theme| ThemeChoice {
            key: format!("builtin:{}", theme.name),
            name: theme.name.to_string(),
            author: String::new(),
            palette: theme.palette(),
            font_family: "mono-default".to_string(),
        })
        .collect()
}

/// A Grappa theme as a choice, when its palette is complete.
fn server_theme_choice(theme: &cordiale_core::rest::ThemeWire) -> Option<ThemeChoice> {
    Some(ThemeChoice {
        key: format!("server:{}", theme.id),
        name: theme.name.clone(),
        author: theme.author.clone(),
        palette: ThemePalette::from_colors(&theme.payload.colors)?,
        font_family: theme.payload.font_family.clone(),
    })
}

/// Palette of the color theme in use, read by the nick and timestamp color
/// helpers so every chat and member row follows it. `None` is the classic
/// light/dark look.
static ACTIVE_PALETTE: std::sync::RwLock<Option<ThemePalette>> = std::sync::RwLock::new(None);

fn active_palette() -> Option<ThemePalette> {
    ACTIVE_PALETTE
        .read()
        .ok()
        .and_then(|palette| palette.clone())
}

fn set_active_palette(palette: Option<ThemePalette>) {
    if let Ok(mut active) = ACTIVE_PALETTE.write() {
        *active = palette;
    }
}

fn slint_color((r, g, b): (u8, u8, u8)) -> slint::Color {
    slint::Color::from_rgb_u8(r, g, b)
}

/// Mirrors a color theme (or the classic look, for `None`) into the window:
/// background, panel colors, color scheme and monospace font.
fn push_palette(ui: &AppWindow, choice: Option<&ThemeChoice>) {
    match choice {
        Some(choice) => {
            let palette = &choice.palette;
            ui.set_palette_bg(slint_color(palette.bg));
            ui.set_palette_bg_alt(slint_color(palette.bg_alt));
            ui.set_palette_fg(slint_color(palette.fg));
            ui.set_palette_accent(slint_color(palette.accent));
            ui.set_palette_muted(slint_color(palette.muted));
            ui.set_palette_border(slint_color(palette.border));
            ui.set_palette_font(font_family_for(&choice.font_family).into());
            ui.set_palette_active(true);
            let scheme = if palette.is_dark() { "dark" } else { "light" };
            ui.set_theme(scheme.into());
        }
        None => {
            ui.set_palette_active(false);
            let theme = persistence::load_settings().unwrap_or_default().theme;
            ui.set_theme(theme_to_slint(theme));
        }
    }
    ui.invoke_apply_color_scheme();
}

/// Mirrors the available color themes into Settings > Themes, marking
/// `selected` (a choice key) as in use.
fn push_theme_choices(state: &WorkerState, ui: &slint::Weak<AppWindow>, selected: Option<&str>) {
    let rows: Vec<(String, String, String, bool, ThemePalette)> = state
        .theme_choices
        .iter()
        .map(|choice| {
            (
                choice.key.clone(),
                choice.name.clone(),
                choice.author.clone(),
                selected == Some(choice.key.as_str()),
                choice.palette.clone(),
            )
        })
        .collect();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<ThemeChoiceRow> = rows
            .into_iter()
            .map(|(key, name, author, selected, palette)| {
                let swatches: Vec<slint::Color> = [
                    palette.bg,
                    palette.fg,
                    palette.accent,
                    palette.muted,
                    palette.mention,
                    palette.mode_op,
                    palette.mode_voiced,
                ]
                .into_iter()
                .chain(palette.nicks.iter().copied().take(8))
                .map(slint_color)
                .collect();
                ThemeChoiceRow {
                    key: key.into(),
                    name: name.into(),
                    author: author.into(),
                    selected,
                    swatches: Rc::new(slint::VecModel::from(swatches)).into(),
                }
            })
            .collect();
        ui.set_theme_choices(Rc::new(slint::VecModel::from(rows)).into());
    });
}

/// After sign-in: loads Grappa's theme gallery (falling back to the
/// built-in copies) and re-applies the saved color theme choice.
async fn load_color_themes(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    let server_choices: Vec<ThemeChoice> = match client.fetch_themes(&token).await {
        Ok(themes) => themes.iter().filter_map(server_theme_choice).collect(),
        Err(err) => {
            persistence::log_line(&format!("theme gallery unavailable: {err:?}"));
            Vec::new()
        }
    };
    state.theme_choices = if server_choices.is_empty() {
        builtin_theme_choices()
    } else {
        server_choices
    };

    let saved = persistence::load_settings().unwrap_or_default().color_theme;
    let active = match saved.as_deref() {
        Some("server") => match client.fetch_active_theme(&token).await {
            Ok(pair) => pair.light.as_ref().and_then(server_theme_choice),
            Err(err) => {
                persistence::log_line(&format!("active theme unavailable: {err:?}"));
                None
            }
        },
        Some(key) => builtin_theme_choices()
            .into_iter()
            .find(|choice| choice.key == key),
        None => None,
    };
    apply_color_theme(state, ui, active);
}

/// Settings > Themes pick. An empty key returns to the classic look; a
/// `server:<id>` key sets the account's active theme on Grappa.
async fn select_color_theme(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, key: &str) {
    let mut settings = persistence::load_settings().unwrap_or_default();
    let choice = if key.is_empty() {
        settings.color_theme = None;
        None
    } else if let Some(id) = key.strip_prefix("server:") {
        let (Some(client), Some(token), Ok(id)) =
            (state.client.clone(), state.token.clone(), id.parse::<i64>())
        else {
            return;
        };
        match client.set_active_theme(&token, id).await {
            Ok(pair) => {
                settings.color_theme = Some("server".to_string());
                pair.light.as_ref().and_then(server_theme_choice)
            }
            Err(err) => {
                persistence::log_line(&format!("theme change failed: {err:?}"));
                let ui = ui.clone();
                let _ = ui.upgrade_in_event_loop(|ui| {
                    ui.set_status_kind("theme-change-failed".into());
                });
                return;
            }
        }
    } else {
        let choice = state
            .theme_choices
            .iter()
            .chain(builtin_theme_choices().iter())
            .find(|choice| choice.key == key)
            .cloned();
        if choice.is_some() {
            settings.color_theme = Some(key.to_string());
        }
        choice
    };
    let _ = persistence::save_settings(&settings);
    apply_color_theme(state, ui, choice);
}

/// Makes `choice` (or the classic look) the theme in use: palette for the
/// color helpers, dark/light for legibility, window colors, and a redraw of
/// the open chat and member list.
fn apply_color_theme(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    choice: Option<ThemeChoice>,
) {
    set_active_palette(choice.as_ref().map(|choice| choice.palette.clone()));
    state.theme = match &choice {
        Some(choice) if choice.palette.is_dark() => Theme::Dark,
        Some(_) => Theme::Light,
        None => persistence::load_settings().unwrap_or_default().theme,
    };
    push_theme_choices(state, ui, choice.as_ref().map(|choice| choice.key.as_str()));
    let current_lines = state
        .current_channel
        .as_ref()
        .and_then(|key| state.messages.get(key))
        .cloned();
    let current_roster = state
        .current_channel
        .as_ref()
        .filter(|_| !state.current_query)
        .map(|key| {
            (
                state.members.get(key).cloned().unwrap_or_default(),
                network_casemapping(state, &key.0),
            )
        });
    let dark_theme = state.theme == Theme::Dark;
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        push_palette(&ui, choice.as_ref());
        if let Some(lines) = current_lines {
            let model = match &current_roster {
                Some((members, casemapping)) => {
                    chat_lines_model_with_roster(&lines, dark_theme, members, *casemapping)
                }
                None => chat_lines_model(&lines, dark_theme),
            };
            ui.set_chat_lines(Rc::new(slint::VecModel::from(model)).into());
        }
        if let Some((members, _)) = current_roster {
            let rows = members_model(&members, dark_theme);
            ui.set_channel_members(Rc::new(slint::VecModel::from(rows)).into());
        }
    });
}

/// Timestamp-prefix color: readable but visually secondary against either
/// theme's default text color.
fn muted_color(dark_theme: bool) -> slint::Color {
    if let Some(palette) = active_palette() {
        return slint_color(palette.muted);
    }
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
    if let Some(palette) = active_palette() {
        return palette.nick_color(fnv1a_hash(nick.as_bytes()));
    }
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

fn network_connection_states_from_entries(
    networks: &[Value],
) -> HashMap<String, NetworkConnectionSnapshot> {
    networks
        .iter()
        .filter_map(|value| {
            let slug = value.get("slug").and_then(Value::as_str)?;
            if slug.trim().is_empty() {
                return None;
            }
            let status = NetworkConnectionStatus::parse(
                value.get("connection_state").and_then(Value::as_str)?,
            )?;
            let reason = value
                .get("connection_state_reason")
                .and_then(Value::as_str)
                .map(str::to_string);
            let changed_at = value
                .get("connection_state_changed_at")
                .and_then(Value::as_str)
                .map(str::to_string);
            Some((
                slug.to_string(),
                NetworkConnectionSnapshot {
                    status,
                    reason,
                    changed_at,
                },
            ))
        })
        .collect()
}

fn record_network_connection_state(
    states: &mut HashMap<String, NetworkConnectionSnapshot>,
    slug: &str,
    snapshot: NetworkConnectionSnapshot,
) -> (bool, bool) {
    let previous = states.insert(slug.to_string(), snapshot.clone());
    let changed = previous
        .as_ref()
        .is_none_or(|previous| previous.status != snapshot.status);
    let return_home = previous.is_some_and(|previous| {
        previous.status != snapshot.status
            && matches!(
                snapshot.status,
                NetworkConnectionStatus::Parked | NetworkConnectionStatus::Failed
            )
    });
    (changed, return_home)
}

fn parse_nullable_wire_string(value: &Value) -> Option<Option<String>> {
    match value {
        Value::Null => Some(None),
        Value::String(value) => Some(Some(value.clone())),
        _ => None,
    }
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

fn parse_connection_state_changed_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<NetworkConnectionTransition> {
    if identifier.is_empty()
        || carrier_topic != format!("grappa:user:{identifier}")
        || payload.get("kind").and_then(Value::as_str) != Some("connection_state_changed")
    {
        return None;
    }

    match payload.get("user_id")? {
        Value::Null | Value::String(_) => {}
        _ => return None,
    }

    let network_id = payload.get("network_id").and_then(Value::as_i64)?;
    if network_id <= 0 {
        return None;
    }
    let network_slug = payload.get("network_slug").and_then(Value::as_str)?;
    if network_slug.trim().is_empty() {
        return None;
    }
    let from = NetworkConnectionStatus::parse(payload.get("from").and_then(Value::as_str)?)?;
    let status = NetworkConnectionStatus::parse(payload.get("to").and_then(Value::as_str)?)?;
    let reason = parse_nullable_wire_string(payload.get("reason")?)?;
    let changed_at = parse_nullable_wire_string(payload.get("at")?)?;

    let network = payload.get("network")?.as_object()?;
    if network.get("slug").and_then(Value::as_str) != Some(network_slug)
        || network
            .get("connection_state")
            .and_then(Value::as_str)
            .and_then(NetworkConnectionStatus::parse)
            != Some(status)
    {
        return None;
    }
    if let Some(row_id) = network.get("id") {
        if row_id.as_i64()? != network_id {
            return None;
        }
    }
    if let Some(row_reason) = network.get("connection_state_reason") {
        if parse_nullable_wire_string(row_reason)? != reason {
            return None;
        }
    }
    if let Some(row_changed_at) = network.get("connection_state_changed_at") {
        if parse_nullable_wire_string(row_changed_at)? != changed_at {
            return None;
        }
    }

    Some(NetworkConnectionTransition {
        network_id,
        network_slug: network_slug.to_string(),
        from,
        snapshot: NetworkConnectionSnapshot {
            status,
            reason,
            changed_at,
        },
    })
}

#[cfg(test)]
fn parse_network_detached_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(i64, String)> {
    parse_network_lifecycle_event(payload, carrier_topic, identifier, "network_detached")
}

#[cfg(test)]
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
    let next_network_ids = network_ids_from_entries(&boot.networks);
    let mut entries = channel_entries_from_channels(&boot.channels);
    entries.retain(|(network, _, _)| next_network_ids.contains_key(network));
    let channel_actions = reconcile_channel_entries(state, identifier, entries);

    // The account's /boot network list is authoritative. A removed network
    // must not be recreated by an old query row or a late channel snapshot.
    state
        .query_windows
        .retain(|query| next_network_ids.contains_key(&query.network));
    state
        .expanded_networks
        .retain(|network, _| next_network_ids.contains_key(network));
    state
        .query_joined
        .retain(|(network, _)| next_network_ids.contains_key(network));
    state
        .query_ready
        .retain(|(network, _)| next_network_ids.contains_key(network));
    state
        .query_full_history_required
        .retain(|(network, _)| next_network_ids.contains_key(network));
    state
        .stale_query_topics
        .retain(|(network, _)| next_network_ids.contains_key(network));
    state
        .recent_channels
        .retain(|(network, _)| next_network_ids.contains_key(network));

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
    state.network_ids = next_network_ids;
    state.network_connection_states = network_connection_states_from_entries(&boot.networks);

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
    state
        .connecting_networks
        .retain(|network| known_networks.contains(network.as_str()));

    let mut actions = channel_actions;
    for action in listener_actions {
        actions.push(match action {
            OwnNickListenerAction::Leave(topic) => ChannelTopicAction::Leave(topic),
            OwnNickListenerAction::Join(topic) => ChannelTopicAction::Join(topic),
        });
    }
    let mut obsolete_topics: Vec<String> = state
        .joined_topics
        .iter()
        .filter(|topic| {
            query_from_topic(identifier, topic)
                .is_some_and(|(network, _)| !state.network_ids.contains_key(&network))
        })
        .cloned()
        .collect();
    obsolete_topics.sort();
    for topic in obsolete_topics {
        state.joined_topics.remove(&topic);
        if !actions.iter().any(
            |action| matches!(action, ChannelTopicAction::Leave(existing) if existing == &topic),
        ) {
            actions.push(ChannelTopicAction::Leave(topic));
        }
    }
    actions
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkLifecycleKind {
    Attached,
    Detached,
}

async fn handle_connection_state_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.clone() else {
        return;
    };
    let Some(transition) =
        parse_connection_state_changed_event(payload, carrier_topic, &identifier)
    else {
        return;
    };
    if state.network_ids.get(&transition.network_slug) != Some(&transition.network_id) {
        persistence::log_line("connection_state_changed rejected: unknown or stale network");
        return;
    }

    let network_slug = transition.network_slug.clone();
    let (snapshot_changed, return_home) = record_network_connection_state(
        &mut state.network_connection_states,
        &network_slug,
        transition.snapshot.clone(),
    );
    let collapsed = snapshot_changed && collapse_if_parked(state, &network_slug);
    if return_home {
        return_home_if_network_selected(state, ui, &network_slug);
    }
    if snapshot_changed || collapsed {
        refresh_network_groups(state, ui);
    }
    persistence::log_line(&format!(
        "connection_state_changed: {network_slug} {} -> {}",
        transition.from.wire_name(),
        transition.snapshot.status.wire_name()
    ));

    reconcile_network_connection_states(state, ui, "connection_state_changed").await;
}

/// Refreshes `GET /networks` and applies each known network's durable
/// connection state. A failed request keeps the current state: callers have
/// already applied whatever their event carried.
async fn reconcile_network_connection_states(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    context: &str,
) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    let networks = match client.fetch_networks(&token).await {
        Ok(networks) => networks,
        Err(error) => {
            persistence::log_line(&format!(
                "{context} network refresh failed; keeping current state: {error:?}"
            ));
            return;
        }
    };

    let refreshed_ids = network_ids_from_entries(&networks);
    let refreshed_states = network_connection_states_from_entries(&networks);
    let mut state_changed = false;
    for (slug, snapshot) in refreshed_states {
        let Some(expected_id) = state.network_ids.get(&slug) else {
            continue;
        };
        if refreshed_ids
            .get(&slug)
            .is_some_and(|refreshed_id| refreshed_id != expected_id)
        {
            continue;
        }
        let (row_changed, return_home) =
            record_network_connection_state(&mut state.network_connection_states, &slug, snapshot);
        if row_changed {
            state_changed |= collapse_if_parked(state, &slug);
        }
        if return_home {
            return_home_if_network_selected(state, ui, &slug);
        }
        state_changed |= row_changed;
    }
    if state_changed {
        refresh_network_groups(state, ui);
    }
}

/// Validates `connection_progress`: `{kind, network, state}` on the exact
/// authenticated user topic, for a network already in the `/boot` map. The
/// state is a closed `connecting | connected` enum; extra fields are ignored.
fn parse_connection_progress(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
    known_networks: &HashMap<String, i64>,
) -> Option<(String, ConnectionProgressState)> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "connection_progress" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() || !known_networks.contains_key(network) {
        return None;
    }
    let progress = ConnectionProgressState::parse(payload.get("state")?.as_str()?)?;
    Some((network.to_string(), progress))
}

/// Applies one progress edge to the per-network connecting set, returning
/// whether the visible badge changed. Duplicates are no-ops.
fn apply_connection_progress(
    connecting: &mut std::collections::HashSet<String>,
    network: &str,
    progress: ConnectionProgressState,
) -> bool {
    match progress {
        ConnectionProgressState::Connecting => connecting.insert(network.to_string()),
        ConnectionProgressState::Connected => connecting.remove(network),
    }
}

/// `connecting` shows a transient per-network badge; `connected` (001
/// RPL_WELCOME) clears it and refetches `GET /networks`, since the durable
/// connection row only arrives through that endpoint, matching Cicchetto.
async fn handle_connection_progress(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.clone() else {
        return;
    };
    let Some((network, progress)) =
        parse_connection_progress(payload, carrier_topic, &identifier, &state.network_ids)
    else {
        persistence::log_line("connection_progress rejected: invalid payload or unknown network");
        return;
    };
    // A `/lusers` only belongs to the connection it was issued on: the
    // registration burst of a new attempt is unsolicited.
    if progress == ConnectionProgressState::Connecting {
        state.lusers_requested.remove(&network);
    }
    if apply_connection_progress(&mut state.connecting_networks, &network, progress) {
        refresh_network_groups(state, ui);
    }
    if progress == ConnectionProgressState::Connected {
        reconcile_network_connection_states(state, ui, "connection_progress").await;
    }
}

/// Validates `recover_progress` on the exact user topic: `network` a
/// non-empty slug, `step`/`status` closed enums, and `reason` present as
/// `null` or any string (an additive server reason must not drop the step).
fn parse_recover_progress(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, RecoverStepEntry)> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "recover_progress" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let step = RecoverStep::parse(payload.get("step")?.as_str()?)?;
    let status = RecoverStepStatus::parse(payload.get("status")?.as_str()?)?;
    let reason = match payload.get("reason")? {
        Value::Null => None,
        Value::String(reason) => Some(reason.clone()),
        _ => return None,
    };
    Some((
        network.to_string(),
        RecoverStepEntry {
            step,
            status,
            reason,
        },
    ))
}

/// Cicchetto's `applyRecoverProgress`: the first event opens the panel for
/// its network, an event for any other network is ignored while one is
/// open, and a known step is replaced in place so the order stays stable.
fn apply_recover_progress(
    panel: &mut Option<RecoverPanel>,
    network: &str,
    entry: RecoverStepEntry,
) -> bool {
    if panel.is_none() {
        *panel = Some(RecoverPanel {
            network: network.to_string(),
            steps: vec![entry],
            outcome: None,
            outcome_reason: None,
        });
        return true;
    }
    let Some(open) = panel.as_mut() else {
        return false;
    };
    if open.network != network {
        return false;
    }
    match open.steps.iter().position(|row| row.step == entry.step) {
        Some(index) if open.steps[index] == entry => false,
        Some(index) => {
            open.steps[index] = entry;
            true
        }
        None => {
            open.steps.push(entry);
            true
        }
    }
}

fn handle_recover_progress(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network, entry)) = parse_recover_progress(payload, carrier_topic, identifier) else {
        persistence::log_line("recover_progress rejected: invalid carrier or payload");
        return;
    };
    if apply_recover_progress(&mut state.recover_panel, &network, entry) {
        push_recover_panel(state, ui);
    }
}

/// Validates `recover_result` on the exact user topic: non-empty `network`,
/// closed `outcome`, and `reason` present as `null` or any string, so an
/// additive failure token never drops this terminal event.
fn parse_recover_result(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, RecoverOutcome, Option<String>)> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "recover_result" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let outcome = RecoverOutcome::parse(payload.get("outcome")?.as_str()?)?;
    let reason = match payload.get("reason")? {
        Value::Null => None,
        Value::String(reason) => Some(reason.clone()),
        _ => return None,
    };
    Some((network.to_string(), outcome, reason))
}

/// Cicchetto's `applyRecoverResult`: a no-op when no panel is open (dismissed
/// mid-flight, or the progress events were lost) or when it belongs to
/// another network; otherwise it records the conclusion.
fn apply_recover_result(
    panel: &mut Option<RecoverPanel>,
    network: &str,
    outcome: RecoverOutcome,
    reason: Option<String>,
) -> bool {
    let Some(open) = panel.as_mut() else {
        return false;
    };
    if open.network != network {
        return false;
    }
    if open.outcome == Some(outcome) && open.outcome_reason == reason {
        return false;
    }
    open.outcome = Some(outcome);
    open.outcome_reason = reason;
    true
}

fn handle_recover_result(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network, outcome, reason)) = parse_recover_result(payload, carrier_topic, identifier)
    else {
        persistence::log_line("recover_result rejected: invalid carrier or payload");
        return;
    };
    if apply_recover_result(&mut state.recover_panel, &network, outcome, reason) {
        push_recover_panel(state, ui);
    }
}

/// Validates `web_session_severed` on the exact user topic. `code` must be a
/// string but any value is accepted: the action (sign out) does not depend on
/// it, and an unknown future code must never leave the client holding a
/// revoked bearer.
fn parse_web_session_severed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<String> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "web_session_severed" {
        return None;
    }
    Some(payload.get("code")?.as_str()?.to_string())
}

/// Grappa sends this best-effort, then revokes the bearer and closes the
/// socket; the IRC session stays up. Like Cicchetto, sign out for every code
/// and show the dedicated notice only for `rate_limit_flood`.
fn handle_web_session_severed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(code) = parse_web_session_severed(payload, carrier_topic, identifier) else {
        persistence::log_line("web_session_severed rejected: invalid carrier or payload");
        return;
    };
    persistence::log_line(&format!("web session severed by server: code={code}"));
    end_revoked_session(state, ui, code == "rate_limit_flood");
}

/// Ends a session whose bearer the server revoked: stops the Phoenix
/// session so it never retries with that bearer, forgets a remembered copy
/// of it, and returns to the sign-in screen through the normal disconnect
/// path. No IRC QUIT is sent — the bouncer's IRC session is unaffected.
fn end_revoked_session(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, flood: bool) {
    if let Some(handle) = state.session.take() {
        handle.shutdown();
    }
    if let (Some(client), Some(identifier)) = (state.client.as_ref(), state.identifier.as_deref()) {
        forget_remembered_bearer(client.base_url(), identifier);
    }
    state.token = None;
    let status = if flood {
        "session-severed-flood"
    } else {
        "reauthentication-required"
    };
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.invoke_disconnect_requested();
        ui.set_saved_profile_identifier("".into());
        ui.set_saved_profile_server_url("".into());
        ui.set_status_kind(status.into());
        ui.set_status_message("".into());
    });
}

/// Validates `auto_away_debounce_changed` on the exact user topic. The key
/// is always present: `null` is meaningful (server default), not missing;
/// a negative or non-integer value is rejected.
fn parse_auto_away_debounce_changed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<AutoAwayDebounce> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "auto_away_debounce_changed" {
        return None;
    }
    match payload.get("auto_away_debounce_seconds")? {
        Value::Null => Some(AutoAwayDebounce::ServerDefault),
        value => match value.as_u64()? {
            0 => Some(AutoAwayDebounce::Disabled),
            seconds => Some(AutoAwayDebounce::Seconds(seconds)),
        },
    }
}

/// Mirrors the server's stored auto-away delay into Settings. Cordiale never
/// originates this value; it only reflects what Grappa announced.
fn handle_auto_away_debounce_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(debounce) = parse_auto_away_debounce_changed(payload, carrier_topic, identifier)
    else {
        persistence::log_line("auto_away_debounce_changed rejected: invalid carrier or payload");
        return;
    };
    if state.auto_away_debounce == Some(debounce) {
        return;
    }
    state.auto_away_debounce = Some(debounce);
    let token = debounce.display_token();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_server_pref_auto_away_debounce(token.into());
    });
}

/// Validates a user-settings echo whose single value is a string or `null`
/// on the exact user topic. The key is always present: `null` is meaningful
/// (the server falls back to its own text), not missing.
fn parse_nullable_setting_echo(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
    kind: &str,
    key: &str,
) -> Option<Option<String>> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != kind {
        return None;
    }
    parse_nullable_wire_string(payload.get(key)?)
}

/// Mirrors the server's remembered QUIT/PART text into Settings as a
/// read-only display copy; Grappa stays the owner of the value.
fn handle_quit_part_reason_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(reason) = parse_nullable_setting_echo(
        payload,
        carrier_topic,
        identifier,
        "quit_part_reason_changed",
        "quit_part_reason",
    ) else {
        persistence::log_line("quit_part_reason_changed rejected: invalid carrier or payload");
        return;
    };
    if state.quit_part_reason.as_ref() == Some(&reason) {
        return;
    }
    state.quit_part_reason = Some(reason.clone());
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_server_pref_leave_message_set(reason.is_some());
        ui.set_server_pref_leave_message(reason.unwrap_or_default().into());
        ui.set_server_pref_leave_message_known(true);
    });
}

/// Mirrors the server's auto-away text into Settings as a read-only display
/// copy; `null` means Grappa keeps its own built-in text, never substituted.
fn handle_auto_away_reason_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(reason) = parse_nullable_setting_echo(
        payload,
        carrier_topic,
        identifier,
        "auto_away_reason_changed",
        "auto_away_reason",
    ) else {
        persistence::log_line("auto_away_reason_changed rejected: invalid carrier or payload");
        return;
    };
    if state.auto_away_reason.as_ref() == Some(&reason) {
        return;
    }
    state.auto_away_reason = Some(reason.clone());
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_server_pref_auto_away_reason_set(reason.is_some());
        ui.set_server_pref_auto_away_reason(reason.unwrap_or_default().into());
        ui.set_server_pref_auto_away_reason_known(true);
    });
}

/// Mirrors `state.recover_panel` into the sidebar panel. The Slint row model
/// is built inside the UI-thread closure because `ModelRc` is not `Send`.
fn push_recover_panel(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (visible, network, rows, outcome, outcome_reason) = match &state.recover_panel {
        Some(panel) => (
            true,
            panel.network.clone(),
            panel
                .steps
                .iter()
                .map(|row| {
                    (
                        row.step.wire_name(),
                        row.status.wire_name(),
                        row.reason.clone().unwrap_or_default(),
                    )
                })
                .collect::<Vec<_>>(),
            panel.outcome.map(RecoverOutcome::wire_name).unwrap_or(""),
            panel.outcome_reason.clone().unwrap_or_default(),
        ),
        None => (false, String::new(), Vec::new(), "", String::new()),
    };
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<RecoverStepRow> = rows
            .into_iter()
            .map(|(step, status, reason)| RecoverStepRow {
                step: step.into(),
                status: status.into(),
                reason: reason.into(),
            })
            .collect();
        ui.set_recover_steps(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_recover_network(network.into());
        ui.set_recover_outcome(outcome.into());
        ui.set_recover_outcome_reason(outcome_reason.into());
        ui.set_recover_visible(visible);
    });
}

/// Requester replies all arrive on the exact authenticated user topic and
/// only on the socket that asked; anything else is rejected before parsing.
fn is_own_user_topic(carrier_topic: &str, identifier: &str) -> bool {
    carrier_topic == format!("grappa:user:{identifier}")
}

/// Validates `who_reply` as strictly as Cicchetto: every user row must carry
/// all string fields, `hops` an integer or `null` and `realname` a string or
/// `null`; one malformed row drops the whole bundle.
fn parse_who_reply(payload: &Value, carrier_topic: &str, identifier: &str) -> Option<WhoReply> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "who_reply" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let target = payload.get("target")?.as_str()?.to_string();
    let mut users = Vec::new();
    for row in payload.get("users")?.as_array()? {
        let text = |key: &str| row.get(key).and_then(Value::as_str).map(str::to_string);
        let hops = match row.get("hops")? {
            Value::Null => None,
            value => Some(value.as_i64()?),
        };
        users.push(WhoUser {
            nick: text("nick")?,
            user: text("user")?,
            host: text("host")?,
            server: text("server")?,
            modes: text("modes")?,
            channel: text("channel")?,
            hops,
            realname: parse_nullable_wire_string(row.get("realname")?)?,
        });
    }
    Some(WhoReply {
        network: network.to_string(),
        target,
        users,
    })
}

/// One plain line per user, in wire order, mirroring the 352 reply layout.
fn who_reply_view(reply: &WhoReply) -> ReplyView {
    let rows = if reply.users.is_empty() {
        vec![("who-empty".to_string(), String::new())]
    } else {
        reply
            .users
            .iter()
            .map(|user| {
                let hops = user
                    .hops
                    .map(|hops| format!(" ({hops})"))
                    .unwrap_or_default();
                let realname = user
                    .realname
                    .as_deref()
                    .map(|realname| format!(" — {realname}"))
                    .unwrap_or_default();
                (
                    String::new(),
                    format!(
                        "{} ({}@{}) {} · {} · {}{hops}{realname}",
                        user.nick, user.user, user.host, user.modes, user.channel, user.server
                    ),
                )
            })
            .collect()
    };
    ReplyView {
        kind: "who_reply",
        subject: reply.target.clone(),
        network: reply.network.clone(),
        rows,
    }
}

/// Stores a requester reply and opens the reply screen. It replaces any
/// earlier reply (last-write-wins, like Cicchetto's per-network modals) and
/// never touches chat history or the selected window.
fn show_reply_view(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, view: ReplyView) {
    push_reply_view(ui, &view, true);
    state.reply_view = Some(view);
}

/// Mirrors a reply view into the UI; `open` also switches to the reply
/// screen. An in-place refresh passes `false` so it never steals the screen.
fn push_reply_view(ui: &slint::Weak<AppWindow>, view: &ReplyView, open: bool) {
    let kind = view.kind;
    let subject = view.subject.clone();
    let network = view.network.clone();
    let rows = view.rows.clone();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<ReplyRow> = rows
            .into_iter()
            .map(|(label, value)| ReplyRow {
                label: label.into(),
                value: value.into(),
            })
            .collect();
        ui.set_reply_rows(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_reply_kind(kind.into());
        ui.set_reply_subject(subject.into());
        ui.set_reply_network(network.into());
        if open {
            ui.set_screen("reply".into());
        }
    });
}

/// Validates `dcc_offer` on the exact user topic: every field is required,
/// `network` and `offer_id` non-empty, `size` a non-negative integer (the
/// peer's claim). The filename was already made safe to display upstream.
fn parse_dcc_offer(payload: &Value, carrier_topic: &str, identifier: &str) -> Option<DccOffer> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "dcc_offer" {
        return None;
    }
    let text = |key: &str| payload.get(key)?.as_str().map(str::to_string);
    let offer = DccOffer {
        network: text("network")?,
        channel: text("channel")?,
        offer_id: text("offer_id")?,
        from: text("from")?,
        filename: text("filename")?,
        size: payload.get("size")?.as_u64()?,
    };
    if offer.network.trim().is_empty() || offer.offer_id.is_empty() {
        return None;
    }
    Some(offer)
}

/// Holds an offer, replacing one with the same `offer_id` in place (the
/// subscribe backfill re-sends every held offer). Returns whether it changed.
fn apply_dcc_offer(offers: &mut Vec<DccOffer>, offer: DccOffer) -> bool {
    match offers
        .iter()
        .position(|held| held.offer_id == offer.offer_id)
    {
        Some(index) if offers[index] == offer => false,
        Some(index) => {
            offers[index] = offer;
            true
        }
        None => {
            offers.push(offer);
            true
        }
    }
}

fn handle_dcc_offer(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(offer) = parse_dcc_offer(payload, carrier_topic, identifier) else {
        persistence::log_line("dcc_offer rejected: invalid carrier or payload");
        return;
    };
    if apply_dcc_offer(&mut state.dcc_offers, offer) {
        push_dcc_offers(state, ui);
    }
}

/// How a held DCC offer left the server's held set (closed on the wire).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DccResolution {
    Accepted,
    Refused,
    Expired,
}

impl DccResolution {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "accepted" => Some(Self::Accepted),
            "refused" => Some(Self::Refused),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }

    fn status_kind(self) -> &'static str {
        match self {
            Self::Accepted => "dcc-accepted",
            Self::Refused => "dcc-refused",
            Self::Expired => "dcc-expired",
        }
    }
}

/// Validates `dcc_offer_resolved` on the exact user topic. `resolution` is
/// the closed `accepted | refused | expired` set: a value a newer server
/// invents drops the event, leaving a stale prompt rather than a wrong one.
fn parse_dcc_offer_resolved(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, DccResolution)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "dcc_offer_resolved" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    payload.get("channel")?.as_str()?;
    let offer_id = payload.get("offer_id")?.as_str()?;
    if network.trim().is_empty() || offer_id.is_empty() {
        return None;
    }
    let resolution = DccResolution::parse(payload.get("resolution")?.as_str()?)?;
    Some((offer_id.to_string(), resolution))
}

/// Drops a held offer by id, returning it; an unknown id (held before this
/// socket, resolved elsewhere) is a silent no-op.
fn apply_dcc_offer_resolved(offers: &mut Vec<DccOffer>, offer_id: &str) -> Option<DccOffer> {
    let index = offers.iter().position(|held| held.offer_id == offer_id)?;
    Some(offers.remove(index))
}

/// Removes the resolved offer on every device and says what happened;
/// whether this device, another one or the hold timeout resolved it, the
/// reaction is the same.
fn handle_dcc_offer_resolved(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((offer_id, resolution)) = parse_dcc_offer_resolved(payload, carrier_topic, identifier)
    else {
        persistence::log_line("dcc_offer_resolved rejected: invalid carrier or payload");
        return;
    };
    let Some(offer) = apply_dcc_offer_resolved(&mut state.dcc_offers, &offer_id) else {
        return;
    };
    push_dcc_offers(state, ui);
    let status = resolution.status_kind();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_dcc_filename(offer.filename.into());
        ui.set_status_dcc_from(offer.from.into());
        ui.set_status_kind(status.into());
    });
}

/// Mirrors the held offers into the sidebar consent panel.
fn push_dcc_offers(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let offers: Vec<(String, String, String, String, String)> = state
        .dcc_offers
        .iter()
        .map(|offer| {
            (
                offer.network.clone(),
                offer.offer_id.clone(),
                offer.from.clone(),
                offer.filename.clone(),
                format_file_size(offer.size),
            )
        })
        .collect();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<DccOfferRow> = offers
            .into_iter()
            .map(|(network, offer_id, from, filename, size)| DccOfferRow {
                network: network.into(),
                offer_id: offer_id.into(),
                from: from.into(),
                filename: filename.into(),
                size: size.into(),
            })
            .collect();
        ui.set_dcc_offers(Rc::new(slint::VecModel::from(rows)).into());
    });
}

/// Binary-prefixed size with one decimal above a KiB (`512 B`, `1.5 MiB`).
fn format_file_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Accepts or refuses a held offer over REST. The panel is not changed
/// here: the offer disappears only when `dcc_offer_resolved` arrives, so
/// every device agrees on what the server actually did.
async fn answer_dcc_offer(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    offer_id: &str,
    accept: bool,
) {
    let (Some(client), Some(token)) = (state.client.as_ref(), state.token.as_deref()) else {
        return;
    };
    let result = if accept {
        client.accept_dcc_offer(token, network, offer_id).await
    } else {
        client.refuse_dcc_offer(token, network, offer_id).await
    };
    let Err(err) = result else {
        return;
    };
    persistence::log_line(&format!("dcc offer answer failed: {err:?}"));
    let status = dcc_answer_error_status(err.status().map(|status| status.as_u16()));
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_kind(status.into());
    });
}

/// Status-bar key for a failed accept/refuse, by the documented statuses.
fn dcc_answer_error_status(status: Option<u16>) -> &'static str {
    match status {
        Some(404) => "dcc-offer-gone",
        Some(429) => "dcc-rate-limited",
        Some(503) => "dcc-not-connected",
        Some(507) => "dcc-no-space",
        _ => "dcc-action-failed",
    }
}

/// Opens the archive screen for `network` and loads its list.
async fn open_archive(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, network: String) {
    state.archive = Some(ArchiveView {
        network,
        entries: None,
        error: None,
    });
    push_archive(state, ui, true);
    load_archive(state, ui).await;
}

/// Refetches the open archive's list. The listing is metered upstream, so
/// it runs only when the screen opens or a push says the list changed.
async fn load_archive(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token), Some(view)) = (
        state.client.clone(),
        state.token.clone(),
        state.archive.as_ref(),
    ) else {
        return;
    };
    let network = view.network.clone();
    let result = client.fetch_archive(&token, &network).await;
    let Some(view) = state.archive.as_mut() else {
        return;
    };
    if view.network != network {
        return;
    }
    match result {
        Ok(entries) => {
            view.entries = Some(entries);
            view.error = None;
        }
        Err(err) => {
            persistence::log_line(&format!("archive fetch failed: {err:?}"));
            view.error = Some(archive_error_key(
                err.status().map(|status| status.as_u16()),
                "archive-fetch-failed",
            ));
        }
    }
    push_archive(state, ui, false);
}

/// Deletes one archived target's scrollback. The list is not edited here:
/// the server's `archive_purged` push drives the refresh on every device.
async fn delete_archive_target(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, target: &str) {
    let (Some(client), Some(token), Some(view)) = (
        state.client.clone(),
        state.token.clone(),
        state.archive.as_ref(),
    ) else {
        return;
    };
    let network = view.network.clone();
    let Err(err) = client.delete_archive_target(&token, &network, target).await else {
        return;
    };
    persistence::log_line(&format!("archive delete failed: {err:?}"));
    if let Some(view) = state.archive.as_mut() {
        if view.network == network {
            view.error = Some(archive_error_key(
                err.status().map(|status| status.as_u16()),
                "archive-delete-failed",
            ));
        }
    }
    push_archive(state, ui, false);
}

/// `429` has its own message (the listing is rate limited upstream).
fn archive_error_key(status: Option<u16>, fallback: &'static str) -> &'static str {
    if status == Some(429) {
        "archive-rate-limited"
    } else {
        fallback
    }
}

/// Mirrors the open archive into the UI; `open` also switches to its screen
/// and clears any pending delete confirmation.
fn push_archive(state: &WorkerState, ui: &slint::Weak<AppWindow>, open: bool) {
    let Some(view) = state.archive.as_ref() else {
        return;
    };
    let network = view.network.clone();
    let loaded = view.entries.is_some();
    let error = view.error.unwrap_or("");
    let rows: Vec<(String, String, String)> = view
        .entries
        .iter()
        .flatten()
        .map(|entry| {
            (
                entry.target.clone(),
                entry.kind.clone(),
                format_epoch_millis(entry.last_activity),
            )
        })
        .collect();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<ArchiveRow> = rows
            .into_iter()
            .map(|(target, kind, last_activity)| ArchiveRow {
                target: target.into(),
                kind: kind.into(),
                last_activity: last_activity.into(),
            })
            .collect();
        ui.set_archive_rows(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_archive_network(network.into());
        ui.set_archive_loaded(loaded);
        ui.set_archive_error(error.into());
        if open {
            ui.set_archive_confirm_target("".into());
            ui.set_screen("archive".into());
        }
    });
}

/// Local date and time of an epoch-millisecond timestamp; out-of-range
/// values are shown raw.
fn format_epoch_millis(millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(millis)
        .map(|parsed| {
            parsed
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| millis.to_string())
}

/// Validates `archive_changed` on the exact user topic: only a non-empty
/// `network_slug` (this kind names the network by slug, not `network`).
fn parse_archive_changed(payload: &Value, carrier_topic: &str, identifier: &str) -> Option<String> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "archive_changed" {
        return None;
    }
    let network = payload.get("network_slug")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    Some(network.to_string())
}

/// A window moved into the archive (for example a PART): refetch the list
/// if that network's archive is open, like Cicchetto's `loadArchive`.
async fn handle_archive_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(network) = parse_archive_changed(payload, carrier_topic, identifier) else {
        persistence::log_line("archive_changed rejected: invalid carrier or payload");
        return;
    };
    if state
        .archive
        .as_ref()
        .is_some_and(|view| view.network == network)
    {
        load_archive(state, ui).await;
    }
}

/// Validates `archive_purged` on the exact user topic: a non-empty
/// `network_slug` and `target` (channel- or query-shaped).
fn parse_archive_purged(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "archive_purged" {
        return None;
    }
    let network = payload.get("network_slug")?.as_str()?;
    let target = payload.get("target")?.as_str()?;
    if network.trim().is_empty() || target.trim().is_empty() {
        return None;
    }
    Some((network.to_string(), target.to_string()))
}

/// Whether a `(network, window)` cache key names the purged target. The
/// server deletes case-insensitively, so the window is compared with the
/// network's casemapping.
fn is_purged_window(
    key: &(String, String),
    network: &str,
    target: &str,
    casemapping: cordiale_core::isupport::CaseMapping,
) -> bool {
    key.0 == network && casemapping.nick_eq(&key.1, target)
}

/// The bouncer deleted a target's scrollback: forget the rows and unread
/// seeds cached for it, so a later re-join can't show deleted history, then
/// refresh the archive if it is open. Read cursors stay, like Cicchetto's.
async fn handle_archive_purged(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network, target)) = parse_archive_purged(payload, carrier_topic, identifier) else {
        persistence::log_line("archive_purged rejected: invalid carrier or payload");
        return;
    };
    let casemapping = state
        .isupport_by_network
        .get(&network)
        .map(|isupport| isupport.casemapping)
        .unwrap_or(cordiale_core::isupport::CaseMapping::Rfc1459);
    let purged = |key: &(String, String)| is_purged_window(key, &network, &target, casemapping);
    state.messages.retain(|key, _| !purged(key));
    state.window_messages.retain(|key, _| !purged(key));
    state.window_mentions.retain(|key, _| !purged(key));
    if state
        .archive
        .as_ref()
        .is_some_and(|view| view.network == network)
    {
        load_archive(state, ui).await;
    }
}

/// Validates `notify_list` on the exact user topic: `networks` maps each
/// network ID (a decimal JSON key) to its entries, each needing an integer
/// `network_id` and string `nick` and `added_at`. One bad key or entry drops
/// the whole snapshot, like Cicchetto's schema. Returns nicks per network.
fn parse_notify_list(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<HashMap<i64, Vec<String>>> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "notify_list" {
        return None;
    }
    let mut lists = HashMap::new();
    for (key, entries) in payload.get("networks")?.as_object()? {
        let network_id: i64 = key.parse().ok()?;
        let mut nicks = Vec::new();
        for entry in entries.as_array()? {
            entry.get("network_id")?.as_i64()?;
            entry.get("added_at")?.as_str()?;
            nicks.push(entry.get("nick")?.as_str()?.to_string());
        }
        lists.insert(network_id, nicks);
    }
    Some(lists)
}

/// Replaces every network's watchlist with the snapshot (an empty map
/// clears them all) and refreshes the Settings list.
fn handle_notify_list(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(lists) = parse_notify_list(payload, carrier_topic, identifier) else {
        persistence::log_line("notify_list rejected: invalid carrier or payload");
        return;
    };
    state.notify_lists = lists;
    push_notify_nicks(state, ui);
}

/// Validates `presence_snapshot` on the exact user topic: an integer
/// `network_id` and a `nicks` map of folded nick to `online | offline |
/// unknown`. One unknown value drops the whole map, like Cicchetto.
fn parse_presence_snapshot(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(i64, HashMap<String, Presence>)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "presence_snapshot" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    let nicks = payload
        .get("nicks")?
        .as_object()?
        .iter()
        .map(|(nick, presence)| Some((presence_key(nick), Presence::parse(presence.as_str()?)?)))
        .collect::<Option<HashMap<_, _>>>()?;
    Some((network_id, nicks))
}

/// Replaces one network's presence map (sent after join for live sessions)
/// and repaints the watchlist.
fn handle_presence_snapshot(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network_id, nicks)) = parse_presence_snapshot(payload, carrier_topic, identifier)
    else {
        persistence::log_line("presence_snapshot rejected: invalid carrier or payload");
        return;
    };
    state.presence_by_network.insert(network_id, nicks);
    push_notify_nicks(state, ui);
}

/// One validated `presence_changed` transition.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PresenceChange {
    network_id: i64,
    nick: String,
    presence: Presence,
    /// Part of the first report after a (re)registration: update the dot,
    /// but don't announce it.
    initial: bool,
}

/// Validates `presence_changed` on the exact user topic. `presence` is
/// `online | offline` and `source` the closed `monitor | watch | ison` set
/// (checked, not shown); `ts` must be a string.
fn parse_presence_changed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<PresenceChange> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "presence_changed" {
        return None;
    }
    let presence = match payload.get("presence")?.as_str()? {
        "online" => Presence::Online,
        "offline" => Presence::Offline,
        _ => return None,
    };
    if !matches!(
        payload.get("source")?.as_str()?,
        "monitor" | "watch" | "ison"
    ) {
        return None;
    }
    payload.get("ts")?.as_str()?;
    let nick = payload.get("nick")?.as_str()?;
    if nick.is_empty() {
        return None;
    }
    Some(PresenceChange {
        network_id: payload.get("network_id")?.as_i64()?,
        nick: nick.to_string(),
        presence,
        initial: payload.get("initial")?.as_bool()?,
    })
}

/// Updates one watched nick's presence and, unless it is part of the
/// initial report, says so in the status bar.
fn handle_presence_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(change) = parse_presence_changed(payload, carrier_topic, identifier) else {
        persistence::log_line("presence_changed rejected: invalid carrier or payload");
        return;
    };
    state
        .presence_by_network
        .entry(change.network_id)
        .or_default()
        .insert(presence_key(&change.nick), change.presence);
    push_notify_nicks(state, ui);
    if change.initial {
        return;
    }
    let network = network_slugs_by_id(&state.network_ids)
        .and_then(|slugs| slugs.get(&change.network_id).cloned())
        .unwrap_or_else(|| change.network_id.to_string());
    let status = if change.presence == Presence::Online {
        "presence-online"
    } else {
        "presence-offline"
    };
    let nick = change.nick;
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_presence_nick(nick.into());
        ui.set_status_presence_network(network.into());
        ui.set_status_kind(status.into());
    });
}

/// Validates `presence_error` on the exact user topic: an integer
/// `network_id`, a `reason` string (`list_full` today; kept open so a new
/// reason still reaches the user) and the rejected target(s) in `detail`.
fn parse_presence_error(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(i64, String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "presence_error" {
        return None;
    }
    Some((
        payload.get("network_id")?.as_i64()?,
        payload.get("reason")?.as_str()?.to_string(),
        payload.get("detail")?.as_str()?.to_string(),
    ))
}

/// The ircd refused a watch registration (MONITOR/WATCH list full). Never
/// silent: the rejected targets go to the status bar. The raw numeric also
/// lands as a server notice upstream, which this does not replace.
fn handle_presence_error(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network_id, reason, detail)) =
        parse_presence_error(payload, carrier_topic, identifier)
    else {
        persistence::log_line("presence_error rejected: invalid carrier or payload");
        return;
    };
    persistence::log_line(&format!(
        "presence error on network {network_id}: reason={reason}"
    ));
    let network = network_slugs_by_id(&state.network_ids)
        .and_then(|slugs| slugs.get(&network_id).cloned())
        .unwrap_or_else(|| network_id.to_string());
    let status = if reason == "list_full" {
        "presence-list-full"
    } else {
        "presence-rejected"
    };
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_presence_nick(detail.into());
        ui.set_status_presence_network(network.into());
        ui.set_status_kind(status.into());
    });
}

/// Peer-away key: the network plus the peer folded with that network's
/// casemapping, so `Alice` and `alice` share one message.
fn peer_away_key(state: &WorkerState, network: &str, peer: &str) -> (String, String) {
    let casemapping = state
        .isupport_by_network
        .get(network)
        .map(|isupport| isupport.casemapping)
        .unwrap_or(cordiale_core::isupport::CaseMapping::Rfc1459);
    (network.to_string(), casemapping.fold(peer))
}

/// The peer-away key of the open private window, if one is open.
fn current_peer_away_key(state: &WorkerState) -> Option<(String, String)> {
    if !state.current_query {
        return None;
    }
    let (network, nick) = state.current_channel.as_ref()?;
    Some(peer_away_key(state, network, nick))
}

/// Shows the open private window's away message, or hides the banner. The
/// banner itself is only drawn while a private window is open.
fn push_peer_away_banner(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (peer, message) = current_peer_away_key(state)
        .and_then(|key| {
            let message = state.peer_away.get(&key)?.clone();
            let peer = state
                .current_channel
                .as_ref()
                .map(|(_, nick)| nick.clone())
                .unwrap_or_default();
            Some((peer, message))
        })
        .map_or((String::new(), None), |(peer, message)| {
            (peer, Some(message))
        });
    let visible = message.is_some();
    let message = message.unwrap_or_default();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_peer_away_peer(peer.into());
        ui.set_peer_away_message(message.into());
        ui.set_peer_away_visible(visible);
    });
}

/// Validates `peer_away` (a standalone 301 RPL_AWAY, not part of a WHOIS)
/// on the exact user topic: `network` and `peer` non-empty, `message` a
/// string that may be empty (no away text was given).
fn parse_peer_away(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "peer_away" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    let peer = payload.get("peer")?.as_str()?;
    if network.trim().is_empty() || peer.is_empty() {
        return None;
    }
    let message = payload.get("message")?.as_str()?;
    Some((network.to_string(), peer.to_string(), message.to_string()))
}

/// Remembers the peer's latest away message (replacing an older one) and
/// refreshes the banner if that peer's private window is open. Never moves
/// focus.
fn handle_peer_away(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network, peer, message)) = parse_peer_away(payload, carrier_topic, identifier) else {
        persistence::log_line("peer_away rejected: invalid carrier or payload");
        return;
    };
    let key = peer_away_key(state, &network, &peer);
    let shown = current_peer_away_key(state).as_ref() == Some(&key);
    state.peer_away.insert(key, message);
    if shown {
        push_peer_away_banner(state, ui);
    }
}

/// The per-file upload limits Grappa advertises, as shown in Settings.
#[derive(Clone, Debug, PartialEq, Eq)]
struct UploadLimits {
    /// `embedded` or `litterbox`.
    host: String,
    image_bytes: u64,
    video_bytes: u64,
    /// `None` when the server omits it (Cicchetto then uses its own default).
    video_seconds: Option<u64>,
    document_bytes: u64,
    audio_bytes: u64,
}

/// Validates `server_settings_changed` like Cicchetto: `upload.active_host`
/// in `embedded | litterbox` and the image/video/document/audio/global caps
/// positive integers are required; the optional fields and
/// `http_host_aliases` (no native use) don't reject the snapshot.
fn parse_server_settings_changed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<UploadLimits> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "server_settings_changed" {
        return None;
    }
    let upload = payload.get("upload")?;
    let cap = |key: &str| upload.get(key)?.as_u64().filter(|bytes| *bytes > 0);
    let host = upload.get("active_host")?.as_str()?;
    if !matches!(host, "embedded" | "litterbox") {
        return None;
    }
    cap("global_cap_bytes")?;
    Some(UploadLimits {
        host: host.to_string(),
        image_bytes: cap("image_per_file_cap_bytes")?,
        video_bytes: cap("video_per_file_cap_bytes")?,
        video_seconds: cap("video_max_duration_seconds"),
        document_bytes: cap("document_per_file_cap_bytes")?,
        audio_bytes: cap("audio_per_file_cap_bytes")?,
    })
}

/// Mirrors the advertised upload limits into Settings > General.
fn handle_server_settings_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(limits) = parse_server_settings_changed(payload, carrier_topic, identifier) else {
        persistence::log_line("server_settings_changed rejected: invalid carrier or payload");
        return;
    };
    if state.upload_limits.as_ref() == Some(&limits) {
        return;
    }
    let row = UploadLimitsRow {
        host: limits.host.clone().into(),
        image: format_file_size(limits.image_bytes).into(),
        video: format_file_size(limits.video_bytes).into(),
        video_seconds: limits
            .video_seconds
            .map(|seconds| seconds.to_string())
            .unwrap_or_default()
            .into(),
        document: format_file_size(limits.document_bytes).into(),
        audio: format_file_size(limits.audio_bytes).into(),
    };
    state.upload_limits = Some(limits);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_server_upload_limits(row);
        ui.set_server_upload_limits_known(true);
    });
}

/// Validates `bundle_hash` on the exact user topic: a non-empty `hash` and
/// an optional `version` (absent or non-string reads as none, like
/// Cicchetto).
fn parse_bundle_hash(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, Option<String>)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "bundle_hash" {
        return None;
    }
    let hash = payload.get("hash")?.as_str()?;
    if hash.is_empty() {
        return None;
    }
    let version = payload
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .map(str::to_string);
    Some((hash.to_string(), version))
}

/// The hash identifies the deployed Cicchetto web bundle, which has no
/// native counterpart: it is consumed and logged when it changes, and never
/// triggers a download or an update of this app.
fn handle_bundle_hash(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(bundle) = parse_bundle_hash(payload, carrier_topic, identifier) else {
        persistence::log_line("bundle_hash rejected: invalid carrier or payload");
        return;
    };
    if state.web_bundle.as_ref() == Some(&bundle) {
        return;
    }
    persistence::log_line(&format!(
        "server web bundle: hash={} version={}",
        bundle.0,
        bundle.1.as_deref().unwrap_or("-")
    ));
    state.web_bundle = Some(bundle);
}

/// Message kinds of Grappa's scrollback (`Message.kind()`), the closed set a
/// mentions entry may carry.
const SCROLLBACK_MESSAGE_KINDS: [&str; 11] = [
    "privmsg",
    "notice",
    "action",
    "join",
    "part",
    "quit",
    "nick_change",
    "mode",
    "topic",
    "kick",
    "server_event",
];

/// Validates `mentions_bundle` on the exact user topic and renders it as a
/// reply view: the away period, the reason when set, then each message in
/// the server's order. Every message needs an integer `server_time`,
/// string `channel`/`sender`, string-or-`null` `body` and a known `kind`;
/// one bad message drops the bundle, like Cicchetto's schema.
fn parse_mentions_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<ReplyView> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "mentions_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let started = payload.get("away_started_at")?.as_str()?;
    let ended = payload.get("away_ended_at")?.as_str()?;
    let reason = parse_nullable_wire_string(payload.get("away_reason")?)?;
    let mut rows = vec![(
        "mentions-away-period".to_string(),
        format!(
            "{} – {}",
            format_iso_timestamp(started),
            format_iso_timestamp(ended)
        ),
    )];
    if let Some(reason) = reason {
        rows.push(("mentions-away-reason".to_string(), reason));
    }
    let messages = payload.get("messages")?.as_array()?;
    for message in messages {
        let server_time = message.get("server_time")?.as_i64()?;
        let channel = message.get("channel")?.as_str()?;
        let sender = message.get("sender")?.as_str()?;
        let body = parse_nullable_wire_string(message.get("body")?)?.unwrap_or_default();
        let kind = message.get("kind")?.as_str()?;
        if !SCROLLBACK_MESSAGE_KINDS.contains(&kind) {
            return None;
        }
        let text = if kind == "action" {
            format!("* {sender} {body}")
        } else {
            format!("<{sender}> {body}")
        };
        rows.push((
            String::new(),
            format!("{} {channel} {text}", format_epoch_millis(server_time)),
        ));
    }
    if messages.is_empty() {
        rows.push(("mentions-empty".to_string(), String::new()));
    }
    Some(ReplyView {
        kind: "mentions_bundle",
        subject: String::new(),
        network: network.to_string(),
        rows,
    })
}

/// Back from away: keeps the summary for `/mentions` and opens it, as
/// Cicchetto focuses its mentions window (returning is the user's action).
fn handle_mentions_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(view) = parse_mentions_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("mentions_bundle rejected: invalid carrier or payload");
        return;
    };
    state
        .mentions_bundles
        .insert(view.network.clone(), view.clone());
    show_reply_view(state, ui, view);
}

/// `/list` alone or `/list <search>`; any other text is not this command.
fn parse_list_command(body: &str) -> Option<String> {
    let trimmed = body.trim();
    let (command, rest) = trimmed
        .split_once(char::is_whitespace)
        .unwrap_or((trimmed, ""));
    command
        .eq_ignore_ascii_case("/list")
        .then(|| rest.trim().to_string())
}

/// Opens the directory screen for `network` and loads its first page.
async fn open_directory(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    query: String,
) {
    state.directory = Some(DirectoryView::new(network, query));
    push_directory(state, ui, true);
    load_directory(state, ui).await;
}

/// Fetches the first page for the open directory's sort and search,
/// replacing any loaded rows (the snapshot may have been replaced).
async fn load_directory(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token), Some(view)) = (
        state.client.clone(),
        state.token.clone(),
        state.directory.as_ref(),
    ) else {
        return;
    };
    let network = view.network.clone();
    let sort = view.sort;
    let query = view.query.clone();
    let result = client
        .fetch_directory(&token, &network, sort, &query, None)
        .await;
    let Some(view) = state.directory.as_mut() else {
        return;
    };
    // The view may have changed network, sort or search meanwhile.
    if view.network != network || view.sort != sort || view.query != query {
        return;
    }
    match result {
        Ok(page) => {
            view.page = Some(page);
            view.error = None;
        }
        Err(err) => {
            persistence::log_line(&format!("directory fetch failed: {err:?}"));
            view.error = Some("directory-fetch-failed");
        }
    }
    push_directory(state, ui, false);
}

/// Appends the next page after the loaded rows, when the server has more.
async fn load_more_directory(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token), Some(view)) = (
        state.client.clone(),
        state.token.clone(),
        state.directory.as_ref(),
    ) else {
        return;
    };
    let Some(cursor) = view.page.as_ref().and_then(|page| page.next_cursor.clone()) else {
        return;
    };
    let network = view.network.clone();
    let sort = view.sort;
    let query = view.query.clone();
    let result = client
        .fetch_directory(&token, &network, sort, &query, Some(&cursor))
        .await;
    let Some(view) = state.directory.as_mut() else {
        return;
    };
    let same_cursor = view
        .page
        .as_ref()
        .and_then(|page| page.next_cursor.as_deref())
        == Some(cursor.as_str());
    if view.network != network || !same_cursor {
        return;
    }
    match result {
        Ok(next) => {
            if let Some(page) = view.page.as_mut() {
                page.entries.extend(next.entries);
                page.next_cursor = next.next_cursor;
                page.total = next.total;
                page.captured_at = next.captured_at;
                page.status = next.status;
            }
            view.error = None;
        }
        Err(err) => {
            persistence::log_line(&format!("directory page fetch failed: {err:?}"));
            view.error = Some("directory-fetch-failed");
        }
    }
    push_directory(state, ui, false);
}

/// Asks Grappa for a fresh `LIST`. The button stays disabled until a
/// `directory_*` push (or a failed request) releases it; the new rows are
/// fetched when those pushes arrive.
async fn refresh_directory(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    let Some(view) = state.directory.as_mut() else {
        return;
    };
    if view.refresh_pending {
        return;
    }
    view.refresh_pending = true;
    view.failed_reason = None;
    let network = view.network.clone();
    push_directory(state, ui, false);
    if let Err(err) = client.refresh_directory(&token, &network).await {
        persistence::log_line(&format!("directory refresh failed: {err:?}"));
        if let Some(view) = state.directory.as_mut() {
            if view.network == network {
                view.refresh_pending = false;
                view.error = Some("directory-refresh-failed");
            }
        }
        push_directory(state, ui, false);
    }
}

/// Mirrors the open directory into the UI; `open` also switches to its
/// screen. Nothing is pushed when no directory is open.
fn push_directory(state: &WorkerState, ui: &slint::Weak<AppWindow>, open: bool) {
    let Some(view) = state.directory.as_ref() else {
        return;
    };
    let network = view.network.clone();
    let sort = view.sort;
    let query = view.query.clone();
    let error = view.error.unwrap_or("");
    let refresh_pending = view.refresh_pending;
    let failed_reason = view.failed_reason.clone().unwrap_or_default();
    let (rows, status, total, captured_at, has_more) = match &view.page {
        Some(page) => (
            page.entries
                .iter()
                .map(|entry| {
                    (
                        entry.name.clone(),
                        entry.user_count.to_string(),
                        entry.topic.clone().unwrap_or_default(),
                        entry.featured,
                    )
                })
                .collect::<Vec<_>>(),
            page.status.clone(),
            page.total.to_string(),
            page.captured_at
                .as_deref()
                .map(format_iso_timestamp)
                .unwrap_or_default(),
            page.next_cursor.is_some(),
        ),
        None => (
            Vec::new(),
            String::new(),
            String::new(),
            String::new(),
            false,
        ),
    };
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<DirectoryRow> = rows
            .into_iter()
            .map(|(name, users, topic, featured)| DirectoryRow {
                name: name.into(),
                users: users.into(),
                topic: topic.into(),
                featured,
            })
            .collect();
        ui.set_directory_rows(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_directory_network(network.into());
        ui.set_directory_sort(sort.into());
        ui.set_directory_query(query.into());
        ui.set_directory_status(status.into());
        ui.set_directory_total(total.into());
        ui.set_directory_captured_at(captured_at.into());
        ui.set_directory_error(error.into());
        ui.set_directory_refresh_pending(refresh_pending);
        ui.set_directory_failed_reason(failed_reason.into());
        ui.set_directory_has_more(has_more);
        if open {
            ui.set_screen("directory".into());
        }
    });
}

/// Local-time rendering of an ISO-8601 timestamp; an unparsable value is
/// shown as sent.
fn format_iso_timestamp(raw: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|parsed| {
            parsed
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| raw.to_string())
}

/// Validates `directory_progress` (`count`) or `directory_complete`
/// (`total`) on the exact user topic: `network` a non-empty slug and the
/// counter a non-negative integer (checked, not used — the rows always come
/// from the REST page).
fn parse_directory_count_signal(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
    kind: &str,
    counter: &str,
) -> Option<String> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != kind {
        return None;
    }
    payload.get(counter)?.as_u64()?;
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    Some(network.to_string())
}

/// A capture is streaming: refetch the first page if that network's
/// directory is open, like Cicchetto's `onDirectoryProgress`.
async fn handle_directory_progress(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(network) = parse_directory_count_signal(
        payload,
        carrier_topic,
        identifier,
        "directory_progress",
        "count",
    ) else {
        persistence::log_line("directory_progress rejected: invalid carrier or payload");
        return;
    };
    reload_directory_after_push(state, ui, &network, None).await;
}

/// The capture finished (323 RPL_LISTEND) and the server replaced its
/// snapshot: refetch the first page, replacing the loaded rows.
async fn handle_directory_complete(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(network) = parse_directory_count_signal(
        payload,
        carrier_topic,
        identifier,
        "directory_complete",
        "total",
    ) else {
        persistence::log_line("directory_complete rejected: invalid carrier or payload");
        return;
    };
    reload_directory_after_push(state, ui, &network, None).await;
}

/// Validates `directory_failed` on the exact user topic: `network` a
/// non-empty slug and `reason` any string (an open set; `timeout` today).
fn parse_directory_failed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "directory_failed" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let reason = payload.get("reason")?.as_str()?;
    Some((network.to_string(), reason.to_string()))
}

/// The capture was abandoned; the server kept its previous snapshot. Shows
/// the reason and refetches, so the list stays the last good one.
async fn handle_directory_failed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network, reason)) = parse_directory_failed(payload, carrier_topic, identifier) else {
        persistence::log_line("directory_failed rejected: invalid carrier or payload");
        return;
    };
    reload_directory_after_push(state, ui, &network, Some(reason)).await;
}

/// Shared tail of the `directory_*` pushes: releases the refresh latch,
/// records (or clears) the capture failure and refetches when the pushed
/// network's directory is the open one.
async fn reload_directory_after_push(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    failed_reason: Option<String>,
) {
    let Some(view) = state.directory.as_mut() else {
        return;
    };
    if view.network != network {
        return;
    }
    view.refresh_pending = false;
    view.failed_reason = failed_reason;
    push_directory(state, ui, false);
    load_directory(state, ui).await;
}

fn handle_who_reply(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(reply) = parse_who_reply(payload, carrier_topic, identifier) else {
        persistence::log_line("who_reply rejected: invalid carrier or payload");
        return;
    };
    show_reply_view(state, ui, who_reply_view(&reply));
}

/// Validates `server_reply`: `source` is the closed `info | version | motd |
/// admin` set and `lines` must hold only strings (kept in wire order, never
/// rewritten). Returns `(network, source, lines)`.
fn parse_server_reply(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, &'static str, Vec<String>)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "server_reply" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let source = match payload.get("source")?.as_str()? {
        "info" => "info",
        "version" => "version",
        "motd" => "motd",
        "admin" => "admin",
        _ => return None,
    };
    let lines = payload
        .get("lines")?
        .as_array()?
        .iter()
        .map(|line| line.as_str().map(str::to_string))
        .collect::<Option<Vec<_>>>()?;
    Some((network.to_string(), source, lines))
}

fn server_reply_view(network: &str, source: &'static str, lines: &[String]) -> ReplyView {
    let rows = if lines.is_empty() {
        vec![("reply-empty".to_string(), String::new())]
    } else {
        lines
            .iter()
            .map(|line| (String::new(), line.clone()))
            .collect()
    };
    ReplyView {
        kind: "server_reply",
        subject: source.to_string(),
        network: network.to_string(),
        rows,
    }
}

fn handle_server_reply(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network, source, lines)) = parse_server_reply(payload, carrier_topic, identifier)
    else {
        persistence::log_line("server_reply rejected: invalid carrier or payload");
        return;
    };
    show_reply_view(state, ui, server_reply_view(&network, source, &lines));
}

/// Validates `whois_bundle` field by field, like Cicchetto: any malformed
/// field drops the whole bundle. `source` must be `user` or `rail` (absent
/// means `user`); `avatar_url` may be absent.
fn parse_whois_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<WhoisBundle> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "whois_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    match payload.get("source") {
        None => {}
        Some(source) if matches!(source.as_str(), Some("user" | "rail")) => {}
        Some(_) => return None,
    }
    let text = |key: &str| parse_nullable_wire_string(payload.get(key)?);
    let flag = |key: &str| payload.get(key)?.as_bool();
    let number = |key: &str| match payload.get(key)? {
        Value::Null => Some(None),
        value => value.as_i64().map(Some),
    };
    let channels = match payload.get("channels")? {
        Value::Null => None,
        Value::Array(items) => Some(
            items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()?,
        ),
        _ => return None,
    };
    let extra_lines = match payload.get("extra_lines")? {
        Value::Null => None,
        Value::Array(items) => Some(
            items
                .iter()
                .map(|item| {
                    Some((
                        item.get("numeric")?.as_i64()?,
                        item.get("text")?.as_str()?.to_string(),
                    ))
                })
                .collect::<Option<Vec<_>>>()?,
        ),
        _ => return None,
    };
    let avatar_url = match payload.get("avatar_url") {
        None => None,
        Some(value) => parse_nullable_wire_string(value)?,
    };
    Some(WhoisBundle {
        network: network.to_string(),
        target: payload.get("target")?.as_str()?.to_string(),
        user: text("user")?,
        host: text("host")?,
        realname: text("realname")?,
        server: text("server")?,
        server_info: text("server_info")?,
        is_operator: flag("is_operator")?,
        oper_text: text("oper_text")?,
        idle_seconds: number("idle_seconds")?,
        signon: number("signon")?,
        channels,
        using_ssl: flag("using_ssl")?,
        is_registered: flag("is_registered")?,
        is_admin: flag("is_admin")?,
        is_services_admin: flag("is_services_admin")?,
        is_helper: flag("is_helper")?,
        is_chanop: flag("is_chanop")?,
        is_agent: flag("is_agent")?,
        is_java: flag("is_java")?,
        umodes: text("umodes")?,
        away_message: text("away_message")?,
        actually_host: text("actually_host")?,
        actually_ip: text("actually_ip")?,
        account: text("account")?,
        secure: flag("secure")?,
        secure_cipher: text("secure_cipher")?,
        certfp: text("certfp")?,
        extra_lines,
        avatar_url,
    })
}

/// `h:mm:ss`, without words to translate.
fn format_idle(seconds: i64) -> String {
    let seconds = seconds.max(0);
    format!(
        "{}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

fn format_signon(epoch_seconds: i64) -> String {
    epoch_seconds
        .checked_mul(1000)
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|moment| {
            moment
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| epoch_seconds.to_string())
}

/// Label-keyed rows for the WHOIS card; empty fields are omitted, boolean
/// flags become label-only rows, extra numerics stay in wire order.
fn whois_bundle_view(bundle: &WhoisBundle) -> ReplyView {
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut push = |label: &str, value: Option<String>| {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            rows.push((label.to_string(), value));
        }
    };
    let userhost = match (&bundle.user, &bundle.host) {
        (Some(user), Some(host)) => Some(format!("{user}@{host}")),
        (None, Some(host)) => Some(host.clone()),
        (Some(user), None) => Some(user.clone()),
        (None, None) => None,
    };
    push("whois-userhost", userhost);
    push("whois-realname", bundle.realname.clone());
    push("whois-account", bundle.account.clone());
    let server = match (&bundle.server, &bundle.server_info) {
        (Some(server), Some(info)) => Some(format!("{server} ({info})")),
        (server, _) => server.clone(),
    };
    push("whois-server", server);
    push(
        "whois-channels",
        bundle.channels.as_ref().map(|channels| channels.join(" ")),
    );
    push("whois-idle", bundle.idle_seconds.map(format_idle));
    push("whois-signon", bundle.signon.map(format_signon));
    push("whois-away", bundle.away_message.clone());
    push("whois-umodes", bundle.umodes.clone());
    let actually = match (&bundle.actually_host, &bundle.actually_ip) {
        (Some(host), Some(ip)) => Some(format!("{host} ({ip})")),
        (host, ip) => host.clone().or_else(|| ip.clone()),
    };
    push("whois-actually", actually);
    push("whois-certfp", bundle.certfp.clone());
    if bundle.secure || bundle.using_ssl {
        rows.push((
            "whois-secure".to_string(),
            bundle.secure_cipher.clone().unwrap_or_default(),
        ));
    }
    if bundle.is_operator {
        rows.push((
            "whois-operator".to_string(),
            bundle.oper_text.clone().unwrap_or_default(),
        ));
    }
    for (flag, label) in [
        (bundle.is_registered, "whois-registered"),
        (bundle.is_admin, "whois-admin"),
        (bundle.is_services_admin, "whois-services-admin"),
        (bundle.is_helper, "whois-helper"),
        (bundle.is_chanop, "whois-chanop"),
        (bundle.is_agent, "whois-agent"),
        (bundle.is_java, "whois-java"),
    ] {
        if flag {
            rows.push((label.to_string(), String::new()));
        }
    }
    for (numeric, text) in bundle.extra_lines.iter().flatten() {
        rows.push((String::new(), format!("{numeric:03} {text}")));
    }
    // The avatar is an authenticated server path; the image itself is not
    // rendered yet, only its availability.
    if bundle.avatar_url.is_some() {
        rows.push(("whois-avatar".to_string(), String::new()));
    }
    ReplyView {
        kind: "whois_bundle",
        subject: bundle.target.clone(),
        network: bundle.network.clone(),
        rows,
    }
}

fn handle_whois_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(bundle) = parse_whois_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("whois_bundle rejected: invalid carrier or payload");
        return;
    };
    let view = whois_bundle_view(&bundle);
    state.whois_card = Some(bundle);
    show_reply_view(state, ui, view);
}

/// Validates `whowas_bundle`: every key is required, the history fields are
/// strings or `null`, and `not_found` separates "no history" (406) from a
/// malformed payload, which is dropped.
fn parse_whowas_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<ReplyView> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "whowas_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let target = payload.get("target")?.as_str()?;
    let text = |key: &str| parse_nullable_wire_string(payload.get(key)?);
    let user = text("user")?;
    let host = text("host")?;
    let realname = text("realname")?;
    let server = text("server")?;
    let logoff_time = text("logoff_time")?;
    let not_found = payload.get("not_found")?.as_bool()?;

    let mut rows: Vec<(String, String)> = Vec::new();
    if not_found {
        rows.push(("whowas-not-found".to_string(), String::new()));
    } else {
        let userhost = match (user, host) {
            (Some(user), Some(host)) => Some(format!("{user}@{host}")),
            (user, host) => user.or(host),
        };
        for (label, value) in [
            ("whois-userhost", userhost),
            ("whois-realname", realname),
            ("whois-server", server),
            ("whowas-logoff", logoff_time),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                rows.push((label.to_string(), value));
            }
        }
    }
    Some(ReplyView {
        kind: "whowas_bundle",
        subject: target.to_string(),
        network: network.to_string(),
        rows,
    })
}

fn handle_whowas_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(view) = parse_whowas_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("whowas_bundle rejected: invalid carrier or payload");
        return;
    };
    show_reply_view(state, ui, view);
}

/// Validates `banlist_bundle`: `mode` is whichever list letter was asked for
/// (never assumed to be `b`), and each entry needs a string `mask` plus a
/// string-or-`null` `setter` and `set_ts`; one bad entry drops the bundle.
/// Entries keep the ircd's order.
fn parse_banlist_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<ReplyView> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "banlist_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let channel = payload.get("channel")?.as_str()?;
    let mode = payload.get("mode")?.as_str()?;
    if mode.is_empty() {
        return None;
    }
    let mut rows: Vec<(String, String)> = Vec::new();
    for entry in payload.get("entries")?.as_array()? {
        let mask = entry.get("mask")?.as_str()?;
        let setter = parse_nullable_wire_string(entry.get("setter")?)?;
        let set_ts = parse_nullable_wire_string(entry.get("set_ts")?)?;
        let details = [setter, set_ts]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        let line = if details.is_empty() {
            mask.to_string()
        } else {
            format!("{mask} — {details}")
        };
        rows.push((String::new(), line));
    }
    if rows.is_empty() {
        rows.push(("banlist-empty".to_string(), String::new()));
    }
    Some(ReplyView {
        kind: "banlist_bundle",
        subject: format!("{channel} +{mode}"),
        network: network.to_string(),
        rows,
    })
}

fn handle_banlist_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(view) = parse_banlist_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("banlist_bundle rejected: invalid carrier or payload");
        return;
    };
    show_reply_view(state, ui, view);
}

/// Validates `invite_ack` (341 RPL_INVITING) on the exact user topic:
/// `network`, `channel` and `peer` are required non-empty strings. Returns
/// them in that order.
fn parse_invite_ack(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "invite_ack" {
        return None;
    }
    let field = |key: &str| {
        payload
            .get(key)?
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
    };
    Some((field("network")?, field("channel")?, field("peer")?))
}

/// Confirms a sent invite in the status bar. Every acknowledgement is shown,
/// even repeats; it is transient and never stored, like Cicchetto's
/// synthetic server-window row (Cordiale has no server window).
fn handle_invite_ack(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network, channel, peer)) = parse_invite_ack(payload, carrier_topic, identifier)
    else {
        persistence::log_line("invite_ack rejected: invalid carrier or payload");
        return;
    };
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_invite_peer(peer.into());
        ui.set_status_invite_channel(channel.into());
        ui.set_status_invite_network(network.into());
        ui.set_status_kind("invite-sent".into());
    });
}

/// The twelve LUSERS counters in display order, each with its reply label.
const LUSERS_COUNTERS: [(&str, &str); 12] = [
    ("total_users", "lusers-total-users"),
    ("invisible", "lusers-invisible"),
    ("servers", "lusers-servers"),
    ("operators", "lusers-operators"),
    ("unknown_connections", "lusers-unknown-connections"),
    ("channels_formed", "lusers-channels-formed"),
    ("local_clients", "lusers-local-clients"),
    ("local_servers", "lusers-local-servers"),
    ("current_local", "lusers-current-local"),
    ("max_local", "lusers-max-local"),
    ("current_global", "lusers-current-global"),
    ("max_global", "lusers-max-global"),
];

/// Validates `lusers_bundle`: `network` is a required non-empty slug. Like
/// Cicchetto, each counter is read on its own and a missing, `null` or
/// non-integer one shows as unknown instead of dropping the other eleven —
/// the bundle is display-only (253 RPL_LUSERUNKNOWN is optional upstream).
fn parse_lusers_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<ReplyView> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "lusers_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let rows = LUSERS_COUNTERS
        .iter()
        .map(|(key, label)| {
            let value = payload
                .get(*key)
                .and_then(Value::as_i64)
                .map_or_else(|| "—".to_string(), |count| count.to_string());
            (label.to_string(), value)
        })
        .collect();
    Some(ReplyView {
        kind: "lusers_bundle",
        subject: String::new(),
        network: network.to_string(),
        rows,
    })
}

/// Shows a LUSERS bundle only when this client asked for it with `/lusers`
/// (consume-once); the unsolicited registration burst is dropped silently.
fn handle_lusers_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some(view) = parse_lusers_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("lusers_bundle rejected: invalid carrier or payload");
        return;
    };
    if !state.lusers_requested.remove(&view.network) {
        return;
    }
    show_reply_view(state, ui, view);
}

/// Common channel prefixes, used only to tell a channel argument from a mode
/// letter in `/banlist`. `+` is left out on purpose: `/banlist +e` means the
/// exception list, not a modeless `+e` channel.
fn looks_like_channel(name: &str) -> bool {
    name.starts_with(['#', '&', '!'])
}

/// Validates `whois_avatar_ready`: `network`, `nick` and `avatar_url` are
/// all required strings. Returns them in that order.
fn parse_whois_avatar_ready(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "whois_avatar_ready" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    Some((
        network.to_string(),
        payload.get("nick")?.as_str()?.to_string(),
        payload.get("avatar_url")?.as_str()?.to_string(),
    ))
}

/// Cicchetto's `patchWhoisAvatarUrl`: patches only the open card for the
/// same network and nick (compared with the network's casemapping); a late
/// completion for a closed or different card is a silent no-op.
fn apply_whois_avatar_ready(
    card: &mut Option<WhoisBundle>,
    network: &str,
    nick: &str,
    avatar_url: String,
    casemapping: cordiale_core::isupport::CaseMapping,
) -> bool {
    let Some(card) = card.as_mut() else {
        return false;
    };
    if card.network != network || !casemapping.nick_eq(&card.target, nick) {
        return false;
    }
    if card.avatar_url.as_deref() == Some(avatar_url.as_str()) {
        return false;
    }
    card.avatar_url = Some(avatar_url);
    true
}

fn handle_whois_avatar_ready(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.identifier.as_deref() else {
        return;
    };
    let Some((network, nick, avatar_url)) =
        parse_whois_avatar_ready(payload, carrier_topic, identifier)
    else {
        persistence::log_line("whois_avatar_ready rejected: invalid carrier or payload");
        return;
    };
    // IRC's default mapping applies until the network's ISUPPORT says
    // otherwise.
    let casemapping = state
        .isupport_by_network
        .get(&network)
        .map(|isupport| isupport.casemapping)
        .unwrap_or(cordiale_core::isupport::CaseMapping::Rfc1459);
    if !apply_whois_avatar_ready(
        &mut state.whois_card,
        &network,
        &nick,
        avatar_url,
        casemapping,
    ) {
        return;
    }
    let Some(card) = state.whois_card.as_ref() else {
        return;
    };
    let shown = state.reply_view.as_ref().is_some_and(|view| {
        view.kind == "whois_bundle" && view.network == card.network && view.subject == card.target
    });
    if shown {
        let view = whois_bundle_view(card);
        push_reply_view(ui, &view, false);
        state.reply_view = Some(view);
    }
}

/// A slash command sent as a user-topic verb and answered by a push (a
/// requester reply, or the `invite_ack` acknowledgement): the WS verb plus
/// its payload without `network_id` (added by `send_user_verb`), or `Usage`
/// when a required argument is missing.
#[derive(Debug, PartialEq)]
enum ReplyCommand {
    Request { verb: &'static str, payload: Value },
    Usage,
}

/// Parses the reply-producing slash commands. `current_target` is the open
/// window's channel (or query nick), used when an argument is optional.
fn parse_reply_command(body: &str, current_target: &str) -> Option<ReplyCommand> {
    let mut words = body.split_whitespace();
    let command = words.next()?.to_ascii_lowercase();
    let args: Vec<&str> = words.collect();
    match command.as_str() {
        "/who" => {
            let target = args.first().copied().unwrap_or(current_target);
            if target.is_empty() {
                return Some(ReplyCommand::Usage);
            }
            Some(ReplyCommand::Request {
                verb: "who",
                payload: serde_json::json!({ "channel": target }),
            })
        }
        "/info" => Some(ReplyCommand::Request {
            verb: "info",
            payload: serde_json::json!({}),
        }),
        "/version" => Some(ReplyCommand::Request {
            verb: "version",
            payload: serde_json::json!({}),
        }),
        // Same payload the member context menu sends; `server` asks a
        // specific server (the two-argument IRC form) or stays `null`.
        "/whois" => {
            let Some(nick) = args.first() else {
                return Some(ReplyCommand::Usage);
            };
            Some(ReplyCommand::Request {
                verb: "whois",
                payload: serde_json::json!({
                    "nick": nick,
                    "server": args.get(1),
                    "source": "user",
                }),
            })
        }
        "/whowas" => {
            let Some(nick) = args.first() else {
                return Some(ReplyCommand::Usage);
            };
            Some(ReplyCommand::Request {
                verb: "whowas",
                payload: serde_json::json!({ "nick": nick }),
            })
        }
        // `/banlist [#channel] [mode]`: the open channel by default, and the
        // server itself defaults the list to `b`, so the mode is sent only
        // when given.
        "/banlist" => {
            let (channel, rest) = match args.first() {
                Some(first) if looks_like_channel(first) => (*first, &args[1..]),
                _ => (current_target, &args[..]),
            };
            if !looks_like_channel(channel) {
                return Some(ReplyCommand::Usage);
            }
            let payload = match rest.first().map(|mode| mode.trim_start_matches('+')) {
                Some(mode) if !mode.is_empty() => {
                    serde_json::json!({ "channel": channel, "mode": mode })
                }
                _ => serde_json::json!({ "channel": channel }),
            };
            Some(ReplyCommand::Request {
                verb: "banlist",
                payload,
            })
        }
        // An optional server argument targets another server's MOTD/ADMIN.
        "/motd" | "/admin" => {
            let verb = if command == "/motd" { "motd" } else { "admin" };
            let payload = match args.first() {
                Some(target) => serde_json::json!({ "target": target }),
                None => serde_json::json!({}),
            };
            Some(ReplyCommand::Request { verb, payload })
        }
        // `/invite <nick> [#channel]`: the open channel by default. The ircd's
        // acknowledgement arrives as `invite_ack`; nothing is shown before it.
        "/invite" => {
            let Some(nick) = args.first() else {
                return Some(ReplyCommand::Usage);
            };
            let channel = args.get(1).copied().unwrap_or(current_target);
            if !looks_like_channel(channel) {
                return Some(ReplyCommand::Usage);
            }
            Some(ReplyCommand::Request {
                verb: "invite",
                payload: serde_json::json!({ "channel": channel, "nick": nick }),
            })
        }
        // `/lusers [mask [server]]`: both optional and positional, mask
        // first; a server is never sent without a mask.
        "/lusers" => {
            let mut payload = serde_json::Map::new();
            if let Some(mask) = args.first() {
                payload.insert("mask".to_string(), Value::from(*mask));
            }
            if let Some(server) = args.get(1) {
                payload.insert("server".to_string(), Value::from(*server));
            }
            Some(ReplyCommand::Request {
                verb: "lusers",
                payload: Value::Object(payload),
            })
        }
        _ => None,
    }
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

    let is_parked = state
        .network_connection_states
        .get(&network_slug)
        .is_some_and(|snapshot| matches!(snapshot.status, NetworkConnectionStatus::Parked));
    if is_parked {
        collapse_if_parked(state, &network_slug);
    }
    if !state.network_ids.contains_key(&network_slug) || is_parked {
        return_home_if_network_selected(state, ui, &network_slug);
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

/// Called only after a successful non-guest bootstrap. Grappa's returned
/// bearer is written to the CredentialStore under the server URL, while
/// `servers.json` records its kind. The typed password is kept separately
/// and only in the OS keyring (`remember_login_password`).
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

/// Pre-fills the identifier for the last remembered profile on `server_url`,
/// and the password field from the login password kept in the OS keyring.
/// The stored bearer is never shown; it is used by the saved-profile
/// sign-in and by the automatic sign-in at launch.
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
    // The kept login password fills the (masked) field, so Connect works
    // without typing it again; a blank field would mean guest sign-in.
    if let Some(password) = remembered_login_password(server_url, &profile.identifier) {
        ui.set_password(password.into());
    }
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

/// Keyring service for a profile's login password (or client token), kept
/// apart from the bearer stored under the bare server URL.
fn login_password_service(server_url: &str) -> String {
    format!("{server_url}#login-password")
}

/// Keeps the password typed for a successful sign-in, only in the OS
/// keyring: the obfuscated file fallback is not safe enough for it, so
/// without a keyring nothing is stored.
fn remember_login_password(server_url: &str, identifier: &str, password: &str) {
    if identifier.is_empty() || password.is_empty() || !KeyringCredentialStore::is_available() {
        return;
    }
    let _ = KeyringCredentialStore.set_secret(
        &login_password_service(server_url),
        identifier,
        password,
    );
}

/// The login password kept for a profile, if the OS keyring has one.
fn remembered_login_password(server_url: &str, identifier: &str) -> Option<String> {
    if identifier.is_empty() || !KeyringCredentialStore::is_available() {
        return None;
    }
    KeyringCredentialStore
        .get_secret(&login_password_service(server_url), identifier)
        .ok()
        .flatten()
        .filter(|password| !password.is_empty())
}

/// Drops a kept login password Grappa no longer accepts.
fn forget_login_password(server_url: &str, identifier: &str) {
    if identifier.is_empty() || !KeyringCredentialStore::is_available() {
        return;
    }
    let _ = KeyringCredentialStore.delete_secret(&login_password_service(server_url), identifier);
}

/// The remembered profile to sign in with at launch on `server_url`: one
/// with a stored bearer or a kept login password.
fn auto_connect_identifier(server_url: &str) -> Option<String> {
    let file = persistence::load_servers_file().unwrap_or_default();
    let profile = file.profiles.iter().find(|profile| {
        profile.server_base_url == server_url
            && profile.remembered
            && file.selected_profile_identifier.as_deref() == Some(profile.identifier.as_str())
    })?;
    let has_bearer = matches!(
        remembered_profile_credential(server_url, &profile.identifier),
        RememberedProfileCredential::Bearer(_)
    );
    (has_bearer || remembered_login_password(server_url, &profile.identifier).is_some())
        .then(|| profile.identifier.clone())
}

fn set_auto_connect(enabled: bool) {
    let mut settings = persistence::load_settings().unwrap_or_default();
    if settings.auto_connect != enabled {
        settings.auto_connect = enabled;
        let _ = persistence::save_settings(&settings);
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

        let grouped = network_groups_data(
            &[],
            &queries,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );
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
    fn render_message_reads_part_quit_and_kick_reasons_from_the_body() {
        let part = serde_json::json!({"kind": "part", "sender": "vjt", "body": "bye"});
        assert_eq!(render_message(&part, None).text, "← vjt left (bye)");
        let quit = serde_json::json!({"kind": "quit", "sender": "vjt", "body": ""});
        assert_eq!(render_message(&quit, None).text, "⇐ vjt quit");

        let kick = serde_json::json!({
            "kind": "kick",
            "sender": "op",
            "body": null,
            "meta": {"target": "spammer"}
        });
        let rendered = render_message(&kick, None);
        assert_eq!(rendered.text, "⊘ spammer was kicked by op");
        assert!(rendered.italic);
        let kick_with_reason = serde_json::json!({
            "kind": "kick",
            "sender": "op",
            "body": "flood",
            "meta": {"target": "spammer"}
        });
        assert_eq!(
            render_message(&kick_with_reason, None).text,
            "⊘ spammer was kicked by op (flood)"
        );
    }

    #[test]
    fn render_message_formats_topic_and_server_events() {
        let topic = serde_json::json!({"kind": "topic", "sender": "vjt", "body": "Rust talk"});
        assert_eq!(
            render_message(&topic, None).text,
            "* vjt changed the topic to: Rust talk"
        );
        let cleared = serde_json::json!({"kind": "topic", "sender": "vjt", "body": ""});
        assert_eq!(
            render_message(&cleared, None).text,
            "* vjt cleared the topic"
        );

        let server_event = serde_json::json!({
            "kind": "server_event",
            "sender": "irc.example.org",
            "body": "Server going down"
        });
        let rendered = render_message(&server_event, None);
        assert_eq!(rendered.nick.as_deref(), Some("irc.example.org"));
        assert_eq!(rendered.text, "Server going down");
        assert!(rendered.italic);
    }

    #[test]
    fn chat_nick_prefix_follows_the_current_channel_roster() {
        use cordiale_core::isupport::CaseMapping;

        let message = render_message(
            &serde_json::json!({"kind": "privmsg", "sender": "{alice}", "body": "hello"}),
            None,
        );
        let messages = vec![message];
        let mut members = vec![("[Alice]".to_string(), "@".to_string())];
        let original_nick = messages[0].nick.clone();

        let op = chat_lines_model_with_roster(&messages, false, &members, CaseMapping::Rfc1459);
        assert_eq!(op[0].nick.to_string(), "{alice}");
        assert_eq!(op[0].nick_prefix.to_string(), "@");

        members[0].1 = "+".to_string();
        let voice = chat_lines_model_with_roster(&messages, false, &members, CaseMapping::Rfc1459);
        assert_eq!(voice[0].nick_prefix.to_string(), "+");
        assert_eq!(messages[0].nick, original_nick);

        let ascii = chat_lines_model_with_roster(&messages, false, &members, CaseMapping::Ascii);
        assert_eq!(ascii[0].nick_prefix.to_string(), "");
        let query = chat_lines_model(&messages, false);
        assert_eq!(query[0].nick_prefix.to_string(), "");
    }

    #[test]
    fn theme_choices_need_a_complete_palette() {
        let builtins = builtin_theme_choices();
        assert_eq!(builtins[0].key, "builtin:irssi-dark");
        assert!(builtins.iter().any(|choice| choice.key == "builtin:sux"));

        let mut colors: HashMap<String, String> = HashMap::new();
        for (index, key) in cordiale_core::theme::BASE_COLOR_KEYS.iter().enumerate() {
            colors.insert(key.to_string(), format!("#{:02x}0000", index));
        }
        for index in 0..16 {
            colors.insert(format!("nick_{index}"), "#00ff00".to_string());
        }
        let mut theme = cordiale_core::rest::ThemeWire {
            id: 12,
            name: "custom".to_string(),
            author: "vjt".to_string(),
            built_in: false,
            payload: cordiale_core::rest::ThemePayloadWire {
                colors,
                font_family: "hack".to_string(),
            },
        };
        let choice = server_theme_choice(&theme).expect("complete palette");
        assert_eq!(choice.key, "server:12");
        assert_eq!(choice.font_family, "hack");

        theme.payload.colors.remove("bg");
        assert!(server_theme_choice(&theme).is_none());
    }

    #[test]
    fn widest_sidebar_label_picks_the_longest_row() {
        let channels = vec![
            ChannelEntry {
                label: "#rust".into(),
                ..Default::default()
            },
            ChannelEntry {
                label: "#a-much-longer-channel".into(),
                mention_badge: " (2)".into(),
                ..Default::default()
            },
        ];
        let groups = vec![
            NetworkGroup {
                network: "libera".into(),
                channels: Rc::new(slint::VecModel::from(channels)).into(),
                ..Default::default()
            },
            NetworkGroup {
                network: "azzurra".into(),
                parked: true,
                ..Default::default()
            },
        ];
        assert_eq!(widest_sidebar_label(&groups), "#a-much-longer-channel (2)");
        assert_eq!(widest_sidebar_label(&[]), "");
    }

    #[test]
    fn members_average_probe_counts_the_bracketed_prefix() {
        assert_eq!(members_average_probe(&[]), "");
        let rows = vec![
            MemberRow {
                name: "Sythos".into(),
                prefix: "@".into(),
                ..Default::default()
            },
            MemberRow {
                name: "vjt".into(),
                ..Default::default()
            },
        ];
        // "[@] Sythos" is 10 characters and "vjt" 3: the average rounds up to 7.
        assert_eq!(members_average_probe(&rows), "nnnnnnn");
    }

    #[test]
    fn upload_ttl_menu_maps_both_ways() {
        assert_eq!(upload_ttl_for_index(0), None);
        assert_eq!(upload_ttl_for_index(3), Some(86_400));
        assert_eq!(upload_ttl_for_index(9), None);
        assert_eq!(upload_ttl_for_index(-1), None);
        assert_eq!(upload_ttl_index(Some(43_200)), 2);
        assert_eq!(upload_ttl_index(Some(7)), 0);
        assert_eq!(upload_ttl_index(None), 0);
    }

    #[test]
    fn notification_toggles_keep_the_rest_of_the_map() {
        let mut prefs = serde_json::json!({
            "channel_mentions": true,
            "channel_messages_only": ["#rust"],
            "notification_sound": "chime"
        })
        .as_object()
        .cloned()
        .unwrap();
        let toggles = NotificationToggles::from_prefs(&prefs);
        assert!(toggles.channel_mentions && toggles.private_messages_all);
        assert!(!toggles.presence_online);
        NotificationToggles {
            presence_online: true,
            ..toggles
        }
        .apply_to(&mut prefs);
        assert_eq!(prefs["presence_online"], serde_json::json!(true));
        assert_eq!(prefs["private_messages_all"], serde_json::json!(true));
        assert_eq!(prefs["notification_sound"], serde_json::json!("chime"));
        assert_eq!(prefs["channel_messages_only"], serde_json::json!(["#rust"]));
    }

    #[test]
    fn attachment_caps_and_errors_follow_the_category() {
        let limits = UploadLimits {
            host: "embedded".to_string(),
            image_bytes: 10,
            video_bytes: 50,
            video_seconds: None,
            document_bytes: 20,
            audio_bytes: 25,
        };
        assert_eq!(upload_cap(&limits, UploadCategory::Image), 10);
        assert_eq!(upload_cap(&limits, UploadCategory::Video), 50);
        assert_eq!(upload_cap(&limits, UploadCategory::Document), 20);
        assert_eq!(upload_cap(&limits, UploadCategory::Audio), 25);
        assert_eq!(attachment_error_status(Some(413)), "attach-too-large");
        assert_eq!(
            attachment_error_status(Some(415)),
            "attach-unsupported-type"
        );
        assert_eq!(attachment_error_status(Some(507)), "attach-no-space");
        assert_eq!(attachment_error_status(None), "attach-failed");
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
    fn only_message_envelopes_render_as_chat_lines() {
        assert!(renders_as_chat_line("message"));
        // Every other kind has its own handler or explicit no-op; none may
        // reach the chat-line path and leak as raw JSON.
        for kind in [
            "channel_created",
            "bundle_hash",
            "mentions_bundle",
            "members_seeded",
            "topic_changed",
            "joined",
            "server_settings_changed",
        ] {
            assert!(!renders_as_chat_line(kind), "{kind}");
        }
        // "parted" is confirmed never to be sent by the server, so it is
        // not a protocol kind at all.
        assert!(ClientEventKind::from_wire_name("parted").is_none());
        assert!(ClientEventKind::from_wire_name("channel_created").is_some());
    }

    #[test]
    fn parse_connection_progress_accepts_only_the_user_topic_and_known_network() {
        let known: HashMap<String, i64> = HashMap::from([("libera".to_string(), 1)]);
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({
            "kind": "connection_progress",
            "network": "libera",
            "state": "connecting",
            "future_field": true
        });
        assert_eq!(
            parse_connection_progress(&payload, topic, "vjt", &known),
            Some(("libera".to_string(), ConnectionProgressState::Connecting))
        );
        let connected = serde_json::json!({
            "kind": "connection_progress",
            "network": "libera",
            "state": "connected"
        });
        assert_eq!(
            parse_connection_progress(&connected, topic, "vjt", &known),
            Some(("libera".to_string(), ConnectionProgressState::Connected))
        );

        // Wrong carrier: another user's topic, or a channel-shaped topic.
        assert_eq!(
            parse_connection_progress(&payload, "grappa:user:other", "vjt", &known),
            None
        );
        assert_eq!(
            parse_connection_progress(
                &payload,
                "grappa:user:vjt/network:libera/channel:#rust",
                "vjt",
                &known
            ),
            None
        );

        for invalid in [
            serde_json::json!({"kind": "connection_state_changed", "network": "libera", "state": "connecting"}),
            serde_json::json!({"kind": "connection_progress", "network": "oftc", "state": "connecting"}),
            serde_json::json!({"kind": "connection_progress", "network": "", "state": "connecting"}),
            serde_json::json!({"kind": "connection_progress", "network": "libera", "state": "failed"}),
            serde_json::json!({"kind": "connection_progress", "network": "libera"}),
            serde_json::json!({"kind": "connection_progress", "state": "connecting"}),
            serde_json::json!({"kind": "connection_progress", "network": 1, "state": "connecting"}),
        ] {
            assert_eq!(
                parse_connection_progress(&invalid, topic, "vjt", &known),
                None,
                "{invalid} must be rejected"
            );
        }
    }

    #[test]
    fn connection_progress_toggles_the_badge_idempotently() {
        let mut connecting = std::collections::HashSet::new();
        assert!(apply_connection_progress(
            &mut connecting,
            "libera",
            ConnectionProgressState::Connecting
        ));
        assert!(!apply_connection_progress(
            &mut connecting,
            "libera",
            ConnectionProgressState::Connecting
        ));
        assert!(connecting.contains("libera"));
        assert!(apply_connection_progress(
            &mut connecting,
            "libera",
            ConnectionProgressState::Connected
        ));
        assert!(!apply_connection_progress(
            &mut connecting,
            "libera",
            ConnectionProgressState::Connected
        ));
        assert!(connecting.is_empty());
    }

    #[test]
    fn parse_recover_progress_validates_carrier_enums_and_open_reason() {
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({
            "kind": "recover_progress",
            "network": "azzurra",
            "step": "identify",
            "status": "failed",
            "reason": "wrong_password",
            "future_field": 1
        });
        assert_eq!(
            parse_recover_progress(&payload, topic, "vjt"),
            Some((
                "azzurra".to_string(),
                RecoverStepEntry {
                    step: RecoverStep::Identify,
                    status: RecoverStepStatus::Failed,
                    reason: Some("wrong_password".to_string()),
                }
            ))
        );
        // A reason token the client doesn't know yet is kept, not rejected.
        let future_reason = serde_json::json!({
            "kind": "recover_progress",
            "network": "azzurra",
            "step": "release",
            "status": "ok",
            "reason": "some_future_reason"
        });
        assert_eq!(
            parse_recover_progress(&future_reason, topic, "vjt").map(|(_, entry)| entry.reason),
            Some(Some("some_future_reason".to_string()))
        );
        let running = serde_json::json!({
            "kind": "recover_progress",
            "network": "azzurra",
            "step": "nick",
            "status": "running",
            "reason": null
        });
        assert_eq!(
            parse_recover_progress(&running, topic, "vjt").map(|(_, entry)| entry.status),
            Some(RecoverStepStatus::Running)
        );

        assert_eq!(
            parse_recover_progress(&payload, "grappa:user:other", "vjt"),
            None
        );
        for invalid in [
            serde_json::json!({"kind": "recover_result", "network": "azzurra", "step": "nick", "status": "ok", "reason": null}),
            serde_json::json!({"kind": "recover_progress", "network": "", "step": "nick", "status": "ok", "reason": null}),
            serde_json::json!({"kind": "recover_progress", "network": "azzurra", "step": "ghost", "status": "ok", "reason": null}),
            serde_json::json!({"kind": "recover_progress", "network": "azzurra", "step": "nick", "status": "done", "reason": null}),
            serde_json::json!({"kind": "recover_progress", "network": "azzurra", "step": "nick", "status": "ok"}),
            serde_json::json!({"kind": "recover_progress", "network": "azzurra", "step": "nick", "status": "ok", "reason": 3}),
        ] {
            assert_eq!(
                parse_recover_progress(&invalid, topic, "vjt"),
                None,
                "{invalid} must be rejected"
            );
        }
    }

    #[test]
    fn recover_progress_opens_isolates_and_upserts_like_cicchetto() {
        let entry = |step, status| RecoverStepEntry {
            step,
            status,
            reason: None,
        };
        let mut panel = None;
        assert!(apply_recover_progress(
            &mut panel,
            "azzurra",
            entry(RecoverStep::Identify, RecoverStepStatus::Running)
        ));
        assert!(apply_recover_progress(
            &mut panel,
            "azzurra",
            entry(RecoverStep::Nick, RecoverStepStatus::Running)
        ));
        // A known step is replaced in place, keeping the original order.
        assert!(apply_recover_progress(
            &mut panel,
            "azzurra",
            entry(RecoverStep::Identify, RecoverStepStatus::Done)
        ));
        // Duplicates are no-ops.
        assert!(!apply_recover_progress(
            &mut panel,
            "azzurra",
            entry(RecoverStep::Identify, RecoverStepStatus::Done)
        ));
        // Another network never mixes into the open panel.
        assert!(!apply_recover_progress(
            &mut panel,
            "libera",
            entry(RecoverStep::Release, RecoverStepStatus::Failed)
        ));
        let open = panel.clone().unwrap();
        assert_eq!(open.network, "azzurra");
        assert_eq!(
            open.steps,
            vec![
                entry(RecoverStep::Identify, RecoverStepStatus::Done),
                entry(RecoverStep::Nick, RecoverStepStatus::Running),
            ]
        );

        // After a dismiss, the next progress event reopens a fresh panel.
        panel = None;
        assert!(apply_recover_progress(
            &mut panel,
            "libera",
            entry(RecoverStep::Register, RecoverStepStatus::Running)
        ));
        assert_eq!(panel.unwrap().network, "libera");
    }

    #[test]
    fn parse_recover_result_keeps_the_terminal_event_with_any_reason() {
        let topic = "grappa:user:vjt";
        let failed = serde_json::json!({
            "kind": "recover_result",
            "network": "azzurra",
            "outcome": "failed",
            "reason": "a_reason_added_later",
            "future_field": []
        });
        assert_eq!(
            parse_recover_result(&failed, topic, "vjt"),
            Some((
                "azzurra".to_string(),
                RecoverOutcome::Failed,
                Some("a_reason_added_later".to_string())
            ))
        );
        let succeeded = serde_json::json!({
            "kind": "recover_result",
            "network": "azzurra",
            "outcome": "succeeded",
            "reason": null
        });
        assert_eq!(
            parse_recover_result(&succeeded, topic, "vjt"),
            Some(("azzurra".to_string(), RecoverOutcome::Succeeded, None))
        );
        assert_eq!(
            parse_recover_result(&succeeded, "grappa:user:other", "vjt"),
            None
        );
        for invalid in [
            serde_json::json!({"kind": "recover_progress", "network": "azzurra", "outcome": "failed", "reason": null}),
            serde_json::json!({"kind": "recover_result", "network": "", "outcome": "failed", "reason": null}),
            serde_json::json!({"kind": "recover_result", "network": "azzurra", "outcome": "partial", "reason": null}),
            serde_json::json!({"kind": "recover_result", "network": "azzurra", "outcome": "failed"}),
            serde_json::json!({"kind": "recover_result", "network": "azzurra", "outcome": "failed", "reason": false}),
        ] {
            assert_eq!(
                parse_recover_result(&invalid, topic, "vjt"),
                None,
                "{invalid} must be rejected"
            );
        }
    }

    #[test]
    fn recover_result_only_concludes_the_open_panel_of_its_network() {
        // No panel open (dismissed, or progress never arrived): no-op.
        let mut panel = None;
        assert!(!apply_recover_result(
            &mut panel,
            "azzurra",
            RecoverOutcome::Succeeded,
            None
        ));
        assert!(panel.is_none());

        assert!(apply_recover_progress(
            &mut panel,
            "azzurra",
            RecoverStepEntry {
                step: RecoverStep::Identify,
                status: RecoverStepStatus::Failed,
                reason: Some("wrong_password".to_string()),
            }
        ));
        // Another network cannot conclude it.
        assert!(!apply_recover_result(
            &mut panel,
            "libera",
            RecoverOutcome::Succeeded,
            None
        ));
        assert_eq!(panel.as_ref().unwrap().outcome, None);

        assert!(apply_recover_result(
            &mut panel,
            "azzurra",
            RecoverOutcome::Failed,
            Some("wrong_password".to_string())
        ));
        // Replaying the same result is a no-op.
        assert!(!apply_recover_result(
            &mut panel,
            "azzurra",
            RecoverOutcome::Failed,
            Some("wrong_password".to_string())
        ));
        let open = panel.unwrap();
        assert_eq!(open.outcome, Some(RecoverOutcome::Failed));
        assert_eq!(open.outcome_reason.as_deref(), Some("wrong_password"));
        assert_eq!(open.steps.len(), 1);
    }

    #[test]
    fn parse_web_session_severed_accepts_any_string_code_on_the_user_topic() {
        let topic = "grappa:user:vjt";
        let flood = serde_json::json!({
            "kind": "web_session_severed",
            "code": "rate_limit_flood",
            "future_field": true
        });
        assert_eq!(
            parse_web_session_severed(&flood, topic, "vjt").as_deref(),
            Some("rate_limit_flood")
        );
        // A code added by a later server still signs the client out.
        let future_code =
            serde_json::json!({"kind": "web_session_severed", "code": "admin_revoked"});
        assert_eq!(
            parse_web_session_severed(&future_code, topic, "vjt").as_deref(),
            Some("admin_revoked")
        );

        assert_eq!(
            parse_web_session_severed(&flood, "grappa:user:other", "vjt"),
            None
        );
        assert_eq!(
            parse_web_session_severed(
                &flood,
                "grappa:user:vjt/network:libera/channel:#rust",
                "vjt"
            ),
            None
        );
        for invalid in [
            serde_json::json!({"kind": "web_session_severed"}),
            serde_json::json!({"kind": "web_session_severed", "code": null}),
            serde_json::json!({"kind": "web_session_severed", "code": 429}),
            serde_json::json!({"kind": "connection_progress", "code": "rate_limit_flood"}),
        ] {
            assert_eq!(
                parse_web_session_severed(&invalid, topic, "vjt"),
                None,
                "{invalid} must be rejected"
            );
        }
    }

    fn who_user_json(nick: &str) -> Value {
        serde_json::json!({
            "nick": nick,
            "user": "~u",
            "host": "example.org",
            "server": "irc.example.org",
            "modes": "H@",
            "channel": "#rust",
            "hops": 0,
            "realname": "Real Name"
        })
    }

    #[test]
    fn parse_who_reply_is_strict_per_row() {
        let topic = "grappa:user:vjt";
        let mut nulls = who_user_json("bob");
        nulls["hops"] = Value::Null;
        nulls["realname"] = Value::Null;
        let payload = serde_json::json!({
            "kind": "who_reply",
            "network": "libera",
            "target": "#rust",
            "users": [who_user_json("alice"), nulls],
            "future_field": 1
        });
        let reply = parse_who_reply(&payload, topic, "vjt").expect("valid who_reply");
        assert_eq!(reply.network, "libera");
        assert_eq!(reply.target, "#rust");
        assert_eq!(reply.users.len(), 2);
        assert_eq!(reply.users[0].hops, Some(0));
        assert_eq!(reply.users[1].hops, None);
        assert_eq!(reply.users[1].realname, None);

        let empty = serde_json::json!({
            "kind": "who_reply", "network": "libera", "target": "#rust", "users": []
        });
        let view = who_reply_view(&parse_who_reply(&empty, topic, "vjt").unwrap());
        assert_eq!(view.rows, vec![("who-empty".to_string(), String::new())]);

        assert!(parse_who_reply(&payload, "grappa:user:other", "vjt").is_none());
        // One malformed row drops the whole bundle.
        let mut bad_row = who_user_json("carol");
        bad_row["modes"] = Value::Null;
        let mut missing_realname = who_user_json("dave");
        missing_realname.as_object_mut().unwrap().remove("realname");
        let mut string_hops = who_user_json("erin");
        string_hops["hops"] = serde_json::json!("2");
        for bad in [bad_row, missing_realname, string_hops] {
            let payload = serde_json::json!({
                "kind": "who_reply",
                "network": "libera",
                "target": "#rust",
                "users": [who_user_json("alice"), bad]
            });
            assert!(parse_who_reply(&payload, topic, "vjt").is_none());
        }
        let no_users =
            serde_json::json!({"kind": "who_reply", "network": "libera", "target": "#rust"});
        assert!(parse_who_reply(&no_users, topic, "vjt").is_none());
    }

    #[test]
    fn parse_server_reply_accepts_only_the_four_sources_and_string_lines() {
        let topic = "grappa:user:vjt";
        for source in ["info", "version", "motd", "admin"] {
            let payload = serde_json::json!({
                "kind": "server_reply",
                "network": "libera",
                "source": source,
                "lines": ["first line", "", "  indented"],
                "future_field": null
            });
            let (network, parsed, lines) =
                parse_server_reply(&payload, topic, "vjt").expect("valid server_reply");
            assert_eq!(network, "libera");
            assert_eq!(parsed, source);
            assert_eq!(lines, vec!["first line", "", "  indented"]);
        }
        let empty = serde_json::json!({
            "kind": "server_reply", "network": "libera", "source": "motd", "lines": []
        });
        let (network, source, lines) = parse_server_reply(&empty, topic, "vjt").unwrap();
        assert_eq!(
            server_reply_view(&network, source, &lines).rows,
            vec![("reply-empty".to_string(), String::new())]
        );
        for invalid in [
            serde_json::json!({"kind": "server_reply", "network": "libera", "source": "stats", "lines": []}),
            serde_json::json!({"kind": "server_reply", "network": "libera", "source": "motd", "lines": ["ok", 7]}),
            serde_json::json!({"kind": "server_reply", "network": "libera", "source": "motd"}),
            serde_json::json!({"kind": "server_reply", "network": "", "source": "motd", "lines": []}),
        ] {
            assert!(
                parse_server_reply(&invalid, topic, "vjt").is_none(),
                "{invalid}"
            );
        }
        assert!(parse_server_reply(&empty, "grappa:user:other", "vjt").is_none());
    }

    #[test]
    fn server_reply_commands_map_to_their_verbs() {
        let request = |verb: &'static str, payload: Value| ReplyCommand::Request { verb, payload };
        assert_eq!(
            parse_reply_command("/info", "#rust"),
            Some(request("info", serde_json::json!({})))
        );
        assert_eq!(
            parse_reply_command("/version", "#rust"),
            Some(request("version", serde_json::json!({})))
        );
        assert_eq!(
            parse_reply_command("/motd", "#rust"),
            Some(request("motd", serde_json::json!({})))
        );
        assert_eq!(
            parse_reply_command("/motd irc.example.org", "#rust"),
            Some(request(
                "motd",
                serde_json::json!({"target": "irc.example.org"})
            ))
        );
        assert_eq!(
            parse_reply_command("/admin hub.example.org", "#rust"),
            Some(request(
                "admin",
                serde_json::json!({"target": "hub.example.org"})
            ))
        );
    }

    fn whois_bundle_json() -> Value {
        serde_json::json!({
            "kind": "whois_bundle",
            "network": "libera",
            "target": "alice",
            "source": "user",
            "user": "~alice",
            "host": "example.org",
            "realname": "Alice",
            "server": "irc.example.org",
            "server_info": "Example IRC",
            "is_operator": false,
            "oper_text": null,
            "idle_seconds": 3725,
            "signon": null,
            "channels": ["#rust", "@#cordiale"],
            "using_ssl": true,
            "is_registered": true,
            "is_admin": false,
            "is_services_admin": false,
            "is_helper": false,
            "is_chanop": false,
            "is_agent": false,
            "is_java": false,
            "umodes": null,
            "away_message": null,
            "actually_host": null,
            "actually_ip": null,
            "account": "alice",
            "secure": true,
            "secure_cipher": "TLS_AES_256_GCM_SHA384",
            "certfp": null,
            "extra_lines": [{"numeric": 320, "text": "is a bot"}],
            "avatar_url": null,
            "future_field": {}
        })
    }

    #[test]
    fn parse_whois_bundle_is_strict_per_field() {
        let topic = "grappa:user:vjt";
        let bundle = parse_whois_bundle(&whois_bundle_json(), topic, "vjt").expect("valid bundle");
        assert_eq!(bundle.target, "alice");
        assert_eq!(bundle.idle_seconds, Some(3725));
        assert_eq!(
            bundle.channels,
            Some(vec!["#rust".to_string(), "@#cordiale".to_string()])
        );
        assert_eq!(
            bundle.extra_lines,
            Some(vec![(320, "is a bot".to_string())])
        );
        assert_eq!(bundle.avatar_url, None);

        let view = whois_bundle_view(&bundle);
        assert_eq!(view.kind, "whois_bundle");
        assert_eq!(view.subject, "alice");
        assert!(view.rows.contains(&(
            "whois-userhost".to_string(),
            "~alice@example.org".to_string()
        )));
        assert!(view
            .rows
            .contains(&("whois-idle".to_string(), "1:02:05".to_string())));
        assert!(view
            .rows
            .contains(&("whois-registered".to_string(), String::new())));
        assert!(view
            .rows
            .contains(&(String::new(), "320 is a bot".to_string())));

        // Tolerated: absent `source` (means user), `rail`, absent avatar.
        let mut tolerated = whois_bundle_json();
        let fields = tolerated.as_object_mut().unwrap();
        fields.remove("source");
        fields.remove("avatar_url");
        assert!(parse_whois_bundle(&tolerated, topic, "vjt").is_some());
        let mut rail = whois_bundle_json();
        rail["source"] = serde_json::json!("rail");
        assert!(parse_whois_bundle(&rail, topic, "vjt").is_some());

        assert!(parse_whois_bundle(&whois_bundle_json(), "grappa:user:other", "vjt").is_none());
        let breakers: [(&str, Option<Value>); 6] = [
            ("source", Some(serde_json::json!("sidebar"))),
            ("is_admin", None),
            ("realname", None),
            ("extra_lines", None),
            ("channels", Some(serde_json::json!(["#ok", 3]))),
            ("idle_seconds", Some(serde_json::json!("12"))),
        ];
        for (key, replacement) in breakers {
            let mut broken = whois_bundle_json();
            match replacement {
                Some(value) => broken[key] = value,
                None => {
                    broken.as_object_mut().unwrap().remove(key);
                }
            }
            assert!(
                parse_whois_bundle(&broken, topic, "vjt").is_none(),
                "{key} must invalidate the bundle"
            );
        }
    }

    #[test]
    fn whois_avatar_ready_patches_only_the_matching_open_card() {
        use cordiale_core::isupport::CaseMapping;
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({
            "kind": "whois_avatar_ready",
            "network": "libera",
            "nick": "ALICE",
            "avatar_url": "/networks/1/peer_avatar/alice"
        });
        let (network, nick, avatar_url) =
            parse_whois_avatar_ready(&payload, topic, "vjt").expect("valid avatar event");
        assert!(parse_whois_avatar_ready(&payload, "grappa:user:other", "vjt").is_none());
        for missing in ["network", "nick", "avatar_url"] {
            let mut broken = payload.clone();
            broken.as_object_mut().unwrap().remove(missing);
            assert!(parse_whois_avatar_ready(&broken, topic, "vjt").is_none());
        }

        // No open card: a late completion is a no-op.
        let mut card = None;
        assert!(!apply_whois_avatar_ready(
            &mut card,
            &network,
            &nick,
            avatar_url.clone(),
            CaseMapping::Rfc1459
        ));

        let mut bundle = parse_whois_bundle(&whois_bundle_json(), topic, "vjt").unwrap();
        bundle.target = "Alice[x]".to_string();
        card = Some(bundle);
        // A different network or nick never gets patched.
        assert!(!apply_whois_avatar_ready(
            &mut card,
            "oftc",
            "alice{x}",
            avatar_url.clone(),
            CaseMapping::Rfc1459
        ));
        assert!(!apply_whois_avatar_ready(
            &mut card,
            "libera",
            "bob",
            avatar_url.clone(),
            CaseMapping::Rfc1459
        ));
        // Same nick under the network's casemapping: patched once.
        assert!(apply_whois_avatar_ready(
            &mut card,
            "libera",
            "alice{x}",
            avatar_url.clone(),
            CaseMapping::Rfc1459
        ));
        assert!(!apply_whois_avatar_ready(
            &mut card,
            "libera",
            "alice{x}",
            avatar_url.clone(),
            CaseMapping::Rfc1459
        ));
        assert_eq!(
            card.unwrap().avatar_url.as_deref(),
            Some("/networks/1/peer_avatar/alice")
        );
    }

    #[test]
    fn parse_whowas_bundle_separates_not_found_from_invalid() {
        let topic = "grappa:user:vjt";
        let found = serde_json::json!({
            "kind": "whowas_bundle",
            "network": "libera",
            "target": "oldnick",
            "user": "~old",
            "host": "example.org",
            "realname": "Old Nick",
            "server": "irc.example.org",
            "logoff_time": "Tue Sep 22 10:00:00 2026",
            "not_found": false
        });
        let view = parse_whowas_bundle(&found, topic, "vjt").expect("valid whowas");
        assert_eq!(view.kind, "whowas_bundle");
        assert_eq!(view.subject, "oldnick");
        assert_eq!(
            view.rows[0],
            ("whois-userhost".to_string(), "~old@example.org".to_string())
        );
        assert!(view.rows.contains(&(
            "whowas-logoff".to_string(),
            "Tue Sep 22 10:00:00 2026".to_string()
        )));

        let not_found = serde_json::json!({
            "kind": "whowas_bundle",
            "network": "libera",
            "target": "ghost",
            "user": null,
            "host": null,
            "realname": null,
            "server": null,
            "logoff_time": null,
            "not_found": true
        });
        assert_eq!(
            parse_whowas_bundle(&not_found, topic, "vjt").unwrap().rows,
            vec![("whowas-not-found".to_string(), String::new())]
        );

        assert!(parse_whowas_bundle(&found, "grappa:user:other", "vjt").is_none());
        for key in ["user", "logoff_time", "not_found", "target"] {
            let mut broken = found.clone();
            broken.as_object_mut().unwrap().remove(key);
            assert!(
                parse_whowas_bundle(&broken, topic, "vjt").is_none(),
                "{key}"
            );
        }
        let mut wrong_type = found.clone();
        wrong_type["not_found"] = serde_json::json!("no");
        assert!(parse_whowas_bundle(&wrong_type, topic, "vjt").is_none());

        assert_eq!(
            parse_reply_command("/whowas oldnick", "#rust"),
            Some(ReplyCommand::Request {
                verb: "whowas",
                payload: serde_json::json!({"nick": "oldnick"})
            })
        );
        assert_eq!(
            parse_reply_command("/whowas", "#rust"),
            Some(ReplyCommand::Usage)
        );
    }

    #[test]
    fn parse_banlist_bundle_keeps_mode_and_entry_order() {
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({
            "kind": "banlist_bundle",
            "network": "libera",
            "channel": "#rust",
            "mode": "e",
            "entries": [
                {"mask": "*!*@a.example", "setter": "op", "set_ts": "1789900000"},
                {"mask": "*!*@b.example", "setter": null, "set_ts": null}
            ]
        });
        let view = parse_banlist_bundle(&payload, topic, "vjt").expect("valid banlist");
        assert_eq!(view.subject, "#rust +e");
        assert_eq!(
            view.rows,
            vec![
                (String::new(), "*!*@a.example — op 1789900000".to_string()),
                (String::new(), "*!*@b.example".to_string()),
            ]
        );
        let empty = serde_json::json!({
            "kind": "banlist_bundle", "network": "libera", "channel": "#rust",
            "mode": "b", "entries": []
        });
        assert_eq!(
            parse_banlist_bundle(&empty, topic, "vjt").unwrap().rows,
            vec![("banlist-empty".to_string(), String::new())]
        );
        assert!(parse_banlist_bundle(&payload, "grappa:user:other", "vjt").is_none());
        let mut no_mode = payload.clone();
        no_mode.as_object_mut().unwrap().remove("mode");
        assert!(parse_banlist_bundle(&no_mode, topic, "vjt").is_none());
        let mut bad_entry = payload.clone();
        bad_entry["entries"][1]["setter"] = serde_json::json!(5);
        assert!(parse_banlist_bundle(&bad_entry, topic, "vjt").is_none());
        let mut missing_ts = payload.clone();
        missing_ts["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("set_ts");
        assert!(parse_banlist_bundle(&missing_ts, topic, "vjt").is_none());
    }

    #[test]
    fn banlist_command_defaults_to_the_open_channel() {
        let request = |payload: Value| ReplyCommand::Request {
            verb: "banlist",
            payload,
        };
        assert_eq!(
            parse_reply_command("/banlist", "#rust"),
            Some(request(serde_json::json!({"channel": "#rust"})))
        );
        assert_eq!(
            parse_reply_command("/banlist +e", "#rust"),
            Some(request(
                serde_json::json!({"channel": "#rust", "mode": "e"})
            ))
        );
        assert_eq!(
            parse_reply_command("/banlist #other I", "#rust"),
            Some(request(
                serde_json::json!({"channel": "#other", "mode": "I"})
            ))
        );
        // In a query window there is no channel to default to.
        assert_eq!(
            parse_reply_command("/banlist", "alice"),
            Some(ReplyCommand::Usage)
        );
    }

    #[test]
    fn parse_auto_away_debounce_keeps_null_and_zero_distinct() {
        let topic = "grappa:user:vjt";
        let payload = |value: Value| serde_json::json!({"kind": "auto_away_debounce_changed", "auto_away_debounce_seconds": value});
        assert_eq!(
            parse_auto_away_debounce_changed(&payload(Value::Null), topic, "vjt"),
            Some(AutoAwayDebounce::ServerDefault)
        );
        assert_eq!(
            parse_auto_away_debounce_changed(&payload(serde_json::json!(0)), topic, "vjt"),
            Some(AutoAwayDebounce::Disabled)
        );
        assert_eq!(
            parse_auto_away_debounce_changed(&payload(serde_json::json!(300)), topic, "vjt"),
            Some(AutoAwayDebounce::Seconds(300))
        );
        assert_eq!(AutoAwayDebounce::ServerDefault.display_token(), "default");
        assert_eq!(AutoAwayDebounce::Disabled.display_token(), "off");
        assert_eq!(AutoAwayDebounce::Seconds(300).display_token(), "300");

        for invalid in [
            payload(serde_json::json!(-1)),
            payload(serde_json::json!(1.5)),
            payload(serde_json::json!("300")),
            serde_json::json!({"kind": "auto_away_debounce_changed"}),
        ] {
            assert_eq!(
                parse_auto_away_debounce_changed(&invalid, topic, "vjt"),
                None,
                "{invalid}"
            );
        }
        assert_eq!(
            parse_auto_away_debounce_changed(&payload(Value::Null), "grappa:user:other", "vjt"),
            None
        );
    }

    #[test]
    fn list_command_takes_an_optional_search() {
        assert_eq!(parse_list_command("/list"), Some(String::new()));
        assert_eq!(
            parse_list_command("  /LIST  rust lang "),
            Some("rust lang".to_string())
        );
        assert_eq!(parse_list_command("/listen"), None);
        assert_eq!(parse_list_command("hello /list"), None);
    }

    #[test]
    fn parse_directory_count_signal_checks_counter_and_network() {
        let topic = "grappa:user:vjt";
        let progress = |payload: &Value| {
            parse_directory_count_signal(payload, topic, "vjt", "directory_progress", "count")
        };
        let complete = |payload: &Value| {
            parse_directory_count_signal(payload, topic, "vjt", "directory_complete", "total")
        };
        assert_eq!(
            progress(
                &serde_json::json!({"kind": "directory_progress", "network": "libera", "count": 250})
            ),
            Some("libera".to_string())
        );
        assert_eq!(
            complete(
                &serde_json::json!({"kind": "directory_complete", "network": "libera", "total": 0})
            ),
            Some("libera".to_string())
        );
        for invalid in [
            serde_json::json!({"kind": "directory_progress", "network": "libera", "count": -1}),
            serde_json::json!({"kind": "directory_progress", "network": "libera"}),
            serde_json::json!({"kind": "directory_progress", "network": "", "count": 1}),
            serde_json::json!({"kind": "directory_complete", "network": "libera", "count": 1}),
        ] {
            assert_eq!(progress(&invalid), None, "{invalid}");
        }
        // `directory_complete` carries `total`, not `count`.
        assert_eq!(
            complete(
                &serde_json::json!({"kind": "directory_complete", "network": "libera", "count": 1})
            ),
            None
        );
        assert_eq!(
            parse_directory_count_signal(
                &serde_json::json!({"kind": "directory_progress", "network": "libera", "count": 1}),
                "grappa:user:other",
                "vjt",
                "directory_progress",
                "count"
            ),
            None
        );
    }

    #[test]
    fn parse_directory_failed_keeps_any_reason() {
        let topic = "grappa:user:vjt";
        assert_eq!(
            parse_directory_failed(
                &serde_json::json!({"kind": "directory_failed", "network": "libera", "reason": "timeout"}),
                topic,
                "vjt"
            ),
            Some(("libera".to_string(), "timeout".to_string()))
        );
        // `reason` is an open set: a future token is kept, not rejected.
        assert_eq!(
            parse_directory_failed(
                &serde_json::json!({"kind": "directory_failed", "network": "libera", "reason": "flood"}),
                topic,
                "vjt"
            ),
            Some(("libera".to_string(), "flood".to_string()))
        );
        for invalid in [
            serde_json::json!({"kind": "directory_failed", "network": "libera"}),
            serde_json::json!({"kind": "directory_failed", "network": "libera", "reason": null}),
            serde_json::json!({"kind": "directory_failed", "network": "", "reason": "timeout"}),
        ] {
            assert_eq!(
                parse_directory_failed(&invalid, topic, "vjt"),
                None,
                "{invalid}"
            );
        }
        assert_eq!(
            parse_directory_failed(
                &serde_json::json!({"kind": "directory_failed", "network": "libera", "reason": "timeout"}),
                "grappa:user:other",
                "vjt"
            ),
            None
        );
    }

    fn dcc_offer_payload() -> Value {
        serde_json::json!({
            "kind": "dcc_offer",
            "network": "libera",
            "channel": "$server",
            "offer_id": "off-1",
            "from": "alice",
            "filename": "notes.txt",
            "size": 1536,
            "future_field": true
        })
    }

    #[test]
    fn parse_dcc_offer_requires_every_field() {
        let topic = "grappa:user:vjt";
        let offer = parse_dcc_offer(&dcc_offer_payload(), topic, "vjt").expect("valid offer");
        assert_eq!(offer.offer_id, "off-1");
        assert_eq!(offer.channel, "$server");
        assert_eq!(offer.size, 1536);
        for key in ["network", "channel", "offer_id", "from", "filename", "size"] {
            let mut missing = dcc_offer_payload();
            missing.as_object_mut().expect("object").remove(key);
            assert_eq!(parse_dcc_offer(&missing, topic, "vjt"), None, "{key}");
        }
        for (key, invalid) in [
            ("size", serde_json::json!(-1)),
            ("size", serde_json::json!("1536")),
            ("offer_id", serde_json::json!("")),
            ("offer_id", serde_json::json!(7)),
            ("network", serde_json::json!(" ")),
        ] {
            let mut payload = dcc_offer_payload();
            payload[key] = invalid;
            assert_eq!(parse_dcc_offer(&payload, topic, "vjt"), None, "{key}");
        }
        assert_eq!(
            parse_dcc_offer(&dcc_offer_payload(), "grappa:user:other", "vjt"),
            None
        );
    }

    #[test]
    fn apply_dcc_offer_replaces_by_offer_id() {
        let topic = "grappa:user:vjt";
        let offer = parse_dcc_offer(&dcc_offer_payload(), topic, "vjt").expect("valid offer");
        let mut offers = Vec::new();
        assert!(apply_dcc_offer(&mut offers, offer.clone()));
        // The subscribe backfill re-sends held offers: same offer, no change.
        assert!(!apply_dcc_offer(&mut offers, offer.clone()));
        let mut renamed = offer.clone();
        renamed.filename = "notes-v2.txt".to_string();
        assert!(apply_dcc_offer(&mut offers, renamed));
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].filename, "notes-v2.txt");
        let mut other = offer;
        other.offer_id = "off-2".to_string();
        assert!(apply_dcc_offer(&mut offers, other));
        assert_eq!(offers.len(), 2);
    }

    #[test]
    fn dcc_offer_resolved_drops_only_a_held_offer() {
        let topic = "grappa:user:vjt";
        let resolved = |resolution: &str| {
            serde_json::json!({
                "kind": "dcc_offer_resolved",
                "network": "libera",
                "channel": "$server",
                "offer_id": "off-1",
                "resolution": resolution
            })
        };
        for (wire, expected) in [
            ("accepted", DccResolution::Accepted),
            ("refused", DccResolution::Refused),
            ("expired", DccResolution::Expired),
        ] {
            assert_eq!(
                parse_dcc_offer_resolved(&resolved(wire), topic, "vjt"),
                Some(("off-1".to_string(), expected))
            );
        }
        // A resolution this client doesn't know drops the event.
        assert_eq!(
            parse_dcc_offer_resolved(&resolved("cancelled"), topic, "vjt"),
            None
        );
        let mut missing_channel = resolved("accepted");
        missing_channel
            .as_object_mut()
            .expect("object")
            .remove("channel");
        assert_eq!(
            parse_dcc_offer_resolved(&missing_channel, topic, "vjt"),
            None
        );
        assert_eq!(
            parse_dcc_offer_resolved(&resolved("accepted"), "grappa:user:other", "vjt"),
            None
        );

        let offer = parse_dcc_offer(&dcc_offer_payload(), topic, "vjt").expect("valid offer");
        let mut offers = vec![offer];
        assert_eq!(apply_dcc_offer_resolved(&mut offers, "unknown"), None);
        assert_eq!(offers.len(), 1);
        let removed = apply_dcc_offer_resolved(&mut offers, "off-1").expect("held");
        assert_eq!(removed.filename, "notes.txt");
        assert!(offers.is_empty());
    }

    #[test]
    fn format_file_size_uses_binary_units() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(1023), "1023 B");
        assert_eq!(format_file_size(1536), "1.5 KiB");
        assert_eq!(format_file_size(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn dcc_answer_errors_map_to_status_keys() {
        assert_eq!(dcc_answer_error_status(Some(404)), "dcc-offer-gone");
        assert_eq!(dcc_answer_error_status(Some(429)), "dcc-rate-limited");
        assert_eq!(dcc_answer_error_status(Some(503)), "dcc-not-connected");
        assert_eq!(dcc_answer_error_status(Some(507)), "dcc-no-space");
        assert_eq!(dcc_answer_error_status(Some(500)), "dcc-action-failed");
        assert_eq!(dcc_answer_error_status(None), "dcc-action-failed");
    }

    #[test]
    fn parse_archive_changed_reads_network_slug() {
        let topic = "grappa:user:vjt";
        assert_eq!(
            parse_archive_changed(
                &serde_json::json!({"kind": "archive_changed", "network_slug": "libera"}),
                topic,
                "vjt"
            ),
            Some("libera".to_string())
        );
        for invalid in [
            serde_json::json!({"kind": "archive_changed", "network": "libera"}),
            serde_json::json!({"kind": "archive_changed", "network_slug": ""}),
            serde_json::json!({"kind": "archive_purged", "network_slug": "libera"}),
        ] {
            assert_eq!(
                parse_archive_changed(&invalid, topic, "vjt"),
                None,
                "{invalid}"
            );
        }
        assert_eq!(
            parse_archive_changed(
                &serde_json::json!({"kind": "archive_changed", "network_slug": "libera"}),
                "grappa:user:other",
                "vjt"
            ),
            None
        );
    }

    #[test]
    fn archive_purged_matches_the_target_case_insensitively() {
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({"kind": "archive_purged", "network_slug": "libera", "target": "#Old"});
        assert_eq!(
            parse_archive_purged(&payload, topic, "vjt"),
            Some(("libera".to_string(), "#Old".to_string()))
        );
        for invalid in [
            serde_json::json!({"kind": "archive_purged", "network_slug": "libera"}),
            serde_json::json!({"kind": "archive_purged", "network_slug": "libera", "target": ""}),
            serde_json::json!({"kind": "archive_purged", "network": "libera", "target": "#old"}),
        ] {
            assert_eq!(
                parse_archive_purged(&invalid, topic, "vjt"),
                None,
                "{invalid}"
            );
        }
        assert_eq!(
            parse_archive_purged(&payload, "grappa:user:other", "vjt"),
            None
        );

        let mapping = cordiale_core::isupport::CaseMapping::Rfc1459;
        let key = |network: &str, window: &str| (network.to_string(), window.to_string());
        assert!(is_purged_window(
            &key("libera", "#old"),
            "libera",
            "#Old",
            mapping
        ));
        assert!(is_purged_window(
            &key("libera", "Nick[a]"),
            "libera",
            "nick{a}",
            mapping
        ));
        assert!(!is_purged_window(
            &key("oftc", "#old"),
            "libera",
            "#Old",
            mapping
        ));
        assert!(!is_purged_window(
            &key("libera", "#older"),
            "libera",
            "#Old",
            mapping
        ));
    }

    #[test]
    fn parse_notify_list_groups_nicks_by_network_id() {
        let topic = "grappa:user:vjt";
        let entry = |network_id: i64, nick: &str| serde_json::json!({"network_id": network_id, "nick": nick, "added_at": "2026-09-23T10:00:00Z"});
        let payload = serde_json::json!({
            "kind": "notify_list",
            "networks": {"7": [entry(7, "alice"), entry(7, "bob")], "9": []}
        });
        let lists = parse_notify_list(&payload, topic, "vjt").expect("valid snapshot");
        assert_eq!(
            lists.get(&7),
            Some(&vec!["alice".to_string(), "bob".to_string()])
        );
        assert_eq!(lists.get(&9), Some(&Vec::new()));
        // An empty snapshot is valid and clears every list.
        assert_eq!(
            parse_notify_list(
                &serde_json::json!({"kind": "notify_list", "networks": {}}),
                topic,
                "vjt"
            ),
            Some(HashMap::new())
        );
        for invalid in [
            serde_json::json!({"kind": "notify_list"}),
            serde_json::json!({"kind": "notify_list", "networks": {"libera": []}}),
            serde_json::json!({"kind": "notify_list", "networks": {"7": [{"network_id": 7, "nick": "alice"}]}}),
            serde_json::json!({"kind": "notify_list", "networks": {"7": [{"network_id": "7", "nick": "alice", "added_at": "x"}]}}),
        ] {
            assert_eq!(parse_notify_list(&invalid, topic, "vjt"), None, "{invalid}");
        }
        assert_eq!(
            parse_notify_list(&payload, "grappa:user:other", "vjt"),
            None
        );
    }

    #[test]
    fn parse_presence_snapshot_keeps_unknown_distinct() {
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({
            "kind": "presence_snapshot",
            "network_id": 7,
            "nicks": {"alice": "online", "Bob": "offline", "carol": "unknown"}
        });
        let (network_id, nicks) =
            parse_presence_snapshot(&payload, topic, "vjt").expect("valid snapshot");
        assert_eq!(network_id, 7);
        assert_eq!(nicks.get("alice"), Some(&Presence::Online));
        assert_eq!(nicks.get("bob"), Some(&Presence::Offline));
        assert_eq!(nicks.get("carol"), Some(&Presence::Unknown));
        for invalid in [
            serde_json::json!({"kind": "presence_snapshot", "network_id": 7, "nicks": {"alice": "away"}}),
            serde_json::json!({"kind": "presence_snapshot", "network_id": "7", "nicks": {}}),
            serde_json::json!({"kind": "presence_snapshot", "network_id": 7}),
        ] {
            assert_eq!(
                parse_presence_snapshot(&invalid, topic, "vjt"),
                None,
                "{invalid}"
            );
        }
        assert_eq!(
            parse_presence_snapshot(&payload, "grappa:user:other", "vjt"),
            None
        );
        // ASCII folding only: IRC brackets are not folded for presence keys.
        assert_eq!(presence_key("Nick[A]"), "nick[a]");
    }

    #[test]
    fn parse_presence_changed_validates_closed_sets() {
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({
            "kind": "presence_changed",
            "network_id": 7,
            "nick": "Alice",
            "presence": "online",
            "initial": false,
            "source": "monitor",
            "ts": "2026-09-23T10:00:00Z"
        });
        assert_eq!(
            parse_presence_changed(&payload, topic, "vjt"),
            Some(PresenceChange {
                network_id: 7,
                nick: "Alice".to_string(),
                presence: Presence::Online,
                initial: false,
            })
        );
        for (key, invalid) in [
            ("presence", serde_json::json!("unknown")),
            ("source", serde_json::json!("guess")),
            ("initial", serde_json::json!("false")),
            ("ts", serde_json::json!(1)),
            ("nick", serde_json::json!("")),
            ("network_id", serde_json::json!("7")),
        ] {
            let mut changed = payload.clone();
            changed[key] = invalid;
            assert_eq!(
                parse_presence_changed(&changed, topic, "vjt"),
                None,
                "{key}"
            );
        }
        assert_eq!(
            parse_presence_changed(&payload, "grappa:user:other", "vjt"),
            None
        );
    }

    #[test]
    fn parse_presence_error_keeps_reason_open() {
        let topic = "grappa:user:vjt";
        let payload = |reason: &str| serde_json::json!({"kind": "presence_error", "network_id": 7, "reason": reason, "detail": "alice,bob"});
        assert_eq!(
            parse_presence_error(&payload("list_full"), topic, "vjt"),
            Some((7, "list_full".to_string(), "alice,bob".to_string()))
        );
        assert_eq!(
            parse_presence_error(&payload("target_rejected"), topic, "vjt"),
            Some((7, "target_rejected".to_string(), "alice,bob".to_string()))
        );
        let mut missing_detail = payload("list_full");
        missing_detail
            .as_object_mut()
            .expect("object")
            .remove("detail");
        assert_eq!(parse_presence_error(&missing_detail, topic, "vjt"), None);
        assert_eq!(
            parse_presence_error(&payload("list_full"), "grappa:user:other", "vjt"),
            None
        );
    }

    #[test]
    fn parse_peer_away_allows_an_empty_message() {
        let topic = "grappa:user:vjt";
        let payload = |message: Value| serde_json::json!({"kind": "peer_away", "network": "libera", "peer": "Alice", "message": message});
        assert_eq!(
            parse_peer_away(&payload(serde_json::json!("lunch")), topic, "vjt"),
            Some((
                "libera".to_string(),
                "Alice".to_string(),
                "lunch".to_string()
            ))
        );
        assert_eq!(
            parse_peer_away(&payload(serde_json::json!("")), topic, "vjt"),
            Some(("libera".to_string(), "Alice".to_string(), String::new()))
        );
        assert_eq!(parse_peer_away(&payload(Value::Null), topic, "vjt"), None);
        assert_eq!(
            parse_peer_away(
                &serde_json::json!({"kind": "peer_away", "network": "libera", "peer": "", "message": "x"}),
                topic,
                "vjt"
            ),
            None
        );
        assert_eq!(
            parse_peer_away(
                &payload(serde_json::json!("lunch")),
                "grappa:user:other",
                "vjt"
            ),
            None
        );
    }

    #[test]
    fn parse_mentions_bundle_keeps_order_and_null_bodies() {
        let topic = "grappa:user:vjt";
        let message = |kind: &str, body: Value| serde_json::json!({"server_time": 1790000000000_i64, "channel": "#rust", "sender": "alice", "body": body, "kind": kind});
        let payload = serde_json::json!({
            "kind": "mentions_bundle",
            "network": "libera",
            "away_started_at": "2026-09-23T08:00:00Z",
            "away_ended_at": "2026-09-23T09:00:00Z",
            "away_reason": null,
            "messages": [message("privmsg", serde_json::json!("vjt: ping")), message("action", Value::Null)]
        });
        let view = parse_mentions_bundle(&payload, topic, "vjt").expect("valid bundle");
        assert_eq!(view.kind, "mentions_bundle");
        assert_eq!(view.network, "libera");
        // Away period, then the two messages in order; no reason row for null.
        assert_eq!(view.rows.len(), 3);
        assert_eq!(view.rows[0].0, "mentions-away-period");
        assert!(view.rows[1].1.ends_with("#rust <alice> vjt: ping"));
        assert!(view.rows[2].1.ends_with("#rust * alice "));

        let mut with_reason = payload.clone();
        with_reason["away_reason"] = serde_json::json!("lunch");
        let view = parse_mentions_bundle(&with_reason, topic, "vjt").expect("valid bundle");
        assert_eq!(
            view.rows[1],
            ("mentions-away-reason".to_string(), "lunch".to_string())
        );

        for (key, invalid) in [
            (
                "messages",
                serde_json::json!([message("wallops", serde_json::json!("x"))]),
            ),
            (
                "messages",
                serde_json::json!([{"server_time": "1", "channel": "#rust", "sender": "a", "body": null, "kind": "privmsg"}]),
            ),
            ("away_reason", serde_json::json!(5)),
            ("away_ended_at", Value::Null),
        ] {
            let mut bad = payload.clone();
            bad[key] = invalid;
            assert!(parse_mentions_bundle(&bad, topic, "vjt").is_none(), "{key}");
        }
        assert!(parse_mentions_bundle(&payload, "grappa:user:other", "vjt").is_none());
    }

    #[test]
    fn parse_server_settings_changed_requires_the_core_caps() {
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({
            "kind": "server_settings_changed",
            "upload": {
                "active_host": "embedded",
                "image_per_file_cap_bytes": 10485760,
                "video_per_file_cap_bytes": 52428800,
                "document_per_file_cap_bytes": 20971520,
                "audio_per_file_cap_bytes": 20971520,
                "global_cap_bytes": 1073741824,
                "per_user_cap_bytes": 104857600,
                "per_visitor_cap_bytes": 10485760,
                "video_max_duration_seconds": 120
            },
            "http_host_aliases": ["irc.example.org"]
        });
        let limits = parse_server_settings_changed(&payload, topic, "vjt").expect("valid snapshot");
        assert_eq!(limits.host, "embedded");
        assert_eq!(limits.image_bytes, 10485760);
        assert_eq!(limits.video_seconds, Some(120));

        // Optional fields may be missing without dropping the snapshot.
        let mut optional_missing = payload.clone();
        optional_missing["upload"]
            .as_object_mut()
            .expect("object")
            .remove("video_max_duration_seconds");
        optional_missing
            .as_object_mut()
            .expect("object")
            .remove("http_host_aliases");
        let limits =
            parse_server_settings_changed(&optional_missing, topic, "vjt").expect("still valid");
        assert_eq!(limits.video_seconds, None);

        for (key, invalid) in [
            ("active_host", serde_json::json!("s3")),
            ("image_per_file_cap_bytes", serde_json::json!(0)),
            ("global_cap_bytes", Value::Null),
            ("audio_per_file_cap_bytes", serde_json::json!("20971520")),
        ] {
            let mut bad = payload.clone();
            bad["upload"][key] = invalid;
            assert_eq!(
                parse_server_settings_changed(&bad, topic, "vjt"),
                None,
                "{key}"
            );
        }
        assert_eq!(
            parse_server_settings_changed(&payload, "grappa:user:other", "vjt"),
            None
        );
    }

    #[test]
    fn parse_bundle_hash_treats_version_as_optional() {
        let topic = "grappa:user:vjt";
        assert_eq!(
            parse_bundle_hash(
                &serde_json::json!({"kind": "bundle_hash", "hash": "abc123", "version": "1.4.2"}),
                topic,
                "vjt"
            ),
            Some(("abc123".to_string(), Some("1.4.2".to_string())))
        );
        for version in [None, Some(Value::Null), Some(serde_json::json!(""))] {
            let mut payload = serde_json::json!({"kind": "bundle_hash", "hash": "abc123"});
            if let Some(version) = version {
                payload["version"] = version;
            }
            assert_eq!(
                parse_bundle_hash(&payload, topic, "vjt"),
                Some(("abc123".to_string(), None))
            );
        }
        for invalid in [
            serde_json::json!({"kind": "bundle_hash", "hash": ""}),
            serde_json::json!({"kind": "bundle_hash"}),
        ] {
            assert_eq!(parse_bundle_hash(&invalid, topic, "vjt"), None, "{invalid}");
        }
        assert_eq!(
            parse_bundle_hash(
                &serde_json::json!({"kind": "bundle_hash", "hash": "abc123"}),
                "grappa:user:other",
                "vjt"
            ),
            None
        );
    }

    #[test]
    fn archive_errors_single_out_rate_limiting() {
        assert_eq!(
            archive_error_key(Some(429), "archive-fetch-failed"),
            "archive-rate-limited"
        );
        assert_eq!(
            archive_error_key(Some(500), "archive-fetch-failed"),
            "archive-fetch-failed"
        );
        assert_eq!(
            archive_error_key(None, "archive-delete-failed"),
            "archive-delete-failed"
        );
    }

    #[test]
    fn invite_command_defaults_to_the_open_channel() {
        assert_eq!(
            parse_reply_command("/invite alice", "#rust"),
            Some(ReplyCommand::Request {
                verb: "invite",
                payload: serde_json::json!({"channel": "#rust", "nick": "alice"})
            })
        );
        assert_eq!(
            parse_reply_command("/invite alice #other", "bob"),
            Some(ReplyCommand::Request {
                verb: "invite",
                payload: serde_json::json!({"channel": "#other", "nick": "alice"})
            })
        );
        assert_eq!(
            parse_reply_command("/invite", "#rust"),
            Some(ReplyCommand::Usage)
        );
        // A query window has no channel to invite into.
        assert_eq!(
            parse_reply_command("/invite alice", "bob"),
            Some(ReplyCommand::Usage)
        );
    }

    #[test]
    fn parse_invite_ack_requires_every_field() {
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({
            "kind": "invite_ack",
            "network": "azzurra",
            "channel": "#rust",
            "peer": "alice",
            "future_field": 1
        });
        assert_eq!(
            parse_invite_ack(&payload, topic, "vjt"),
            Some((
                "azzurra".to_string(),
                "#rust".to_string(),
                "alice".to_string()
            ))
        );
        for key in ["network", "channel", "peer"] {
            let mut missing = payload.clone();
            missing.as_object_mut().expect("object").remove(key);
            assert_eq!(parse_invite_ack(&missing, topic, "vjt"), None, "{key}");
            let mut empty = payload.clone();
            empty[key] = serde_json::json!("");
            assert_eq!(parse_invite_ack(&empty, topic, "vjt"), None, "{key}");
        }
        assert_eq!(parse_invite_ack(&payload, "grappa:user:other", "vjt"), None);
    }

    #[test]
    fn lusers_command_sends_mask_and_server_only_when_given() {
        let request = |payload: Value| {
            Some(ReplyCommand::Request {
                verb: "lusers",
                payload,
            })
        };
        assert_eq!(
            parse_reply_command("/lusers", "#rust"),
            request(serde_json::json!({}))
        );
        assert_eq!(
            parse_reply_command("/lusers *", "#rust"),
            request(serde_json::json!({"mask": "*"}))
        );
        assert_eq!(
            parse_reply_command("/LUSERS * irc.example.org extra", "#rust"),
            request(serde_json::json!({"mask": "*", "server": "irc.example.org"}))
        );
    }

    #[test]
    fn parse_lusers_bundle_shows_unknown_counters_without_dropping_the_rest() {
        let topic = "grappa:user:vjt";
        let payload = serde_json::json!({
            "kind": "lusers_bundle",
            "network": "azzurra",
            "total_users": 120,
            "invisible": 30,
            "servers": 4,
            "operators": 2,
            "unknown_connections": null,
            "channels_formed": 55,
            "local_clients": 40,
            "local_servers": 1,
            "current_local": 40,
            "max_local": 90,
            "current_global": "garbled",
            "future_field": true
        });
        let view = parse_lusers_bundle(&payload, topic, "vjt").expect("valid bundle");
        assert_eq!(view.kind, "lusers_bundle");
        assert_eq!(view.network, "azzurra");
        assert_eq!(view.rows.len(), 12);
        assert_eq!(
            view.rows[0],
            ("lusers-total-users".to_string(), "120".to_string())
        );
        assert_eq!(
            view.rows[4],
            ("lusers-unknown-connections".to_string(), "—".to_string())
        );
        // A non-integer counter and a missing one both read as unknown.
        assert_eq!(view.rows[10].1, "—");
        assert_eq!(view.rows[11].1, "—");

        for invalid in [
            serde_json::json!({"kind": "lusers_bundle", "total_users": 1}),
            serde_json::json!({"kind": "lusers_bundle", "network": ""}),
            serde_json::json!({"kind": "lusers_bundle", "network": 7}),
            serde_json::json!({"kind": "whowas_bundle", "network": "azzurra"}),
        ] {
            assert!(
                parse_lusers_bundle(&invalid, topic, "vjt").is_none(),
                "{invalid}"
            );
        }
        assert!(parse_lusers_bundle(&payload, "grappa:user:other", "vjt").is_none());
    }

    #[test]
    fn parse_nullable_setting_echo_keeps_null_distinct_from_missing() {
        let topic = "grappa:user:vjt";
        let kind = "quit_part_reason_changed";
        let key = "quit_part_reason";
        let payload = |value: Value| serde_json::json!({"kind": kind, key: value});
        assert_eq!(
            parse_nullable_setting_echo(&payload(Value::Null), topic, "vjt", kind, key),
            Some(None)
        );
        assert_eq!(
            parse_nullable_setting_echo(
                &payload(serde_json::json!("bye")),
                topic,
                "vjt",
                kind,
                key
            ),
            Some(Some("bye".to_string()))
        );
        assert_eq!(
            parse_nullable_setting_echo(&payload(serde_json::json!("")), topic, "vjt", kind, key),
            Some(Some(String::new()))
        );

        for invalid in [
            payload(serde_json::json!(1)),
            payload(serde_json::json!(["bye"])),
            serde_json::json!({"kind": kind}),
            serde_json::json!({"kind": "auto_away_reason_changed", key: "bye"}),
        ] {
            assert_eq!(
                parse_nullable_setting_echo(&invalid, topic, "vjt", kind, key),
                None,
                "{invalid}"
            );
        }
        assert_eq!(
            parse_nullable_setting_echo(
                &payload(Value::Null),
                "grappa:user:other",
                "vjt",
                kind,
                key
            ),
            None
        );
        // The auto-away echo shares the shape under its own kind and key.
        assert_eq!(
            parse_nullable_setting_echo(
                &serde_json::json!({"kind": "auto_away_reason_changed", "auto_away_reason": null}),
                topic,
                "vjt",
                "auto_away_reason_changed",
                "auto_away_reason"
            ),
            Some(None)
        );
    }

    #[test]
    fn whois_command_requires_a_nick() {
        assert_eq!(
            parse_reply_command("/whois alice", "#rust"),
            Some(ReplyCommand::Request {
                verb: "whois",
                payload: serde_json::json!({"nick": "alice", "server": null, "source": "user"})
            })
        );
        assert_eq!(
            parse_reply_command("/whois alice irc.example.org", "#rust"),
            Some(ReplyCommand::Request {
                verb: "whois",
                payload: serde_json::json!({
                    "nick": "alice",
                    "server": "irc.example.org",
                    "source": "user"
                })
            })
        );
        assert_eq!(
            parse_reply_command("/whois", "#rust"),
            Some(ReplyCommand::Usage)
        );
        assert_eq!(format_idle(59), "0:00:59");
        assert_eq!(format_idle(-5), "0:00:00");
    }

    #[test]
    fn who_command_defaults_to_the_open_window() {
        assert_eq!(
            parse_reply_command("/who", "#rust"),
            Some(ReplyCommand::Request {
                verb: "who",
                payload: serde_json::json!({"channel": "#rust"})
            })
        );
        assert_eq!(
            parse_reply_command("/WHO #other extra", "#rust"),
            Some(ReplyCommand::Request {
                verb: "who",
                payload: serde_json::json!({"channel": "#other"})
            })
        );
        assert_eq!(parse_reply_command("/who", ""), Some(ReplyCommand::Usage));
        assert_eq!(parse_reply_command("hello /who", "#rust"), None);
        assert_eq!(parse_reply_command("/whoever", "#rust"), None);
    }

    #[test]
    fn connecting_label_outranks_the_durable_connection_label() {
        let entries = vec![
            (
                "libera".to_string(),
                "#rust".to_string(),
                "#rust".to_string(),
            ),
            (
                "oftc".to_string(),
                "#debian".to_string(),
                "#debian".to_string(),
            ),
        ];
        let connection_states = HashMap::from([(
            "libera".to_string(),
            NetworkConnectionSnapshot {
                status: NetworkConnectionStatus::Failing,
                reason: None,
                changed_at: None,
            },
        )]);
        let mut groups = network_groups_data(
            &entries,
            &[],
            &HashMap::new(),
            &connection_states,
            &HashMap::new(),
        );
        let connecting = std::collections::HashSet::from(["libera".to_string()]);
        apply_connecting_labels(&mut groups, &connecting);
        assert_eq!(groups[0].0, "libera");
        assert_eq!(groups[0].4, "connecting");
        assert_eq!(groups[1].0, "oftc");
        assert_eq!(groups[1].4, "");
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
    fn parse_connection_state_changed_accepts_guest_user_topic_and_additive_fields() {
        let payload = serde_json::json!({
            "kind": "connection_state_changed",
            "user_id": null,
            "network_id": 7,
            "network_slug": "libera",
            "from": "connected",
            "to": "failing",
            "reason": "connection lost",
            "at": "2026-09-22T10:20:30Z",
            "network": {
                "slug": "libera",
                "nick": "sythos",
                "connection_state": "failing",
                "connection_state_reason": "connection lost",
                "connection_state_changed_at": "2026-09-22T10:20:30Z",
                "future_field": true
            },
            "future_field": true
        });

        let transition =
            parse_connection_state_changed_event(&payload, "grappa:user:guest", "guest")
                .expect("valid visitor transition");
        assert_eq!(transition.network_id, 7);
        assert_eq!(transition.network_slug, "libera");
        assert_eq!(transition.from, NetworkConnectionStatus::Connected);
        assert_eq!(transition.snapshot.status, NetworkConnectionStatus::Failing);
        assert_eq!(
            transition.snapshot.reason.as_deref(),
            Some("connection lost")
        );
        assert_eq!(
            transition.snapshot.changed_at.as_deref(),
            Some("2026-09-22T10:20:30Z")
        );
    }

    #[test]
    fn parse_connection_state_changed_rejects_invalid_or_mismatched_rows() {
        let valid = serde_json::json!({
            "kind": "connection_state_changed",
            "user_id": "user-1",
            "network_id": 7,
            "network_slug": "libera",
            "from": "failing",
            "to": "failed",
            "reason": null,
            "at": null,
            "network": {
                "id": 7,
                "slug": "libera",
                "connection_state": "failed",
                "connection_state_reason": null,
                "connection_state_changed_at": null
            }
        });
        assert!(
            parse_connection_state_changed_event(&valid, "grappa:user:sythos", "sythos").is_some()
        );

        for (path, value) in [
            ("user_id", serde_json::json!(7)),
            ("network_id", serde_json::json!(0)),
            ("from", serde_json::json!("unknown")),
            ("to", serde_json::json!("unknown")),
            ("network_slug", serde_json::json!("other")),
        ] {
            let mut invalid = valid.clone();
            invalid[path] = value;
            assert!(
                parse_connection_state_changed_event(&invalid, "grappa:user:sythos", "sythos")
                    .is_none()
            );
        }

        let mut mismatched_slug = valid.clone();
        mismatched_slug["network"]["slug"] = serde_json::json!("other");
        assert!(parse_connection_state_changed_event(
            &mismatched_slug,
            "grappa:user:sythos",
            "sythos"
        )
        .is_none());

        let mut mismatched_status = valid.clone();
        mismatched_status["network"]["connection_state"] = serde_json::json!("failing");
        assert!(parse_connection_state_changed_event(
            &mismatched_status,
            "grappa:user:sythos",
            "sythos"
        )
        .is_none());

        let mut mismatched_id = valid.clone();
        mismatched_id["network"]["id"] = serde_json::json!(9);
        assert!(parse_connection_state_changed_event(
            &mismatched_id,
            "grappa:user:sythos",
            "sythos"
        )
        .is_none());

        assert!(
            parse_connection_state_changed_event(&valid, "grappa:user:other", "sythos").is_none()
        );
    }

    #[test]
    fn network_connection_states_keep_failing_distinct_from_terminal_failure() {
        let states = network_connection_states_from_entries(&[
            serde_json::json!({"slug":"libera", "connection_state":"failing"}),
            serde_json::json!({"slug":"oftc", "connection_state":"failed"}),
            serde_json::json!({"slug":"bad", "connection_state":"future_state"}),
        ]);

        assert_eq!(states.len(), 2);
        assert_eq!(states["libera"].status.sidebar_label(), "reconnecting");
        assert_eq!(states["oftc"].status.sidebar_label(), "connection failed");
    }

    #[test]
    fn network_connection_transition_returns_home_only_on_a_new_terminal_state() {
        let mut states = network_connection_states_from_entries(&[
            serde_json::json!({"slug":"libera", "connection_state":"connected"}),
            serde_json::json!({"slug":"oftc", "connection_state":"failing"}),
            serde_json::json!({"slug":"already-parked", "connection_state":"parked"}),
        ]);
        let parked = NetworkConnectionSnapshot {
            status: NetworkConnectionStatus::Parked,
            reason: None,
            changed_at: Some("2026-09-22T10:20:30Z".to_string()),
        };

        assert_eq!(
            record_network_connection_state(&mut states, "libera", parked.clone()),
            (true, true)
        );
        assert_eq!(
            record_network_connection_state(&mut states, "libera", parked.clone()),
            (false, false)
        );
        assert_eq!(
            record_network_connection_state(&mut states, "already-parked", parked.clone()),
            (false, false)
        );

        let failed = NetworkConnectionSnapshot {
            status: NetworkConnectionStatus::Failed,
            reason: None,
            changed_at: None,
        };
        assert_eq!(
            record_network_connection_state(&mut states, "oftc", failed),
            (true, true)
        );
    }

    #[test]
    fn network_groups_show_per_network_connection_state() {
        let entries = vec![(
            "libera".to_string(),
            "#rust".to_string(),
            "#rust".to_string(),
        )];
        let connection_states = HashMap::from([(
            "libera".to_string(),
            NetworkConnectionSnapshot {
                status: NetworkConnectionStatus::Parked,
                reason: None,
                changed_at: None,
            },
        )]);
        let groups = network_groups_data(
            &entries,
            &[],
            &HashMap::new(),
            &connection_states,
            &HashMap::new(),
        );
        assert_eq!(groups[0].4, "paused");
        assert!(groups[0].5);
        assert!(!groups[0].1);
        let reopened = network_groups_data(
            &entries,
            &[],
            &HashMap::from([("libera".to_string(), true)]),
            &connection_states,
            &HashMap::new(),
        );
        assert!(reopened[0].1);
    }

    #[test]
    fn a_network_remains_in_the_sidebar_after_its_last_channel_is_removed() {
        let networks = HashMap::from([("libera".to_string(), 7)]);
        let groups = network_groups_data(&[], &[], &HashMap::new(), &HashMap::new(), &networks);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "libera");
        assert!(groups[0].2.is_empty());
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
        let message_snapshot = |messages: &HashMap<(String, String), Vec<RenderedMessage>>| {
            let mut snapshot = messages
                .iter()
                .map(|(key, messages)| {
                    (
                        key.clone(),
                        messages
                            .iter()
                            .map(|message| {
                                (
                                    message.timestamp.clone(),
                                    message.nick.clone(),
                                    message.text.clone(),
                                    message.italic,
                                    message.message_id,
                                    message.server_time,
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            snapshot.sort_by(|left, right| left.0.cmp(&right.0));
            snapshot
        };
        let first_messages = message_snapshot(&state.messages);
        let first_members = state.members.clone();
        let first_cursors = state.read_cursors.clone();
        let first_counts = (state.window_messages.clone(), state.window_mentions.clone());

        let second_actions = apply_network_rest_refresh(&mut state, "sythos", &boot, &me);

        assert_eq!(first_actions.len(), 2);
        assert!(second_actions.is_empty());
        assert_eq!(state.channel_entries, first_channel_entries);
        assert_eq!(state.joined_topics, first_joined_topics);
        assert_eq!(message_snapshot(&state.messages), first_messages);
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
    fn authoritative_refresh_removes_deleted_network_windows_and_listeners() {
        let mut state = WorkerState::new();
        state.identifier = Some("sythos".to_string());
        state.network_ids.insert("deleted".to_string(), 9);
        state.query_windows.push(QueryWindow {
            network: "deleted".to_string(),
            target_nick: "alice".to_string(),
            opened_at: "now".to_string(),
        });
        let obsolete_topic = channel_topic("sythos", "deleted", "alice");
        state.joined_topics.insert(obsolete_topic.clone());
        state
            .query_ready
            .insert(("deleted".to_string(), "alice".to_string()));
        let boot = BootResponse {
            networks: vec![serde_json::json!({"id": 7, "slug": "libera", "nick": "sythos"})],
            channels: HashMap::from([(
                "deleted".to_string(),
                vec![serde_json::json!({"name": "#stale", "joined": true})],
            )]),
            heads: HashMap::new(),
        };
        let me = MeResponse {
            read_cursors: serde_json::json!({}),
            unread_counts: serde_json::json!({}),
            badge_count: serde_json::json!(0),
            is_admin: false,
        };
        let actions = apply_network_rest_refresh(&mut state, "sythos", &boot, &me);
        assert_eq!(actions.len(), 2);
        assert!(actions.contains(&ChannelTopicAction::Leave(obsolete_topic)));
        assert!(actions.contains(&ChannelTopicAction::Join(channel_topic(
            "sythos", "libera", "sythos"
        ))));
        assert!(!state.network_ids.contains_key("deleted"));
        assert!(state.channel_entries.is_empty());
        assert!(state.query_windows.is_empty());
        assert!(state.query_ready.is_empty());
        assert_eq!(
            state.joined_topics,
            std::collections::HashSet::from([channel_topic("sythos", "libera", "sythos")])
        );
        let groups = network_groups_data(
            &state.channel_entries,
            &state.query_windows,
            &state.expanded_networks,
            &state.network_connection_states,
            &state.network_ids,
        );
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "libera");
    }

    #[test]
    fn read_cursor_write_back_is_forward_only() {
        let mut state = WorkerState::new();
        let key = ("libera".to_string(), "#Rust".to_string());
        let line = |id| RenderedMessage {
            timestamp: "10:00".to_string(),
            nick: Some("foo".to_string()),
            text: "hi".to_string(),
            italic: false,
            message_id: Some(id),
            server_time: Some(id),
        };
        assert_eq!(read_cursor_to_write(&mut state), None);
        state.current_channel = Some(key.clone());
        state.messages.insert(key.clone(), vec![line(7), line(9)]);
        assert_eq!(
            read_cursor_to_write(&mut state),
            Some(("libera".to_string(), "#Rust".to_string(), 9))
        );
        assert_eq!(
            state.read_cursors.get(&window_state_key("libera", "#Rust")),
            Some(&9)
        );
        assert_eq!(read_cursor_to_write(&mut state), None);
        state.messages.get_mut(&key).unwrap().push(line(12));
        assert_eq!(
            read_cursor_to_write(&mut state),
            Some(("libera".to_string(), "#Rust".to_string(), 12))
        );
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
