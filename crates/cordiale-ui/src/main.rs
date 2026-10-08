#![windows_subsystem = "windows"]

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

mod admin_handlers;
mod admin_uploads;
mod ceremony;
#[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
mod ceremony_ctap;
mod channels;
mod dates;
mod debug_info;
mod frames;
mod history;
mod home;
#[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
mod key_prompt;
mod mentions;
mod passkeys;
mod player;
mod queries;
mod reply;
mod slash;
mod taskbar;
mod totp;
mod ui_callbacks;
#[cfg(windows)]
mod webauthn_windows;
mod worker_commands;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Number, Value};
use tokio::sync::mpsc;

use cordiale_core::bootstrap::{
    bootstrap, bootstrap_with_bearer, bootstrap_with_login_bearer, bootstrap_with_recovery_code,
    bootstrap_with_share_token, bootstrap_with_totp, BootstrapError, BootstrapOutcome,
};
use cordiale_core::cleartext;
use cordiale_core::client::{GrappaClient, GrappaClientError, LoginError};
use cordiale_core::credentials::{
    resolve_credential_store, CredentialStore, KeyringCredentialStore,
};
use cordiale_core::domain::{AuthMethod, Profile};
use cordiale_core::isupport::{parse_isupport_changed, IsupportState};
use cordiale_core::passkey_origin::{check_override, passkey_origin, OverrideCheck};
use cordiale_core::persistence::{self, Theme};
use cordiale_core::presence::{
    is_presence_noise, presence_hidden, reconcile, toggled_pref, PresencePref,
};
use cordiale_core::profile::{gender_for_index, has_avatar, IgnoreEntry, ProfileFields};
use cordiale_core::protocol::CLIENT_PROTOCOL_VERSION;
use cordiale_core::rest::{
    ActiveThemePair, ArchiveEntry, BootResponse, DateFormat, DirectoryPage, DisplayPrefs,
    LoginRequest, MeResponse, SendMessageRequest,
};
use cordiale_core::rest::{PasskeyMode, PasskeyOptions, PasskeyRequestOptions};
use cordiale_core::session::{spawn_session, SessionEvent, SessionHandle};
use cordiale_core::share;
use cordiale_core::theme::{font_family_for, ThemePalette, BUILTIN_THEMES};
use cordiale_core::upload::{
    attachment_message, mime_for_filename, remaining_lifetime_label, UploadCategory,
};
use cordiale_core::video_processing::{self, ShrinkError};
use cordiale_core::wire_event::ClientEventKind;

use admin_handlers::*;
use channels::*;
use frames::*;
use history::*;
use mentions::*;
use queries::*;
use slash::*;
use ui_callbacks::*;
use worker_commands::*;

/// The default server offered on first launch.
const DEFAULT_SERVER_URL: &str = "https://irc.sindro.me";

/// Everything the UI thread can ask the background worker to do. Sent over
/// a plain `tokio::sync::mpsc` channel whose sender is a normal, non-async
/// value — callbacks fire on the UI thread and just call `.send()`.
enum WorkerCommand {
    /// The TOTP or recovery code for the pending sign-in.
    TotpVerify(String),
    /// Leaves the code step and forgets its challenge.
    TotpCancel,
    /// Settings > Security: reads the TOTP status.
    SecurityTotpRefresh,
    /// Starts TOTP enrolment with the account password.
    SecurityTotpStart(String),
    /// Arms TOTP with the first code from the authenticator app.
    SecurityTotpConfirm(String),
    /// Disarms TOTP with the account password.
    SecurityTotpDisable(String),
    /// Closes the enrolment or recovery-codes step.
    SecurityTotpDone,
    /// Connect screen: signs in with a share token or link minted on another
    /// device.
    ShareConsume {
        server_url: String,
        input: String,
    },
    /// Connect screen: signs a passwordless account in with one of its
    /// recovery codes. The code is a credential and only lives in this
    /// message.
    RecoverySignIn {
        server_url: String,
        identifier: String,
        code: String,
    },
    /// Settings > Security: mints a share token for this session.
    SecurityShareMint,
    /// Settings > Security: reads the passkey mode and list.
    SecurityPasskeysRefresh,
    /// Deletes a passkey (`id`) with the account password.
    SecurityPasskeyDelete {
        id: String,
        password: String,
    },
    /// Signs in with a passkey (issue #160).
    PasskeySignIn(PasskeySignIn),
    /// Settings > Security: registers a passkey (name, password).
    SecurityPasskeyAdd {
        name: String,
        password: String,
    },
    /// Switches the account to `second_factor` or `disabled`.
    SecurityPasskeyMode {
        mode: PasskeyMode,
        password: String,
    },
    /// First step to passwordless: shows the recovery codes.
    SecurityPasswordlessPrepare(String),
    /// Arms passwordless once the codes were saved.
    SecurityPasswordlessActivate,
    /// Leaves the passwordless step, armed or not: forgets the codes and
    /// their token.
    SecurityPasswordlessCancel,
    Connect {
        server_url: String,
        identifier: String,
        credential: ConnectCredential,
    },
    SelectChannel {
        network: String,
        channel: String,
    },
    SelectNetwork(String),
    /// Home page: parks a connected network (after its confirmation).
    HomeDisconnect(String),
    HomeReconnect(String),
    /// Home page: detaches a network from the session (after confirmation).
    HomeRemove(String),
    HomeRecover(String),
    /// Home page: attaches an available network.
    HomeConnect(String),
    /// Home page: a featured channel, joined first when it isn't.
    HomeFeaturedOpen {
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
    /// Invite banner: declines the invite over REST. The banner itself is
    /// removed only by the `window_invite_declined` push.
    DeclineInvite {
        network: String,
        channel: String,
    },
    DismissRecover,
    DirectoryRefresh,
    DirectoryLoadMore,
    DirectorySort(String),
    DirectorySearch(String),
    DirectoryClose,
    /// The sidebar "Channels" entry of a network: opens its directory.
    DirectoryOpen(String),
    /// A directory row: joins the channel (or opens it when joined).
    DirectoryActivate(String),
    DccOfferAnswer {
        network: String,
        offer_id: String,
        accept: bool,
    },
    ArchiveDelete(String),
    /// A link clicked in the chat: the viewer or the browser opens it.
    OpenLink(String),
    /// Tunes a station: `builtin:<id>` or `custom:<index>`.
    RadioTune(String),
    RadioStop,
    /// Volume from 0 to 100.
    RadioVolume(i32),
    RadioEvent(u64, player::PlayerEvent),
    RadioTrack {
        generation: u64,
        track: Option<cordiale_core::radio::Track>,
    },
    ArchiveClose,
    /// Backfills the next channel queued after a reconnect, one at a time.
    CatchUpNext,
    /// Flips one user mode of the network shown in the user-mode view.
    UmodeToggle(String),
    UmodeClose,
    DismissPeerAway,
    ToggleNetwork(String),
    SendMessage {
        body: String,
    },
    /// A picked file and what was chosen for it.
    AttachFile(std::path::PathBuf, UploadOptions),
    UploadPrefsChanged {
        ttl: Option<i64>,
        confirm: bool,
    },
    ComposeTextChanged(String),
    ToggleTheme,
    SelectColorTheme(String),
    /// Night slot of the account's theme pair; "" goes back to one theme.
    SelectNightTheme(String),
    /// Opens the theme editor on a theme key, or on a copy of the theme in
    /// use for "".
    ThemeEdit(String),
    ThemeSave {
        theme_id: Option<i64>,
        name: String,
        payload: Value,
    },
    ThemeDelete(i64),
    ThemePublish(i64, bool),
    ThemeCopy(i64),
    ThemeBackgroundUpload(std::path::PathBuf),
    /// Leaves the editor, putting back the theme in use.
    ThemeEditorCancel,
    /// The OS switched between light (`false`) and dark (`true`).
    SystemScheme(bool),
    /// The window is now in the foreground (`true`) or not (`false`).
    Foreground(bool),
    /// The app is quitting: tells Grappa, then signals `done`.
    Quit(std::sync::mpsc::Sender<()>),
    SaveDisplayPrefs(DisplayPrefs),
    LoadNotificationPrefs,
    EditNotificationPrefs(NotificationEdit),
    MuteCurrentWindow(i32),
    /// Turns Denoise on or off for the open channel.
    ToggleDenoise,
    SaveNotificationPrefs(NotificationToggles),
    AdminRefresh,
    AdminDisconnectSession(String),
    AdminReconnectSession(String),
    AdminTerminateSession(String),
    AdminUserToggleAdmin(String, bool),
    AdminUserDelete(String),
    AdminVisitorDelete(String),
    AdminUploadsRefresh,
    /// Early delete of a live upload, by id (after its confirmation).
    AdminUploadDelete(String),
    AdminNetworkResetCircuit(String),
    AdminUserCreate {
        name: String,
        password: String,
        is_admin: bool,
    },
    AdminUserSetPassword {
        user_id: String,
        password: String,
    },
    AdminNetworkCreate(String),
    AdminServersLoad(String),
    AdminCredentialBind {
        user_id: String,
        network_id: String,
        nick: String,
        auth_method: String,
        password: String,
    },
    AdminCredentialUnbind {
        user_id: String,
        network_id: String,
    },
    AdminVhostAdd {
        address: String,
        in_pool: bool,
    },
    AdminVhostSet {
        vhost_id: String,
        field: String,
        value: bool,
    },
    AdminVhostDelete(String),
    AdminGrantAdd {
        vhost_id: String,
        subject_type: String,
        subject_id: String,
    },
    AdminSubjectSearch(String),
    AdminGrantRevoke(String),
    AdminServerAdd {
        network_id: String,
        host: String,
        port: String,
        tls: bool,
    },
    AdminServerDelete {
        network_id: String,
        server_id: String,
    },
    AdminServerEdit {
        network_id: String,
        server_id: String,
        host: String,
        port: String,
        tls: bool,
        enabled: bool,
    },
    AdminFeaturedAdd {
        network_id: String,
        name: String,
        description: String,
    },
    AdminFeaturedSet {
        network_id: String,
        featured_id: String,
        enabled: bool,
    },
    AdminFeaturedDelete {
        network_id: String,
        featured_id: String,
    },
    /// How many messages deleting the network would take with it.
    AdminNetworkCount(String),
    AdminCredentialEdit {
        user_id: String,
        network_id: String,
        nick: String,
        ident: String,
        realname: String,
        sasl_user: String,
        password: String,
    },
    AdminSettingsLoad,
    AdminSettingsSave(AdminSettingsForm),
    AdminNetworkDelete(String),
    AdminNetworkSave {
        slug: String,
        visitor_enabled: bool,
        visitor_cap: String,
        user_cap: String,
        ip_cap: String,
    },
    AdminReaperRun,
    SettingsNetworkSelected(String),
    IdentitySave {
        nick: String,
        ident: String,
        realname: String,
    },
    /// The edited CTCP USERINFO profile of the Settings network.
    ProfileSave(ProfileFields),
    /// An image picked as the Settings network's own avatar.
    AvatarUpload(std::path::PathBuf),
    AvatarRemove,
    /// An ignore rule of the Settings network: mask and optional text
    /// pattern, whose pair is the rule's identity (protocol v31).
    IgnoreAdd {
        mask: String,
        text_pattern: Option<String>,
    },
    IgnoreRemove {
        mask: String,
        text_pattern: Option<String>,
    },
    PerformSave(String),
    PersonalPrefsSave {
        leave_message: String,
        away_message: String,
        away_delay: String,
        show_peer_profiles: bool,
        /// The auto-away nick suffix as typed; `None` when the server
        /// doesn't offer the setting (older than protocol v32).
        away_nick_suffix: Option<String>,
    },
    DccAutoAcceptToggle(bool),
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
    /// A row of the mentions summary was clicked (its index in the rows).
    OpenMention(usize),
    /// Rebuilds the open window's rows from the stored history, trimming
    /// its oldest rows first when `trim` is set. The chat pane asks for it:
    /// only the pane knows whether the reader follows the newest line, and
    /// whether its rows still match the stored history.
    RebuildChat {
        key: (String, String),
        trim: bool,
    },
    MemberModeAction {
        verb: String,
        nick: String,
    },
    MemberKick(String),
    MemberBan(String),
    MemberBanHost(String),
    MemberKickBan(String),
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

/// Which passkey sign-in the user asked for.
enum PasskeySignIn {
    /// The passkey step of a pending password sign-in.
    SecondFactor,
    /// A passwordless account, from the connect screen.
    Passwordless {
        server_url: String,
        identifier: String,
    },
}

fn main() -> Result<(), slint::PlatformError> {
    persistence::init_storage();
    let ui = AppWindow::new()?;
    debug_info::watch_renderer(ui.window());

    // Settings > Credits: Cordiale's own info only, never a list of
    // Grappa/Cicchetto's contributors — explicit project-owner
    // requirement.
    ui.set_credits_copyright_text(format!("© {} Sythos", current_year()).into());
    ui.set_app_version(cordiale_core::APP_VERSION.into());

    let remembered_server_url = load_remembered_server_url();
    ui.set_server_url(remembered_server_url.clone().into());
    prefill_remembered_profile(&ui, &remembered_server_url);
    load_passkey_origin_field(&ui, &remembered_server_url);

    let settings = persistence::load_settings().unwrap_or_default();
    // A remembered http:// server that isn't this device waits for the
    // connect screen, where the cleartext warning asks for a confirmation.
    let auto_connect = settings.auto_connect
        && settings.language.is_some()
        && !cleartext::is_cleartext_remote(&remembered_server_url);
    ui.set_next_screen(if settings.language.is_none() {
        "language".into()
    } else {
        "connect".into()
    });
    if let Some(language) = settings.language {
        let _ = slint::select_bundled_translation(language_code(language));
    }
    dates::set_language(settings.language);
    push_date_format_examples(&ui);
    ui.set_theme(theme_to_slint(settings.theme));
    ui.set_palette_muted(slint_color(classic_muted(settings.theme == Theme::Dark)));
    ui.set_font_size_percent(i32::from(settings.effective_font_size_percent()));
    ui.set_ban_type_index(settings.default_ban_type.index());
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

    ui.set_radio_volume(i32::from(settings.radio_volume));
    ui.set_pref_shrink_videos(settings.shrink_videos);
    ui.set_video_shrink_available(video_processing::is_available());
    push_radio_stations(&ui, &settings.radio_stations);

    let (worker_tx, worker_rx) = mpsc::unbounded_channel::<WorkerCommand>();
    let ui_weak = ui.as_weak();
    let worker_self = worker_tx.clone();
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("failed to start network runtime");
        runtime.block_on(async move {
            // Run independently of Grappa sign-in: an unavailable release
            // service must never delay the client or interrupt its session.
            let update_ui = ui_weak.clone();
            tokio::spawn(async move {
                match cordiale_core::release::check_newer_release().await {
                    Ok(Some(tag)) => {
                        let _ = update_ui.upgrade_in_event_loop(move |ui| {
                            ui.set_available_update_version(tag.into());
                        });
                    }
                    Ok(None) => {}
                    Err(err) => {
                        persistence::log_line(&format!("release check failed: {err}"));
                    }
                }
            });
            run_worker(worker_rx, worker_self, ui_weak).await;
        });
    });

    register_radio_callbacks(&ui, &worker_tx);
    register_connect_callbacks(&ui, &worker_tx);
    register_security_callbacks(&ui, &worker_tx);

    // Passkey ceremonies (issue #160), where the platform can run one.
    ui.set_passkey_available(ceremony::available());
    // USB security keys have no system dialog: Cordiale's own prompt asks
    // for the PIN and the touch (issue #161).
    #[cfg(all(feature = "ctap-hid", any(target_os = "linux", target_os = "macos")))]
    key_prompt::install(&ui);

    register_passkey_callbacks(&ui, &worker_tx);
    register_saved_profile_callbacks(&ui, &worker_tx);

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

    register_navigation_callbacks(&ui, &worker_tx);
    register_member_callbacks(&ui, &worker_tx);
    register_channel_callbacks(&ui, &worker_tx);
    register_directory_callbacks(&ui, &worker_tx);
    register_dcc_archive_callbacks(&ui, &worker_tx);
    register_link_callbacks(&ui, &worker_tx);
    register_view_callbacks(&ui, &worker_tx);
    register_attach_callbacks(&ui, &worker_tx);

    // Grappa wants to know whether Cordiale is in the foreground: it feeds
    // auto-away and the push suppression. The window counts as foreground
    // when it has keyboard focus and is not minimized. The state is polled
    // from winit rather than rebuilt from window events: Wayland reports no
    // minimize, and macOS' focus events are unreliable (Slint queries the
    // window itself there too). Grappa debounces the signal by minutes, so
    // a second of latency is invisible.
    let foreground_timer = slint::Timer::default();
    {
        use slint::winit_030::WinitWindowAccessor;
        let tx_for_foreground = worker_tx.clone();
        let weak_for_foreground = ui.as_weak();
        let mut reported = None;
        foreground_timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(1),
            move || {
                let Some(ui) = weak_for_foreground.upgrade() else {
                    return;
                };
                let foreground = ui
                    .window()
                    .with_winit_window(|window| {
                        window_in_foreground(window.has_focus(), window.is_minimized())
                    })
                    .unwrap_or(false);
                if reported != Some(foreground) {
                    reported = Some(foreground);
                    let _ = tx_for_foreground.send(WorkerCommand::Foreground(foreground));
                }
            },
        );
    }

    register_composer_callbacks(&ui, &worker_tx);
    register_theme_callbacks(&ui, &worker_tx);
    register_notification_callbacks(&ui, &worker_tx);
    register_admin_user_callbacks(&ui, &worker_tx);
    register_admin_network_callbacks(&ui, &worker_tx);
    register_admin_access_callbacks(&ui, &worker_tx);
    register_admin_settings_callbacks(&ui, &worker_tx);
    register_settings_callbacks(&ui, &worker_tx);

    let result = ui.run();

    // Closing the window quits: tell Grappa the client is leaving, so
    // auto-away doesn't wait for the visibility report to go stale. Bounded,
    // so an unreachable server can't hold the exit up.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    if worker_tx.send(WorkerCommand::Quit(done_tx)).is_ok() {
        let _ = done_rx.recv_timeout(std::time::Duration::from_secs(2));
    }
    result
}

/// Whether the window counts as being in the foreground: it has keyboard
/// focus and is not minimized. `minimized` is `None` where the platform
/// can't tell (Wayland), which is taken as not minimized: such a window
/// loses focus when it is minimized anyway.
fn window_in_foreground(focused: bool, minimized: Option<bool>) -> bool {
    focused && !minimized.unwrap_or(false)
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

/// One open Grappa query window. `dm_conversation_id` (protocol v34 to v36)
/// names the conversation across a peer's nick change; it is `None` for
/// servers older than v34, for v37 and later (which dropped it) or when the
/// server has no conversation for the window.
/// `opened_at` is retained from the server's full snapshot so a unique
/// stable opening can be matched across a rename when no id is available,
/// without guessing from list position.
#[derive(Clone, Debug, PartialEq, Eq)]
struct QueryWindow {
    network: String,
    target_nick: String,
    opened_at: String,
    dm_conversation_id: Option<i64>,
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
    /// The delay as typed in Settings: empty, `0` (off), or seconds.
    fn edit_text(self) -> String {
        match self {
            Self::ServerDefault => String::new(),
            Self::Disabled => "0".to_string(),
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

struct PanelState {
    /// Lines of the live admin feed, newest first (capped).
    admin_events: Vec<String>,
    /// Last `GET /admin/settings`, to tell whether addressing was edited.
    admin_settings: Option<Value>,
    /// The last `GET /admin/uploads` answer, which decides what may be
    /// deleted.
    admin_uploads: Option<cordiale_core::admin::AdminUploadsResponse>,
    /// The network id whose scrollback count the server last answered; only
    /// that network may be deleted.
    admin_network_count_for: Option<String>,
    /// `/kb` requests waiting for their `resolve_userhost` reply, by ref.
    pending_kickbans: HashMap<String, PendingKickBan>,
    /// Identity-recovery panel driven entirely by server pushes; `None`
    /// until the first `recover_progress` and again after a dismiss.
    recover_panel: Option<RecoverPanel>,
    /// Latest requester reply shown on the reply screen; never persisted
    /// and never rendered into a chat window.
    reply_view: Option<ReplyView>,
    /// The WHOIS card currently shown, kept so a later `whois_avatar_ready`
    /// can patch exactly this card and no other.
    whois_card: Option<WhoisBundle>,
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
    /// Latest back-from-away mentions summary per network, kept apart from
    /// `reply_view` so a later reply can't lose it; `/mentions` reopens it.
    mentions_bundles: HashMap<String, ReplyView>,
    /// Where each row of that summary leads, row for row (`None`: nowhere).
    mention_jumps: HashMap<String, Vec<Option<MentionJump>>>,
}

struct SettingsState {
    /// Channels where Denoise was turned on or off, in Grappa's key
    /// spelling (`muted_key`); the rest follow their size. Kept in
    /// `settings.json`.
    presence_pins: std::collections::BTreeMap<String, PresencePref>,
    /// Pins whose upload to Grappa isn't confirmed yet.
    presence_unsynced: std::collections::BTreeSet<String>,
    /// When this device muted each conversation (unix seconds, Grappa's key
    /// spelling): Grappa stores no "muted at", only the end of the mute.
    /// Kept in `settings.json`.
    mute_since: std::collections::BTreeMap<String, i64>,
    /// The account's command aliases, read on the first slash command and
    /// dropped whenever they change so the next one reads them again.
    aliases: Option<HashMap<String, String>>,
    /// Display copy of the account-wide auto-away delay; `None` until the
    /// server announces it. Grappa applies the value itself.
    auto_away_debounce: Option<AutoAwayDebounce>,
    /// Display copy of the remembered QUIT/PART text: outer `None` until
    /// announced, inner `None` for `null` (the server's own fallback).
    quit_part_reason: Option<Option<String>>,
    /// Display copy of the auto-away text, same shape as `quit_part_reason`
    /// (inner `None`: the server keeps its built-in text).
    auto_away_reason: Option<Option<String>>,
    /// Display copy of the auto-away nick suffix (protocol v32), same
    /// shape; inner `None` means the rename is off. Never combined with
    /// the nick: the actual nick comes from the nick events alone.
    away_nick_suffix: Option<Option<String>>,
    /// The network the self-service Identity/Ignores/Perform/Notify
    /// sections currently act on.
    settings_network: Option<String>,
    /// The profile fields as Grappa last reported them for
    /// `settings_network`; a save sends only what differs from this.
    profile_baseline: ProfileFields,
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
    /// Ref of the `watchlist` list request whose reply holds the account's
    /// keyword patterns.
    pending_watchlist_ref: Option<String>,
    /// Current app theme, kept here too (not just in Slint's `theme`
    /// property) so message-rendering helpers running on this thread can
    /// pick a legible color without an extra hop to the UI thread.
    theme: Theme,
    /// Color themes offered in Settings > Themes: Grappa's gallery when the
    /// server has one, the built-in copies otherwise.
    theme_choices: Vec<ThemeChoice>,
    /// The account's day and night themes on Grappa, when one is in use.
    theme_pair: Option<(ThemeChoice, Option<ThemeChoice>)>,
    /// Whether the OS is in dark mode, which picks the night theme.
    system_dark: bool,
    /// Whether the window is in the foreground, as last reported by the UI
    /// thread. Kept across sign-outs so the next session starts right.
    foreground: bool,
}

struct NetworkState {
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
    /// Network whose user modes are on screen (bare `/umode`).
    umode_view_network: Option<String>,
    /// Presence watchlist nicks per network ID, replaced whole by every
    /// `notify_list` snapshot (sent after join and after each change).
    notify_lists: HashMap<i64, Vec<String>>,
    /// Watched-nick presence per network ID, keyed by ASCII-folded nick.
    /// A nick missing here reads as `unknown`.
    presence_by_network: HashMap<i64, HashMap<String, Presence>>,
    /// Last standalone away message (301) per `(network, folded peer)`,
    /// shown above that peer's private window until dismissed.
    peer_away: HashMap<(String, String), String>,
}

struct TranscriptState {
    /// Channels to backfill after a reconnect, with the highest message id
    /// they held when the socket dropped (live rows arriving after the
    /// rejoin must not move the anchor). Drained one channel at a time.
    catch_up_anchors: std::collections::BTreeMap<(String, String), i64>,
    /// Keyed by `(network, channel)`; holds messages already rendered for
    /// that channel so switching channels doesn't lose history.
    messages: MessagesByChannel,
    /// Keyed by `(network, channel)`; an unsent compose draft per channel,
    /// mirroring Cicchetto's own per-channel drafts (confirmed by the
    /// Grappa/Cicchetto maintainer) so switching channels doesn't lose or
    /// leak what's half-typed.
    drafts: HashMap<(String, String), String>,
    /// Keyed by `(network, channel)`; the channel topic, as pushed on the
    /// channel's Phoenix topic — see `handle_frame`.
    topics: HashMap<(String, String), String>,
    /// Keyed by `(network, channel)`; the last complete channel-mode
    /// snapshot received on the Phoenix channel topic.
    channel_modes: HashMap<(String, String), ChannelModes>,
    /// Keyed by `(network, channel)`; the member list seeded by
    /// `members_seeded` on the channel's Phoenix topic, then kept current
    /// from join/part/quit/nick frames.
    members: MembersByChannel,
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
    /// `?before=` cursors already fetched per window: the same page is
    /// never asked for twice.
    history_cursors_fetched: std::collections::HashSet<((String, String), i64)>,
    /// Query keys removed/renamed by a later full snapshot. Since Grappa
    /// shares the channel-shaped Phoenix topic for channels and queries,
    /// remember these identities so their late frames are ignored without
    /// swallowing ordinary channel traffic.
    stale_query_topics: std::collections::HashSet<(String, String)>,
}

struct SessionState {
    client: Option<GrappaClient>,
    token: Option<String>,
    guest_session: bool,
    /// The subject label of the realtime topics (`grappa:user:<label>`):
    /// the account name, or `visitor:<id>` for a guest.
    identifier: Option<String>,
    /// The name typed at sign-in, which keys the remembered profile.
    login_identifier: Option<String>,
    session: Option<SessionHandle>,
    joined_topics: std::collections::HashSet<String>,
    /// The server's `protocol_version`, from `/api/config` at sign-in and
    /// again from the user-topic join reply. `None` until known; see
    /// `rename_inference_applies`.
    server_protocol_version: Option<u32>,
    /// How the open chat pane's update asks the worker for a rebuild
    /// (`WorkerCommand::RebuildChat`); `None` until the worker runs.
    chat_rebuild_tx: Option<mpsc::UnboundedSender<WorkerCommand>>,
    /// Own-nick listener topics become usable only after a successful
    /// Phoenix join reply. Keys are canonical topic strings.
    own_listener_ready: std::collections::HashSet<String>,
    /// Set to stop the videos being shrunk for the session that ends (see
    /// `cancel_video_shrinks`).
    shrink_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// A sign-in waiting for its second factor (issue #118).
    pending_totp: Option<PendingTotp>,
    /// The token confirming a TOTP enrolment started in Settings.
    totp_enrollment: Option<String>,
    /// The token proving the passwordless recovery codes were shown
    /// (valid ten minutes). A credential: never logged nor on screen.
    passwordless_recovery_token: Option<String>,
}

struct WindowState {
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
    /// Last server-confirmed read message ID per canonical channel-shaped
    /// window key. The network is preserved and only the channel segment is
    /// ASCII-folded, matching Cicchetto's channel key.
    read_cursors: HashMap<(String, String), i64>,
    /// Account-wide unread badge from `/me` or the latest read-cursor push.
    badge_count: u64,
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
    /// Channel-selection MRU, used when a dismissed pseudo-window was open.
    recent_channels: Vec<(String, String)>,
    /// `current_channel` is the active window's `(network, target)` key;
    /// this flag disambiguates query topics from channel topics.
    current_query: bool,
    current_query_ready: bool,
    current_channel: Option<(String, String)>,
}

struct WorkerState {
    /// Connection handles and session identity.
    conn: SessionState,
    /// Per-window message content, history paging and query-window bookkeeping.
    transcript: TranscriptState,
    /// Caches of account settings and local preferences.
    prefs: SettingsState,
    /// Screens and pending requests fed by slash commands and server pushes.
    panels: PanelState,
    /// Window lifecycle, counts and selection.
    windows: WindowState,
    /// Per-network caches keyed by network slug or id.
    networks: NetworkState,
    /// The home page's own state (subject, available networks, row
    /// errors, featured channels); its rows come from the snapshots above.
    home: home::HomeState,
}

impl WorkerState {
    fn new() -> Self {
        let settings = persistence::load_settings().unwrap_or_default();
        WorkerState {
            conn: SessionState {
                client: None,
                token: None,
                guest_session: false,
                identifier: None,
                login_identifier: None,
                session: None,
                joined_topics: std::collections::HashSet::new(),
                server_protocol_version: None,
                chat_rebuild_tx: None,
                own_listener_ready: std::collections::HashSet::new(),
                shrink_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                pending_totp: None,
                totp_enrollment: None,
                passwordless_recovery_token: None,
            },
            transcript: TranscriptState {
                catch_up_anchors: std::collections::BTreeMap::new(),
                messages: HashMap::new(),
                drafts: HashMap::new(),
                topics: HashMap::new(),
                channel_modes: HashMap::new(),
                members: HashMap::new(),
                query_windows: Vec::new(),
                pending_own_nick_dms: VecDeque::new(),
                query_joined: std::collections::HashSet::new(),
                query_ready: std::collections::HashSet::new(),
                query_full_history_required: std::collections::HashSet::new(),
                history_start_reached: std::collections::HashSet::new(),
                history_cursors_fetched: std::collections::HashSet::new(),
                stale_query_topics: std::collections::HashSet::new(),
            },
            prefs: SettingsState {
                presence_pins: settings.presence_pins,
                presence_unsynced: settings.presence_unsynced,
                mute_since: settings.mute_since,
                aliases: None,
                auto_away_debounce: None,
                quit_part_reason: None,
                auto_away_reason: None,
                away_nick_suffix: None,
                settings_network: None,
                profile_baseline: ProfileFields::default(),
                upload_limits: None,
                notification_prefs: None,
                web_bundle: None,
                watch_patterns: Vec::new(),
                pending_watchlist_ref: None,
                theme: settings.theme,
                theme_choices: builtin_theme_choices(),
                theme_pair: None,
                system_dark: false,
                foreground: false,
            },
            panels: PanelState {
                admin_events: Vec::new(),
                admin_settings: None,
                admin_uploads: None,
                admin_network_count_for: None,
                pending_kickbans: HashMap::new(),
                recover_panel: None,
                reply_view: None,
                whois_card: None,
                lusers_requested: std::collections::HashSet::new(),
                directory: None,
                dcc_offers: Vec::new(),
                archive: None,
                mentions_bundles: HashMap::new(),
                mention_jumps: HashMap::new(),
            },
            windows: WindowState {
                window_states: HashMap::new(),
                window_failures: HashMap::new(),
                window_kicks: HashMap::new(),
                invited_by: HashMap::new(),
                window_mentions: HashMap::new(),
                window_messages: HashMap::new(),
                read_cursors: HashMap::new(),
                badge_count: 0,
                expanded_networks: HashMap::new(),
                channel_entries: Vec::new(),
                channel_topics: std::collections::HashSet::new(),
                recent_channels: Vec::new(),
                current_query: false,
                current_query_ready: false,
                current_channel: None,
            },
            networks: NetworkState {
                network_ids: HashMap::new(),
                network_connection_states: HashMap::new(),
                connecting_networks: std::collections::HashSet::new(),
                own_nicks: HashMap::new(),
                away_states: HashMap::new(),
                session_identities: HashMap::new(),
                isupport_by_network: HashMap::new(),
                user_modes_by_network: HashMap::new(),
                supported_user_modes_by_network: HashMap::new(),
                umode_view_network: None,
                notify_lists: HashMap::new(),
                presence_by_network: HashMap::new(),
                peer_away: HashMap::new(),
            },
            home: home::HomeState::default(),
        }
    }

    /// Whether `key`'s transcript hides join/part/quit/nick-change/mode
    /// lines: the channel's own choice, else its size.
    fn denoise_active(&self, key: &(String, String)) -> bool {
        let pref = self
            .prefs
            .presence_pins
            .get(&muted_key(&key.0, &key.1))
            .copied();
        presence_hidden(pref, self.transcript.members.get(key).map(Vec::len))
    }

    /// Whether a line arriving live belongs in `key`'s open transcript.
    fn transcript_shows(&self, key: &(String, String), line: &RenderedMessage) -> bool {
        !(line.presence_noise && self.denoise_active(key))
    }
}

/// The single background worker: owns the tokio runtime, the REST client,
/// and the realtime session for the whole app lifetime. Multiplexes UI
/// commands and realtime session events with `tokio::select!`; when there's
/// no session yet, the event branch parks on `std::future::pending()` so it
/// never fires.
async fn run_worker(
    mut commands: mpsc::UnboundedReceiver<WorkerCommand>,
    worker_self: mpsc::UnboundedSender<WorkerCommand>,
    ui: slint::Weak<AppWindow>,
) {
    let mut state = WorkerState::new();
    state.conn.chat_rebuild_tx = Some(worker_self.clone());
    let radio_events = worker_self.clone();
    let radio = player::RadioPlayer::spawn(move |generation, event| {
        let _ = radio_events.send(WorkerCommand::RadioEvent(generation, event));
    });
    let volume = persistence::load_settings()
        .unwrap_or_default()
        .radio_volume;
    radio.set_volume(f32::from(volume) / 100.0);
    let mut radio_state = RadioState::default();
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
                        if let Some(network) = state.prefs.settings_network.clone() {
                            let ui_for_network = ui.clone();
                            let loaded_network = network.clone();
                            let _ = ui_for_network.upgrade_in_event_loop(move |ui| {
                                ui.set_settings_network(network.into());
                            });
                            load_identity_settings(&mut state, &ui, &loaded_network).await;
                            handle_settings_network_refresh(&state, &ui).await;
                        }
                    }
                    Some(WorkerCommand::TotpVerify(code)) => {
                        handle_totp_verify(&mut state, &mut session_events, &ui, code).await;
                        if let Some(network) = state.prefs.settings_network.clone() {
                            let ui_for_network = ui.clone();
                            let loaded_network = network.clone();
                            let _ = ui_for_network.upgrade_in_event_loop(move |ui| {
                                ui.set_settings_network(network.into());
                            });
                            load_identity_settings(&mut state, &ui, &loaded_network).await;
                            handle_settings_network_refresh(&state, &ui).await;
                        }
                    }
                    Some(WorkerCommand::ShareConsume { server_url, input }) => {
                        handle_share_consume(
                            &mut state,
                            &mut session_events,
                            &ui,
                            server_url,
                            input,
                        )
                        .await;
                        if let Some(network) = state.prefs.settings_network.clone() {
                            let ui_for_network = ui.clone();
                            let _ = ui_for_network.upgrade_in_event_loop(move |ui| {
                                ui.set_settings_network(network.into());
                            });
                            handle_settings_network_refresh(&state, &ui).await;
                        }
                    }
                    Some(WorkerCommand::RecoverySignIn {
                        server_url,
                        identifier,
                        code,
                    }) => {
                        handle_recovery_sign_in(
                            &mut state,
                            &mut session_events,
                            &ui,
                            server_url,
                            identifier,
                            code,
                        )
                        .await;
                        if let Some(network) = state.prefs.settings_network.clone() {
                            let ui_for_network = ui.clone();
                            let loaded_network = network.clone();
                            let _ = ui_for_network.upgrade_in_event_loop(move |ui| {
                                ui.set_settings_network(network.into());
                            });
                            load_identity_settings(&mut state, &ui, &loaded_network).await;
                            handle_settings_network_refresh(&state, &ui).await;
                        }
                    }
                    Some(WorkerCommand::SecurityShareMint) => {
                        handle_security_share_mint(&state, &ui).await;
                    }
                    Some(WorkerCommand::TotpCancel) => {
                        state.conn.pending_totp = None;
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_connecting(false);
                            ui.set_totp_code("".into());
                            ui.set_screen("connect".into());
                        });
                    }
                    Some(WorkerCommand::SecurityTotpRefresh) => {
                        handle_security_totp_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::SecurityTotpStart(password)) => {
                        handle_security_totp_start(&mut state, &ui, password).await;
                    }
                    Some(WorkerCommand::SecurityTotpConfirm(code)) => {
                        handle_security_totp_confirm(&mut state, &ui, code).await;
                    }
                    Some(WorkerCommand::SecurityTotpDisable(password)) => {
                        handle_security_totp_disable(&state, &ui, password).await;
                    }
                    Some(WorkerCommand::SecurityTotpDone) => {
                        run_security_totp_done(&mut state, &ui);
                    }
                    Some(WorkerCommand::SecurityPasskeysRefresh) => {
                        handle_security_passkeys_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::SecurityPasskeyDelete { id, password }) => {
                        handle_security_passkey_delete(&state, &ui, id, password).await;
                    }
                    Some(WorkerCommand::PasskeySignIn(request)) => {
                        handle_passkey_sign_in(&mut state, &mut session_events, &ui, request)
                            .await;
                        if let Some(network) = state.prefs.settings_network.clone() {
                            let ui_for_network = ui.clone();
                            let loaded_network = network.clone();
                            let _ = ui_for_network.upgrade_in_event_loop(move |ui| {
                                ui.set_settings_network(network.into());
                            });
                            load_identity_settings(&mut state, &ui, &loaded_network).await;
                            handle_settings_network_refresh(&state, &ui).await;
                        }
                    }
                    Some(WorkerCommand::SecurityPasskeyAdd { name, password }) => {
                        let change = PasskeyChange::Add { name, password };
                        spawn_passkey_change(&state, &ui, &worker_self, change);
                    }
                    Some(WorkerCommand::SecurityPasskeyMode { mode, password }) => {
                        let change = PasskeyChange::Mode { mode, password };
                        spawn_passkey_change(&state, &ui, &worker_self, change);
                    }
                    Some(WorkerCommand::SecurityPasswordlessPrepare(password)) => {
                        handle_security_passwordless_prepare(&mut state, &ui, password).await;
                    }
                    Some(WorkerCommand::SecurityPasswordlessActivate) => {
                        // Kept until armed: a cancelled prompt can be tried again.
                        if let Some(recovery_token) = state.conn.passwordless_recovery_token.clone() {
                            let change = PasskeyChange::Passwordless { recovery_token };
                            spawn_passkey_change(&state, &ui, &worker_self, change);
                        }
                    }
                    Some(WorkerCommand::SecurityPasswordlessCancel) => {
                        state.conn.passwordless_recovery_token = None;
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_security_passwordless_codes(slint::ModelRc::default());
                            ui.set_security_passkey_error("".into());
                        });
                    }
                    Some(WorkerCommand::SelectChannel { network, channel }) => {
                        write_back_read_cursor(&mut state);
                        handle_select_channel(&mut state, &ui, network, channel).await;
                    }
                    Some(WorkerCommand::SelectNetwork(network)) => {
                        run_select_network(&mut state, &ui, network).await;
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
                    Some(WorkerCommand::DeclineInvite { network, channel }) => {
                        decline_invite(&state, &ui, &network, &channel).await;
                    }
                    Some(WorkerCommand::DismissRecover) => {
                        state.panels.recover_panel = None;
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
                        if let Some(view) = state.panels.directory.as_mut() {
                            view.sort = sort;
                        }
                        load_directory(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::DirectorySearch(query)) => {
                        if let Some(view) = state.panels.directory.as_mut() {
                            view.query = query.trim().to_string();
                        }
                        load_directory(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::DirectoryClose) => {
                        close_directory(&mut state, &ui);
                    }
                    Some(WorkerCommand::DirectoryOpen(network)) => {
                        run_directory_open(&mut state, &ui, network).await;
                    }
                    Some(WorkerCommand::DirectoryActivate(channel)) => {
                        directory_activate(&mut state, &ui, channel).await;
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
                    Some(WorkerCommand::OpenLink(href)) => {
                        match cordiale_core::media::validated_url(&href) {
                            Ok(url) => {
                                let href = url.to_string();
                                match audio_link(&state, &href) {
                                    Some(hint) => {
                                        play_audio_link(&mut radio_state, &radio, &ui, &href, hint)
                                    }
                                    None => open_link(&state, &ui, href),
                                }
                            }
                            Err(refusal) => link_refused(&ui, refusal),
                        }
                    }
                    Some(WorkerCommand::RadioTune(key)) => {
                        tune_radio(&mut radio_state, &radio, &worker_self, &ui, &key);
                    }
                    Some(WorkerCommand::RadioStop) => {
                        radio.stop();
                        radio_state.stop();
                        push_radio_now(&ui, &radio_state);
                    }
                    Some(WorkerCommand::RadioVolume(volume)) => {
                        radio.set_volume(volume.clamp(0, 100) as f32 / 100.0);
                    }
                    Some(WorkerCommand::RadioEvent(generation, event)) => {
                        handle_radio_event(&mut radio_state, &ui, generation, event);
                    }
                    Some(WorkerCommand::RadioTrack { generation, track }) => {
                        if let Some(tuned) = radio_state
                            .tuned
                            .as_mut()
                            .filter(|_| radio_state.generation == generation)
                        {
                            if let Some(track) = track {
                                tuned.track = Some((track, std::time::Instant::now()));
                            }
                            push_radio_now(&ui, &radio_state);
                        }
                    }
                    Some(WorkerCommand::ArchiveClose) => {
                        state.panels.archive = None;
                    }
                    Some(WorkerCommand::CatchUpNext) => {
                        handle_catch_up_next(&mut state, &ui, &worker_self).await;
                    }
                    Some(WorkerCommand::UmodeToggle(letter)) => {
                        toggle_user_mode(&state, &letter);
                    }
                    Some(WorkerCommand::UmodeClose) => {
                        state.networks.umode_view_network = None;
                    }
                    Some(WorkerCommand::DismissPeerAway) => {
                        if let Some(key) = current_peer_away_key(&state) {
                            state.networks.peer_away.remove(&key);
                        }
                        push_peer_away_banner(&state, &ui);
                    }
                    Some(WorkerCommand::ToggleNetwork(network)) => {
                        let initially_expanded = !state.networks.network_connection_states.get(&network).is_some_and(
                            |snapshot| matches!(snapshot.status, NetworkConnectionStatus::Parked),
                        );
                        let expanded = state.windows.expanded_networks.entry(network).or_insert(initially_expanded);
                        *expanded = !*expanded;
                        refresh_network_groups(&state, &ui);
                    }
                    Some(WorkerCommand::AttachFile(path, options)) => {
                        handle_attach_file(&mut state, &ui, path, options).await;
                    }
                    Some(WorkerCommand::UploadPrefsChanged { ttl, confirm }) => {
                        run_upload_prefs_changed(&mut state, ttl, confirm).await;
                    }
                    Some(WorkerCommand::SendMessage { body }) => {
                        handle_send_message(&mut state, &ui, body).await;
                        if let Some(key) = state.windows.current_channel.clone() {
                            state.transcript.drafts.remove(&key);
                        }
                    }
                    Some(WorkerCommand::ComposeTextChanged(text)) => {
                        if let Some(key) = state.windows.current_channel.clone() {
                            if text.is_empty() {
                                state.transcript.drafts.remove(&key);
                            } else {
                                state.transcript.drafts.insert(key, text);
                            }
                        }
                    }
                    Some(WorkerCommand::ToggleTheme) => {
                        handle_toggle_theme(&mut state, &ui);
                    }
                    Some(WorkerCommand::SelectColorTheme(key)) => {
                        select_color_theme(&mut state, &ui, &key).await;
                    }
                    Some(WorkerCommand::ThemeEdit(key)) => {
                        open_theme_editor(&state, &ui, &key).await;
                    }
                    Some(WorkerCommand::ThemeSave {
                        theme_id,
                        name,
                        payload,
                    }) => {
                        save_theme(&mut state, &ui, theme_id, &name, &payload).await;
                    }
                    Some(WorkerCommand::ThemeDelete(theme_id)) => {
                        if let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) {
                            let result = client.delete_theme(&token, theme_id).await;
                            report_theme_action(&ui, result.err());
                            load_color_themes(&mut state, &ui).await;
                        }
                    }
                    Some(WorkerCommand::ThemePublish(theme_id, published)) => {
                        if let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) {
                            let result = client.set_theme_published(&token, theme_id, published).await;
                            report_theme_action(&ui, result.err());
                            load_color_themes(&mut state, &ui).await;
                        }
                    }
                    Some(WorkerCommand::ThemeCopy(theme_id)) => {
                        run_theme_copy(&mut state, &ui, theme_id).await;
                    }
                    Some(WorkerCommand::ThemeBackgroundUpload(path)) => {
                        upload_theme_background(&state, &ui, &path).await;
                    }
                    Some(WorkerCommand::ThemeEditorCancel) => {
                        load_color_themes(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::SelectNightTheme(key)) => {
                        select_night_theme(&mut state, &ui, &key).await;
                    }
                    Some(WorkerCommand::SystemScheme(dark)) => {
                        let changed = state.prefs.system_dark != dark;
                        state.prefs.system_dark = dark;
                        if changed && state.prefs.theme_pair.as_ref().is_some_and(|pair| pair.1.is_some()) {
                            apply_theme_pair(&mut state, &ui);
                        }
                    }
                    Some(WorkerCommand::Foreground(foreground)) => {
                        state.prefs.foreground = foreground;
                        if let Some(session) = &state.conn.session {
                            session.set_foreground(foreground);
                        }
                    }
                    Some(WorkerCommand::Quit(done)) => {
                        if let Some(handle) = state.conn.session.take() {
                            let _ = handle.close().await;
                        }
                        let _ = done.send(());
                    }
                    Some(WorkerCommand::EditNotificationPrefs(edit)) => {
                        handle_notification_edit(&mut state, &ui, edit).await;
                    }
                    Some(WorkerCommand::MuteCurrentWindow(seconds)) => {
                        if let Some((network, target)) = state.windows.current_channel.clone() {
                            let until = (seconds > 0).then(|| {
                                chrono::Utc::now().timestamp() + i64::from(seconds)
                            });
                            let edit = NotificationEdit::Mute(muted_key(&network, &target), until);
                            handle_notification_edit(&mut state, &ui, edit).await;
                        }
                    }
                    Some(WorkerCommand::ToggleDenoise) => {
                        handle_toggle_denoise(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::LoadNotificationPrefs) => {
                        handle_load_notification_prefs(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::SaveNotificationPrefs(toggles)) => {
                        handle_save_notification_prefs(&mut state, &ui, toggles).await;
                    }
                    Some(WorkerCommand::SaveDisplayPrefs(prefs)) => {
                        if let Some(bold) = prefs.bold_mentions {
                            BOLD_MENTIONS.store(bold, std::sync::atomic::Ordering::Relaxed);
                        }
                        handle_save_display_prefs(&state, &ui, prefs).await;
                        if let Some(key) = state.windows.current_channel.clone() {
                            push_members_update(&state, &ui, &key);
                        }
                    }
                    Some(WorkerCommand::AdminRefresh) => {
                        run_admin_refresh(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::AdminUploadsRefresh) => {
                        handle_admin_uploads_refresh(&mut state, &ui, None).await;
                    }
                    Some(WorkerCommand::AdminUploadDelete(upload_id)) => {
                        handle_admin_upload_delete(&mut state, &ui, upload_id).await;
                    }
                    Some(WorkerCommand::AdminDisconnectSession(session_id)) => {
                        handle_admin_disconnect_session(&state, &ui, session_id).await;
                    }
                    Some(WorkerCommand::AdminReconnectSession(session_id)) => {
                        handle_admin_write(&state, &ui, AdminWrite::ReconnectSession(session_id))
                            .await;
                    }
                    Some(WorkerCommand::AdminTerminateSession(session_id)) => {
                        handle_admin_write(&state, &ui, AdminWrite::TerminateSession(session_id))
                            .await;
                    }
                    Some(WorkerCommand::AdminUserToggleAdmin(user_id, is_admin)) => {
                        if let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) {
                            let _ = client
                                .set_admin_user_is_admin(token, &user_id, is_admin)
                                .await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::AdminUserDelete(user_id)) => {
                        if let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) {
                            let _ = client.delete_admin_user(token, &user_id).await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::AdminVisitorDelete(visitor_id)) => {
                        if let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) {
                            let _ = client.delete_admin_visitor(token, &visitor_id).await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::AdminNetworkResetCircuit(network_id)) => {
                        if let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) {
                            let _ = client.reset_admin_circuit(token, &network_id).await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::AdminUserCreate {
                        name,
                        password,
                        is_admin,
                    }) => {
                        handle_admin_write(&state, &ui, AdminWrite::CreateUser { name, password, is_admin })
                            .await;
                    }
                    Some(WorkerCommand::AdminUserSetPassword { user_id, password }) => {
                        handle_admin_write(&state, &ui, AdminWrite::SetPassword { user_id, password })
                            .await;
                    }
                    Some(WorkerCommand::AdminNetworkCreate(slug)) => {
                        handle_admin_write(&state, &ui, AdminWrite::CreateNetwork(slug)).await;
                    }
                    Some(WorkerCommand::AdminCredentialBind {
                        user_id,
                        network_id,
                        nick,
                        auth_method,
                        password,
                    }) => {
                        run_admin_credential_bind(
                            &mut state,
                            &ui,
                            user_id,
                            network_id,
                            nick,
                            auth_method,
                            password,
                        )
                        .await;
                    }
                    Some(WorkerCommand::AdminCredentialUnbind {
                        user_id,
                        network_id,
                    }) => {
                        run_admin_credential_unbind(&mut state, &ui, user_id, network_id).await;
                    }
                    Some(WorkerCommand::AdminVhostAdd { address, in_pool }) => {
                        handle_admin_write(&state, &ui, AdminWrite::AddVhost { address, in_pool })
                            .await;
                    }
                    Some(WorkerCommand::AdminVhostSet {
                        vhost_id,
                        field,
                        value,
                    }) => {
                        run_admin_vhost_set(&mut state, &ui, vhost_id, field, value).await;
                    }
                    Some(WorkerCommand::AdminVhostDelete(vhost_id)) => {
                        handle_admin_write(&state, &ui, AdminWrite::DeleteVhost(vhost_id)).await;
                    }
                    Some(WorkerCommand::AdminGrantAdd {
                        vhost_id,
                        subject_type,
                        subject_id,
                    }) => {
                        run_admin_grant_add(
                            &mut state,
                            &ui,
                            vhost_id,
                            subject_type,
                            subject_id,
                        )
                        .await;
                    }
                    Some(WorkerCommand::AdminSubjectSearch(query)) => {
                        handle_admin_subject_search(&state, &ui, &query).await;
                    }
                    Some(WorkerCommand::AdminGrantRevoke(grant_id)) => {
                        handle_admin_write(&state, &ui, AdminWrite::RevokeGrant(grant_id)).await;
                    }
                    Some(WorkerCommand::AdminServersLoad(network_id)) => {
                        push_admin_servers(&state, &ui, &network_id).await;
                        push_admin_featured(&state, &ui, &network_id).await;
                    }
                    Some(WorkerCommand::AdminServerEdit {
                        network_id,
                        server_id,
                        host,
                        port,
                        tls,
                        enabled,
                    }) => match cordiale_core::admin::admin_server_changes(&host, &port, tls, enabled)
                    {
                        Some(changes) => {
                            handle_admin_write(
                                &state,
                                &ui,
                                AdminWrite::EditServer {
                                    network_id: network_id.clone(),
                                    server_id,
                                    changes,
                                },
                            )
                            .await;
                            push_admin_servers(&state, &ui, &network_id).await;
                        }
                        None => {
                            let _ = ui.upgrade_in_event_loop(|ui| {
                                ui.set_status_kind("admin-server-invalid".into());
                            });
                        }
                    },
                    Some(WorkerCommand::AdminFeaturedAdd {
                        network_id,
                        name,
                        description,
                    }) => {
                        run_admin_featured_add(
                            &mut state,
                            &ui,
                            network_id,
                            name,
                            description,
                        )
                        .await;
                    }
                    Some(WorkerCommand::AdminFeaturedSet {
                        network_id,
                        featured_id,
                        enabled,
                    }) => {
                        run_admin_featured_set(
                            &mut state,
                            &ui,
                            network_id,
                            featured_id,
                            enabled,
                        )
                        .await;
                    }
                    Some(WorkerCommand::AdminFeaturedDelete {
                        network_id,
                        featured_id,
                    }) => {
                        run_admin_featured_delete(&mut state, &ui, network_id, featured_id).await;
                    }
                    Some(WorkerCommand::AdminNetworkCount(network_id)) => {
                        handle_admin_network_count(&mut state, &ui, network_id).await;
                    }
                    Some(WorkerCommand::AdminCredentialEdit {
                        user_id,
                        network_id,
                        nick,
                        ident,
                        realname,
                        sasl_user,
                        password,
                    }) => match cordiale_core::admin::admin_credential_changes(
                        &nick, &ident, &realname, &sasl_user, &password,
                    ) {
                        Some(changes) => {
                            handle_admin_write(
                                &state,
                                &ui,
                                AdminWrite::EditCredential {
                                    user_id,
                                    network_id,
                                    changes,
                                },
                            )
                            .await;
                        }
                        None => {
                            let _ = ui.upgrade_in_event_loop(|ui| {
                                ui.set_status_kind("admin-credential-invalid".into());
                            });
                        }
                    },
                    Some(WorkerCommand::AdminServerAdd {
                        network_id,
                        host,
                        port,
                        tls,
                    }) => {
                        run_admin_server_add(&mut state, &ui, network_id, host, port, tls).await;
                    }
                    Some(WorkerCommand::AdminServerDelete {
                        network_id,
                        server_id,
                    }) => {
                        run_admin_server_delete(&mut state, &ui, network_id, server_id).await;
                    }
                    Some(WorkerCommand::AdminSettingsLoad) => {
                        handle_admin_settings_load(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::AdminSettingsSave(form)) => {
                        run_admin_settings_save(&mut state, &ui, form).await;
                    }
                    Some(WorkerCommand::AdminNetworkDelete(network_id)) => {
                        if admin_network_delete_armed(&state, &network_id) {
                            state.panels.admin_network_count_for = None;
                            handle_admin_write(&state, &ui, AdminWrite::DeleteNetwork(network_id))
                                .await;
                        } else {
                            persistence::log_line("admin network delete refused: no count");
                        }
                    }
                    Some(WorkerCommand::AdminNetworkSave {
                        slug,
                        visitor_enabled,
                        visitor_cap,
                        user_cap,
                        ip_cap,
                    }) => {
                        run_admin_network_save(
                            &mut state,
                            &ui,
                            slug,
                            visitor_enabled,
                            visitor_cap,
                            user_cap,
                            ip_cap,
                        )
                        .await;
                    }
                    Some(WorkerCommand::AdminReaperRun) => {
                        if let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) {
                            let _ = client.run_admin_reaper(token).await;
                        }
                        handle_admin_refresh(&state, &ui).await;
                    }
                    Some(WorkerCommand::SettingsNetworkSelected(network)) => {
                        load_identity_settings(&mut state, &ui, &network).await;
                        state.prefs.settings_network = Some(network);
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
                    Some(WorkerCommand::ProfileSave(edited)) => {
                        handle_profile_save(&mut state, &ui, edited).await;
                    }
                    Some(WorkerCommand::AvatarUpload(path)) => {
                        handle_avatar_upload(&state, &ui, path).await;
                    }
                    Some(WorkerCommand::AvatarRemove) => {
                        handle_avatar_remove(&state, &ui).await;
                    }
                    Some(WorkerCommand::PersonalPrefsSave {
                        leave_message,
                        away_message,
                        away_delay,
                        show_peer_profiles,
                        away_nick_suffix,
                    }) => {
                        run_personal_prefs_save(
                            &mut state,
                            &ui,
                            leave_message,
                            away_message,
                            away_delay,
                            show_peer_profiles,
                            away_nick_suffix,
                        )
                        .await;
                    }
                    Some(WorkerCommand::DccAutoAcceptToggle(enabled)) => {
                        run_dcc_auto_accept_toggle(&mut state, enabled).await;
                    }
                    Some(WorkerCommand::IgnoreAdd { mask, text_pattern }) => {
                        run_ignore_add(&mut state, &ui, mask, text_pattern).await;
                    }
                    Some(WorkerCommand::IgnoreRemove { mask, text_pattern }) => {
                        run_ignore_remove(&mut state, &ui, mask, text_pattern).await;
                    }
                    Some(WorkerCommand::PerformSave(text)) => {
                        run_perform_save(&mut state, text).await;
                    }
                    Some(WorkerCommand::AliasAdd { command, expansion }) => {
                        handle_alias_upsert(&state, &ui, Some((command, expansion))).await;
                        state.prefs.aliases = None;
                    }
                    Some(WorkerCommand::AliasRemove(command)) => {
                        handle_alias_remove(&state, &ui, command).await;
                        state.prefs.aliases = None;
                    }
                    Some(WorkerCommand::VhostToggle(address)) => {
                        handle_vhost_toggle(&state, &ui, address).await;
                    }
                    // The server answers each change with a full `notify_list`
                    // snapshot; the local edit only avoids a stale row until
                    // it arrives.
                    Some(WorkerCommand::NotifyAdd(nick)) => {
                        run_notify_add(&mut state, &ui, nick).await;
                    }
                    Some(WorkerCommand::NotifyRemove(nick)) => {
                        run_notify_remove(&mut state, &ui, nick).await;
                    }
                    Some(WorkerCommand::WatchPatternAdd(pattern)) => {
                        run_watch_pattern_add(&mut state, &ui, pattern);
                    }
                    Some(WorkerCommand::WatchPatternRemove(pattern)) => {
                        run_watch_pattern_remove(&mut state, &ui, pattern);
                    }
                    Some(WorkerCommand::Disconnect) => {
                        persistence::log_line("disconnect requested");
                        cancel_video_shrinks(&mut state);
                        // A manual disconnect is how the user switches
                        // accounts: don't sign back in at the next launch.
                        set_auto_connect(false);
                        // Before a guest logout revokes the bearer, so the
                        // "leaving" hint still reaches Grappa.
                        if let Some(handle) = state.conn.session.take() {
                            drop(handle.close());
                        }
                        let guest_logout_failed = if state.conn.guest_session {
                            if let (Some(client), Some(token), Some(identifier)) = (
                                state.conn.client.as_ref(),
                                state.conn.token.as_deref(),
                                state.conn.login_identifier.as_deref(),
                            ) {
                                match client.logout(token).await {
                                    Ok(()) => {
                                        forget_guest_bearer(client.base_url(), identifier);
                                        false
                                    }
                                    Err(error)
                                        if error.status().map(|status| status.as_u16()) == Some(401) =>
                                    {
                                        forget_guest_bearer(client.base_url(), identifier);
                                        true
                                    }
                                    Err(error) => {
                                        persistence::log_line(&format!(
                                            "guest logout was not confirmed: {error:?}"
                                        ));
                                        true
                                    }
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        session_events = None;
                        // The OS scheme and the window's state outlive the
                        // account.
                        let system_dark = state.prefs.system_dark;
                        let foreground = state.prefs.foreground;
                        state = WorkerState::new();
                        state.conn.chat_rebuild_tx = Some(worker_self.clone());
                        state.prefs.system_dark = system_dark;
                        state.prefs.foreground = foreground;
                        push_home(&state, &ui);
                        // Like Cicchetto, signing out stops the radio.
                        radio.stop();
                        radio_state.stop();
                        push_radio_now(&ui, &radio_state);
                        if guest_logout_failed {
                            let _ = ui.upgrade_in_event_loop(|ui| {
                                ui.set_status_kind("guest-logout-unconfirmed".into());
                            });
                        }
                    }
                    Some(WorkerCommand::LoadOlderHistory) => {
                        handle_load_older_history(&mut state, &ui).await;
                    }
                    Some(WorkerCommand::OpenMention(index)) => {
                        handle_open_mention(&mut state, &ui, index).await;
                    }
                    Some(WorkerCommand::RebuildChat { key, trim }) => {
                        handle_rebuild_chat(&mut state, &ui, &key, trim);
                    }
                    Some(WorkerCommand::GoHome) => {
                        write_back_read_cursor(&mut state);
                        close_directory(&mut state, &ui);
                        if let Some(previous) = state.windows.current_channel.take() {
                            trim_window_history(&mut state, &previous);
                        }
                        state.windows.current_query = false;
                        state.windows.current_query_ready = false;
                    }
                    Some(WorkerCommand::HomeDisconnect(network)) => {
                        home_set_connection_state(&mut state, &ui, network, "parked").await;
                    }
                    Some(WorkerCommand::HomeReconnect(network)) => {
                        home_set_connection_state(&mut state, &ui, network, "connected").await;
                    }
                    Some(WorkerCommand::HomeRemove(network)) => {
                        home_remove_network(&mut state, &ui, network).await;
                    }
                    Some(WorkerCommand::HomeRecover(network)) => {
                        if state.networks.network_ids.contains_key(&network) {
                            send_user_network_verb(&state, &network, "recover");
                        }
                    }
                    Some(WorkerCommand::HomeConnect(network)) => {
                        home_connect_network(&mut state, &ui, network).await;
                    }
                    Some(WorkerCommand::HomeFeaturedOpen { network, channel }) => {
                        write_back_read_cursor(&mut state);
                        home_open_featured(&mut state, &ui, network, channel).await;
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
                    Some(WorkerCommand::MemberBanHost(nick)) => {
                        start_member_host_ban(&mut state, &ui, nick, None);
                    }
                    Some(WorkerCommand::MemberKickBan(nick)) => {
                        start_member_host_ban(&mut state, &ui, nick, Some(String::new()));
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
                        // A reconnect can land on an upgraded server; a join
                        // reply without the field keeps what sign-in learned.
                        if protocol_version.is_some() {
                            state.conn.server_protocol_version = protocol_version;
                        }
                        // Without this, a status set to "disconnected" or
                        // "reconnecting" by an earlier drop just sits
                        // there forever once the session actually comes
                        // back — nothing else ever clears it.
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_status_kind("signed-in".into());
                            ui.set_status_message("".into());
                            ui.set_status_retry_secs(0);
                        });
                        request_watch_patterns(&mut state);
                        // Grappa doesn't replay what a channel said while
                        // the socket was down: backfill it over REST.
                        if !state.transcript.catch_up_anchors.is_empty() {
                            let _ = worker_self.send(WorkerCommand::CatchUpNext);
                        }
                    }
                    Some(SessionEvent::Frame(frame)) => {
                        handle_frame(&mut state, &ui, frame).await;
                    }
                    Some(SessionEvent::Disconnected { reason, .. }) if state.conn.session.is_none() => {
                        // A deliberately ended session (sign-out, revoked
                        // bearer) still reports its final socket close; it
                        // must not overwrite the sign-in screen's status.
                        persistence::log_line(&format!("ended session closed: {reason}"));
                    }
                    Some(SessionEvent::Reconnecting { reason, .. }) if state.conn.session.is_none() => {
                        persistence::log_line(&format!("ended session not reconnecting: {reason}"));
                    }
                    Some(SessionEvent::Disconnected { reason, retry_in }) => {
                        persistence::log_line(&format!(
                            "session disconnected: {reason}, retrying in {retry_in:?}"
                        ));
                        note_catch_up_anchors(&mut state);
                        reset_query_session_readiness(&mut state);
                        state.conn.own_listener_ready.clear();
                        state.networks.supported_user_modes_by_network.clear();
                        if !state.networks.connecting_networks.is_empty() {
                            state.networks.connecting_networks.clear();
                            refresh_network_groups(&state, &ui);
                        }
                        let retry_secs = wait_secs(retry_in);
                        let _ = ui.upgrade_in_event_loop(move |ui| {
                            ui.set_status_retry_secs(retry_secs);
                            ui.set_status_kind("disconnected".into());
                            ui.set_status_message(reason.into());
                            ui.set_current_query_ready(false);
                        });
                    }
                    Some(SessionEvent::Reconnecting { reason, retry_in }) => {
                        persistence::log_line(&format!(
                            "session reconnecting: {reason}, retrying in {retry_in:?}"
                        ));
                        note_catch_up_anchors(&mut state);
                        reset_query_session_readiness(&mut state);
                        state.conn.own_listener_ready.clear();
                        state.networks.supported_user_modes_by_network.clear();
                        if !state.networks.connecting_networks.is_empty() {
                            state.networks.connecting_networks.clear();
                            refresh_network_groups(&state, &ui);
                        }
                        let retry_secs = wait_secs(retry_in);
                        let _ = ui.upgrade_in_event_loop(move |ui| {
                            ui.set_status_retry_secs(retry_secs);
                            ui.set_status_kind("reconnecting".into());
                            ui.set_status_message(reason.into());
                            ui.set_current_query_ready(false);
                        });
                    }
                    Some(SessionEvent::JoinRefused { reason }) => {
                        // Stopped for good: retrying the same topics can't work.
                        persistence::log_line(&format!("session join refused: {reason}"));
                        state.conn.session = None;
                        session_events = None;
                        let _ = ui.upgrade_in_event_loop(move |ui| {
                            ui.set_status_kind("session-refused".into());
                            ui.set_status_message(reason.into());
                            ui.set_current_query_ready(false);
                        });
                    }
                    Some(SessionEvent::CertificateRejected { reason }) => {
                        // Stopped for good: the server's certificate stays
                        // untrusted until the store or the server changes.
                        persistence::log_line(&format!("session certificate rejected: {reason}"));
                        state.conn.session = None;
                        session_events = None;
                        let _ = ui.upgrade_in_event_loop(move |ui| {
                            ui.set_status_kind("certificate-untrusted".into());
                            ui.set_status_message(reason.into());
                            ui.set_current_query_ready(false);
                        });
                    }
                    Some(SessionEvent::UpgradeRequired {
                        protocol_version,
                        min_protocol_version,
                    }) => {
                        // Stopped for good: no retry helps until Cordiale is updated.
                        persistence::log_line(&format!(
                            "session upgrade required: declared client_proto={CLIENT_PROTOCOL_VERSION}, server protocol_version={protocol_version:?}, min_protocol_version={min_protocol_version:?}"
                        ));
                        state.conn.session = None;
                        session_events = None;
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_status_kind("upgrade-required".into());
                            ui.set_status_message("".into());
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
    let previous_guest_bearer = is_guest_attempt
        .then(|| remembered_guest_bearer(&server_url, identifier.trim()))
        .flatten();
    let result = match credential {
        ConnectCredential::FormValue(password) => {
            // Older releases stored the entered password/client token in
            // the credential store. Drop that legacy value; only a bearer
            // returned by a successful login may be persisted now.
            if !is_guest_attempt {
                discard_legacy_profile_secret(&server_url, &identifier);
            }

            // A blank password is a guest sign-in under the typed nickname,
            // sent without a `password` field, as Cicchetto does. Grappa
            // keys visitors by nick, so a shared fixed name would make every
            // guest after the first collide with it (#88).
            let (login_identifier, login_password, auth) = if is_guest_attempt {
                (identifier.trim().to_string(), String::new(), "guest")
            } else {
                (identifier.clone(), password, "typed")
            };
            persistence::log_line(&format!(
                "connect attempt: server={server_url} identifier={login_identifier} \
                 guest={is_guest_attempt} auth={auth}"
            ));
            let request = LoginRequest {
                identifier: login_identifier,
                password: login_password,
            };
            if is_guest_attempt {
                bootstrap_with_login_bearer(&client, &request, previous_guest_bearer.as_deref())
                    .await
            } else {
                bootstrap(&client, &request).await
            }
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

    if previous_guest_bearer.is_some() {
        if let Err(error) = &result {
            if stale_guest_bearer(error) {
                forget_guest_bearer(&server_url, identifier.trim());
            }
        }
    }

    let context = ConnectContext {
        client,
        server_url,
        identifier,
        is_guest_attempt,
        typed_password,
        used_remembered_password,
    };
    finish_connect(state, session_events, ui, context, result).await;
}

/// What a sign-in needs to finish once Grappa has answered, kept across a
/// TOTP step so the second factor completes the same sign-in.
struct ConnectContext {
    client: GrappaClient,
    server_url: String,
    identifier: String,
    is_guest_attempt: bool,
    typed_password: Option<String>,
    used_remembered_password: bool,
}

/// A password sign-in waiting for its second factor: a TOTP (or
/// recovery) code, a passkey (issue #160), or either.
struct PendingTotp {
    context: ConnectContext,
    /// `None` when a passkey is the only way to finish.
    challenge_token: Option<String>,
    /// The passkey ceremony Grappa offered, while this platform can run
    /// it and it hasn't been spent on an answer.
    passkey: Option<Box<PasskeyOptions<PasskeyRequestOptions>>>,
}

/// Completes a sign-in with Grappa's answer: the session on success, the
/// error on the connect screen otherwise. A `202 two_factor_required` with
/// a TOTP challenge instead opens the code step (issue #118).
async fn finish_connect(
    state: &mut WorkerState,
    session_events: &mut Option<mpsc::UnboundedReceiver<SessionEvent>>,
    ui: &slint::Weak<AppWindow>,
    context: ConnectContext,
    result: Result<BootstrapOutcome, BootstrapError>,
) {
    if let Err(BootstrapError::Login(LoginError::TwoFactorRequired(challenge))) = &result {
        let passkey = challenge
            .passkey_options
            .clone()
            .filter(|_| ceremony::available());
        if challenge.challenge_token.is_some() || passkey.is_some() {
            persistence::log_line(&format!(
                "connect needs a second factor: server={} code={} passkey={}",
                context.server_url,
                challenge.challenge_token.is_some(),
                passkey.is_some()
            ));
            // A passkey account without TOTP: only its recovery codes open
            // the code door, so the step asks for one of those.
            let recovery_only = challenge.recovery_code_only();
            let code_accepted = challenge.challenge_token.is_some();
            let passkey_offered = passkey.is_some();
            state.conn.pending_totp = Some(PendingTotp {
                context,
                challenge_token: challenge.challenge_token.clone(),
                passkey,
            });
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_totp_recovery_only(recovery_only);
                ui.set_totp_code_accepted(code_accepted);
                ui.set_totp_passkey_offered(passkey_offered);
            });
            show_totp_step(ui, "");
            return;
        }
    }
    let ConnectContext {
        client,
        server_url,
        identifier,
        is_guest_attempt,
        typed_password,
        used_remembered_password,
    } = context;

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
            if is_guest_attempt {
                remember_guest_bearer(&server_url, identifier.trim(), &outcome.token);
            } else {
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
            state.windows.channel_entries = entries.clone();
            state.transcript.query_windows.clear();
            state.conn.server_protocol_version = Some(outcome.compatibility.protocol_version);
            state.transcript.pending_own_nick_dms.clear();
            state.transcript.query_joined.clear();
            state.transcript.query_ready.clear();
            state.transcript.query_full_history_required.clear();
            state.transcript.stale_query_topics.clear();
            state.windows.window_states =
                joined_window_states_from_boot_channels(&outcome.boot.channels);
            state.windows.window_failures.clear();
            state.windows.window_kicks.clear();
            state.windows.invited_by.clear();
            state.windows.window_mentions = window_mentions_from_me(&outcome.me.unread_counts);
            state.windows.window_messages = window_messages_from_me(&outcome.me.unread_counts);
            state.windows.recent_channels.clear();
            state.transcript.topics.clear();
            // Mode snapshots are replayed on each subscribed channel topic,
            // not included in `/boot`; never carry them across identities.
            state.transcript.channel_modes.clear();
            // `/me` is the cold seed for the server-authoritative read cursor
            // and account-wide badge; replace prior identity state before
            // opening the new Phoenix session.
            state.windows.read_cursors = read_cursors_from_me(&outcome.me.read_cursors);
            state.windows.badge_count = normalize_badge_count(Some(&outcome.me.badge_count));
            state.transcript.members.clear();
            state.transcript.messages = messages_from_boot(&outcome);
            state.networks.network_ids = network_ids_from_boot(&outcome);
            state.networks.network_connection_states = connection_states;
            state.networks.connecting_networks.clear();
            state.panels.recover_panel = None;
            state.panels.reply_view = None;
            state.panels.whois_card = None;
            state.prefs.auto_away_debounce = None;
            state.prefs.quit_part_reason = None;
            state.prefs.auto_away_reason = None;
            state.prefs.away_nick_suffix = None;
            state.panels.lusers_requested.clear();
            close_directory(state, ui);
            state.panels.dcc_offers.clear();
            state.panels.archive = None;
            state.networks.notify_lists.clear();
            state.networks.presence_by_network.clear();
            state.networks.peer_away.clear();
            state.panels.mentions_bundles.clear();
            state.panels.mention_jumps.clear();
            state.prefs.upload_limits = None;
            cancel_video_shrinks(state);
            state.prefs.web_bundle = None;
            state.networks.own_nicks = network_nicks_from_boot(&outcome);
            state.networks.away_states.clear();
            state.networks.session_identities.clear();
            state.networks.isupport_by_network.clear();
            state.networks.user_modes_by_network.clear();
            state.networks.supported_user_modes_by_network.clear();
            state.conn.own_listener_ready.clear();
            state.transcript.catch_up_anchors.clear();
            state.prefs.notification_prefs = None;
            state.windows.current_query = false;
            state.windows.current_query_ready = false;
            state.windows.current_channel = None;
            state.home = home::HomeState::default();
            state.home.apply_me(&outcome.me);
            // The Grappa login `subject` is opaque (and absent when reusing
            // a bearer); admin status comes only from the separate `/me`
            // response, where it is a top-level field.
            let is_admin = outcome.me.is_admin;
            let token = outcome.token.clone();
            // Realtime topics use Grappa's own subject label from `/me`: the
            // account name as stored (the login matched it case-insensitively)
            // or `visitor:<id>` for a guest, never the typed text, which the
            // topic check compares exactly (issue #82).
            let session_identifier =
                realtime_identifier(&outcome.me, is_guest_attempt, &identifier);
            persistence::log_line(&format!(
                "realtime topics: {} label from /me: {}",
                outcome.me.kind.as_deref().unwrap_or("unknown"),
                outcome.me.topic_label().is_some()
            ));

            let ws_url = to_ws_url(&server_url);
            let (handle, events) = spawn_session(ws_url, token.clone(), session_identifier.clone());
            handle.set_foreground(state.prefs.foreground);
            for network in state.networks.network_ids.keys() {
                handle.join_topic(
                    channel_topic(&session_identifier, network, SERVER_WINDOW_NAME),
                    false,
                );
            }
            for entry in &entries {
                handle.join_topic(channel_topic(&session_identifier, &entry.0, &entry.1), true);
            }
            for (network, nick) in &state.networks.own_nicks {
                handle.join_topic(
                    own_nick_listener_topic(&session_identifier, network, nick),
                    false,
                );
            }
            *session_events = Some(events);

            state.conn.client = Some(client);
            state.conn.token = Some(token.clone());
            state.conn.guest_session = is_guest_attempt;
            state.conn.identifier = Some(session_identifier.clone());
            state.conn.login_identifier = Some(identifier.clone());
            state.conn.session = Some(handle);
            state.conn.joined_topics = entries
                .iter()
                .map(|(network, channel, _)| channel_topic(&session_identifier, network, channel))
                .collect();
            for network in state.networks.network_ids.keys() {
                state.conn.joined_topics.insert(channel_topic(
                    &session_identifier,
                    network,
                    SERVER_WINDOW_NAME,
                ));
            }
            state.windows.channel_topics =
                channel_topics_for_entries(&session_identifier, &entries);
            for (network, nick) in &state.networks.own_nicks {
                state.conn.joined_topics.insert(own_nick_listener_topic(
                    &session_identifier,
                    network,
                    nick,
                ));
            }

            sync_presence_pins(state).await;
            handle_load_notification_prefs(state, ui).await;

            let prefs_client = GrappaClient::new(server_url.clone());
            let prefs_token = token.clone();
            let ui_for_prefs = ui.clone();
            tokio::spawn(async move {
                if let Ok(prefs) = prefs_client.fetch_display_prefs(&prefs_token).await {
                    let _ = ui_for_prefs.upgrade_in_event_loop(move |ui| {
                        apply_display_prefs(&ui, &prefs);
                    });
                }
                load_personal_prefs(&prefs_client, &prefs_token, &ui_for_prefs).await;
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
            let mut distinct_networks: Vec<String> =
                state.networks.network_ids.keys().cloned().collect();
            distinct_networks.sort();
            state.prefs.settings_network = distinct_networks.first().cloned();
            let network_count = distinct_networks.len();
            let channel_count = entries.len();
            let groups_data = network_groups_data(
                &entries,
                &state.transcript.query_windows,
                &state.windows.expanded_networks,
                &state.networks.network_connection_states,
                &state.networks.network_ids,
            );
            let window_states = state.windows.window_states.clone();
            let window_mentions = state.windows.window_mentions.clone();
            let window_messages = state.windows.window_messages.clone();
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
                ui.set_personal_prefs_loaded(false);
                ui.set_server_upload_limits_known(false);
                ui.set_current_query(false);
                ui.set_current_server_window(false);
                ui.set_current_query_ready(false);
                let networks: Vec<slint::SharedString> =
                    distinct_networks.into_iter().map(Into::into).collect();
                ui.set_known_networks(Rc::new(slint::VecModel::from(networks)).into());
                let groups = network_groups_model(
                    groups_data,
                    window_states,
                    window_mentions,
                    window_messages,
                    None,
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
                    (channel == SERVER_WINDOW_NAME
                        && state.networks.network_ids.contains_key(network)
                        && !state
                            .networks
                            .network_connection_states
                            .get(network)
                            .is_some_and(|snapshot| {
                                matches!(snapshot.status, NetworkConnectionStatus::Parked)
                            }))
                        || entries.iter().any(|(n, c, _)| n == network && c == channel)
                });
            load_color_themes(state, &ui).await;
            push_home(state, &ui);
            load_featured_channels(state, &ui).await;
            if let Some((network, channel)) = restore_channel {
                handle_select_channel(state, &ui, network, channel).await;
            } else if let Some(network) = state
                .networks
                .network_ids
                .keys()
                .filter(|network| {
                    !state
                        .networks
                        .network_connection_states
                        .get(*network)
                        .is_some_and(|snapshot| {
                            matches!(snapshot.status, NetworkConnectionStatus::Parked)
                        })
                })
                .min()
                .cloned()
            {
                handle_select_channel(state, &ui, network, SERVER_WINDOW_NAME.to_string()).await;
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

/// Puts `text` on the system clipboard (a TOTP key, link or recovery
/// codes); a clipboard that can't be opened is only logged.
fn copy_text(text: &str) {
    match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(text.to_string())) {
        Ok(()) => {}
        Err(err) => persistence::log_line(&format!("clipboard copy failed: {err}")),
    }
}

/// Settings > Security: reads whether TOTP is armed. A per-client token is
/// refused (403 `client_token_scope`) and the page says so; a visitor
/// session has no account, so it asks nothing and the page says that.
async fn handle_security_totp_refresh(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    if !home::account_security_available(state.home.session_kind()) {
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_security_totp_state("visitor".into());
            ui.set_security_totp_error("".into());
        });
        return;
    }
    let status = match client.fetch_totp_status(&token).await {
        Ok(true) => "enabled",
        Ok(false) => "disabled",
        Err(err) => {
            persistence::log_line(&format!("totp status failed: {err:?}"));
            if totp::settings_error_key(&err) == "client-token" {
                "client-token"
            } else {
                "unavailable"
            }
        }
    };
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_security_totp_state(status.into());
        ui.set_security_totp_error("".into());
    });
}

fn set_security_busy(ui: &slint::Weak<AppWindow>, busy: bool) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_security_totp_busy(busy);
        if busy {
            ui.set_security_totp_error("".into());
        }
    });
}

fn set_security_error(ui: &slint::Weak<AppWindow>, err: &GrappaClientError) {
    persistence::log_line(&format!("totp settings refused: {err:?}"));
    let key = totp::settings_error_key(err);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_security_totp_busy(false);
        ui.set_security_totp_error(key.into());
        if key == "client-token" {
            ui.set_security_totp_state("client-token".into());
        }
    });
}

/// Starts enrolment: shows the unarmed secret as text and QR code and
/// waits for its first code. The password field is cleared either way.
async fn handle_security_totp_start(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    password: String,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    set_security_busy(ui, true);
    let _ = ui.upgrade_in_event_loop(|ui| ui.set_security_password("".into()));
    match client.start_totp_enrollment(&token, &password).await {
        Ok(enrollment) => {
            state.conn.totp_enrollment = Some(enrollment.enrollment_token.clone());
            let qr = totp::qr_rgb(&enrollment.provisioning_uri);
            let _ = ui.upgrade_in_event_loop(move |ui| {
                let image = qr
                    .map(|(side, rgb)| {
                        slint::Image::from_rgb8(slint::SharedPixelBuffer::clone_from_slice(
                            &rgb, side, side,
                        ))
                    })
                    .unwrap_or_default();
                ui.set_security_totp_qr(image);
                ui.set_security_totp_secret(enrollment.secret.into());
                ui.set_security_totp_uri(enrollment.provisioning_uri.into());
                ui.set_security_totp_code("".into());
                ui.set_security_totp_step("enroll".into());
                ui.set_security_totp_busy(false);
            });
        }
        Err(err) => {
            if totp::settings_error_key(&err) == "already-enabled" {
                let _ = ui.upgrade_in_event_loop(|ui| ui.set_security_totp_state("enabled".into()));
            }
            set_security_error(ui, &err);
        }
    }
}

/// Arms TOTP with the first code and shows the recovery codes, once.
async fn handle_security_totp_confirm(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    code: String,
) {
    let (Some(client), Some(token), Some(enrollment)) = (
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.conn.totp_enrollment.clone(),
    ) else {
        return;
    };
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    set_security_busy(ui, true);
    match client
        .confirm_totp_enrollment(&token, &enrollment, &code)
        .await
    {
        Ok(codes) => {
            state.conn.totp_enrollment = None;
            let _ = ui.upgrade_in_event_loop(move |ui| {
                let codes: Vec<slint::SharedString> = codes.into_iter().map(Into::into).collect();
                ui.set_security_recovery_codes(Rc::new(slint::VecModel::from(codes)).into());
                ui.set_security_totp_secret("".into());
                ui.set_security_totp_uri("".into());
                ui.set_security_totp_qr(slint::Image::default());
                ui.set_security_totp_code("".into());
                ui.set_security_totp_state("enabled".into());
                ui.set_security_totp_step("codes".into());
                ui.set_security_totp_busy(false);
            });
        }
        Err(err) => set_security_error(ui, &err),
    }
}

/// Disarms TOTP after re-authenticating with the password.
async fn handle_security_totp_disable(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    password: String,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    set_security_busy(ui, true);
    let _ = ui.upgrade_in_event_loop(|ui| ui.set_security_password("".into()));
    match client.disable_totp(&token, &password).await {
        Ok(()) => {
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_security_totp_state("disabled".into());
                ui.set_security_totp_busy(false);
            });
        }
        Err(err) => set_security_error(ui, &err),
    }
}

/// Settings > Security: reads the passkey mode and list. A per-client token
/// is refused (403 `client_token_scope`) and the page says so; a visitor
/// session has no account, so it asks nothing and the page says that.
async fn handle_security_passkeys_refresh(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    if !home::account_security_available(state.home.session_kind()) {
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_security_passkeys(slint::ModelRc::default());
            ui.set_security_passkey_state("visitor".into());
            ui.set_security_passkey_busy(false);
        });
        return;
    }
    match client.fetch_passkeys(&token).await {
        Ok(status) => {
            let mode = passkeys::mode_key(status.mode);
            let _ = ui.upgrade_in_event_loop(move |ui| {
                let rows: Vec<PasskeyRow> = status
                    .passkeys
                    .into_iter()
                    .map(|passkey| PasskeyRow {
                        id: passkey.id.into(),
                        name: passkey.name.unwrap_or_default().into(),
                        added: format_iso_timestamp(&passkey.inserted_at).into(),
                        last_used: passkey
                            .last_used_at
                            .as_deref()
                            .map(format_iso_timestamp)
                            .unwrap_or_default()
                            .into(),
                    })
                    .collect();
                ui.set_security_passkeys(Rc::new(slint::VecModel::from(rows)).into());
                ui.set_security_passkey_mode(mode.into());
                ui.set_security_passkey_state("loaded".into());
                ui.set_security_passkey_busy(false);
            });
        }
        Err(err) => {
            persistence::log_line(&format!("passkey status failed: {err:?}"));
            let status = if passkeys::settings_error_key(&err) == "client-token" {
                "client-token"
            } else {
                "unavailable"
            };
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_security_passkeys(slint::ModelRc::default());
                ui.set_security_passkey_state(status.into());
                ui.set_security_passkey_busy(false);
            });
        }
    }
}

/// Deletes a passkey after re-authenticating with the password, then
/// reloads the list. The password field is cleared either way; a passkey
/// that is already gone only refreshes the list.
async fn handle_security_passkey_delete(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    id: String,
    password: String,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_security_passkey_busy(true);
        ui.set_security_passkey_error("".into());
        ui.set_security_passkey_password("".into());
    });
    let key = match client.delete_passkey(&token, &id, &password).await {
        Ok(()) => "",
        Err(err) => {
            persistence::log_line(&format!("passkey delete refused: {err:?}"));
            match passkeys::settings_error_key(&err) {
                "gone" => "",
                key => key,
            }
        }
    };
    if key.is_empty() {
        handle_security_passkeys_refresh(state, ui).await;
    } else {
        let _ = ui.upgrade_in_event_loop(move |ui| {
            ui.set_security_passkey_busy(false);
            ui.set_security_passkey_error(key.into());
            if key == "client-token" {
                ui.set_security_passkey_state("client-token".into());
            }
        });
    }
}

/// A Settings > Security change that needs a passkey ceremony.
enum PasskeyChange {
    Add { name: String, password: String },
    Mode { mode: PasskeyMode, password: String },
    Passwordless { recovery_token: String },
}

/// Runs a passkey change in its own task: the system prompt can stay open
/// for minutes, and the worker keeps serving the session meanwhile. The
/// password field is cleared up front; the list is read again at the end.
fn spawn_passkey_change(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    worker_self: &mpsc::UnboundedSender<WorkerCommand>,
    change: PasskeyChange,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let ui = ui.clone();
    let worker = worker_self.clone();
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_security_passkey_busy(true);
        ui.set_security_passkey_error("".into());
        ui.set_security_passkey_password("".into());
    });
    tokio::spawn(async move {
        let passwordless = matches!(change, PasskeyChange::Passwordless { .. });
        let key = match run_passkey_change(&client, &token, &ui, change).await {
            Ok(()) => "",
            Err(key) => key,
        };
        let _ = ui.upgrade_in_event_loop(move |ui| {
            ui.set_security_passkey_busy(false);
            ui.set_security_passkey_error(key.into());
            if key.is_empty() {
                ui.set_security_passkey_name("".into());
            }
            if key == "client-token" {
                ui.set_security_passkey_state("client-token".into());
            }
        });
        // Armed: the recovery codes and their token are done with.
        if passwordless && key.is_empty() {
            let _ = worker.send(WorkerCommand::SecurityPasswordlessCancel);
        }
        let _ = worker.send(WorkerCommand::SecurityPasskeysRefresh);
    });
}

/// Options, ceremony and answer for one change; the error is the page's
/// `security-passkey-error` key.
async fn run_passkey_change(
    client: &GrappaClient,
    token: &str,
    ui: &slint::Weak<AppWindow>,
    change: PasskeyChange,
) -> Result<(), &'static str> {
    let origin = ceremony_origin_for(client.base_url());
    let options = match change {
        PasskeyChange::Add { name, password } => {
            let options = client
                .start_passkey_registration(token, &password, &name)
                .await
                .map_err(|err| {
                    passkey_change_refused("registration options", &err, "add-failed")
                })?;
            let credential =
                ceremony::run_registration(&options, &origin, passkey_parent(ui).await)
                    .await
                    .map_err(|err| passkey_ceremony_failed(&err))?;
            client
                .finish_passkey_registration(token, &credential)
                .await
                .map_err(|err| passkey_change_refused("registration", &err, "add-failed"))?;
            return Ok(());
        }
        PasskeyChange::Mode { mode, password } => client
            .start_passkey_mode_change(token, &password, mode)
            .await
            .map_err(|err| passkey_change_refused("mode options", &err, "mode-failed"))?,
        // A 401 here is the recovery token: bound to this session and good
        // for ten minutes.
        PasskeyChange::Passwordless { recovery_token } => client
            .start_passwordless_activation(token, &recovery_token)
            .await
            .map_err(|err| {
                match passkey_change_refused("passwordless options", &err, "mode-failed") {
                    "refused" => "expired",
                    key => key,
                }
            })?,
    };
    let assertion = ceremony::run_assertion(&options, &origin, passkey_parent(ui).await)
        .await
        .map_err(|err| passkey_ceremony_failed(&err))?;
    client
        .finish_passkey_mode_change(token, &assertion)
        .await
        .map_err(|err| passkey_change_refused("mode change", &err, "mode-failed"))?;
    Ok(())
}

fn passkey_change_refused(
    step: &str,
    err: &GrappaClientError,
    fallback: &'static str,
) -> &'static str {
    persistence::log_line(&format!("passkey {step} refused: {err:?}"));
    match passkeys::settings_error_key(err) {
        "failed" | "gone" => fallback,
        key => key,
    }
}

fn passkey_ceremony_failed(err: &ceremony::CeremonyError) -> &'static str {
    persistence::log_line(&format!("passkey ceremony not run: {err}"));
    passkeys::ceremony_error_key(err)
}

/// First step to passwordless: Grappa makes the recovery codes, shown
/// before anything is armed. They start working only once the passkey
/// assertion of the second step succeeds.
async fn handle_security_passwordless_prepare(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    password: String,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_security_passkey_busy(true);
        ui.set_security_passkey_error("".into());
        ui.set_security_passkey_password("".into());
    });
    match client.prepare_passwordless(&token, &password).await {
        Ok(recovery) => {
            state.conn.passwordless_recovery_token = Some(recovery.recovery_token);
            let codes = recovery.recovery_codes;
            let _ = ui.upgrade_in_event_loop(move |ui| {
                let codes: Vec<slint::SharedString> = codes.into_iter().map(Into::into).collect();
                ui.set_security_passwordless_codes(Rc::new(slint::VecModel::from(codes)).into());
                ui.set_security_passkey_busy(false);
            });
        }
        Err(err) => {
            let key = passkey_change_refused("passwordless recovery", &err, "mode-failed");
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_security_passkey_busy(false);
                ui.set_security_passkey_error(key.into());
                if key == "client-token" {
                    ui.set_security_passkey_state("client-token".into());
                }
            });
        }
    }
}

/// Forgets a share link on screen: it is a credential, so it never outlives
/// the moment the user is done with it.
fn clear_share_link(ui: &AppWindow) {
    ui.set_security_share_link("".into());
    ui.set_security_share_expires("".into());
    ui.set_security_share_qr(slint::Image::default());
    ui.set_security_share_error("".into());
    ui.set_security_share_busy(false);
}

/// Settings > Security: mints a share token and shows it as a link and QR
/// code, the way Cicchetto's "open on another device" does. The token only
/// ever lives in the UI properties (never in the log) and is dropped by
/// `clear_share_link`.
async fn handle_security_share_mint(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_security_share_busy(true);
        ui.set_security_share_error("".into());
    });
    match client.mint_share_token(&token).await {
        Ok(minted) => {
            let link = share::share_link(client.base_url(), &minted.token);
            let qr = totp::qr_rgb(&link);
            let expires = share_expiry_text(&minted.expires_at);
            let _ = ui.upgrade_in_event_loop(move |ui| {
                let image = qr
                    .map(|(side, rgb)| {
                        slint::Image::from_rgb8(slint::SharedPixelBuffer::clone_from_slice(
                            &rgb, side, side,
                        ))
                    })
                    .unwrap_or_default();
                ui.set_security_share_qr(image);
                ui.set_security_share_link(link.into());
                ui.set_security_share_expires(expires.into());
                ui.set_security_share_busy(false);
            });
        }
        Err(err) => {
            persistence::log_line(&format!("share token mint refused: {err:?}"));
            let key = share_mint_error_key(&err);
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_security_share_busy(false);
                ui.set_security_share_error(key.into());
            });
        }
    }
}

/// When a share token stops working, in the user's time zone; empty if
/// Grappa's timestamp can't be read.
fn share_expiry_text(expires_at: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(expires_at)
        .map(|expiry| dates::render_date_time(&expiry.with_timezone(&chrono::Local), false))
        .unwrap_or_default()
}

/// Status key for a refused `POST /me/share-token`: a per-client token can't
/// mint one, and neither can an incognito guest.
fn share_mint_error_key(err: &GrappaClientError) -> &'static str {
    match (err.status().map(|status| status.as_u16()), err.code()) {
        (_, Some("client_token_scope")) => "client-token",
        (_, Some("forbidden")) => "incognito",
        (Some(429), _) => "throttled",
        _ => "failed",
    }
}

/// Status key for a refused `POST /auth/share/consume`. Expired and used
/// tokens can't be retried; the user asks the other device for a new one.
fn share_consume_error_key(err: &GrappaClientError) -> &'static str {
    match (err.status().map(|status| status.as_u16()), err.code()) {
        (_, Some("share_token_expired")) => "share-expired",
        (_, Some("share_token_consumed")) => "share-consumed",
        (_, Some("not_found")) | (Some(404), _) => "share-gone",
        (_, Some("too_many_attempts")) | (Some(429), _) => "too-many-attempts",
        (Some(400 | 401), _) => "share-invalid",
        _ => "share-failed",
    }
}

/// Who a consumed share token signed in. A user keeps its account name, so
/// the session is remembered like a password sign-in. A guest (visitor) has
/// no name to key a remembered bearer by, so it runs as an unnamed guest
/// session that isn't remembered.
fn shared_identity(subject: Option<&Value>, me: &MeResponse) -> (String, bool) {
    let kind = subject
        .and_then(|subject| subject.get("kind"))
        .and_then(Value::as_str)
        .or(me.kind.as_deref());
    let name = subject
        .and_then(|subject| subject.get("name"))
        .and_then(Value::as_str)
        .or(me.name.as_deref())
        .filter(|name| !name.is_empty());
    match (kind, name) {
        (Some("visitor"), _) | (_, None) => (String::new(), true),
        (_, Some(name)) => (name.to_string(), false),
    }
}

/// Signs in with a share token (or the link holding it) pasted on the share
/// screen. The answer is login-shaped, so the session is finished like any
/// other sign-in. The token is single use: it is never logged, and the
/// field is emptied once it has been spent.
async fn handle_share_consume(
    state: &mut WorkerState,
    session_events: &mut Option<mpsc::UnboundedReceiver<SessionEvent>>,
    ui: &slint::Weak<AppWindow>,
    server_url: String,
    input: String,
) {
    let Some(share_token) = share::token_from_input(&input) else {
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_connecting(false);
            ui.set_status_kind("share-invalid".into());
        });
        return;
    };
    let server_url = normalize_server_url(&server_url);
    remember_server_url(&server_url);

    let client = GrappaClient::new(server_url.clone());
    persistence::log_line(&format!(
        "connect attempt: server={server_url} auth=share_token"
    ));
    let result = bootstrap_with_share_token(&client, &share_token).await;
    let (identifier, is_guest_attempt) = match &result {
        Ok(outcome) => shared_identity(outcome.subject.as_ref(), &outcome.me),
        Err(_) => (String::new(), false),
    };
    if result.is_ok() {
        let _ = ui.upgrade_in_event_loop(|ui| ui.set_share_token_input("".into()));
    }
    let context = ConnectContext {
        client,
        server_url,
        identifier,
        is_guest_attempt,
        typed_password: None,
        used_remembered_password: false,
    };
    finish_connect(state, session_events, ui, context, result).await;
}

/// The account name and recovery code as they go to Grappa: the name
/// trimmed and the code without the whitespace a copy or a dash-grouped
/// paste can carry. `None` when either is empty.
fn recovery_input(identifier: &str, code: &str) -> Option<(String, String)> {
    let identifier = identifier.trim();
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    (!identifier.is_empty() && !code.is_empty()).then(|| (identifier.to_string(), code))
}

/// Status key for a refused `POST /auth/passkeys/recover`. Grappa answers a
/// wrong, already used or unknown-account code with the same opaque 401
/// (recovery codes don't expire), so one message covers them; a throttle
/// and a busy server are told apart because waiting is the only fix.
fn recovery_error_key(err: &GrappaClientError) -> &'static str {
    match (err.status().map(|status| status.as_u16()), err.code()) {
        (Some(429), _) | (_, Some("too_many_attempts")) => "totp-throttled",
        (Some(503), _) | (_, Some("db_unavailable")) => "recovery-busy",
        (Some(401), _) | (_, Some("invalid_two_factor")) => "recovery-invalid",
        _ => "recovery-failed",
    }
}

/// Signs a passwordless account in with a recovery code from the recovery
/// screen, then finishes the session like any other sign-in. The code is
/// spent by the server and is never logged or kept.
async fn handle_recovery_sign_in(
    state: &mut WorkerState,
    session_events: &mut Option<mpsc::UnboundedReceiver<SessionEvent>>,
    ui: &slint::Weak<AppWindow>,
    server_url: String,
    identifier: String,
    code: String,
) {
    let Some((identifier, code)) = recovery_input(&identifier, &code) else {
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_connecting(false);
            ui.set_status_kind("recovery-invalid".into());
        });
        return;
    };
    let server_url = normalize_server_url(&server_url);
    remember_server_url(&server_url);

    let client = GrappaClient::new(server_url.clone());
    persistence::log_line(&format!(
        "connect attempt: server={server_url} identifier={identifier} guest=false \
         auth=recovery_code"
    ));
    let result = bootstrap_with_recovery_code(&client, &identifier, &code).await;
    let context = ConnectContext {
        client,
        server_url,
        identifier,
        is_guest_attempt: false,
        typed_password: None,
        used_remembered_password: false,
    };
    finish_connect(state, session_events, ui, context, result).await;
}

/// Shows the code step of a two-factor sign-in, with `status` ("" or a
/// `totp-*` key) under the field.
fn show_totp_step(ui: &slint::Weak<AppWindow>, status: &'static str) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_connecting(false);
        ui.set_status_message("".into());
        ui.set_status_kind(status.into());
        ui.set_screen("totp".into());
    });
}

/// Status key for a refused `POST /auth/totp/verify`. An expired challenge
/// can't be retried: the sign-in starts again from the password.
fn totp_error_key(err: &GrappaClientError) -> &'static str {
    match (err.status().map(|status| status.as_u16()), err.code()) {
        (_, Some("two_factor_challenge_expired")) => "totp-expired",
        (_, Some("invalid_two_factor")) | (Some(401), None) => "totp-invalid",
        (Some(429), _) | (_, Some("too_many_attempts")) => "totp-throttled",
        _ => "totp-failed",
    }
}

/// Verifies the pending sign-in's code. Success finishes the sign-in like
/// any other; a wrong code or a throttle keeps the step open (the
/// challenge stays valid for its five minutes); an expired challenge goes
/// back to the password.
async fn handle_totp_verify(
    state: &mut WorkerState,
    session_events: &mut Option<mpsc::UnboundedReceiver<SessionEvent>>,
    ui: &slint::Weak<AppWindow>,
    code: String,
) {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let Some(pending) = state.conn.pending_totp.take() else {
        return;
    };
    let Some(challenge_token) = pending.challenge_token.clone() else {
        state.conn.pending_totp = Some(pending);
        return;
    };
    if code.is_empty() {
        state.conn.pending_totp = Some(pending);
        show_totp_step(ui, "totp-invalid");
        return;
    }
    let result = bootstrap_with_totp(&pending.context.client, &challenge_token, &code).await;
    match result {
        Err(BootstrapError::TwoFactor(err)) => {
            persistence::log_line(&format!("totp verify refused: {err:?}"));
            let key = totp_error_key(&err);
            if key == "totp-expired" {
                let _ = ui.upgrade_in_event_loop(|ui| {
                    ui.set_connecting(false);
                    ui.set_totp_code("".into());
                    ui.set_screen("connect".into());
                    ui.set_status_kind("totp-expired".into());
                });
            } else {
                state.conn.pending_totp = Some(pending);
                show_totp_step(ui, key);
            }
        }
        other => {
            let _ = ui.upgrade_in_event_loop(|ui| ui.set_totp_code("".into()));
            finish_connect(state, session_events, ui, pending.context, other).await;
        }
    }
}

/// Signs in with a passkey (issue #160). The options, the ceremony and
/// the verify go through one client: Grappa binds a challenge to its
/// caller's address.
async fn handle_passkey_sign_in(
    state: &mut WorkerState,
    session_events: &mut Option<mpsc::UnboundedReceiver<SessionEvent>>,
    ui: &slint::Weak<AppWindow>,
    request: PasskeySignIn,
) {
    match request {
        PasskeySignIn::SecondFactor => {
            handle_passkey_second_factor(state, session_events, ui).await;
        }
        PasskeySignIn::Passwordless {
            server_url,
            identifier,
        } => {
            handle_passkey_login(state, session_events, ui, server_url, identifier).await;
        }
    }
}

/// Finishes the pending password sign-in with a passkey. A ceremony that
/// didn't run leaves the challenge usable for another try; once Grappa has
/// answered it is spent, and only the code door (if any) is left.
async fn handle_passkey_second_factor(
    state: &mut WorkerState,
    session_events: &mut Option<mpsc::UnboundedReceiver<SessionEvent>>,
    ui: &slint::Weak<AppWindow>,
) {
    let Some(mut pending) = state.conn.pending_totp.take() else {
        return;
    };
    let Some(options) = pending.passkey.take() else {
        state.conn.pending_totp = Some(pending);
        show_totp_step(ui, "");
        return;
    };
    let origin = ceremony_origin_for(&pending.context.server_url);
    let parent = passkey_parent(ui).await;
    let assertion = match ceremony::run_assertion(&options, &origin, parent).await {
        Ok(assertion) => assertion,
        Err(err) => {
            persistence::log_line(&format!("passkey second factor not run: {err}"));
            pending.passkey = Some(options);
            state.conn.pending_totp = Some(pending);
            show_totp_step(ui, passkeys::ceremony_error_key(&err));
            return;
        }
    };
    let verified = pending
        .context
        .client
        .verify_passkey_second_factor(&assertion)
        .await;
    match verified {
        Ok(login) => {
            let result = bootstrap_with_bearer(&pending.context.client, &login.token).await;
            let _ = ui.upgrade_in_event_loop(|ui| ui.set_totp_code("".into()));
            finish_connect(state, session_events, ui, pending.context, result).await;
        }
        Err(err) => {
            persistence::log_line(&format!("passkey second factor refused: {err:?}"));
            let key = passkeys::sign_in_error_key(&err);
            if pending.challenge_token.is_some() {
                state.conn.pending_totp = Some(pending);
                let _ = ui.upgrade_in_event_loop(|ui| ui.set_totp_passkey_offered(false));
                show_totp_step(ui, key);
            } else {
                show_connect_error(ui, key);
            }
        }
    }
}

/// Signs a passwordless account in from the connect screen: no password,
/// just a discoverable passkey for the server's RP ID.
async fn handle_passkey_login(
    state: &mut WorkerState,
    session_events: &mut Option<mpsc::UnboundedReceiver<SessionEvent>>,
    ui: &slint::Weak<AppWindow>,
    server_url: String,
    identifier: String,
) {
    let server_url = normalize_server_url(&server_url);
    remember_server_url(&server_url);
    let identifier = identifier.trim().to_string();
    let client = GrappaClient::new(server_url.clone());
    persistence::log_line(&format!(
        "connect attempt: server={server_url} identifier={identifier} guest=false auth=passkey"
    ));
    let options = match client.passkey_login_options(&identifier).await {
        Ok(options) => options,
        Err(err) => {
            persistence::log_line(&format!("passkey sign-in options refused: {err:?}"));
            show_connect_error(ui, passkeys::sign_in_error_key(&err));
            return;
        }
    };
    let origin = ceremony_origin_for(&server_url);
    let parent = passkey_parent(ui).await;
    let assertion = match ceremony::run_assertion(&options, &origin, parent).await {
        Ok(assertion) => assertion,
        Err(err) => {
            persistence::log_line(&format!("passkey sign-in not run: {err}"));
            show_connect_error(ui, passkeys::ceremony_error_key(&err));
            return;
        }
    };
    let verified = client.verify_passkey_login(&assertion).await;
    let result = match verified {
        Ok(login) => bootstrap_with_bearer(&client, &login.token).await,
        Err(err) => {
            persistence::log_line(&format!("passkey sign-in refused: {err:?}"));
            show_connect_error(ui, passkeys::sign_in_error_key(&err));
            return;
        }
    };
    let context = ConnectContext {
        client,
        server_url,
        identifier,
        is_guest_attempt: false,
        typed_password: None,
        used_remembered_password: false,
    };
    finish_connect(state, session_events, ui, context, result).await;
}

/// The origin a ceremony with `server_url` claims: the per-server override
/// when one is saved, else the one rebuilt from the URL (issue #163).
fn ceremony_origin_for(server_url: &str) -> String {
    let saved = persistence::load_passkey_origin_override(server_url);
    passkey_origin(server_url, saved.as_deref())
}

/// Cordiale's window, read on the UI thread, for the system passkey
/// dialog to sit on.
async fn passkey_parent(ui: &slint::Weak<AppWindow>) -> Option<ceremony::ParentWindow> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let _ = sender.send(ceremony::parent_window(ui.window()));
    });
    receiver.await.ok().flatten()
}

/// Back to the connect screen with `key` under the form.
fn show_connect_error(ui: &slint::Weak<AppWindow>, key: &'static str) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_connecting(false);
        ui.set_totp_code("".into());
        ui.set_screen("connect".into());
        ui.set_status_message("".into());
        ui.set_status_kind(key.into());
    });
}

/// The subject label for the realtime topics: `/me`'s label when it gives
/// one, otherwise `guest` for a guest sign-in and the typed name for an
/// account (older servers).
fn realtime_identifier(me: &MeResponse, guest: bool, typed: &str) -> String {
    me.topic_label().unwrap_or_else(|| {
        if guest {
            "guest".to_string()
        } else {
            typed.to_string()
        }
    })
}

/// Whether `identifier` appears in `members` holding op or any role the
/// network ranks above it — gates `MemberContextMenu`'s
/// Op/Deop/Voice/Devoice/Kick/Ban items, as accurate as `members`
/// (snapshots plus live MODE changes).
fn is_own_nick_an_op(members: &[MemberEntry], identifier: &str, ranking: &MemberRanking) -> bool {
    members
        .iter()
        .any(|(name, prefix)| name == identifier && ranking.is_op_or_above(prefix))
}

async fn handle_send_message(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, body: String) {
    if state.windows.current_query && !state.windows.current_query_ready {
        return;
    }
    let body = if body.trim_start().starts_with('/') {
        let aliases = user_aliases(state).await;
        match cordiale_core::slash::expand_aliases(&body, &aliases) {
            Ok(line) => line,
            Err(chain) => {
                set_command_status(ui, "alias-too-deep", chain);
                return;
            }
        }
    } else {
        body
    };
    let (Some(client), Some(token), Some((network, channel))) = (
        &state.conn.client,
        &state.conn.token,
        &state.windows.current_channel,
    ) else {
        let _ = ui.upgrade_in_event_loop(|ui| ui.set_status_kind("no-active-network".into()));
        return;
    };
    if channel == SERVER_WINDOW_NAME && !body.trim_start().starts_with('/') {
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_status_kind("server-window-commands-only".into());
        });
        return;
    }

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
        let bundle = state.panels.mentions_bundles.get(network.as_str()).cloned();
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
                    state.panels.lusers_requested.insert(network.to_string());
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
    if let Some(command) = cordiale_core::slash::parse(&body) {
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
    if let Err(err) = client.send_message(token, network, channel, &request).await {
        set_send_failed_status(ui, &err);
    }
}

/// The status bar's wait, in whole seconds (at least 1).
fn wait_secs(wait: std::time::Duration) -> i32 {
    i32::try_from(cordiale_core::backoff::display_seconds(wait)).unwrap_or(i32::MAX)
}

/// Tells the user how long the server asked them to hold off.
fn set_rate_limited_status(ui: &slint::Weak<AppWindow>, wait: std::time::Duration) {
    let secs = wait_secs(wait);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_retry_secs(secs);
        ui.set_status_kind("rate-limited".into());
    });
}

/// Reports a message post that failed: the wait a throttle (`429`) asked
/// for when it gave one, the generic failure otherwise.
fn set_send_failed_status(ui: &slint::Weak<AppWindow>, err: &GrappaClientError) {
    match err.retry_after() {
        Some(wait) if err.status().is_some_and(|status| status.as_u16() == 429) => {
            set_rate_limited_status(ui, wait);
        }
        _ => {
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_status_kind("send-failed".into());
            });
        }
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
    options: UploadOptions,
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
    // The window open when the upload starts is where the link goes, even
    // if another one is opened while the file is on its way.
    let Some((network, channel)) = state.windows.current_channel.clone() else {
        set_status("attach-no-window", filename);
        return;
    };
    if channel == SERVER_WINDOW_NAME {
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_status_kind("server-window-commands-only".into());
        });
        return;
    }
    if state.windows.current_query && !state.windows.current_query_ready {
        return;
    }
    let Some((mime, category)) = mime_for_filename(&filename) else {
        set_status("attach-unsupported-type", filename);
        return;
    };
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    if options.shrink && category == UploadCategory::Video {
        if !video_processing::is_available() {
            set_status("attach-shrink-unavailable", filename);
            return;
        }
        let video_cap = state
            .prefs
            .upload_limits
            .as_ref()
            .map(|limits| upload_cap(limits, category));
        let job = UploadJob {
            client,
            token,
            network,
            channel,
            ui: ui.clone(),
            filename,
            expire: options.expire,
        };
        // The encoder takes as long as the video does: its own task keeps
        // session frames and other commands moving meanwhile.
        tokio::spawn(shrink_and_upload(
            job,
            path,
            video_cap,
            state.conn.shrink_cancel.clone(),
        ));
        return;
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            persistence::log_line(&format!("attachment read failed: {err}"));
            set_status("attach-read-failed", filename);
            return;
        }
    };
    let over_cap = state
        .prefs
        .upload_limits
        .as_ref()
        .is_some_and(|limits| bytes.len() as u64 > upload_cap(limits, category));
    if over_cap {
        set_status("attach-too-large", filename);
        return;
    }
    // No progress or success text: the outcome goes to the log, and a stale
    // status from an earlier attempt is cleared, raw message included.
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_status_kind("".into());
        ui.set_status_message("".into());
    });
    let job = UploadJob {
        client,
        token,
        network,
        channel,
        ui: ui.clone(),
        filename,
        expire: options.expire,
    };
    upload_and_post(job, mime, category, bytes).await;
}

/// What the user chose for one upload, fixed when they confirm it (or when
/// the question is off, from the saved defaults) and carried unchanged to
/// the upload: Settings changing meanwhile doesn't touch it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UploadOptions {
    /// The lifetime to request (`expire`), `None` for the server's default.
    expire: Option<i64>,
    /// Shrink the video first. Ignored for other types of file.
    shrink: bool,
}

/// Stops the videos being shrunk for the session that is ending, so that
/// they are not uploaded under the next one. Later uploads get a fresh flag.
fn cancel_video_shrinks(state: &mut WorkerState) {
    state
        .conn
        .shrink_cancel
        .store(true, std::sync::atomic::Ordering::Relaxed);
    state.conn.shrink_cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
}

/// Where an upload goes and how: everything the task that sends it needs,
/// taken when the file is accepted so that it doesn't depend on what the
/// window shows when the upload ends.
struct UploadJob {
    client: GrappaClient,
    token: String,
    network: String,
    channel: String,
    ui: slint::Weak<AppWindow>,
    filename: String,
    expire: Option<i64>,
}

fn set_attach_status(ui: &slint::Weak<AppWindow>, kind: &'static str, name: String) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_attach_name(name.into());
        ui.set_status_kind(kind.into());
    });
}

/// Uploads `bytes` and posts the link in the job's window.
async fn upload_and_post(
    job: UploadJob,
    mime: &'static str,
    category: UploadCategory,
    bytes: Vec<u8>,
) {
    let UploadJob {
        client,
        token,
        network,
        channel,
        ui,
        filename,
        expire,
    } = job;
    match client
        .upload_file(&token, &filename, mime, bytes, expire)
        .await
    {
        Ok(uploaded) => {
            persistence::log_line(&format!("attachment uploaded: slug={}", uploaded.slug));
            let expiry = attach_expiry(&uploaded.expires_at, chrono::Utc::now());
            let remaining = match &expiry {
                AttachExpiry::Live(label) => Some(label.as_str()),
                AttachExpiry::Expired => {
                    set_attach_status(&ui, "attach-expired", filename);
                    return;
                }
                AttachExpiry::Unknown => None,
            };
            let request =
                SendMessageRequest::plain(attachment_message(category, &uploaded.url, remaining));
            if let Err(err) = client
                .send_message(&token, &network, &channel, &request)
                .await
            {
                set_send_failed_status(&ui, &err);
            } else if remaining.is_none() {
                set_attach_status(&ui, "attach-expiry-unknown", filename);
            }
        }
        Err(err) => {
            persistence::log_line(&format!("attachment upload failed: {err:?}"));
            set_attach_status(
                &ui,
                attachment_error_status(err.status().map(|status| status.as_u16())),
                filename,
            );
        }
    }
}

/// Status-bar key for a video that was not shrunk, `None` when it was
/// stopped on purpose (nothing to report).
fn shrink_error_status(error: &ShrinkError) -> Option<&'static str> {
    match error {
        ShrinkError::Unavailable => Some("attach-shrink-unavailable"),
        ShrinkError::Cancelled => None,
        ShrinkError::Failed(_) => Some("attach-shrink-failed"),
        ShrinkError::NotSmaller => Some("attach-shrink-not-smaller"),
        ShrinkError::OverCap => Some("attach-shrink-too-large"),
    }
}

/// Puts the outcome of a video that was not shrunk in the status bar.
fn report_shrink_error(ui: &slint::Weak<AppWindow>, name: &str, error: &ShrinkError) {
    match shrink_error_status(error) {
        Some(kind) => set_attach_status(ui, kind, name.to_string()),
        None => {
            let _ = ui.upgrade_in_event_loop(|ui| ui.set_status_kind("".into()));
        }
    }
}

/// Shrinks the video at `path` into a temporary file, checks the result
/// against the server's cap for videos (the original may be over it), then
/// uploads the result. Nothing goes up unless the shrunk copy does: a failed
/// or useless shrink is reported and the original is left alone. `cancel`
/// is set when the session ends.
async fn shrink_and_upload(
    job: UploadJob,
    path: std::path::PathBuf,
    video_cap: Option<u64>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let ui = job.ui.clone();
    let original_name = job.filename.clone();
    let Ok(original_len) = std::fs::metadata(&path).map(|meta| meta.len()) else {
        set_attach_status(&ui, "attach-read-failed", original_name.clone());
        return;
    };
    set_attach_status(&ui, "attach-shrinking", original_name.clone());
    let progress_ui = ui.clone();
    let progress_name = original_name.clone();
    let task_cancel = cancel.clone();
    let shrunk = tokio::task::spawn_blocking(move || {
        video_processing::shrink(&path, &task_cancel, &|percent| {
            set_attach_status(
                &progress_ui,
                "attach-shrinking",
                format!("{progress_name} ({percent}%)"),
            );
        })
    })
    .await;
    let video = match shrunk {
        Ok(Ok(video)) => video,
        Ok(Err(error)) => {
            persistence::log_line(&format!("video shrink stopped: {error:?}"));
            report_shrink_error(&ui, &original_name, &error);
            return;
        }
        Err(err) => {
            persistence::log_line(&format!("video shrink task failed: {err}"));
            report_shrink_error(&ui, &original_name, &ShrinkError::Failed(err.to_string()));
            return;
        }
    };
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        report_shrink_error(&ui, &original_name, &ShrinkError::Cancelled);
        return;
    }
    let shrunk_len = std::fs::metadata(&video.path).map_or(u64::MAX, |meta| meta.len());
    if let Err(error) = video_processing::check_result(original_len, shrunk_len, video_cap) {
        report_shrink_error(&ui, &original_name, &error);
        return;
    }
    let bytes = match std::fs::read(&video.path) {
        Ok(bytes) => bytes,
        Err(err) => {
            persistence::log_line(&format!("shrunk video read failed: {err}"));
            set_attach_status(&ui, "attach-read-failed", original_name.clone());
            return;
        }
    };
    let (filename, mime) = (video.filename.clone(), video.mime);
    // The temporary folder goes now: the bytes are in memory.
    drop(video);
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_status_kind("".into());
        ui.set_status_message("".into());
    });
    let job = UploadJob { filename, ..job };
    upload_and_post(job, mime, UploadCategory::Video, bytes).await;
}

/// What the server's `expires_at` says about a fresh upload.
#[derive(Debug, PartialEq, Eq)]
enum AttachExpiry {
    /// Still live: the remaining lifetime as it goes after the link.
    Live(String),
    /// Gone, or about to be: not announced as an attachment.
    Expired,
    /// Missing or unreadable: the link goes without a duration.
    Unknown,
}

/// The lifetime left at `now`, from the expiry the server returned (not the
/// one asked for: the upload itself takes time).
fn attach_expiry(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> AttachExpiry {
    let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
        return AttachExpiry::Unknown;
    };
    let remaining = (expires.with_timezone(&chrono::Utc) - now).num_seconds();
    match remaining_lifetime_label(remaining) {
        Some(label) => AttachExpiry::Live(label),
        None => AttachExpiry::Expired,
    }
}

thread_local! {
    /// The file the upload confirmation is showing (UI thread only).
    static PENDING_UPLOAD: RefCell<Option<std::path::PathBuf>> = const { RefCell::new(None) };
}

/// Largest image the confirmation decodes for its thumbnail.
const PREVIEW_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// A thumbnail of an image file, `None` when it can't be decoded here.
fn upload_preview(path: &std::path::Path) -> Option<slint::Image> {
    if std::fs::metadata(path).ok()?.len() > PREVIEW_MAX_BYTES {
        return None;
    }
    if let Ok(decoded) = image::open(path) {
        let thumb = decoded.thumbnail(640, 360).to_rgba8();
        let buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
            thumb.as_raw(),
            thumb.width(),
            thumb.height(),
        );
        return Some(slint::Image::from_rgba8(buffer));
    }
    slint::Image::load_from_path(path).ok()
}

/// Asks for the upload when Settings says so, then hands `path` to the
/// worker with the chosen lifetime: the paperclip, a dropped file and a
/// paste all end here, as in Cicchetto. With the question on, the popup
/// (preview, lifetime menu) answers through `finish_upload_confirm`; its
/// lifetime and its "shrink videos" switch (videos only) start from the
/// saved ones and never write them back.
fn confirm_and_attach(
    ui: &AppWindow,
    tx: &mpsc::UnboundedSender<WorkerCommand>,
    path: std::path::PathBuf,
) {
    if ui.get_pref_upload_confirm() {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let category = mime_for_filename(&name).map(|(_, category)| category);
        let size = std::fs::metadata(&path).map_or(0, |meta| meta.len());
        let preview = match category {
            Some(UploadCategory::Image) => upload_preview(&path),
            _ => None,
        };
        ui.set_upload_confirm_has_preview(preview.is_some());
        ui.set_upload_confirm_preview(preview.unwrap_or_default());
        let kind = match category {
            Some(UploadCategory::Image) => "image",
            Some(UploadCategory::Video) => "video",
            Some(UploadCategory::Audio) => "audio",
            Some(UploadCategory::Document) => "document",
            None => "",
        };
        ui.set_upload_confirm_kind(kind.into());
        ui.set_upload_confirm_name(name.into());
        ui.set_upload_confirm_size(format_file_size(size).into());
        ui.set_upload_confirm_ttl_index(ui.get_pref_upload_ttl_index());
        ui.set_upload_confirm_shrink(ui.get_pref_shrink_videos());
        PENDING_UPLOAD.with(|pending| *pending.borrow_mut() = Some(path));
        ui.set_upload_confirm_open(true);
        return;
    }
    let options = UploadOptions {
        expire: upload_ttl_for_index(ui.get_pref_upload_ttl_index()),
        shrink: ui.get_pref_shrink_videos(),
    };
    let _ = tx.send(WorkerCommand::AttachFile(path, options));
}

/// Closes the upload popup: with `send`, the pending file goes to the worker
/// with the lifetime picked there; otherwise nothing is uploaded or posted.
fn finish_upload_confirm(ui: &AppWindow, tx: &mpsc::UnboundedSender<WorkerCommand>, send: bool) {
    let options = UploadOptions {
        expire: upload_ttl_for_index(ui.get_upload_confirm_ttl_index()),
        shrink: ui.get_upload_confirm_shrink(),
    };
    ui.set_upload_confirm_open(false);
    ui.set_upload_confirm_preview(slint::Image::default());
    let Some(path) = PENDING_UPLOAD.with(|pending| pending.borrow_mut().take()) else {
        return;
    };
    if send {
        let _ = tx.send(WorkerCommand::AttachFile(path, options));
    }
}

/// Lines of pasted text above which Cordiale offers a .txt upload.
const PASTE_UPLOAD_LINES: usize = 2;

/// What the clipboard holds that should go up as a file: an image (saved
/// as PNG), or, when the user agrees, a multi-line text (saved as
/// `paste.txt`). `None` lets the compose box paste as usual.
fn clipboard_upload(ui: &AppWindow) -> Option<std::path::PathBuf> {
    let mut clipboard = arboard::Clipboard::new().ok()?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or_default();
    let folder = std::env::temp_dir()
        .join("cordiale-paste")
        .join(stamp.to_string());
    if let Ok(image) = clipboard.get_image() {
        let width = u32::try_from(image.width).ok()?;
        let height = u32::try_from(image.height).ok()?;
        let pixels = image::RgbaImage::from_raw(width, height, image.bytes.into_owned())?;
        std::fs::create_dir_all(&folder).ok()?;
        let path = folder.join("image.png");
        if let Err(err) = pixels.save_with_format(&path, image::ImageFormat::Png) {
            persistence::log_line(&format!("pasted image not saved: {err}"));
            return None;
        }
        return Some(path);
    }
    let text = clipboard.get_text().ok()?;
    if text.lines().count() < PASTE_UPLOAD_LINES {
        return None;
    }
    let answer = rfd::MessageDialog::new()
        .set_title(ui.get_paste_upload_title().as_str())
        .set_description(
            ui.invoke_paste_upload_text(i32::try_from(text.lines().count()).unwrap_or(i32::MAX))
                .as_str(),
        )
        .set_buttons(rfd::MessageButtons::YesNo)
        .show();
    if !matches!(answer, rfd::MessageDialogResult::Yes) {
        return None;
    }
    std::fs::create_dir_all(&folder).ok()?;
    let path = folder.join("paste.txt");
    std::fs::write(&path, text).ok()?;
    Some(path)
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
/// Since protocol v26 a 507 is either the instance being full or the
/// subject's own upload cap, and nothing on the wire tells them apart, so
/// `attach-no-space` carries neutral copy that doesn't blame either.
fn attachment_error_status(status: Option<u16>) -> &'static str {
    match status {
        Some(413) => "attach-too-large",
        Some(415) => "attach-unsupported-type",
        Some(507) => "attach-no-space",
        _ => "attach-failed",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StatusmsgTarget {
    /// The channel window where Grappa delivers the message.
    channel: String,
    /// The complete membership-level run, for example `@+`.
    level: String,
}

/// The account's aliases, fetched once and cached until they change.
async fn user_aliases(state: &mut WorkerState) -> HashMap<String, String> {
    if state.prefs.aliases.is_none() {
        if let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) {
            match client.fetch_aliases(&token).await {
                Ok(aliases) => state.prefs.aliases = Some(aliases),
                Err(err) => persistence::log_line(&format!("aliases fetch failed: {err:?}")),
            }
        }
    }
    state.prefs.aliases.clone().unwrap_or_default()
}

/// A `/kb`, Kickban or Ban host waiting for the target's host; the kick
/// follows the ban only when `kick_reason` is set. The ban form is fixed
/// when the request starts, so changing the setting meanwhile doesn't
/// alter it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingKickBan {
    network: String,
    channel: String,
    nick: String,
    kick_reason: Option<String>,
    ban_type: cordiale_core::ban::BanType,
}

/// Shows a slash-command outcome in the status bar; `hint` fills its `{}`.
fn set_command_status(ui: &slint::Weak<AppWindow>, kind: &'static str, hint: String) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_command_hint(hint.into());
        ui.set_status_kind(kind.into());
    });
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
    state.prefs.theme = new_theme;

    // Re-render the currently open channel's history too: an mIRC-colored
    // message that was legible a moment ago (see `ensure_legible`) can
    // stop being legible the instant the background flips, and shouldn't
    // have to wait for a channel reselect to catch up.
    let current_lines = state
        .windows
        .current_channel
        .as_ref()
        .and_then(|key| state.transcript.messages.get(key))
        .cloned();
    let current_roster = state
        .windows
        .current_channel
        .as_ref()
        .filter(|_| !state.windows.current_query)
        .map(|key| {
            (
                state
                    .transcript
                    .members
                    .get(key)
                    .cloned()
                    .unwrap_or_default(),
                network_casemapping(state, &key.0),
                state.denoise_active(key),
            )
        });

    refresh_mention_context(state);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_theme(theme_to_slint(new_theme));
        ui.invoke_apply_color_scheme();
        if let Some(lines) = current_lines {
            let model = match current_roster {
                Some((members, casemapping, denoise)) => chat_lines_model_with_roster(
                    &lines,
                    new_theme == Theme::Dark,
                    &members,
                    casemapping,
                    denoise,
                ),
                None => chat_lines_model(&lines, new_theme == Theme::Dark),
            };
            show_chat_lines(&ui, model);
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
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    match client.fetch_notification_prefs(&token).await {
        Ok(prefs) => {
            push_notification_toggles(ui, NotificationToggles::from_prefs(&prefs));
            push_notification_lists(ui, &prefs);
            state.prefs.notification_prefs = Some(prefs);
            sync_mute_bar(state, ui);
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
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.prefs.notification_prefs.clone(),
    ) else {
        return;
    };
    let mut prefs = stored.clone();
    toggles.apply_to(&mut prefs);
    match client.set_notification_prefs(&token, &prefs).await {
        Ok(()) => state.prefs.notification_prefs = Some(prefs),
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

/// A station ready to tune: its name, stream URL, decoder hint and
/// now-playing feed.
struct TunableStation {
    title: String,
    url: String,
    hint: &'static str,
    source: Option<cordiale_core::radio::NowPlayingSource>,
}

/// `builtin:<id>` from Cicchetto's list, or `custom:<index>` from Settings.
fn tunable_station(key: &str) -> Option<TunableStation> {
    use cordiale_core::radio::{RadioCodec, RADIO_STATIONS};
    if let Some(id) = key.strip_prefix("builtin:") {
        let station = RADIO_STATIONS.iter().find(|station| station.id == id)?;
        return Some(TunableStation {
            title: station.title.to_string(),
            url: station.stream_url.to_string(),
            hint: station.codec.extension(),
            source: station.now_playing,
        });
    }
    let index: usize = key.strip_prefix("custom:")?.parse().ok()?;
    let station = persistence::load_settings()
        .ok()?
        .radio_stations
        .into_iter()
        .nth(index)?;
    let codec = RadioCodec::from_setting_key(&station.codec);
    Some(TunableStation {
        title: station.name,
        url: station.url,
        hint: codec.extension(),
        source: None,
    })
}

/// A custom station from the Settings form; `None` without a name or an
/// http(s) URL. `codec_index` follows the form's menu (`RADIO_CODECS`).
fn custom_radio_station(
    name: &str,
    url: &str,
    codec_index: i32,
) -> Option<persistence::CustomRadioStation> {
    let name = name.trim();
    let url = url.trim();
    let valid_url = is_http_url(url);
    if name.is_empty() || !valid_url {
        return None;
    }
    Some(persistence::CustomRadioStation {
        name: name.to_string(),
        url: url.to_string(),
        codec: usize::try_from(codec_index)
            .ok()
            .and_then(|index| cordiale_core::radio::RADIO_CODECS.get(index))
            .copied()
            .unwrap_or(cordiale_core::radio::RadioCodec::Mp3)
            .setting_key()
            .to_string(),
    })
}

/// An `http://` or `https://` URL with a host and no spaces.
fn is_http_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    rest.is_some_and(|rest| {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        !host.is_empty() && !url.chars().any(char::is_whitespace)
    })
}

/// Mirrors the station list (Cicchetto's, then the custom ones) and the
/// custom list of Settings > Radio.
fn push_radio_stations(ui: &AppWindow, custom: &[persistence::CustomRadioStation]) {
    use cordiale_core::radio::{RadioCodec, RADIO_CODECS, RADIO_STATIONS};
    let mut rows: Vec<RadioRow> = RADIO_STATIONS
        .iter()
        .map(|station| {
            let format = match station.bitrate {
                Some(bitrate) => format!("{} {bitrate}k", station.codec.label()),
                None => station.codec.label().to_string(),
            };
            RadioRow {
                key: format!("builtin:{}", station.id).into(),
                title: station.title.into(),
                detail: format!("{} · {format}", station.genres.join(", ")).into(),
                description: station.description.into(),
                custom: false,
            }
        })
        .collect();
    let custom_rows: Vec<CustomRadioRow> = custom
        .iter()
        .map(|station| CustomRadioRow {
            name: station.name.clone().into(),
            url: station.url.clone().into(),
            codec_index: RADIO_CODECS
                .iter()
                .position(|codec| codec.setting_key() == station.codec)
                .and_then(|index| i32::try_from(index).ok())
                .unwrap_or(0),
            codec_label: RadioCodec::from_setting_key(&station.codec).label().into(),
        })
        .collect();
    rows.extend(custom.iter().enumerate().map(|(index, station)| {
        let codec = RadioCodec::from_setting_key(&station.codec).label();
        RadioRow {
            key: format!("custom:{index}").into(),
            title: station.name.clone().into(),
            detail: codec.into(),
            description: station.url.clone().into(),
            custom: true,
        }
    }));
    ui.set_radio_stations(Rc::new(slint::VecModel::from(rows)).into());
    ui.set_radio_custom_stations(Rc::new(slint::VecModel::from(custom_rows)).into());
}

/// The station on air, as the worker tracks it.
struct TunedRadio {
    key: String,
    title: String,
    source: Option<cordiale_core::radio::NowPlayingSource>,
    /// Last track the feed gave, and when.
    track: Option<(cordiale_core::radio::Track, std::time::Instant)>,
    /// Last title the stream itself carried (ICY), for stations without a
    /// feed.
    stream_title: Option<String>,
    /// "connecting", "playing", "failed", "ended" (a station stopped) or
    /// "finished" (an audio file played to its end).
    status: &'static str,
    error: String,
    /// An audio link from the chat rather than a station: `/np` ignores
    /// it, like Cicchetto.
    upload: bool,
}

#[derive(Default)]
struct RadioState {
    generation: u64,
    tuned: Option<TunedRadio>,
    poll: Option<tokio::task::JoinHandle<()>>,
}

impl RadioState {
    fn stop(&mut self) {
        self.generation += 1;
        self.tuned = None;
        if let Some(poll) = self.poll.take() {
            poll.abort();
        }
    }
}

impl Drop for RadioState {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What `/np` reads, shared with the slash command handler.
#[derive(Clone, Default)]
struct RadioNowPlaying {
    station: Option<String>,
    has_feed: bool,
    track: Option<(cordiale_core::radio::Track, std::time::Instant)>,
    stream_title: Option<String>,
}

static RADIO_NOW_PLAYING: std::sync::Mutex<Option<RadioNowPlaying>> = std::sync::Mutex::new(None);

fn tune_radio(
    radio_state: &mut RadioState,
    radio: &player::RadioPlayer,
    worker_self: &mpsc::UnboundedSender<WorkerCommand>,
    ui: &slint::Weak<AppWindow>,
    key: &str,
) {
    let Some(station) = tunable_station(key) else {
        return;
    };
    radio_state.stop();
    let generation = radio_state.generation;
    radio.play(&station.url, station.hint, generation);
    if let Some(source) = station.source {
        let tx = worker_self.clone();
        radio_state.poll = Some(tokio::spawn(async move {
            loop {
                let track = cordiale_core::radio::fetch_now_playing(source).await;
                if tx
                    .send(WorkerCommand::RadioTrack { generation, track })
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(
                    cordiale_core::radio::NOW_PLAYING_POLL_SECS,
                ))
                .await;
            }
        }));
    }
    radio_state.tuned = Some(TunedRadio {
        key: key.to_string(),
        title: station.title,
        source: station.source,
        track: None,
        stream_title: None,
        status: "connecting",
        error: String::new(),
        upload: false,
    });
    push_radio_now(ui, radio_state);
}

/// The decoder hint when a clicked link is audio the player takes.
fn audio_link(state: &WorkerState, href: &str) -> Option<&'static str> {
    let base = state
        .conn
        .client
        .as_ref()
        .map(|client| client.base_url().to_string())
        .unwrap_or_default();
    match cordiale_core::media::link_target(href, &base) {
        cordiale_core::media::LinkTarget::Audio(hint) => Some(hint),
        _ => None,
    }
}

/// Plays an audio link from the chat in the integrated player, replacing
/// whatever was on, as Cicchetto's mini-player does.
fn play_audio_link(
    radio_state: &mut RadioState,
    radio: &player::RadioPlayer,
    ui: &slint::Weak<AppWindow>,
    href: &str,
    hint: &'static str,
) {
    radio_state.stop();
    radio.play(href, hint, radio_state.generation);
    let title = href
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();
    radio_state.tuned = Some(TunedRadio {
        key: String::new(),
        title,
        source: None,
        track: None,
        stream_title: None,
        status: "connecting",
        error: String::new(),
        upload: true,
    });
    push_radio_now(ui, radio_state);
}

fn handle_radio_event(
    radio_state: &mut RadioState,
    ui: &slint::Weak<AppWindow>,
    generation: u64,
    event: player::PlayerEvent,
) {
    if radio_state.generation != generation {
        return;
    }
    let Some(tuned) = radio_state.tuned.as_mut() else {
        return;
    };
    match event {
        player::PlayerEvent::Playing => tuned.status = "playing",
        player::PlayerEvent::Title(title) => tuned.stream_title = Some(title),
        player::PlayerEvent::Failed(error) => {
            persistence::log_line(&format!("radio stream failed: {error}"));
            tuned.status = "failed";
            tuned.error = error;
        }
        player::PlayerEvent::Ended => {
            tuned.status = if tuned.upload { "finished" } else { "ended" };
        }
    }
    push_radio_now(ui, radio_state);
}

/// Mirrors the station on air into the player bar and `/np`.
fn push_radio_now(ui: &slint::Weak<AppWindow>, radio_state: &RadioState) {
    let now = radio_state
        .tuned
        .as_ref()
        .filter(|tuned| !tuned.upload)
        .map(|tuned| RadioNowPlaying {
            station: Some(tuned.title.clone()),
            has_feed: tuned.source.is_some(),
            track: tuned.track.clone(),
            stream_title: tuned.stream_title.clone(),
        });
    let upload = radio_state.tuned.as_ref().is_some_and(|tuned| tuned.upload);
    let label = now
        .as_ref()
        .and_then(|now| match (&now.track, &now.stream_title) {
            (Some((track, _)), _) => Some(track.label()),
            (None, Some(title)) => Some(title.clone()),
            (None, None) => None,
        })
        .unwrap_or_default();
    if let Ok(mut shared) = RADIO_NOW_PLAYING.lock() {
        *shared = now;
    }
    let (key, title, status, error) = match &radio_state.tuned {
        Some(tuned) => (
            tuned.key.clone(),
            tuned.title.clone(),
            tuned.status,
            tuned.error.clone(),
        ),
        None => (String::new(), String::new(), "", String::new()),
    };
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_radio_upload(upload);
        ui.set_radio_tuned_key(key.into());
        ui.set_radio_station(title.into());
        ui.set_radio_track(label.into());
        ui.set_radio_status(status.into());
        ui.set_radio_error(error.into());
    });
}

/// Sound presets Grappa accepts for `notification_sound`, in the order of
/// the Settings menu.
const NOTIFICATION_SOUNDS: [&str; 10] = [
    "none",
    "tone",
    "chime",
    "blip",
    "pop",
    "icq",
    "xp_notify",
    "xp_ding",
    "xp_balloon",
    "xp_exclamation",
];

/// One change to the push-notification map beyond the five switches.
#[derive(Debug, Clone, PartialEq)]
enum NotificationEdit {
    /// `"channel"` or `"private"` list, and the channel or nick to add.
    AddToList(String, String),
    RemoveFromList(String, String),
    /// Mutes a conversation key until a unix time, or for good (`None`).
    Mute(String, Option<i64>),
    Unmute(String),
    Sound(String),
}

/// Writes the Denoise choices (and which ones Grappa hasn't confirmed) to
/// `settings.json`.
fn save_presence_settings(state: &WorkerState) {
    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.presence_pins = state.prefs.presence_pins.clone();
    settings.presence_unsynced = state.prefs.presence_unsynced.clone();
    let _ = persistence::save_settings(&settings);
}

/// At sign-in the account's Denoise choices replace the local ones, except
/// for a local change Grappa never confirmed, which is sent again. If the
/// server can't be reached the local choices stay as they are.
async fn sync_presence_pins(state: &mut WorkerState) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let server = match client.fetch_presence_pins(&token).await {
        Ok(server) => server,
        Err(error) => {
            persistence::log_line(&format!("denoise choices fetch failed: {error:?}"));
            return;
        }
    };
    let reconciled = reconcile(
        &state.prefs.presence_pins,
        &state.prefs.presence_unsynced,
        &server,
    );
    state.prefs.presence_pins = reconciled.pins;
    state.prefs.presence_unsynced.clear();
    let upload = if reconciled.push.is_empty() {
        None
    } else {
        Some(client.put_presence_pins(&token, &reconciled.push).await)
    };
    if let Some(Err(error)) = upload {
        persistence::log_line(&format!("denoise choices upload failed: {error:?}"));
        state
            .prefs
            .presence_unsynced
            .extend(reconciled.push.into_keys());
    }
    save_presence_settings(state);
}

/// Rebuilds the open channel's transcript (and the Denoise state shown in
/// the Actions menu) from the stored history, without touching the roster.
fn push_chat_lines_update(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    key: &(String, String),
) {
    let lines = state
        .transcript
        .messages
        .get(key)
        .cloned()
        .unwrap_or_default();
    let members = state
        .transcript
        .members
        .get(key)
        .cloned()
        .unwrap_or_default();
    let casemapping = network_casemapping(state, &key.0);
    let denoise = state.denoise_active(key);
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_denoise(denoise);
        let model =
            chat_lines_model_with_roster(&lines, dark_theme, &members, casemapping, denoise);
        show_chat_lines(&ui, model);
    });
}

/// Flips Denoise for the open channel. The transcript changes at once, then
/// the choice goes to Grappa; a failed upload is kept and sent again at the
/// next sign-in.
async fn handle_toggle_denoise(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let Some(key) = state.windows.current_channel.clone() else {
        return;
    };
    if state.windows.current_query || key.1 == SERVER_WINDOW_NAME {
        return;
    }
    let pin_key = muted_key(&key.0, &key.1);
    let pref = toggled_pref(state.denoise_active(&key));
    state.prefs.presence_pins.insert(pin_key.clone(), pref);
    state.prefs.presence_unsynced.insert(pin_key.clone());
    save_presence_settings(state);
    push_chat_lines_update(state, ui, &key);

    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let pins = std::collections::BTreeMap::from([(pin_key.clone(), pref)]);
    if let Err(error) = client.put_presence_pins(&token, &pins).await {
        persistence::log_line(&format!(
            "denoise save failed for {}/{}: {error:?}",
            key.0, key.1
        ));
        return;
    }
    state.prefs.presence_unsynced.remove(&pin_key);
    save_presence_settings(state);
    if pref == PresencePref::Show {
        reload_history_tail(state, ui, &key).await;
    }
}

/// Grappa's key for a muted conversation or a channel's Denoise choice: the
/// network slug and the channel or peer nick, ASCII-lowercased like
/// Cicchetto's channel key.
fn muted_key(network: &str, target: &str) -> String {
    format!("{network} {}", target.to_ascii_lowercase())
}

fn notification_list_field(list: &str) -> Option<&'static str> {
    match list {
        "channel" => Some("channel_messages_only"),
        "private" => Some("private_messages_only"),
        _ => None,
    }
}

/// Applies an edit to the stored map; `false` when it doesn't apply.
fn apply_notification_edit(
    prefs: &mut serde_json::Map<String, Value>,
    edit: &NotificationEdit,
) -> bool {
    match edit {
        NotificationEdit::AddToList(list, value)
        | NotificationEdit::RemoveFromList(list, value) => {
            let Some(field) = notification_list_field(list) else {
                return false;
            };
            let value = value.trim().to_ascii_lowercase();
            let mut items: Vec<String> = prefs
                .get(field)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            items.retain(|item| item != &value);
            if matches!(edit, NotificationEdit::AddToList(..)) {
                items.push(value);
            }
            prefs.insert(field.to_string(), Value::from(items));
        }
        NotificationEdit::Mute(key, until) => {
            let muted = prefs
                .entry("muted_targets")
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            let Value::Object(muted) = muted else {
                return false;
            };
            muted.insert(key.clone(), serde_json::json!({ "until": until }));
        }
        NotificationEdit::Unmute(key) => {
            if let Some(Value::Object(muted)) = prefs.get_mut("muted_targets") {
                muted.remove(key);
            }
        }
        NotificationEdit::Sound(sound) => {
            if !NOTIFICATION_SOUNDS.contains(&sound.as_str()) {
                return false;
            }
            prefs.insert("notification_sound".to_string(), Value::from(sound.clone()));
        }
    }
    true
}

/// Rows of the muted list: `(label, key)`, with the snooze end when there
/// is one.
fn muted_rows(prefs: &serde_json::Map<String, Value>) -> Vec<(String, String)> {
    let Some(Value::Object(muted)) = prefs.get("muted_targets") else {
        return Vec::new();
    };
    let mut rows: Vec<(String, String)> = muted
        .iter()
        .map(|(key, entry)| {
            let name = key.replacen(' ', " · ", 1);
            let label = match entry.get("until").and_then(Value::as_i64) {
                Some(until) => match chrono::DateTime::from_timestamp(until, 0) {
                    Some(time) => format!(
                        "{name} → {}",
                        dates::render_date_time(&time.with_timezone(&chrono::Local), false)
                    ),
                    None => name,
                },
                None => format!("{name} → ∞"),
            };
            (label, key.clone())
        })
        .collect();
    rows.sort();
    rows
}

fn push_notification_lists(ui: &slint::Weak<AppWindow>, prefs: &serde_json::Map<String, Value>) {
    let list = |field: &str| -> Vec<String> {
        prefs
            .get(field)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let channels = list("channel_messages_only");
    let privates = list("private_messages_only");
    let muted = muted_rows(prefs);
    let sound = prefs
        .get("notification_sound")
        .and_then(Value::as_str)
        .and_then(|sound| {
            NOTIFICATION_SOUNDS
                .iter()
                .position(|preset| *preset == sound)
        })
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or(0);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let strings = |items: Vec<String>| -> slint::ModelRc<slint::SharedString> {
            let items: Vec<slint::SharedString> = items.into_iter().map(Into::into).collect();
            Rc::new(slint::VecModel::from(items)).into()
        };
        ui.set_notify_only_channels(strings(channels));
        ui.set_notify_only_privates(strings(privates));
        let muted: Vec<MutedRow> = muted
            .into_iter()
            .map(|(label, key)| MutedRow {
                label: label.into(),
                key: key.into(),
            })
            .collect();
        ui.set_notify_muted(Rc::new(slint::VecModel::from(muted)).into());
        ui.set_notify_sound_index(sound);
    });
}

/// The mute of the open conversation, as the bar above the compose box
/// shows it.
#[derive(Debug, PartialEq, Eq)]
struct MuteBar {
    /// Key of the mute in the stored map, for the Unmute button.
    key: String,
    /// Unix seconds the user muted at, when this device knows it.
    since: Option<i64>,
    /// Unix seconds the mute ends, `None` for a permanent one.
    until: Option<i64>,
}

/// The live mute of `key` in the stored prefs. An entry with no `until` is
/// permanent, as Grappa reads it; a malformed or elapsed one is no mute.
/// `since` is this device's own record (Grappa keeps no "muted at"), left
/// out when it can't be right: in the future, or not before the mute ends.
fn current_mute(
    prefs: &serde_json::Map<String, Value>,
    key: &str,
    since: &std::collections::BTreeMap<String, i64>,
    now: i64,
) -> Option<MuteBar> {
    let entry = prefs
        .get("muted_targets")?
        .as_object()?
        .get(key)?
        .as_object()?;
    let until = match entry.get("until") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_i64().filter(|until| *until > 0)?),
    };
    if until.is_some_and(|until| until <= now) {
        return None;
    }
    let since = since
        .get(key)
        .copied()
        .filter(|since| *since <= now && until.is_none_or(|until| *since < until));
    Some(MuteBar {
        key: key.to_string(),
        since,
        until,
    })
}

/// Time left on a timed mute as `(hours, minutes)`, rounded up to the
/// minute; `None` once it is over. Up to an hour it is minutes alone.
fn mute_remaining(until: i64, now: i64) -> Option<(i32, i32)> {
    let seconds = until.saturating_sub(now);
    if seconds <= 0 {
        return None;
    }
    let minutes = i32::try_from(seconds.saturating_add(59) / 60).unwrap_or(i32::MAX);
    Some(if minutes <= 60 {
        (0, minutes)
    } else {
        (minutes / 60, minutes % 60)
    })
}

/// `HH:MM` of a unix time in the local zone.
fn local_clock_time(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%H:%M")
                .to_string()
        })
        .unwrap_or_default()
}

/// Drops the "muted at" records of conversations the stored map no longer
/// mutes; `true` when any went.
fn forget_lifted_mutes(
    since: &mut std::collections::BTreeMap<String, i64>,
    prefs: &serde_json::Map<String, Value>,
) -> bool {
    let muted = prefs.get("muted_targets").and_then(Value::as_object);
    let before = since.len();
    since.retain(|key, _| muted.is_some_and(|muted| muted.contains_key(key)));
    since.len() != before
}

/// Writes the "muted at" records to `settings.json`.
fn save_mute_settings(state: &WorkerState) {
    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.mute_since = state.prefs.mute_since.clone();
    let _ = persistence::save_settings(&settings);
}

/// Shows the mute bar for the open conversation, from the stored prefs.
fn push_mute_bar(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let now = chrono::Utc::now().timestamp();
    let mute = state
        .windows
        .current_channel
        .as_ref()
        .zip(state.prefs.notification_prefs.as_ref())
        .and_then(|((network, target), prefs)| {
            current_mute(
                prefs,
                &muted_key(network, target),
                &state.prefs.mute_since,
                now,
            )
        });
    let _ = ui.upgrade_in_event_loop(move |ui| apply_mute_bar(&ui, mute.as_ref(), now));
}

/// Drops the "muted at" records of lifted mutes, then refreshes the bar.
fn sync_mute_bar(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    if let Some(prefs) = &state.prefs.notification_prefs {
        if forget_lifted_mutes(&mut state.prefs.mute_since, prefs) {
            save_mute_settings(state);
        }
    }
    push_mute_bar(state, ui);
}

fn apply_mute_bar(ui: &AppWindow, mute: Option<&MuteBar>, now: i64) {
    let Some(mute) = mute else {
        ui.set_current_mute_active(false);
        return;
    };
    let since = mute.since.map(local_clock_time).unwrap_or_default();
    let until = mute.until.map(|until| until.to_string());
    ui.set_current_mute_key(mute.key.clone().into());
    ui.set_current_mute_since(since.into());
    ui.set_current_mute_until(until.unwrap_or_default().into());
    ui.set_current_mute_hours(0);
    ui.set_current_mute_minutes(0);
    ui.set_current_mute_active(true);
    update_mute_countdown(ui, now);
}

/// Refreshes the time left on a timed mute; the bar goes away when it is
/// over. A permanent mute (no `until`) is left alone.
fn update_mute_countdown(ui: &AppWindow, now: i64) {
    let Ok(until) = ui.get_current_mute_until().parse::<i64>() else {
        return;
    };
    match mute_remaining(until, now) {
        Some((hours, minutes)) => {
            ui.set_current_mute_hours(hours);
            ui.set_current_mute_minutes(minutes);
        }
        None => ui.set_current_mute_active(false),
    }
}

/// Applies one notification edit over the stored map (read first when
/// needed) and saves the whole map, as Grappa's PUT requires.
async fn handle_notification_edit(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    edit: NotificationEdit,
) {
    if state.prefs.notification_prefs.is_none() {
        handle_load_notification_prefs(state, ui).await;
    }
    let (Some(client), Some(token), Some(stored)) = (
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.prefs.notification_prefs.clone(),
    ) else {
        return;
    };
    let mut prefs = stored.clone();
    if !apply_notification_edit(&mut prefs, &edit) {
        return;
    }
    match client.set_notification_prefs(&token, &prefs).await {
        Ok(()) => {
            push_notification_lists(ui, &prefs);
            state.prefs.notification_prefs = Some(prefs);
            if let NotificationEdit::Mute(key, _) = &edit {
                state
                    .prefs
                    .mute_since
                    .insert(key.clone(), chrono::Utc::now().timestamp());
                save_mute_settings(state);
            }
            sync_mute_bar(state, ui);
        }
        Err(err) => {
            persistence::log_line(&format!("notification prefs save failed: {err:?}"));
            push_notification_lists(ui, &stored);
            let _ = ui.upgrade_in_event_loop(|ui| ui.set_status_kind("notify-prefs-failed".into()));
        }
    }
}

/// Rows fetched per older-history page.
const OLDER_HISTORY_PAGE: usize = 100;

/// Where the chat pane's top line goes once `prepended` older lines went in
/// above the `old_rows` it had.
#[derive(Debug, Clone, Copy, PartialEq)]
struct ChatAnchor {
    /// The new index of the line that was at the top of the pane.
    row: usize,
    /// How far that line was scrolled past the pane's top edge.
    offset: f32,
    /// The `ListView`'s average row height before the page went in: what
    /// it still seeks by until it lays the new rows out.
    row_height: f32,
}

/// Slint's `ListView` places row `i` at `i` times its average row height
/// (`content-height / rows`, see `update_visible_instances` in Slint's
/// `internal/core/model/repeater.rs`), laying out real row heights only
/// around the viewport. So the top line is the row at `-scroll_y` over that
/// average. `measured_rows` is the row count `content_height` was measured
/// for, `rows` how many there are now (the result is kept inside them).
fn top_line_anchor(
    scroll_y: f32,
    content_height: f32,
    measured_rows: usize,
    rows: usize,
) -> Option<ChatAnchor> {
    if measured_rows == 0 || rows == 0 || content_height <= 0.0 {
        return None;
    }
    let row_height = content_height / measured_rows as f32;
    let scrolled = (-scroll_y).max(0.0);
    let line = (scrolled / row_height + 1e-3).floor() as usize;
    let top = line.min(rows - 1);
    // Past the end (a stale position): the last line, flush.
    let offset = if line > top {
        0.0
    } else {
        (scrolled - top as f32 * row_height).max(0.0)
    };
    Some(ChatAnchor {
        row: top,
        offset,
        row_height,
    })
}

/// Where a chat pane that is rebuilt (the reader went to the media viewer
/// or another screen and came back) has to scroll to, or `None` when it
/// should just open on the newest line: it was following it, or there is
/// nothing saved to go by. `scroll_y` and `content_height` are the pane's
/// last measures, taken with `measured_rows` lines; `rows` is how many
/// lines it holds now. Lines that arrived in the meantime go in after the
/// reader's, so the line they were on keeps its index.
fn resume_scroll_anchor(
    follow_bottom: bool,
    scroll_y: f32,
    content_height: f32,
    measured_rows: usize,
    rows: usize,
) -> Option<ChatAnchor> {
    if follow_bottom {
        return None;
    }
    top_line_anchor(scroll_y, content_height, measured_rows, rows)
}

/// Scrolls the chat pane so `anchor.row` is back at its top. A jump that
/// far makes the `ListView` seek by its average row height straight to the
/// row that `content-y` falls in (half a row in, so rounding can't miss it)
/// and put it flush with the top; one frame later, once the real heights
/// of the rows around it are laid out, the reader's offset into that line
/// is scrolled back in. Called right after the model swap, before the
/// `ListView` lays the new rows out, so it still seeks by the old average.
fn restore_chat_anchor(ui: &AppWindow, anchor: ChatAnchor) {
    ui.set_chat_scroll_y(-(anchor.row as f32 + 0.5) * anchor.row_height);
    if anchor.offset > 0.0 {
        let weak = ui.as_weak();
        slint::Timer::single_shot(std::time::Duration::from_millis(32), move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_chat_scroll_y(ui.get_chat_scroll_y() - anchor.offset);
            }
        });
    }
}

/// Saves the display preferences. A refusal is not left looking like a
/// saved choice: the stored preferences are read back and shown again, and
/// a 422 (a `date_format` outside Grappa's closed set) says so.
async fn handle_save_display_prefs(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    prefs: DisplayPrefs,
) {
    let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) else {
        return;
    };
    if prefs.date_format.is_some() {
        dates::set_format(prefs.date_format);
    }
    let Err(err) = client.update_display_prefs(token, &prefs).await else {
        return;
    };
    persistence::log_line(&format!("display prefs save failed: {err:?}"));
    let kind = display_prefs_error_key(err.status().map(|status| status.as_u16()));
    let stored = client.fetch_display_prefs(token).await.ok();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        if let Some(stored) = stored {
            apply_display_prefs(&ui, &stored);
        }
        ui.set_status_kind(kind.into());
    });
}

/// Status key for a failed display-preferences save.
fn display_prefs_error_key(status: Option<u16>) -> &'static str {
    if status == Some(422) {
        "display-prefs-rejected"
    } else {
        "display-prefs-save-failed"
    }
}

/// Fetches `/admin/overview` and `/admin/sessions` and pushes them to the
/// UI. Only meaningful for an `is_admin` account with a full web session —
/// a per-client token gets `403` here, surfaced as an empty refresh
/// (see `docs/protocol-notes.md` §4ter).
/// One admin write from the Users or Networks tab. Passwords are never
/// logged.
enum AdminWrite {
    CreateUser {
        name: String,
        password: String,
        is_admin: bool,
    },
    SetPassword {
        user_id: String,
        password: String,
    },
    CreateNetwork(String),
    UpdateNetwork {
        slug: String,
        settings: Value,
    },
    DeleteNetwork(String),
    AddServer {
        network_id: String,
        host: String,
        port: u16,
        tls: bool,
    },
    DeleteServer {
        network_id: String,
        server_id: String,
    },
    UpdateSettings(Value),
    BindCredential(Value),
    UnbindCredential {
        user_id: String,
        network_id: String,
    },
    AddVhost {
        address: String,
        in_pool: bool,
    },
    UpdateVhost {
        vhost_id: String,
        changes: Value,
    },
    DeleteVhost(String),
    GrantVhost {
        vhost_id: String,
        subject_type: String,
        subject_id: String,
    },
    RevokeGrant(String),
    ReconnectSession(String),
    TerminateSession(String),
    EditServer {
        network_id: String,
        server_id: String,
        changes: Value,
    },
    AddFeatured {
        network_id: String,
        body: Value,
    },
    SetFeatured {
        network_id: String,
        featured_id: String,
        enabled: bool,
    },
    DeleteFeatured {
        network_id: String,
        featured_id: String,
    },
    EditCredential {
        user_id: String,
        network_id: String,
        changes: Value,
    },
}

/// The server settings editor's size fields: `(subtree, key)` in the order
/// of the `admin-setting-sizes` model, all in MiB.
const ADMIN_SIZE_SETTINGS: [(&str, &str); 9] = [
    ("upload", "image_per_file_cap_bytes"),
    ("upload", "video_per_file_cap_bytes"),
    ("upload", "document_per_file_cap_bytes"),
    ("upload", "audio_per_file_cap_bytes"),
    ("upload", "global_cap_bytes"),
    ("upload", "per_user_cap_bytes"),
    ("upload", "per_visitor_cap_bytes"),
    ("dcc", "max_transfer_bytes"),
    ("dcc", "global_cap_bytes"),
];
const UPLOAD_HOSTS: [&str; 2] = ["embedded", "litterbox"];
const ADDRESSING_MODES: [&str; 2] = ["pool_with_reservations", "static_mapping_with_reservations"];

/// What the server settings editor sends back.
#[derive(Debug, Clone, PartialEq)]
struct AdminSettingsForm {
    host_index: i32,
    sizes: Vec<String>,
    video_seconds: String,
    mode_index: i32,
    prefix: String,
}

/// Most admin feed lines kept for the Events tab.
const ADMIN_EVENTS_CAP: usize = 200;

/// Refreshes every self-service settings section: Ignores/Perform for
/// `state.settings_network` (empty if none picked yet), plus the
/// account-scoped Aliases/Vhost — see `docs/protocol-notes.md` §4quater.
async fn handle_settings_network_refresh(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) else {
        return;
    };

    let ignores: Vec<IgnoreEntry> = match &state.prefs.settings_network {
        Some(network) => client
            .fetch_ignores(token, network)
            .await
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let perform_text = match &state.prefs.settings_network {
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
    let dcc_auto_accept = match &state.prefs.settings_network {
        Some(network) => client
            .fetch_dcc_auto_accept(token, network)
            .await
            .unwrap_or(false),
        None => false,
    };

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
        ui.set_settings_ignores(ignore_rows_model(ignores));
        ui.set_settings_ignore_error("".into());
        ui.set_perform_text(perform_text.into());
        ui.set_settings_aliases(Rc::new(slint::VecModel::from(alias_rows)).into());
        ui.set_settings_vhost_options(Rc::new(slint::VecModel::from(vhost_rows)).into());
        ui.set_pref_dcc_auto_accept(dcc_auto_accept);
    });
}

/// The ignore list as Slint rows, keeping every pair (two rules may share
/// a mask).
fn ignore_rows_model(entries: Vec<IgnoreEntry>) -> slint::ModelRc<IgnoreRow> {
    let rows: Vec<IgnoreRow> = entries
        .into_iter()
        .map(|entry| IgnoreRow {
            mask: entry.mask.into(),
            text_pattern: entry.text_pattern.unwrap_or_default().into(),
        })
        .collect();
    Rc::new(slint::VecModel::from(rows)).into()
}

/// Shows `entries` as the Settings ignore list, with `error` under it.
fn push_ignore_entries(
    ui: &slint::Weak<AppWindow>,
    entries: Vec<IgnoreEntry>,
    error: &'static str,
) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_settings_ignores(ignore_rows_model(entries));
        ui.set_settings_ignore_error(error.into());
    });
}

/// A Settings add/remove: the response carries the resulting list, which
/// is rendered as is; a refusal keeps the list and says why.
fn push_ignore_mutation(
    ui: &slint::Weak<AppWindow>,
    result: Result<cordiale_core::profile::IgnoreMutationResponse, GrappaClientError>,
) {
    match result {
        Ok(response) => push_ignore_entries(ui, response.entries(), ""),
        Err(err) => {
            persistence::log_line(&format!("ignore change failed: {err:?}"));
            let error = ignore_error_key(&err);
            let _ = ui.upgrade_in_event_loop(move |ui| ui.set_settings_ignore_error(error.into()));
        }
    }
}

/// Grappa's two 422 codes for an ignore change are distinct because the
/// user typed two things (protocol v31).
fn ignore_error_key(err: &GrappaClientError) -> &'static str {
    match err.code() {
        Some("invalid_text_pattern") => "invalid-text-pattern",
        Some("invalid_mask") => "invalid-mask",
        _ => "failed",
    }
}

/// The Settings text-pattern field: blank means no pattern; anything else
/// goes to Grappa trimmed, and Grappa refuses a CR/LF-bearing one itself.
fn ignore_pattern_from_ui(pattern: &str) -> Option<String> {
    let pattern = pattern.trim();
    (!pattern.is_empty()).then(|| pattern.to_string())
}

/// Loads the account's away/leave messages, auto-away delay and
/// peer-profile opt-in into the Settings editors.
async fn load_personal_prefs(client: &GrappaClient, token: &str, ui: &slint::Weak<AppWindow>) {
    let leave = client.fetch_quit_part_reason(token).await;
    let away = client.fetch_auto_away_reason(token).await;
    let delay = client.fetch_auto_away_debounce(token).await;
    let peers = client.fetch_show_peer_profiles(token).await;
    // A server older than protocol v32 has no suffix setting: the field is
    // simply not offered, and the rest of the section still loads.
    let suffix = client.fetch_away_nick_suffix(token).await;
    let (Ok(leave), Ok(away), Ok(delay), Ok(peers)) = (leave, away, delay, peers) else {
        persistence::log_line("personal settings load failed");
        return;
    };
    let (suffix_supported, suffix) = match suffix {
        Ok(suffix) => (true, suffix),
        Err(err) => {
            persistence::log_line(&format!("away nick suffix not available: {err:?}"));
            (false, None)
        }
    };
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_edit_leave_message(leave.unwrap_or_default().into());
        ui.set_edit_away_message(away.unwrap_or_default().into());
        ui.set_away_nick_suffix_supported(suffix_supported);
        ui.set_edit_away_nick_suffix(suffix.unwrap_or_default().into());
        ui.set_edit_away_delay(away_delay_text(delay).into());
        ui.set_pref_show_peer_profiles(peers);
        ui.set_personal_prefs_loaded(true);
    });
}

/// The auto-away delay as typed in Settings: empty for the server default,
/// `0` for off, otherwise seconds.
fn away_delay_text(seconds: Option<i64>) -> String {
    seconds
        .map(|seconds| seconds.to_string())
        .unwrap_or_default()
}

/// Parses the typed auto-away delay back: `Ok(None)` when empty, `Err` for
/// anything but a non-negative whole number.
fn parse_away_delay(text: &str) -> Result<Option<i64>, ()> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    match text.parse::<i64>() {
        Ok(seconds) if seconds >= 0 => Ok(Some(seconds)),
        _ => Err(()),
    }
}

async fn handle_personal_prefs_save(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    leave_message: String,
    away_message: String,
    away_delay: String,
    show_peer_profiles: bool,
    away_nick_suffix: Option<String>,
) {
    let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) else {
        return;
    };
    let set_status = |kind: &'static str| {
        let _ = ui.upgrade_in_event_loop(move |ui| ui.set_status_kind(kind.into()));
    };
    let Ok(delay) = parse_away_delay(&away_delay) else {
        set_status("away-delay-invalid");
        return;
    };
    let leave = leave_message.trim();
    let away = away_message.trim();
    let results = [
        client
            .set_quit_part_reason(token, (!leave.is_empty()).then_some(leave))
            .await,
        client
            .set_auto_away_reason(token, (!away.is_empty()).then_some(away))
            .await,
        client.set_auto_away_debounce(token, delay).await,
        client
            .set_show_peer_profiles(token, show_peer_profiles)
            .await,
    ];
    if let Some(Err(err)) = results.into_iter().find(Result::is_err) {
        persistence::log_line(&format!("personal settings save failed: {err:?}"));
        set_status("personal-prefs-failed");
        return;
    }
    // Empty switches the rename off. Grappa validates the tail; a refusal
    // gets its own message rather than the generic one.
    if let Some(suffix) = away_nick_suffix {
        let suffix = suffix.trim();
        if let Err(err) = client
            .set_away_nick_suffix(token, (!suffix.is_empty()).then_some(suffix))
            .await
        {
            persistence::log_line(&format!("away nick suffix save failed: {err:?}"));
            set_status(away_nick_suffix_error_key(
                err.status().map(|status| status.as_u16()),
            ));
            return;
        }
    }
    set_status("personal-prefs-saved");
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

async fn handle_identity_save(state: &WorkerState, nick: String, ident: String, realname: String) {
    let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) else {
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
    let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) else {
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
    let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) else {
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
    let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) else {
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
        .prefs
        .settings_network
        .as_ref()
        .and_then(|network| state.networks.network_ids.get(network))
        .copied();
    let presence = network_id.and_then(|id| state.networks.presence_by_network.get(&id));
    let rows: Vec<(String, &'static str)> = network_id
        .and_then(|id| state.networks.notify_lists.get(&id))
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
/// `SettingsState::watch_patterns` for why they are session-local.
/// Asks Grappa for the account's keyword patterns (`watchlist` with
/// `action: "list"`), so the list reflects what other clients changed too;
/// the reply is matched by its ref.
fn request_watch_patterns(state: &mut WorkerState) {
    let (Some(session), Some(identifier)) = (&state.conn.session, &state.conn.identifier) else {
        return;
    };
    let message_ref = session.send_tracked_command(
        format!("grappa:user:{identifier}"),
        "watchlist",
        serde_json::json!({ "action": "list" }),
    );
    state.prefs.pending_watchlist_ref = Some(message_ref);
}

/// The `GET /networks` row of `network`.
fn network_row<'a>(networks: &'a [Value], network: &str) -> Option<&'a Value> {
    networks
        .iter()
        .find(|row| row.get("slug").and_then(Value::as_str) == Some(network))
}

/// The account's current nick on `network`, from a `GET /networks` row.
fn network_nick(networks: &[Value], network: &str) -> Option<String> {
    network_row(networks, network)?
        .get("nick")?
        .as_str()
        .filter(|nick| !nick.is_empty())
        .map(str::to_string)
}

/// Fills the identity editor's nick, and the profile editor, from the
/// `network` row. Grappa no longer reports ident and realname, so those
/// stay as typed.
async fn load_identity_settings(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
) {
    let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) else {
        return;
    };
    let Ok(networks) = client.fetch_networks(token).await else {
        return;
    };
    if let Some(nick) = network_nick(&networks, network) {
        let _ = ui.upgrade_in_event_loop(move |ui| ui.set_identity_nick(nick.into()));
    }
    if let Some(row) = network_row(&networks, network) {
        let fields = ProfileFields::from_credential(row);
        show_profile(ui, &fields, has_avatar(row));
        state.prefs.profile_baseline = fields;
    }
}

/// Puts `fields` in the profile editor, and whether the network has an
/// avatar next to the picker.
fn show_profile(ui: &slint::Weak<AppWindow>, fields: &ProfileFields, avatar: bool) {
    let fields = fields.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_profile_gender_index(i32::try_from(fields.gender_index()).unwrap_or(0));
        ui.set_profile_age(fields.age.into());
        ui.set_profile_location(fields.location.into());
        ui.set_profile_languages(fields.languages.into());
        ui.set_profile_custom(fields.custom.into());
        ui.set_profile_has_avatar(avatar);
    });
}

/// Status-bar key for a refused profile save: Grappa answers 422 for a
/// value that breaks its limits.
fn profile_error_status(status: Option<u16>) -> &'static str {
    match status {
        Some(422) => "profile-invalid",
        _ => "profile-failed",
    }
}

/// Saves the edited profile fields of the Settings network, sending only
/// the ones that differ from what Grappa last reported, then shows what it
/// returns.
async fn handle_profile_save(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    edited: ProfileFields,
) {
    let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) else {
        return;
    };
    let set_status = |kind: &'static str| {
        let _ = ui.upgrade_in_event_loop(move |ui| ui.set_status_kind(kind.into()));
    };
    if !edited.is_valid() {
        set_status("profile-invalid");
        return;
    }
    let request = state.prefs.profile_baseline.changes_to(&edited);
    if request.is_empty() {
        set_status("profile-saved");
        return;
    }
    match client
        .update_network_profile(token, network, &request)
        .await
    {
        Ok(credential) => {
            let saved = ProfileFields::from_credential(&credential);
            show_profile(ui, &saved, has_avatar(&credential));
            state.prefs.profile_baseline = saved;
            set_status("profile-saved");
        }
        Err(err) => {
            persistence::log_line(&format!("profile save failed: {err:?}"));
            set_status(profile_error_status(
                err.status().map(|status| status.as_u16()),
            ));
        }
    }
}

/// Uploads a picked image as the Settings network's own avatar. The checks
/// and their messages are the paperclip's: the avatar rides the same image
/// allowlist and cap.
async fn handle_avatar_upload(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    path: std::path::PathBuf,
) {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let set_status = |kind: &'static str, name: String| {
        let _ = ui.upgrade_in_event_loop(move |ui| {
            ui.set_status_attach_name(name.into());
            ui.set_status_kind(kind.into());
        });
    };
    let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) else {
        return;
    };
    let Some((mime, UploadCategory::Image)) = mime_for_filename(&filename) else {
        set_status("attach-unsupported-type", filename);
        return;
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            persistence::log_line(&format!("avatar read failed: {err}"));
            set_status("attach-read-failed", filename);
            return;
        }
    };
    let over_cap = state
        .prefs
        .upload_limits
        .as_ref()
        .is_some_and(|limits| bytes.len() as u64 > upload_cap(limits, UploadCategory::Image));
    if over_cap {
        set_status("attach-too-large", filename);
        return;
    }
    set_status("attach-uploading", filename.clone());
    match client
        .upload_network_avatar(token, network, &filename, mime, bytes)
        .await
    {
        Ok(credential) => {
            let avatar = has_avatar(&credential);
            let _ = ui.upgrade_in_event_loop(move |ui| ui.set_profile_has_avatar(avatar));
            set_status("avatar-saved", filename);
        }
        Err(err) => {
            persistence::log_line(&format!("avatar upload failed: {err:?}"));
            set_status(
                attachment_error_status(err.status().map(|status| status.as_u16())),
                filename,
            );
        }
    }
}

/// Removes the Settings network's own avatar.
async fn handle_avatar_remove(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) else {
        return;
    };
    match client.delete_network_avatar(token, network).await {
        Ok(credential) => {
            let avatar = has_avatar(&credential);
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_profile_has_avatar(avatar);
                ui.set_status_kind("avatar-removed".into());
            });
        }
        Err(err) => {
            persistence::log_line(&format!("avatar removal failed: {err:?}"));
            let _ =
                ui.upgrade_in_event_loop(|ui| ui.set_status_kind("avatar-remove-failed".into()));
        }
    }
}

fn push_watch_patterns(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let patterns: Vec<slint::SharedString> = state
        .prefs
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
    let (Some(session), Some(identifier)) = (&state.conn.session, &state.conn.identifier) else {
        return;
    };
    // Grappa hard-rejects a non-integer `network_id` (`is_integer/1`
    // guard server-side, no slug fallback) — see
    // `docs/protocol-notes.md` §4ter. Silently do nothing rather than
    // send a request guaranteed to be rejected if the id isn't known.
    let Some(&network_id) = state.networks.network_ids.get(network) else {
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
    if state.windows.current_query {
        return None;
    }
    let session = state.conn.session.as_ref()?;
    let identifier = state.conn.identifier.as_ref()?;
    let (network, channel) = state.windows.current_channel.as_ref()?;
    let network_id = *state.networks.network_ids.get(network)?;
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

/// "Ban host" (`kick_reason: None`) and Kickban (`Some(reason)`) on the
/// open channel; the host is resolved first, like `/kb`. Never in a DM or
/// server window, and Kickban only for a nick the member list shows.
fn start_member_host_ban(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    nick: String,
    kick_reason: Option<String>,
) {
    let Some((_, _, _, channel)) = user_topic_channel_network(state) else {
        return;
    };
    let channel = channel.to_string();
    let Some((network, _)) = state.windows.current_channel.clone() else {
        return;
    };
    if kick_reason.is_some() && !frames::is_channel_member(state, &network, &channel, &nick) {
        return;
    }
    // The menu entries are explicit: always the host form, whatever the
    // default ban type is.
    let ban_type = cordiale_core::ban::BanType::Host;
    slash::start_kickban(state, ui, &network, channel, nick, kick_reason, ban_type);
}

/// "Ban nick": always the fixed `{nick}!*@*` mask, whatever the default
/// ban type ends up being.
fn send_member_ban(state: &WorkerState, nick: &str) {
    let Some((session, topic, network_id, channel)) = user_topic_channel_network(state) else {
        return;
    };
    let mask = frames::ban_nick_mask(nick);
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
    let (Some(client), Some(token), Some((network, channel))) = (
        &state.conn.client,
        &state.conn.token,
        &state.windows.current_channel,
    ) else {
        return;
    };
    let request = SendMessageRequest::ctcp(nick, &verb, None);
    if let Err(err) = client.send_message(token, network, channel, &request).await {
        set_send_failed_status(ui, &err);
    }
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

/// Cicchetto's compact `+nt` form; empty-but-known modes remain distinguishable
/// from an unknown snapshot in `TranscriptState::channel_modes`.
fn format_channel_modes(modes: &[String]) -> String {
    if modes.is_empty() {
        String::new()
    } else {
        format!("+{}", modes.join(""))
    }
}

/// The one-line status above the topic (issue #110): the network with its
/// user modes, then the window with its channel modes, as
/// `Azzurra +Sir · #grappa +rnt`. Flags come only from a server snapshot
/// (`umode_changed`, `channel_modes_changed`): none yet, or an empty one,
/// shows the bare name rather than an invented `+`. A DM or `$server`
/// window has no channel modes to show.
fn window_status_line(
    network: &str,
    user_modes: Option<&[String]>,
    window: &str,
    channel_modes: Option<&[String]>,
) -> String {
    let with_modes = |name: &str, modes: Option<&[String]>| {
        let flags = modes.map(format_channel_modes).unwrap_or_default();
        if flags.is_empty() {
            name.to_string()
        } else {
            format!("{name} {flags}")
        }
    };
    format!(
        "{} · {}",
        with_modes(network, user_modes),
        with_modes(window, channel_modes)
    )
}

/// The status line of the window on screen, "" when none is (home).
fn window_status_for(state: &WorkerState) -> String {
    let Some((network, window)) = state.windows.current_channel.as_ref() else {
        return String::new();
    };
    let user_modes = state
        .networks
        .user_modes_by_network
        .get(network)
        .map(Vec::as_slice);
    let channel_modes = if state.windows.current_query || window == SERVER_WINDOW_NAME {
        None
    } else {
        state
            .transcript
            .channel_modes
            .get(&(network.clone(), window.clone()))
            .map(|snapshot| snapshot.modes.as_slice())
    };
    window_status_line(network, user_modes, window, channel_modes)
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

/// The read cursor to send when leaving the open window: its newest message,
/// if that is past the known cursor. The local cursor advances at once
/// (forward-only), as in Cicchetto; the `read_cursor_set` push confirms it.
fn read_cursor_to_write(state: &mut WorkerState) -> Option<(String, String, i64)> {
    let (network, target) = state.windows.current_channel.clone()?;
    let newest = query_high_water_id(state, &(network.clone(), target.clone()))?;
    let key = window_state_key(&network, &target);
    if state
        .windows
        .read_cursors
        .get(&key)
        .is_some_and(|&cursor| cursor >= newest)
    {
        return None;
    }
    state.windows.read_cursors.insert(key, newest);
    Some((network, target, newest))
}

/// Marks the window being left as read on the server (Cicchetto does it on
/// focus-leave). Fire-and-forget: a failure only leaves the unread count as
/// the server has it.
fn write_back_read_cursor(state: &mut WorkerState) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
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

/// Declines an invite over REST. The banner and the invited row stay as they
/// are: they go away only when `window_invite_declined` arrives, so a decision
/// taken on another device behaves the same way.
async fn decline_invite(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    channel: &str,
) {
    let (Some(client), Some(token)) = (state.conn.client.as_ref(), state.conn.token.as_deref())
    else {
        return;
    };
    let Err(err) = client.decline_invite(token, network, channel).await else {
        return;
    };
    persistence::log_line(&format!("invite decline failed: {err:?}"));
    let Some(status) = decline_invite_error_status(err.status().map(|status| status.as_u16()))
    else {
        return;
    };
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_kind(status.into());
    });
}

/// Status-bar key for a failed decline. A `404` (`not_invited`) means the
/// window already left the invited state, so the banner is on its way out and
/// there is nothing to report.
fn decline_invite_error_status(status: Option<u16>) -> Option<&'static str> {
    match status {
        Some(404) => None,
        _ => Some("invite-decline-failed"),
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

/// Pushes `state.members[key]` (and the derived op-gating flag) to the UI
/// — shared by every member-list mutation path (`members_seeded`,
/// incremental join/part/nick_change, channel selection).
fn push_members_update(state: &WorkerState, ui: &slint::Weak<AppWindow>, key: &(String, String)) {
    if state.windows.current_query {
        return;
    }
    let members = state
        .transcript
        .members
        .get(key)
        .cloned()
        .unwrap_or_default();
    let ranking = MemberRanking::new(state.networks.isupport_by_network.get(&key.0));
    let can_moderate = state
        .conn
        .identifier
        .as_deref()
        .is_some_and(|identifier| is_own_nick_an_op(&members, identifier, &ranking));
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let lines = state
        .transcript
        .messages
        .get(key)
        .cloned()
        .unwrap_or_default();
    let casemapping = network_casemapping(state, &key.0);
    let denoise = state.denoise_active(key);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_can_moderate_members(can_moderate);
        ui.set_current_denoise(denoise);
        let member_rows = members_model(&members, dark_theme, &ranking);
        ui.set_members_average_nick(members_average_probe(&member_rows).into());
        ui.set_channel_members(Rc::new(slint::VecModel::from(member_rows)).into());
        let chat_lines =
            chat_lines_model_with_roster(&lines, dark_theme, &members, casemapping, denoise);
        show_chat_lines(&ui, chat_lines);
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
    /// A join/part/quit/nick-change/mode line that Denoise hides; it stays
    /// in the stored history so toggling Denoise off brings it back.
    presence_noise: bool,
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
    let structural = payload
        .get("meta")
        .and_then(|meta| meta.get("structural"))
        .and_then(Value::as_bool)
        == Some(true);
    let presence_noise = is_presence_noise(kind, structural);
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
            presence_noise,
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
            presence_noise,
        },
        (None, Some(body)) => RenderedMessage {
            timestamp,
            nick: None,
            text: body.to_string(),
            italic,
            message_id: message_id(payload),
            server_time: server_time(payload),
            presence_noise,
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
            presence_noise,
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

fn compare_rendered_message_order(
    left: &RenderedMessage,
    right: &RenderedMessage,
) -> std::cmp::Ordering {
    left.server_time
        .cmp(&right.server_time)
        .then_with(|| left.message_id.cmp(&right.message_id))
}

/// Rows one catch-up page holds: Grappa's HTTP page ceiling, and the gap
/// size past which Cicchetto stops paging forward.
const CATCH_UP_PAGE: usize = 200;
/// The gap probe only has to tell "within a page" from "beyond it", so it
/// stops counting one row past the threshold.
const CATCH_UP_PROBE_CAP: u64 = CATCH_UP_PAGE as u64 + 1;
/// Pause between two channels' catch-up, so a session with many channels
/// doesn't trip the reverse proxy's rate limit.
const CATCH_UP_PACING: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CatchUpPlan {
    /// Nothing was said while the socket was down.
    Nothing,
    /// The gap fits in one page: read it with `?after=`.
    PageForward,
    /// Too far behind to page through: reload the tail, mark the hole.
    ReloadTail,
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

/// Where a live message went in a window's stored rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveInsert {
    /// After every row there was: the pane can just add one row at its end.
    Appended,
    /// The rows had to be put back in order: the pane rebuilds them all.
    Reordered,
}

/// Rows a window keeps in memory once it is trimmed. Generous on purpose:
/// it is many screens of even a busy channel, and what the reader pages
/// back through (`?before=`) stays for as long as the pane isn't following
/// the newest line.
const CHAT_HISTORY_CAP: usize = 5_000;
/// How far past `CHAT_HISTORY_CAP` a window may grow before it is trimmed,
/// so the rows are dropped (and the pane rebuilt) once per few hundred
/// messages instead of on every one.
const CHAT_HISTORY_TRIM_SLACK: usize = 500;

/// Makes `key` the open window. The one it replaces is trimmed: nobody is
/// reading it back any more.
fn open_window(state: &mut WorkerState, key: &(String, String)) {
    let previous = state.windows.current_channel.replace(key.clone());
    if let Some(previous) = previous.filter(|previous| previous != key) {
        trim_window_history(state, &previous);
    }
    publish_held_rows(state);
}

/// Rebuilds the open window's rows after a `WorkerCommand::RebuildChat`; a
/// window that is no longer open is only trimmed. `trim` is set only when
/// the pane followed the newest line when it asked, and the rows are swapped
/// only if it still does: a reader who has scrolled back since keeps the
/// pane as it is.
fn handle_rebuild_chat(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    key: &(String, String),
    trim: bool,
) {
    let trimmed = trim && trim_window_history(state, key);
    publish_held_rows(state);
    // Requests queued while rows were still being added find nothing left
    // to drop: the pane already has what the first one gave it.
    if (trim && !trimmed) || state.windows.current_channel.as_ref() != Some(key) {
        return;
    }
    let lines = state
        .transcript
        .messages
        .get(key)
        .cloned()
        .unwrap_or_default();
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let roster = (!state.windows.current_query).then(|| {
        (
            state
                .transcript
                .members
                .get(key)
                .cloned()
                .unwrap_or_default(),
            network_casemapping(state, &key.0),
            state.denoise_active(key),
        )
    });
    let _ = ui.upgrade_in_event_loop(move |ui| {
        if trimmed {
            // Older rows can be paged in again.
            ui.set_history_start_reached(false);
            if !ui.get_chat_follow_bottom() {
                return;
            }
        }
        let model = match roster {
            Some((members, casemapping, denoise)) => {
                chat_lines_model_with_roster(&lines, dark_theme, &members, casemapping, denoise)
            }
            None => chat_lines_model(&lines, dark_theme),
        };
        show_chat_lines(&ui, model);
    });
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
    if let Some(bold) = prefs.bold_mentions {
        BOLD_MENTIONS.store(bold, std::sync::atomic::Ordering::Relaxed);
    }
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
    // Absent means the server default; the selector shows `auto` without
    // marking it as the user's choice.
    dates::set_format(prefs.date_format);
    let format = prefs.date_format.unwrap_or_default();
    let index = DateFormat::ALL
        .iter()
        .position(|candidate| *candidate == format)
        .unwrap_or(0);
    ui.set_pref_date_format_index(i32::try_from(index).unwrap_or(0));
    ui.set_pref_date_format_set(prefs.date_format.is_some());
    push_date_format_examples(ui);
}

/// Refreshes the date selector's live examples (today, in each format).
fn push_date_format_examples(ui: &AppWindow) {
    let examples: Vec<slint::SharedString> =
        dates::examples().into_iter().map(Into::into).collect();
    ui.set_date_format_examples(Rc::new(slint::VecModel::from(examples)).into());
}

const SERVER_WINDOW_NAME: &str = "$server";

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
/// Phoenix socket URL, per `docs/protocol-notes.md` §2. `client_proto` is a
/// plain integer: the server silently drops anything it can't read as one.
fn to_ws_url(base_url: &str) -> String {
    let with_scheme = if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("wss://{base_url}")
    };
    format!(
        "{}/socket/websocket?vsn=2.0.0&client_proto={CLIENT_PROTOCOL_VERSION}",
        with_scheme.trim_end_matches('/')
    )
}

/// `(name, prefix)` — `prefix` holds every IRC role marker the member has
/// (`@` op, `%` halfop, `+` voice...), highest first, so dropping one
/// keeps the next; empty for a plain member. Only the first is shown.
type MemberEntry = (String, String);

/// The role marker shown for a member: the highest one it holds.
fn highest_prefix(prefix: &str) -> &str {
    prefix
        .char_indices()
        .nth(1)
        .map_or(prefix, |(end, _)| &prefix[..end])
}
type MembersByChannel = HashMap<(String, String), Vec<MemberEntry>>;

/// Where a role symbol sits in the network's PREFIX, for sorting and for
/// the moderation gate.
struct MemberRanking {
    /// The network's role symbols, highest first (`prefix_symbol_order`).
    order: Vec<String>,
    /// Index in `order` of the op symbol (the one the `o` mode grants), or
    /// `None` when the network has no op level.
    op_rank: Option<usize>,
}

impl MemberRanking {
    fn new(isupport: Option<&IsupportState>) -> Self {
        let order = cordiale_core::isupport::prefix_symbol_order(isupport);
        let op_rank = cordiale_core::isupport::prefix_symbol_for_mode(isupport, "o")
            .and_then(|op| order.iter().position(|symbol| *symbol == op));
        Self { order, op_rank }
    }

    /// Whether `prefix` (a member's role symbols, highest first) holds op or
    /// something the network ranks above it.
    fn is_op_or_above(&self, prefix: &str) -> bool {
        self.op_rank
            .is_some_and(|op_rank| prefix_rank(prefix, &self.order) <= op_rank)
    }
}

/// Index in `order` (highest first) of the highest symbol in `prefix`; a
/// plain member or an unknown symbol ranks after every known one.
fn prefix_rank(prefix: &str, order: &[String]) -> usize {
    let top = highest_prefix(prefix);
    if top.is_empty() {
        return order.len();
    }
    order
        .iter()
        .position(|symbol| symbol.as_str() == top)
        .unwrap_or(order.len())
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

/// The open window as a counts key plus whether it is a query, for the
/// sidebar's selected row.
fn selected_window(state: &WorkerState) -> Option<(WindowCountsKey, bool)> {
    let (network, target) = state.windows.current_channel.as_ref()?;
    Some((
        window_counts_key(network, target),
        state.windows.current_query,
    ))
}

/// Builds the actual sidebar `NetworkGroup` Slint model out of
/// `network_groups_data`'s plain grouping — must run on the UI thread,
/// see that function's doc comment for why.
fn network_groups_model(
    data: Vec<NetworkGroupData>,
    window_states: HashMap<(String, String), ChannelWindowState>,
    window_mentions: HashMap<WindowCountsKey, u64>,
    window_messages: HashMap<WindowCountsKey, u64>,
    selected: Option<(WindowCountsKey, bool)>,
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
                        let selected = selected.as_ref().is_some_and(|(key, query)| {
                            !query && *key == window_counts_key(&network, &channel)
                        });
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
                            selected,
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
                        let selected = selected.as_ref().is_some_and(|(key, query)| {
                            *query && *key == window_counts_key(&network, &nick)
                        });
                        QueryEntry {
                            network: network.clone().into(),
                            nick: nick.into(),
                            label: label.into(),
                            mention_badge: mention_badge.into(),
                            mentions_description: mentions_description.into(),
                            selected,
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
/// Why the open channel window is inactive, for the banner above its
/// chat: `(kind, actor, reason)` with kind `kicked` or `failed`, or all
/// empty. A failed join falls back to the IRC numeric when there's no
/// reason text.
fn window_note(state: &WorkerState) -> (&'static str, String, String) {
    let Some((network, channel)) = state
        .windows
        .current_channel
        .as_ref()
        .filter(|_| !state.windows.current_query)
    else {
        return ("", String::new(), String::new());
    };
    let key = window_state_key(network, channel);
    if let Some(kick) = state.windows.window_kicks.get(&key) {
        return (
            "kicked",
            kick.by.clone().unwrap_or_default(),
            kick.reason.clone().unwrap_or_default(),
        );
    }
    if let Some(failure) = state.windows.window_failures.get(&key) {
        let reason = failure
            .reason
            .clone()
            .or_else(|| failure.numeric.as_ref().map(ToString::to_string))
            .unwrap_or_default();
        return ("failed", String::new(), reason);
    }
    ("", String::new(), String::new())
}

fn push_window_note(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (kind, actor, reason) = window_note(state);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_window_note_kind(kind.into());
        ui.set_window_note_actor(actor.into());
        ui.set_window_note_reason(reason.into());
    });
}

fn refresh_network_groups(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let unread_badge = i32::try_from(state.windows.badge_count).unwrap_or(i32::MAX);
    {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| ui.set_unread_badge(unread_badge));
    }
    push_window_note(state, ui);
    let mut data = network_groups_data(
        &state.windows.channel_entries,
        &state.transcript.query_windows,
        &state.windows.expanded_networks,
        &state.networks.network_connection_states,
        &state.networks.network_ids,
    );
    apply_connecting_labels(&mut data, &state.networks.connecting_networks);
    let window_states = state.windows.window_states.clone();
    let window_mentions = state.windows.window_mentions.clone();
    let window_messages = state.windows.window_messages.clone();
    let selected = selected_window(state);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let groups = network_groups_model(
            data,
            window_states,
            window_mentions,
            window_messages,
            selected,
        );
        ui.set_sidebar_widest_label(widest_sidebar_label(&groups).into());
        ui.set_network_groups(Rc::new(slint::VecModel::from(groups)).into());
    });
    push_home(state, &ui);
}

/// Mirrors the home page. Its rows come from the same snapshots as the
/// sidebar (attached networks, their connection state and nick, the
/// services verdict), so the two never disagree; `state.home` adds what
/// only the home page shows.
fn push_home(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let inputs: Vec<home::HomeRowInput> = state
        .networks
        .network_ids
        .keys()
        .map(|network| {
            let snapshot = state.networks.network_connection_states.get(network);
            home::HomeRowInput {
                network: network.clone(),
                nick: state.networks.own_nicks.get(network).cloned(),
                state: snapshot.map_or("connected", |snapshot| snapshot.status.wire_name()),
                reason: snapshot.and_then(|snapshot| snapshot.reason.clone()),
                identified: state
                    .networks
                    .session_identities
                    .get(network)
                    .is_some_and(|identity| identity.identified),
            }
        })
        .collect();
    let rows = home::home_rows(&state.home, inputs);
    let (named_nick, named_network) =
        home::registered_naming(&state.home, &rows).unwrap_or_default();
    let session_kind = state.home.session_kind();
    let available = state.home.available.clone();
    let connecting = state.home.connecting.clone().unwrap_or_default();
    let (available_error_network, available_error) =
        state.home.available_error.clone().unwrap_or_default();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<HomeNetworkRow> = rows
            .into_iter()
            .map(|row| {
                let featured: Vec<HomeFeaturedLink> = row
                    .featured
                    .into_iter()
                    .map(|link| HomeFeaturedLink {
                        name: link.name.into(),
                        description: link.description.unwrap_or_default().into(),
                    })
                    .collect();
                HomeNetworkRow {
                    network: row.network.into(),
                    nick: row.nick.into(),
                    state: row.state.into(),
                    connected: row.connected,
                    reason: row.reason.into(),
                    error: row.error.into(),
                    reconnecting: row.reconnecting,
                    can_remove: row.can_remove,
                    can_recover: row.can_recover,
                    featured: Rc::new(slint::VecModel::from(featured)).into(),
                    featured_error: row.featured_error.into(),
                }
            })
            .collect();
        let attached: Vec<slint::SharedString> =
            rows.iter().map(|row| row.network.clone()).collect();
        let available: Vec<slint::SharedString> = available.into_iter().map(Into::into).collect();
        ui.set_home_session_kind(session_kind.into());
        ui.set_home_named_nick(named_nick.into());
        ui.set_home_named_network(named_network.into());
        ui.set_home_networks(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_home_available(Rc::new(slint::VecModel::from(available)).into());
        ui.set_home_connecting(connecting.into());
        ui.set_home_available_error(available_error.into());
        ui.set_home_available_error_network(available_error_network.into());
        // A confirmation for a network that has since gone is dropped.
        let pending = ui.get_home_confirm_network();
        if !pending.is_empty() && !attached.contains(&pending) {
            ui.set_home_confirm_network("".into());
            ui.set_home_confirm_kind("".into());
        }
    });
}

/// Fetches the featured channels of every attached network not fetched
/// yet. A failure leaves the section empty rather than breaking the page,
/// as in Cicchetto; only a user-initiated join reports its error.
async fn load_featured_channels(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let mut missing: Vec<String> = state
        .networks
        .network_ids
        .keys()
        .filter(|network| !state.home.featured.contains_key(*network))
        .cloned()
        .collect();
    if missing.is_empty() {
        return;
    }
    missing.sort();
    for network in missing {
        let channels = match client.fetch_featured_channels(&token, &network).await {
            Ok(channels) => channels,
            Err(err) => {
                persistence::log_line(&format!("featured channels failed: {err:?}"));
                Vec::new()
            }
        };
        if state.networks.network_ids.contains_key(&network) {
            state.home.featured.insert(network, channels);
        }
    }
    push_home(state, ui);
}

/// Home page Disconnect (`parked`) or Reconnect (`connected`). Success is
/// the row changing on `connection_state_changed`; a failure stays on the
/// row, never silently.
async fn home_set_connection_state(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    target: &'static str,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    if !state.networks.network_ids.contains_key(&network) {
        return;
    }
    let reconnect = target == "connected";
    state.home.row_errors.remove(&network);
    if reconnect {
        state.home.reconnecting.insert(network.clone());
    }
    push_home(state, ui);
    let result = client
        .set_connection_state(&token, &network, target, None)
        .await;
    state.home.reconnecting.remove(&network);
    if let Err(err) = result {
        persistence::log_line(&format!("home {target} failed: {err:?}"));
        let key = if reconnect {
            "reconnect-failed"
        } else {
            "disconnect-failed"
        };
        state.home.row_errors.insert(network, key);
    }
    push_home(state, ui);
}

/// Home page Remove: `DELETE /session/networks/:slug` (protocol v28). The
/// row goes when `network_detached` lands and `/boot` + `/me` are re-read;
/// a refusal stays on the row so it doesn't just sit there unexplained.
async fn home_remove_network(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    if !state.networks.network_ids.contains_key(&network) {
        return;
    }
    state.home.row_errors.remove(&network);
    push_home(state, ui);
    if let Err(err) = client.detach_network(&token, &network).await {
        persistence::log_line(&format!("network remove failed: {err:?}"));
        let key = home::remove_error_key(err.status().map(|status| status.as_u16()));
        state.home.row_errors.insert(network, key);
        push_home(state, ui);
    }
}

/// Home page one-tap connect of an available network. `network_attached`
/// brings the new row; `/me` is re-read here too so the button leaves the
/// available list even if that push is late.
async fn home_connect_network(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    if state.home.connecting.is_some() || !state.home.available.contains(&network) {
        return;
    }
    state.home.connecting = Some(network.clone());
    state.home.available_error = None;
    push_home(state, ui);
    let result = client.attach_network(&token, &network).await;
    state.home.connecting = None;
    match result {
        Ok(()) => {
            if let Ok(me) = client.fetch_me(&token).await {
                state.home.apply_me(&me);
            }
        }
        Err(err) => {
            persistence::log_line(&format!("network connect failed: {err:?}"));
            state.home.available_error = Some((network, "connect-failed"));
        }
    }
    push_home(state, ui);
}

/// Home page featured channel: joined first when it isn't, then focused,
/// like Cicchetto (the intent follows the tap). A failed join is shown on
/// the network's row.
async fn home_open_featured(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    channel: String,
) {
    if !state.networks.network_ids.contains_key(&network) {
        return;
    }
    state.home.featured_errors.remove(&network);
    let joined = matches!(
        state
            .windows
            .window_states
            .get(&(network.clone(), channel.clone())),
        Some(ChannelWindowState::Joined)
    );
    if !joined {
        let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone())
        else {
            return;
        };
        if let Err(err) = client.join_channel(&token, &network, &channel, None).await {
            persistence::log_line(&format!("featured join failed: {err:?}"));
            state.home.featured_errors.insert(network, channel);
            push_home(state, ui);
            return;
        }
    }
    push_home(state, ui);
    handle_select_channel(state, ui, network, channel).await;
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
/// What a chat line is checked against to count as a mention: the own
/// nick on the open window's network and the /hilight patterns, plus
/// whether mentions are bold (Settings > Display). Read by the line
/// builder like the theme palette.
#[derive(Clone, Default)]
struct MentionContext {
    own_nick: Option<String>,
    patterns: Vec<String>,
}

static MENTION_CONTEXT: std::sync::RwLock<Option<MentionContext>> = std::sync::RwLock::new(None);
static BOLD_MENTIONS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Points the mention check at the open window's network.
fn refresh_mention_context(state: &WorkerState) {
    let own_nick = state
        .windows
        .current_channel
        .as_ref()
        .and_then(|(network, _)| state.networks.own_nicks.get(network))
        .cloned();
    if let Ok(mut context) = MENTION_CONTEXT.write() {
        *context = Some(MentionContext {
            own_nick,
            patterns: state.prefs.watch_patterns.clone(),
        });
    }
}

fn mention_context() -> MentionContext {
    MENTION_CONTEXT
        .read()
        .ok()
        .and_then(|context| context.clone())
        .unwrap_or_default()
}

/// Cicchetto's mention rule: a line someone else wrote that contains the
/// own nick or a /hilight pattern as a whole word (ASCII word boundaries,
/// case-insensitive), with mIRC formatting ignored.
fn is_mention(text: &str, sender: Option<&str>, context: &MentionContext) -> bool {
    let Some(own) = context.own_nick.as_deref().filter(|own| !own.is_empty()) else {
        return false;
    };
    if sender.is_some_and(|sender| sender.eq_ignore_ascii_case(own)) {
        return false;
    }
    let plain: String = cordiale_core::formatting::parse_mirc_text(text)
        .into_iter()
        .map(|segment| segment.text)
        .collect();
    std::iter::once(own)
        .chain(context.patterns.iter().map(String::as_str))
        .any(|term| contains_word(&plain, term))
}

/// Whether `term` occurs in `body` with no ASCII word character right
/// before or after it.
fn contains_word(body: &str, term: &str) -> bool {
    let term = term.trim();
    if term.is_empty() {
        return false;
    }
    let body_lower = body.to_ascii_lowercase();
    let term_lower = term.to_ascii_lowercase();
    let word = |ch: char| ch.is_ascii_alphanumeric() || ch == '_';
    body_lower.match_indices(&term_lower).any(|(start, found)| {
        let before = body_lower[..start].chars().next_back();
        let after = body_lower[start + found.len()..].chars().next();
        !before.is_some_and(word) && !after.is_some_and(word)
    })
}

fn chat_line_from_message(
    message: &RenderedMessage,
    dark_theme: bool,
    nick_prefix: &str,
) -> ChatLine {
    // Event lines (joins, parts, notices...) are italic and never count as
    // mentions, like Cicchetto's privmsg-only rule.
    let mention =
        !message.italic && is_mention(&message.text, message.nick.as_deref(), &mention_context());
    let (nick, nick_color_value) = match &message.nick {
        Some(nick) => {
            let (r, g, b) = nick_color(nick, dark_theme);
            (nick.clone(), slint::Color::from_rgb_u8(r, g, b))
        }
        None => (String::new(), slint::Color::from_rgb_u8(0, 0, 0)),
    };

    let default_color = if dark_theme {
        (255, 255, 255)
    } else {
        (0, 0, 0)
    };
    let runs: Vec<(String, (u8, u8, u8), bool)> =
        cordiale_core::formatting::parse_mirc_text(&message.text)
            .into_iter()
            .map(|segment| {
                let color = segment
                    .color
                    .map_or(default_color, |rgb| ensure_legible(rgb, dark_theme));
                (segment.text, color, segment.bold)
            })
            .collect();
    let bold_mention = mention && BOLD_MENTIONS.load(std::sync::atomic::Ordering::Relaxed);
    let runs: Vec<(String, (u8, u8, u8), bool)> = runs
        .into_iter()
        .map(|(text, color, bold)| (text, color, bold || bold_mention))
        .collect();
    let body = slint::StyledText::from_markdown(&message_markdown(&runs, message.italic))
        .unwrap_or_else(|_| {
            let plain: String = runs.iter().map(|run| run.0.as_str()).collect();
            slint::StyledText::from_plain_text(&plain)
        });

    ChatLine {
        timestamp: message.timestamp.clone().into(),
        timestamp_color: muted_color(dark_theme),
        nick: nick.into(),
        nick_prefix: nick_prefix.into(),
        nick_color: nick_color_value,
        italic: message.italic,
        body,
        reply_body: message.text.clone().into(),
        mention,
    }
}

/// A message's mIRC runs as Slint styled-text markup, so a line with
/// several colors wraps as one paragraph. Every run gets an explicit
/// `<font color>` (the default color too): emphasis markers then always sit
/// next to a tag bracket, where CommonMark reliably opens and closes them.
/// Text is backslash-escaped, so nothing a user typed becomes markup.
fn message_markdown(runs: &[(String, (u8, u8, u8), bool)], italic: bool) -> String {
    let mut markdown = String::new();
    for (text, (r, g, b), bold) in runs {
        let text: String = text
            .chars()
            .filter(|ch| *ch != slint_markdown_placeholder())
            .collect();
        if text.is_empty() {
            continue;
        }
        let core = text.trim();
        let leading = &text[..text.len() - text.trim_start().len()];
        let trailing = &text[text.trim_end().len()..];
        let marker = match (*bold, italic) {
            (true, true) => "***",
            (true, false) => "**",
            (false, true) => "*",
            (false, false) => "",
        };
        markdown.push_str(&format!("<font color=\"#{r:02x}{g:02x}{b:02x}\">"));
        markdown.push_str(&escape_markdown(leading));
        if !core.is_empty() {
            markdown.push_str(marker);
            markdown.push_str(&linked_markdown(core));
            markdown.push_str(marker);
        }
        markdown.push_str(&escape_markdown(trailing));
        markdown.push_str("</font>");
    }
    markdown
}

/// Escaped text with its links as markdown links, which the chat's
/// `StyledText` draws in the link color and reports when clicked.
fn linked_markdown(text: &str) -> String {
    let mut markdown = String::new();
    let mut last = 0;
    for link in cordiale_core::media::find_links(text) {
        markdown.push_str(&escape_markdown(&text[last..link.range.start]));
        markdown.push('[');
        markdown.push_str(&escape_markdown(&text[link.range.clone()]));
        markdown.push_str("](<");
        markdown.push_str(&link.href);
        markdown.push_str(">)");
        last = link.range.end;
    }
    markdown.push_str(&escape_markdown(&text[last..]));
    markdown
}

/// Asks the system to open an http(s) URL in the browser. The browser gets
/// the validated, normalised URL rather than `href` itself; anything else is
/// refused and only logged (without the link, which may hold a token).
fn open_in_browser(href: &str) {
    let url = match cordiale_core::media::validated_url(href) {
        Ok(url) => url,
        Err(refusal) => {
            persistence::log_line(&format!("browser not opened: {refusal}"));
            return;
        }
    };
    let mut command = if cfg!(target_os = "windows") {
        let mut command = std::process::Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler");
        command
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else {
        std::process::Command::new("xdg-open")
    };
    if let Err(err) = command.arg(url.as_str()).spawn() {
        persistence::log_line(&format!("browser not opened: {err}"));
    }
}

/// Opens a folder in the system's file manager, creating it first if it
/// doesn't exist yet.
fn open_folder(dir: &std::path::Path) {
    if let Err(err) = std::fs::create_dir_all(dir) {
        persistence::log_line(&format!("folder not created: {err}"));
        return;
    }
    let mut command = if cfg!(target_os = "windows") {
        std::process::Command::new("explorer")
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else {
        std::process::Command::new("xdg-open")
    };
    if let Err(err) = command.arg(dir).spawn() {
        persistence::log_line(&format!("folder not opened: {err}"));
    }
}

/// A clicked link that isn't opened: the viewer says so, as it does for a
/// file that couldn't be shown. The link itself is not logged.
fn link_refused(ui: &slint::Weak<AppWindow>, refusal: cordiale_core::media::LinkRefusal) {
    persistence::log_line(&format!("link not opened: {refusal}"));
    let reason = refusal.to_string();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_media_url("".into());
        ui.set_media_title("".into());
        ui.set_media_error(reason.into());
        ui.set_media_kind("failed".into());
        ui.set_media_zoom(false);
        ui.set_media_open(true);
    });
}

/// A clicked chat link, already validated and normalised: images and text uploads (and https images
/// elsewhere) open in the viewer, like Cicchetto; anything else in the
/// browser. Grappa files are read with the session; other hosts without
/// any credential.
fn open_link(state: &WorkerState, ui: &slint::Weak<AppWindow>, href: String) {
    use cordiale_core::media::{self, FetchError, LinkTarget};
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        open_in_browser(&href);
        return;
    };
    let target = media::link_target(&href, client.base_url());
    if target == LinkTarget::Browser {
        open_in_browser(&href);
        return;
    }
    let title = href
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();
    let url = href.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_media_url(url.into());
        ui.set_media_title(title.into());
        ui.set_media_kind("loading".into());
        ui.set_media_zoom(false);
        ui.set_media_open(true);
    });
    let ui = ui.clone();
    tokio::spawn(async move {
        let on_grappa = href.starts_with(&format!("{}/", client.base_url().trim_end_matches('/')));
        let text = target == LinkTarget::Text;
        let limit = if text {
            media::MAX_TEXT_BYTES
        } else {
            media::MAX_IMAGE_BYTES
        };
        let fetched = if on_grappa {
            client
                .fetch_server_file(&token, &href)
                .await
                .map(|(bytes, content_type)| {
                    let cut = text && bytes.len() > limit;
                    let mut bytes = bytes;
                    bytes.truncate(limit);
                    (bytes, content_type, cut)
                })
                .map_err(|err| match err.status().map(|status| status.as_u16()) {
                    Some(404 | 410) => FetchError::Gone,
                    _ => FetchError::Failed(format!("{err:?}")),
                })
        } else {
            media::fetch_public(&href, limit, text).await
        };
        let outcome = fetched.map(|(bytes, content_type, cut)| {
            if text {
                return MediaContent::Text(String::from_utf8_lossy(&bytes).into_owned(), cut);
            }
            let extension = avatar_extension(content_type.as_deref())
                .or_else(|| href.rsplit('.').next().filter(|ext| ext.len() <= 4))
                .unwrap_or("png")
                .to_ascii_lowercase();
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&href, &mut hasher);
            let path = std::env::temp_dir().join(format!(
                "cordiale-media-{:016x}.{extension}",
                std::hash::Hasher::finish(&hasher)
            ));
            match std::fs::write(&path, bytes) {
                Ok(()) => MediaContent::Image(path),
                Err(err) => MediaContent::Failed(err.to_string()),
            }
        });
        let _ = ui.upgrade_in_event_loop(move |ui| {
            if ui.get_media_url().as_str() != href {
                return;
            }
            match outcome {
                Ok(MediaContent::Image(path)) => match slint::Image::load_from_path(&path) {
                    Ok(image) => {
                        ui.set_media_image(image);
                        ui.set_media_kind("image".into());
                    }
                    Err(_) => {
                        ui.set_media_error("unsupported image".into());
                        ui.set_media_kind("failed".into());
                    }
                },
                Ok(MediaContent::Text(body, cut)) => {
                    ui.set_media_text(body.into());
                    ui.set_media_truncated(cut);
                    ui.set_media_kind("text".into());
                }
                Ok(MediaContent::Failed(reason)) => {
                    ui.set_media_error(reason.into());
                    ui.set_media_kind("failed".into());
                }
                Err(FetchError::Gone) => ui.set_media_kind("gone".into()),
                Err(FetchError::TooLarge) => {
                    ui.set_media_error("too large".into());
                    ui.set_media_kind("failed".into());
                }
                Err(FetchError::Failed(reason)) => {
                    persistence::log_line(&format!("media fetch failed: {reason}"));
                    ui.set_media_error(reason.into());
                    ui.set_media_kind("failed".into());
                }
            }
        });
    });
}

/// What the viewer shows once a file is downloaded.
enum MediaContent {
    Image(std::path::PathBuf),
    /// The text, and whether it was cut at the size limit.
    Text(String, bool),
    Failed(String),
}

/// Slint's `@markdown` interpolation placeholder, never valid in chat text.
fn slint_markdown_placeholder() -> char {
    '\u{e541}'
}

/// Escapes every ASCII punctuation character (CommonMark allows a
/// backslash before any of them). IRC lines have no line breaks; a stray
/// one becomes a space so the body stays one paragraph.
fn escape_markdown(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch == '\n' || ch == '\r' {
            escaped.push(' ');
            continue;
        }
        if ch.is_ascii_punctuation() {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn chat_lines_model(messages: &[RenderedMessage], dark_theme: bool) -> Vec<ChatLine> {
    chat_lines_model_with_roster(
        messages,
        dark_theme,
        &[],
        cordiale_core::isupport::CaseMapping::Rfc1459,
        false,
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
        .map(|(_, prefix)| highest_prefix(prefix))
        .unwrap_or("")
}

/// `hide_presence` leaves the Denoise lines out of the model only: they stay
/// in `messages`, so turning Denoise off rebuilds the model with them back.
fn chat_lines_model_with_roster(
    messages: &[RenderedMessage],
    dark_theme: bool,
    members: &[MemberEntry],
    casemapping: cordiale_core::isupport::CaseMapping,
    hide_presence: bool,
) -> Vec<ChatLine> {
    messages
        .iter()
        .filter(|message| !(hide_presence && message.presence_noise))
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

/// Runs `mutate` against the chat pane's persistent row model, installing
/// one on `chat-lines` first if it isn't a `VecModel` yet (only true before
/// the very first render). See `show_chat_lines` for why the model is kept
/// around instead of being replaced on every update.
fn with_chat_lines_model(ui: &AppWindow, mutate: impl FnOnce(&slint::VecModel<ChatLine>)) {
    use slint::Model as _;
    if let Some(model) = ui
        .get_chat_lines()
        .as_any()
        .downcast_ref::<slint::VecModel<ChatLine>>()
    {
        mutate(model);
        return;
    }
    let model = Rc::new(slint::VecModel::from(Vec::<ChatLine>::new()));
    mutate(&model);
    ui.set_chat_lines(model.into());
}

/// Replaces the chat pane's contents in place: a window switch, a history
/// page, an edit/redaction re-render, a theme change... Every one of these
/// call sites used to hand `chat-lines` a brand-new model object
/// (`ui.set_chat_lines(Rc::new(VecModel::from(model)).into())`), which made
/// the `ListView` throw away its whole layout estimate on every update —
/// Slint's `ListView` re-estimates its scrolled content height from the
/// average height of the rows it currently has instantiated
/// (`internal/core/model/repeater.rs`, `update_visible_instances`), and
/// swapping in a new model resets that estimate from scratch instead of
/// just the rows. Reusing the same `VecModel` (`set_vec` fires a gentler
/// "reset" notification that keeps the estimate) is what lets
/// `appwindow.slint`'s `chat-list.follow-bottom` logic hold the view
/// steady instead of jumping (GitHub issue #89).
fn show_chat_lines(ui: &AppWindow, lines: Vec<ChatLine>) {
    with_chat_lines_model(ui, |model| model.set_vec(lines));
}

fn network_casemapping(state: &WorkerState, network: &str) -> cordiale_core::isupport::CaseMapping {
    state
        .networks
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

/// The color of a member's role marker: the theme's op color for op and
/// anything the network ranks above it, then the halfop and voice colors,
/// or the nick's own color on the classic look and for any other role.
fn role_color(prefix: &str, nick_rgb: (u8, u8, u8), ranking: &MemberRanking) -> slint::Color {
    let rgb = match (active_palette(), prefix.chars().next()) {
        (Some(palette), _) if ranking.is_op_or_above(prefix) => palette.mode_op,
        (Some(palette), Some('%')) => palette.mode_halfop,
        (Some(palette), Some('+')) => palette.mode_voiced,
        _ => nick_rgb,
    };
    slint_color(rgb)
}

fn members_model(
    members: &[MemberEntry],
    dark_theme: bool,
    ranking: &MemberRanking,
) -> Vec<MemberRow> {
    members
        .iter()
        .map(|(name, prefix)| {
            let (r, g, b) = nick_color(name, dark_theme);
            MemberRow {
                prefix_color: role_color(prefix, (r, g, b), ranking),
                name: name.clone().into(),
                prefix: highest_prefix(prefix).into(),
                color: slint::Color::from_rgb_u8(r, g, b),
            }
        })
        .collect()
}

/// State kept across repeated Tab presses on the compose box so they cycle
/// through the other matches instead of repeating the first one. Lives on
/// the UI thread only (see `main`); there's nothing to persist across
/// restarts or send to the worker.
#[derive(Clone, Debug, PartialEq)]
struct NickCompletionCycle {
    /// Text before the completed word, kept byte-for-byte as typed (any
    /// leading whitespace included) and put back ahead of whichever entry
    /// is shown.
    prefix: String,
    /// The word exactly as the user typed it, before any Tab press.
    original: String,
    /// Matching nicks that produced this cycle, in member-list order.
    matches: Vec<String>,
    /// Index into `matches` currently shown, or `matches.len()` for "the
    /// original text, uncompleted" — the last stop before the cycle wraps.
    index: usize,
    /// The exact compose-box text this cycle last produced. Continuing the
    /// cycle on the next Tab press requires the box to still hold exactly
    /// this text; anything else means a manual edit happened in between and
    /// the cycle restarts from scratch.
    last_text: String,
}

/// Moves `index` one step forward or backward through `len` slots, wrapping
/// at either end.
fn step_cycle_index(index: usize, len: usize, forward: bool) -> usize {
    if forward {
        (index + 1) % len
    } else {
        (index + len - 1) % len
    }
}

/// Renders one stop of the cycle: `index == matches.len()` restores the
/// original typed text verbatim (no suffix — it was never a completion);
/// any other index is `prefix` + that match + the addressing suffix.
fn render_nick_completion(
    prefix: &str,
    original: &str,
    matches: &[String],
    index: usize,
) -> String {
    if index == matches.len() {
        format!("{prefix}{original}")
    } else {
        // ": " only when the completed word opens the line (nothing before
        // it to address), a plain space mid-sentence — matches Cicchetto.
        let suffix = if prefix.is_empty() { ": " } else { " " };
        format!("{prefix}{}{suffix}", matches[index])
    }
}

/// Tab-completes the word before the caret in the compose box against
/// `candidates` (already in the order Tab-completion should prefer, i.e.
/// the channel member list's on-screen order — see `members_model`).
///
/// The compose `LineEdit` (Slint 1.18's std-widgets) exposes no way to read
/// the caret position — `LineEditInterface` only has a setter
/// (`set-selection-offsets`), confirmed against the widget's `.slint`
/// source. So this always treats the caret as being at the very end of
/// `text` and completes its last whitespace-delimited word; the caller
/// places the real caret at the end after applying the result, which is
/// exactly where this function assumed it to be.
///
/// Returns `None` when there's nothing to complete (empty trailing word, or
/// no candidate matches it) — the caller leaves the text untouched. Matches
/// candidates case-insensitively on an ASCII fold (nicks are compared
/// byte-for-byte otherwise; the worker's own casemapping fold isn't
/// reachable from the UI thread without a lot of new plumbing for a rarely
/// relevant edge case — non-ASCII nick characters that only differ by
/// case).
fn complete_nick(
    text: &str,
    candidates: &[String],
    forward: bool,
    cycle: Option<&NickCompletionCycle>,
) -> Option<(String, NickCompletionCycle)> {
    if let Some(cycle) = cycle {
        if cycle.last_text == text {
            let slots = cycle.matches.len() + 1;
            let index = step_cycle_index(cycle.index, slots, forward);
            let new_text =
                render_nick_completion(&cycle.prefix, &cycle.original, &cycle.matches, index);
            return Some((
                new_text.clone(),
                NickCompletionCycle {
                    index,
                    last_text: new_text,
                    ..cycle.clone()
                },
            ));
        }
    }

    // Fresh completion: find the word right before the (assumed) end
    // caret, i.e. everything after the last whitespace run.
    let word_start = text
        .char_indices()
        .rev()
        .find(|(_, c)| c.is_whitespace())
        .map(|(idx, c)| idx + c.len_utf8())
        .unwrap_or(0);
    let prefix = &text[..word_start];
    let word = &text[word_start..];
    if word.is_empty() {
        return None;
    }

    let folded_word = word.to_ascii_lowercase();
    let matches: Vec<String> = candidates
        .iter()
        .filter(|nick| nick.to_ascii_lowercase().starts_with(&folded_word))
        .cloned()
        .collect();
    if matches.is_empty() {
        return None;
    }

    // The top-of-member-list match always wins the first Tab press,
    // regardless of direction — cycling only kicks in on the next press.
    let new_text = render_nick_completion(prefix, word, &matches, 0);
    Some((
        new_text.clone(),
        NickCompletionCycle {
            prefix: prefix.to_string(),
            original: word.to_string(),
            matches,
            index: 0,
            last_text: new_text,
        },
    ))
}

/// Tab-completion candidates for the currently open window, in the order
/// completion should prefer them: the open channel's member list as shown
/// in the member column (`channel-members`, already in `state.members[key]`
/// order), or — in a private query window, which carries no member list of
/// its own — the peer's nick as the sole candidate. That's a deliberate
/// choice beyond what's strictly required: Cicchetto (the reference web
/// client) has no candidates at all in a query window and Tab silently does
/// nothing there, but completing to the one nick you can possibly be
/// addressing is more useful and no more surprising.
fn nick_completion_candidates(ui: &AppWindow) -> Vec<String> {
    use slint::Model as _;

    if ui.get_current_query() {
        let peer = ui.get_current_query_peer_nick();
        return if peer.is_empty() {
            Vec::new()
        } else {
            vec![peer.to_string()]
        };
    }

    ui.get_channel_members()
        .iter()
        .map(|row| row.name.to_string())
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
    background: Option<ThemeBackground>,
    /// Owned by the account: editable, deletable, publishable.
    mine: bool,
    published: bool,
    /// The payload's wallpaper as Grappa stores it, to reopen in the editor.
    background_wire: Option<cordiale_core::rest::ThemeBackgroundWire>,
}

/// A theme's wallpaper, resolved to the path Grappa serves it at.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ThemeBackground {
    path: String,
    tile: bool,
    /// 0 to 100.
    opacity: u8,
}

/// The wallpaper of a theme payload, as Cicchetto resolves it: a built-in
/// key wins over an uploaded image; anything but `"repeat"` is full-bleed.
fn theme_background(
    wire: Option<&cordiale_core::rest::ThemeBackgroundWire>,
) -> Option<ThemeBackground> {
    let wire = wire?;
    let safe = |value: &str| {
        !value.is_empty()
            && value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    };
    let path = match (wire.builtin.as_deref(), wire.image_id.as_deref()) {
        (Some(key), _) if safe(key) => format!("/backgrounds/{key}.webp"),
        (_, Some(id)) if safe(id) => format!("/uploads/{id}"),
        _ => return None,
    };
    let opacity = wire
        .opacity
        .as_ref()
        .and_then(serde_json::Number::as_f64)
        .unwrap_or(1.0)
        .clamp(0.0, 1.0);
    Some(ThemeBackground {
        path,
        tile: wire.size.as_deref() == Some("repeat"),
        opacity: (opacity * 100.0).round() as u8,
    })
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
            background: None,
            mine: false,
            published: false,
            background_wire: None,
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
        background: theme_background(theme.payload.background.as_ref()),
        mine: theme.mine,
        published: theme.published,
        background_wire: theme.payload.background.clone(),
    })
}

/// Theme wallpapers are fetched in the background; a newer theme pick
/// makes an older download's result irrelevant.
static THEME_BACKGROUND_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Shows the theme's wallpaper behind the window (or removes it): the image
/// is downloaded from Grappa into a temp file named after its path, since
/// Slint loads images from files and caches them by path.
fn load_theme_background(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    background: Option<ThemeBackground>,
) {
    use std::sync::atomic::Ordering;
    let generation = THEME_BACKGROUND_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    let (Some(background), Some(client), Some(token)) = (
        background,
        state.conn.client.clone(),
        state.conn.token.clone(),
    ) else {
        let _ = ui.upgrade_in_event_loop(|ui| ui.set_palette_background_set(false));
        return;
    };
    let ui = ui.clone();
    tokio::spawn(async move {
        let file = match client.fetch_server_file(&token, &background.path).await {
            Ok((bytes, content_type)) => {
                let extension = avatar_extension(content_type.as_deref()).unwrap_or("webp");
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&background.path, &mut hasher);
                let path = std::env::temp_dir().join(format!(
                    "cordiale-wallpaper-{:016x}.{extension}",
                    std::hash::Hasher::finish(&hasher)
                ));
                std::fs::write(&path, bytes).ok().map(|()| path)
            }
            Err(err) => {
                persistence::log_line(&format!("theme wallpaper unavailable: {err:?}"));
                None
            }
        };
        if THEME_BACKGROUND_GENERATION.load(Ordering::SeqCst) != generation {
            return;
        }
        let _ = ui.upgrade_in_event_loop(move |ui| {
            let image = file.and_then(|file| slint::Image::load_from_path(&file).ok());
            match image {
                Some(image) => {
                    ui.set_palette_background(image);
                    ui.set_palette_background_tile(background.tile);
                    ui.set_palette_background_opacity(f32::from(background.opacity) / 100.0);
                    ui.set_palette_background_set(true);
                }
                None => ui.set_palette_background_set(false),
            }
        });
    });
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
            ui.set_palette_mention(slint_color(palette.mention));
            ui.set_palette_bg_alt(slint_color(palette.bg_alt));
            ui.set_palette_fg(slint_color(palette.fg));
            ui.set_palette_accent(slint_color(palette.accent));
            ui.set_palette_muted(slint_color(palette.muted_text()));
            ui.set_palette_border(slint_color(palette.border));
            ui.set_palette_font(font_family_for(&choice.font_family).into());
            ui.set_palette_active(true);
            let scheme = if palette.is_dark() { "dark" } else { "light" };
            ui.set_theme(scheme.into());
        }
        None => {
            ui.set_palette_active(false);
            let theme = persistence::load_settings().unwrap_or_default().theme;
            ui.set_palette_muted(slint_color(classic_muted(theme == Theme::Dark)));
            ui.set_theme(theme_to_slint(theme));
        }
    }
    ui.invoke_apply_color_scheme();
}

/// Mirrors the available color themes into Settings > Themes, marking
/// `selected` (a choice key) as in use.
fn push_theme_choices(state: &WorkerState, ui: &slint::Weak<AppWindow>, selected: Option<&str>) {
    let (day, night) = match &state.prefs.theme_pair {
        Some((day, night)) => (
            Some(day.key.as_str()),
            night.as_ref().map(|night| night.key.as_str()),
        ),
        None => (selected, None),
    };
    let rows: Vec<(ThemeChoice, bool, bool)> = state
        .prefs
        .theme_choices
        .iter()
        .map(|choice| {
            (
                choice.clone(),
                day == Some(choice.key.as_str()),
                night == Some(choice.key.as_str()),
            )
        })
        .collect();
    let editable = state
        .prefs
        .theme_choices
        .iter()
        .any(|choice| choice.key.starts_with("server:"));
    let pair_active = state.prefs.theme_pair.is_some();
    let has_night = night.is_some();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_theme_pair_active(pair_active);
        ui.set_theme_has_night(has_night);
        ui.set_theme_editing_available(editable);
        let rows: Vec<ThemeChoiceRow> = rows
            .into_iter()
            .map(|(choice, selected, night)| {
                let palette = &choice.palette;
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
                    server: choice.key.starts_with("server:"),
                    key: choice.key.into(),
                    name: choice.name.into(),
                    author: choice.author.into(),
                    selected,
                    night,
                    mine: choice.mine,
                    published: choice.published,
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
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let mut server_choices: Vec<ThemeChoice> = match client.fetch_themes(&token).await {
        Ok(themes) => themes.iter().filter_map(server_theme_choice).collect(),
        Err(err) => {
            persistence::log_line(&format!("theme gallery unavailable: {err:?}"));
            Vec::new()
        }
    };
    // The gallery lists published themes; the account's own drafts join it.
    if !server_choices.is_empty() {
        if let Ok(mine) = client.fetch_my_themes(&token).await {
            for choice in mine.iter().filter_map(server_theme_choice) {
                if !server_choices.iter().any(|known| known.key == choice.key) {
                    server_choices.push(choice);
                }
            }
        }
    }
    state.prefs.theme_choices = if server_choices.is_empty() {
        builtin_theme_choices()
    } else {
        server_choices
    };

    let saved = persistence::load_settings().unwrap_or_default().color_theme;
    state.prefs.theme_pair = None;
    let active = match saved.as_deref() {
        Some("server") => match client.fetch_active_theme(&token).await {
            Ok(pair) => {
                state.prefs.theme_pair = theme_pair_choices(&pair);
                return apply_theme_pair(state, ui);
            }
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

/// The Grappa id in a `server:<id>` theme key.
fn server_theme_id(key: &str) -> Option<i64> {
    key.strip_prefix("server:")?.parse().ok()
}

/// The editor's wallpaper menu: keys ("" none, "upload" the uploaded
/// image, then Grappa's built-in keys) and their names.
fn editor_background_menu(
    ui: &AppWindow,
    builtins: &[(String, String)],
) -> (Vec<slint::SharedString>, Vec<slint::SharedString>) {
    let mut keys: Vec<slint::SharedString> = vec!["".into(), "upload".into()];
    let mut names = vec![
        ui.get_editor_no_wallpaper_label(),
        ui.get_editor_uploaded_wallpaper_label(),
    ];
    for (key, name) in builtins {
        keys.push(key.clone().into());
        names.push(name.clone().into());
    }
    (keys, names)
}

/// Opens the editor on `key` (an owned Grappa theme) or, for "", on a new
/// theme starting from the one in use.
async fn open_theme_editor(state: &WorkerState, ui: &slint::Weak<AppWindow>, key: &str) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let source = if key.is_empty() {
        state
            .prefs
            .theme_pair
            .as_ref()
            .map(|pair| pair.0.clone())
            .or_else(|| state.prefs.theme_choices.first().cloned())
    } else {
        state
            .prefs
            .theme_choices
            .iter()
            .find(|choice| choice.key == key && choice.mine)
            .cloned()
    };
    let Some(source) = source else {
        return;
    };
    let theme_id = if key.is_empty() {
        -1
    } else {
        server_theme_id(key)
            .and_then(|id| i32::try_from(id).ok())
            .unwrap_or(-1)
    };
    let name = if key.is_empty() {
        String::new()
    } else {
        source.name.clone()
    };
    let builtins = client
        .fetch_theme_backgrounds(&token)
        .await
        .unwrap_or_default();
    let colors: Vec<(String, (u8, u8, u8))> = source.palette.color_entries();
    let font_index = cordiale_core::theme::FONT_FAMILIES
        .iter()
        .position(|font| *font == source.font_family)
        .unwrap_or(0);
    let wire = source.background_wire.clone().unwrap_or_default();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let (keys, names) = editor_background_menu(&ui, &builtins);
        let background_index = match (wire.builtin.as_deref(), wire.image_id.as_deref()) {
            (Some(builtin), _) => keys
                .iter()
                .position(|key| key.as_str() == builtin)
                .unwrap_or(0),
            (None, Some(_)) => 1,
            (None, None) => 0,
        };
        let rows: Vec<EditorColor> = colors
            .into_iter()
            .map(|(key, rgb)| EditorColor {
                nick_index: key
                    .strip_prefix("nick_")
                    .and_then(|index| index.parse().ok())
                    .unwrap_or(-1),
                key: key.into(),
                value: cordiale_core::theme::to_hex(rgb).into(),
                color: slint_color(rgb),
                valid: true,
            })
            .collect();
        ui.set_editor_theme_id(theme_id);
        ui.set_editor_name(name.into());
        ui.set_editor_font_index(i32::try_from(font_index).unwrap_or(0));
        ui.set_editor_colors(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_editor_background_keys(Rc::new(slint::VecModel::from(keys)).into());
        ui.set_editor_background_names(Rc::new(slint::VecModel::from(names)).into());
        ui.set_editor_background_index(i32::try_from(background_index).unwrap_or(0));
        ui.set_editor_image_id(wire.image_id.clone().unwrap_or_default().into());
        ui.set_editor_tile(wire.size.as_deref() == Some("repeat"));
        let opacity = wire
            .opacity
            .as_ref()
            .and_then(serde_json::Number::as_f64)
            .unwrap_or(1.0)
            .clamp(0.0, 1.0);
        ui.set_editor_opacity((opacity * 100.0).round() as i32);
        ui.set_settings_section("theme-editor".into());
    });
}

/// The editor's colors as Grappa's `colors` map, when all 27 are valid.
fn editor_colors(ui: &AppWindow) -> Option<HashMap<String, String>> {
    use slint::Model as _;
    ui.get_editor_colors()
        .iter()
        .map(|row| {
            let rgb = cordiale_core::theme::parse_hex(row.value.trim())?;
            Some((row.key.to_string(), cordiale_core::theme::to_hex(rgb)))
        })
        .collect()
}

/// The payload the editor would save: colors, font and wallpaper.
fn editor_payload(ui: &AppWindow) -> Option<Value> {
    use slint::Model as _;
    let colors = editor_colors(ui)?;
    ThemePalette::from_colors(&colors)?;
    let font = usize::try_from(ui.get_editor_font_index())
        .ok()
        .and_then(|index| cordiale_core::theme::FONT_FAMILIES.get(index))
        .copied()
        .unwrap_or("mono-default");
    let key = usize::try_from(ui.get_editor_background_index())
        .ok()
        .and_then(|index| ui.get_editor_background_keys().row_data(index))
        .unwrap_or_default();
    let image_id = ui.get_editor_image_id();
    let (builtin, image_id) = match key.as_str() {
        "" => (None, None),
        "upload" if !image_id.is_empty() => (None, Some(image_id.to_string())),
        "upload" => (None, None),
        builtin => (Some(builtin.to_string()), None),
    };
    let opacity = f64::from(ui.get_editor_opacity().clamp(0, 100)) / 100.0;
    Some(serde_json::json!({
        "colors": colors,
        "font_family": font,
        "background": {
            "image_id": image_id,
            "builtin": builtin,
            "size": if ui.get_editor_tile() { "repeat" } else { "cover" },
            "opacity": opacity,
        },
    }))
}

/// Shows the editor's colors and font on the window while editing, like
/// Cicchetto's live preview; Cancel puts the theme in use back.
fn preview_editor_theme(ui: &AppWindow) {
    let Some(palette) = editor_colors(ui).and_then(|colors| ThemePalette::from_colors(&colors))
    else {
        return;
    };
    let font_family = usize::try_from(ui.get_editor_font_index())
        .ok()
        .and_then(|index| cordiale_core::theme::FONT_FAMILIES.get(index))
        .copied()
        .unwrap_or("mono-default")
        .to_string();
    let preview = ThemeChoice {
        key: String::new(),
        name: String::new(),
        author: String::new(),
        palette,
        font_family,
        background: None,
        mine: true,
        published: false,
        background_wire: None,
    };
    push_palette(ui, Some(&preview));
}

/// Saves the edited theme, then makes it the day theme like Cicchetto's
/// Save (the night theme, if any, stays).
async fn save_theme(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    theme_id: Option<i64>,
    name: &str,
    payload: &Value,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let saved = match client.save_theme(&token, theme_id, name, payload).await {
        Ok(saved) => saved,
        Err(err) => return report_theme_action(ui, Some(err)),
    };
    let night = state
        .prefs
        .theme_pair
        .as_ref()
        .and_then(|pair| pair.1.as_ref())
        .and_then(|night| server_theme_id(&night.key))
        .filter(|night| *night != saved.id);
    if let Err(err) = client.set_active_theme(&token, saved.id, night).await {
        return report_theme_action(ui, Some(err));
    }
    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.color_theme = Some("server".to_string());
    let _ = persistence::save_settings(&settings);
    load_color_themes(state, ui).await;
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_settings_section("themes".into());
        ui.set_status_kind("theme-saved".into());
    });
}

/// Shows why a theme action failed: 422 for an invalid theme or a taken
/// name, 429 for Grappa's daily limit on new themes.
fn report_theme_action(ui: &slint::Weak<AppWindow>, err: Option<GrappaClientError>) {
    let Some(err) = err else {
        return;
    };
    persistence::log_line(&format!("theme action failed: {err:?}"));
    let status = err.status().map(|status| status.as_u16());
    let (kind, hint) = match status {
        Some(422) => ("theme-refused", String::new()),
        Some(429) => ("theme-rate-limited", String::new()),
        Some(code) => ("theme-action-failed", code.to_string()),
        None => ("theme-action-failed", "network error".to_string()),
    };
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_command_hint(hint.into());
        ui.set_status_kind(kind.into());
    });
}

/// Uploads a picked wallpaper to Grappa, which re-encodes it, and selects
/// it in the editor.
async fn upload_theme_background(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    path: &std::path::Path,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "wallpaper".to_string());
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let mime = match extension.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        _ => "application/octet-stream",
    };
    let result = match std::fs::read(path) {
        Ok(bytes) => client
            .upload_theme_background(&token, &filename, mime, bytes)
            .await
            .map_err(|err| {
                persistence::log_line(&format!("wallpaper upload failed: {err:?}"));
                err.status()
                    .map(|status| status.as_u16().to_string())
                    .unwrap_or_else(|| "network error".to_string())
            }),
        Err(err) => Err(err.to_string()),
    };
    let _ = ui.upgrade_in_event_loop(move |ui| match result {
        Ok(image_id) => {
            ui.set_editor_image_id(image_id.into());
            ui.set_editor_background_index(1);
        }
        Err(reason) => {
            ui.set_status_command_hint(reason.into());
            ui.set_status_kind("theme-background-failed".into());
        }
    });
}

/// Day and night choices of Grappa's active pair; `None` without a day
/// theme.
fn theme_pair_choices(pair: &ActiveThemePair) -> Option<(ThemeChoice, Option<ThemeChoice>)> {
    let light = pair.light.as_ref().and_then(server_theme_choice)?;
    let dark = pair.dark.as_ref().and_then(server_theme_choice);
    Some((light, dark))
}

/// The theme of the pair the OS scheme calls for: the night one in dark
/// mode when there is one, else the day one.
fn pair_theme_for(pair: &(ThemeChoice, Option<ThemeChoice>), system_dark: bool) -> &ThemeChoice {
    match &pair.1 {
        Some(night) if system_dark => night,
        _ => &pair.0,
    }
}

fn apply_theme_pair(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let choice = state
        .prefs
        .theme_pair
        .as_ref()
        .map(|pair| pair_theme_for(pair, state.prefs.system_dark).clone());
    apply_color_theme(state, ui, choice);
}

/// Follows the OS light/dark setting on a thread of its own: the current
/// mode first, then every change.
fn watch_system_scheme(tx: mpsc::UnboundedSender<WorkerCommand>) {
    thread::spawn(move || {
        let is_dark = |mode: dark_light::Mode| mode == dark_light::Mode::Dark;
        if let Ok(mode) = dark_light::detect() {
            let _ = tx.send(WorkerCommand::SystemScheme(is_dark(mode)));
        }
        let watcher = match dark_light::subscribe() {
            Ok(watcher) => watcher,
            Err(err) => {
                persistence::log_line(&format!("system color scheme not watched: {err}"));
                return;
            }
        };
        for mode in watcher.iter() {
            if tx.send(WorkerCommand::SystemScheme(is_dark(mode))).is_err() {
                break;
            }
        }
    });
}

/// Settings > Themes night pick: `server:<id>` becomes the night theme next
/// to the day one in use, "" goes back to the day theme at all hours.
async fn select_night_theme(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, key: &str) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(light) = state
        .prefs
        .theme_pair
        .as_ref()
        .and_then(|pair| pair.0.key.strip_prefix("server:"))
        .and_then(|id| id.parse::<i64>().ok())
    else {
        return;
    };
    let dark = if key.is_empty() {
        None
    } else {
        match key
            .strip_prefix("server:")
            .and_then(|id| id.parse::<i64>().ok())
        {
            Some(id) => Some(id),
            None => return,
        }
    };
    match client.set_active_theme(&token, light, dark).await {
        Ok(pair) => {
            state.prefs.theme_pair = theme_pair_choices(&pair);
            apply_theme_pair(state, ui);
        }
        Err(err) => {
            persistence::log_line(&format!("night theme change failed: {err:?}"));
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_status_kind("theme-change-failed".into());
            });
        }
    }
}

/// Settings > Themes pick. An empty key returns to the classic look; a
/// `server:<id>` key sets the account's active theme on Grappa.
async fn select_color_theme(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, key: &str) {
    let mut settings = persistence::load_settings().unwrap_or_default();
    let choice = if key.is_empty() {
        settings.color_theme = None;
        None
    } else if let Some(id) = key.strip_prefix("server:") {
        let (Some(client), Some(token), Ok(id)) = (
            state.conn.client.clone(),
            state.conn.token.clone(),
            id.parse::<i64>(),
        ) else {
            return;
        };
        let night = state
            .prefs
            .theme_pair
            .as_ref()
            .and_then(|pair| pair.1.as_ref())
            .and_then(|night| night.key.strip_prefix("server:"))
            .and_then(|night| night.parse::<i64>().ok())
            .filter(|night| *night != id);
        match client.set_active_theme(&token, id, night).await {
            Ok(pair) => {
                settings.color_theme = Some("server".to_string());
                let _ = persistence::save_settings(&settings);
                state.prefs.theme_pair = theme_pair_choices(&pair);
                return apply_theme_pair(state, ui);
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
            .prefs
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
    state.prefs.theme_pair = None;
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
    load_theme_background(
        state,
        ui,
        choice.as_ref().and_then(|choice| choice.background.clone()),
    );
    state.prefs.theme = match &choice {
        Some(choice) if choice.palette.is_dark() => Theme::Dark,
        Some(_) => Theme::Light,
        None => persistence::load_settings().unwrap_or_default().theme,
    };
    push_theme_choices(state, ui, choice.as_ref().map(|choice| choice.key.as_str()));
    let current_lines = state
        .windows
        .current_channel
        .as_ref()
        .and_then(|key| state.transcript.messages.get(key))
        .cloned();
    let current_roster = state
        .windows
        .current_channel
        .as_ref()
        .filter(|_| !state.windows.current_query)
        .map(|key| {
            (
                state
                    .transcript
                    .members
                    .get(key)
                    .cloned()
                    .unwrap_or_default(),
                network_casemapping(state, &key.0),
                state.denoise_active(key),
                MemberRanking::new(state.networks.isupport_by_network.get(&key.0)),
            )
        });
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        push_palette(&ui, choice.as_ref());
        if let Some(lines) = current_lines {
            let model = match &current_roster {
                Some((members, casemapping, denoise, _)) => chat_lines_model_with_roster(
                    &lines,
                    dark_theme,
                    members,
                    *casemapping,
                    *denoise,
                ),
                None => chat_lines_model(&lines, dark_theme),
            };
            show_chat_lines(&ui, model);
        }
        if let Some((members, _, _, ranking)) = current_roster {
            let rows = members_model(&members, dark_theme, &ranking);
            ui.set_channel_members(Rc::new(slint::VecModel::from(rows)).into());
        }
    });
}

/// Secondary text in the classic look: at least 4.5:1 on the window
/// background, on a section card and on a hover tint, in both schemes.
fn classic_muted(dark_theme: bool) -> (u8, u8, u8) {
    if dark_theme {
        (0x96, 0x96, 0x96)
    } else {
        (0x66, 0x66, 0x66)
    }
}

/// Timestamp-prefix color: readable but visually secondary against either
/// theme's default text color.
fn muted_color(dark_theme: bool) -> slint::Color {
    match active_palette() {
        Some(palette) => slint_color(palette.muted_text()),
        None => slint_color(classic_muted(dark_theme)),
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

/// User modes a normal user may flip; every other letter is set by the
/// server or services and shows read-only, as in Cicchetto.
const SETTABLE_UMODES: [&str; 5] = ["i", "w", "s", "x", "R"];

/// Letters the user-mode view describes, offered when a network hasn't
/// advertised its own set (RPL_MYINFO).
const KNOWN_UMODES: [&str; 27] = [
    "i", "w", "s", "x", "R", "b", "c", "d", "e", "f", "g", "k", "K", "m", "n", "y", "F", "I", "j",
    "S", "o", "O", "r", "a", "A", "h", "z",
];

/// The user-mode view's rows: `(letter, settable, active)`. The server's
/// advertised set (else the known letters) plus every active mode, settable
/// ones first.
fn umode_rows(active: &[String], supported: &[String]) -> Vec<(String, bool, bool)> {
    let mut letters: Vec<String> = if supported.is_empty() {
        KNOWN_UMODES
            .iter()
            .map(|letter| letter.to_string())
            .collect()
    } else {
        supported.to_vec()
    };
    for letter in active {
        if !letters.contains(letter) {
            letters.push(letter.clone());
        }
    }
    let mut rows: Vec<(String, bool, bool)> = letters
        .into_iter()
        .map(|letter| {
            let settable = SETTABLE_UMODES.contains(&letter.as_str());
            let is_active = active.contains(&letter);
            (letter, settable, is_active)
        })
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

/// Refreshes the user-mode view, switching to it when `open`.
fn push_umode_view(state: &WorkerState, ui: &slint::Weak<AppWindow>, open: bool) {
    let Some(network) = state.networks.umode_view_network.clone() else {
        return;
    };
    let empty = Vec::new();
    let active = state
        .networks
        .user_modes_by_network
        .get(&network)
        .unwrap_or(&empty);
    let supported = state
        .networks
        .supported_user_modes_by_network
        .get(&network)
        .unwrap_or(&empty);
    let rows = umode_rows(active, supported);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<UmodeToggle> = rows
            .into_iter()
            .map(|(letter, settable, active)| UmodeToggle {
                letter: letter.into(),
                settable,
                active,
            })
            .collect();
        ui.set_umode_network(network.into());
        ui.set_umode_toggles(Rc::new(slint::VecModel::from(rows)).into());
        if open {
            ui.set_screen("umodes".into());
        }
    });
}

/// Sends `+x` or `-x` for a settable mode; the view updates when Grappa
/// pushes the new modes back.
fn toggle_user_mode(state: &WorkerState, letter: &str) {
    let Some(network) = state.networks.umode_view_network.as_deref() else {
        return;
    };
    if !SETTABLE_UMODES.contains(&letter) {
        return;
    }
    let active = state
        .networks
        .user_modes_by_network
        .get(network)
        .is_some_and(|modes| modes.iter().any(|mode| mode == letter));
    let sign = if active { '-' } else { '+' };
    send_user_verb(
        state,
        network,
        "umode",
        serde_json::json!({ "modes": format!("{sign}{letter}") }),
    );
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkLifecycleKind {
    Attached,
    Detached,
}

/// Ends a session whose bearer the server revoked: stops the Phoenix
/// session so it never retries with that bearer, forgets a remembered copy
/// of it, and returns to the sign-in screen through the normal disconnect
/// path. No IRC QUIT is sent — the bouncer's IRC session is unaffected.
fn end_revoked_session(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, flood: bool) {
    if let Some(handle) = state.conn.session.take() {
        handle.shutdown();
    }
    if let (Some(client), Some(identifier)) = (
        state.conn.client.as_ref(),
        state.conn.login_identifier.as_deref(),
    ) {
        if state.conn.guest_session {
            forget_guest_bearer(client.base_url(), identifier);
        } else {
            forget_remembered_bearer(client.base_url(), identifier);
        }
    }
    state.conn.token = None;
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

/// Status key for a refused auto-away nick suffix: 422 is a tail that isn't
/// legal in a nick.
fn away_nick_suffix_error_key(status: Option<u16>) -> &'static str {
    if status == Some(422) {
        "away-nick-suffix-invalid"
    } else {
        "personal-prefs-failed"
    }
}

/// Mirrors `state.recover_panel` into the sidebar panel. The Slint row model
/// is built inside the UI-thread closure because `ModelRc` is not `Send`.
fn push_recover_panel(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (visible, network, rows, outcome, outcome_reason) = match &state.panels.recover_panel {
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

/// Stores a requester reply and opens the reply screen. It replaces any
/// earlier reply (last-write-wins, like Cicchetto's per-network modals) and
/// never touches chat history or the selected window.
fn show_reply_view(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, view: ReplyView) {
    push_reply_view(ui, &view, true);
    state.panels.reply_view = Some(view);
}

/// Mirrors a reply view into the UI; `open` also switches to the reply
/// screen. An in-place refresh passes `false` so it never steals the screen.
fn push_reply_view(ui: &slint::Weak<AppWindow>, view: &ReplyView, open: bool) {
    let kind = view.kind;
    let subject = view.subject.clone();
    let network = view.network.clone();
    let rows = view.rows.clone();
    // Only the message rows of the mentions summary (no label) lead anywhere.
    let mentions = kind == "mentions_bundle";
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<ReplyRow> = rows
            .into_iter()
            .map(|(label, value)| ReplyRow {
                jump: mentions && label.is_empty(),
                label: label.into(),
                value: value.into(),
            })
            .collect();
        ui.set_reply_rows(Rc::new(slint::VecModel::from(rows)).into());
        // A WHOIS avatar arrives after the card; any new view starts
        // without the previous one's picture.
        ui.set_reply_avatar_visible(false);
        ui.set_reply_kind(kind.into());
        ui.set_reply_subject(subject.into());
        ui.set_reply_network(network.into());
        if open {
            ui.set_screen("reply".into());
        }
    });
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
    let (Some(client), Some(token)) = (state.conn.client.as_ref(), state.conn.token.as_deref())
    else {
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
    state.panels.archive = Some(ArchiveView {
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
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.panels.archive.as_ref(),
    ) else {
        return;
    };
    let network = view.network.clone();
    let result = client.fetch_archive(&token, &network).await;
    let Some(view) = state.panels.archive.as_mut() else {
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
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.panels.archive.as_ref(),
    ) else {
        return;
    };
    let network = view.network.clone();
    let Err(err) = client.delete_archive_target(&token, &network, target).await else {
        return;
    };
    persistence::log_line(&format!("archive delete failed: {err:?}"));
    if let Some(view) = state.panels.archive.as_mut() {
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
    let Some(view) = state.panels.archive.as_ref() else {
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
        .map(|parsed| dates::render_date_time(&parsed.with_timezone(&chrono::Local), false))
        .unwrap_or_else(|| millis.to_string())
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

/// Peer-away key: the network plus the peer folded with that network's
/// casemapping, so `Alice` and `alice` share one message.
fn peer_away_key(state: &WorkerState, network: &str, peer: &str) -> (String, String) {
    let casemapping = state
        .networks
        .isupport_by_network
        .get(network)
        .map(|isupport| isupport.casemapping)
        .unwrap_or(cordiale_core::isupport::CaseMapping::Rfc1459);
    (network.to_string(), casemapping.fold(peer))
}

/// The peer-away key of the open private window, if one is open.
fn current_peer_away_key(state: &WorkerState) -> Option<(String, String)> {
    if !state.windows.current_query {
        return None;
    }
    let (network, nick) = state.windows.current_channel.as_ref()?;
    Some(peer_away_key(state, network, nick))
}

/// Shows the open private window's away message, or hides the banner. The
/// banner itself is only drawn while a private window is open.
fn push_peer_away_banner(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (peer, message) = current_peer_away_key(state)
        .and_then(|key| {
            let message = state.networks.peer_away.get(&key)?.clone();
            let peer = state
                .windows
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

/// Closes the directory pane, if open, and gives the chat its place back.
fn close_directory(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    if state.panels.directory.take().is_none() {
        return;
    }
    let _ = ui.upgrade_in_event_loop(|ui| ui.set_directory_open(false));
}

/// A directory row: joined first when it isn't, then focused, like
/// Cicchetto (the intent follows the tap). A failed join stays on the pane.
async fn directory_activate(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, channel: String) {
    let Some(network) = state
        .panels
        .directory
        .as_ref()
        .map(|view| view.network.clone())
    else {
        return;
    };
    if !state.networks.network_ids.contains_key(&network) {
        return;
    }
    // The directory keeps the server's `LIST` spelling; window states are
    // keyed ASCII-folded, like Cicchetto's `channelKey`.
    let joined = state
        .windows
        .window_states
        .get(&window_state_key(&network, &channel))
        == Some(&ChannelWindowState::Joined);
    if !joined {
        let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone())
        else {
            return;
        };
        if let Err(err) = client.join_channel(&token, &network, &channel, None).await {
            persistence::log_line(&format!("directory join failed: {err:?}"));
            if let Some(view) = state.panels.directory.as_mut() {
                view.error = Some("directory-join-failed");
            }
            push_directory(state, ui, false);
            return;
        }
    }
    // Focus the sidebar's own spelling of the window when it has one.
    let key = window_state_key(&network, &channel);
    let channel = state
        .windows
        .channel_entries
        .iter()
        .find(|(known_network, known_channel, _)| {
            window_state_key(known_network, known_channel) == key
        })
        .map(|(_, known_channel, _)| known_channel.clone())
        .unwrap_or(channel);
    write_back_read_cursor(state);
    handle_select_channel(state, ui, network, channel).await;
}

/// Seconds since `captured_epoch` (Unix seconds as pushed to the UI), or
/// -1 when there is no capture; a clock behind the server reads as 0.
fn directory_age_seconds(captured_epoch: &str, now: i64) -> i32 {
    match captured_epoch.parse::<i64>() {
        Ok(captured) => (now - captured).clamp(0, i64::from(i32::MAX)) as i32,
        Err(_) => -1,
    }
}

/// Opens the directory pane for `network` and loads its first page.
async fn open_directory(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    query: String,
) {
    state.panels.directory = Some(DirectoryView::new(network, query));
    push_directory(state, ui, true);
    load_directory(state, ui).await;
}

/// Fetches the first page for the open directory's sort and search,
/// replacing any loaded rows (the snapshot may have been replaced).
async fn load_directory(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token), Some(view)) = (
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.panels.directory.as_ref(),
    ) else {
        return;
    };
    let network = view.network.clone();
    let sort = view.sort;
    let query = view.query.clone();
    let result = client
        .fetch_directory(&token, &network, sort, &query, None)
        .await;
    let Some(view) = state.panels.directory.as_mut() else {
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
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.panels.directory.as_ref(),
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
    let Some(view) = state.panels.directory.as_mut() else {
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
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let Some(view) = state.panels.directory.as_mut() else {
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
        if let Some(view) = state.panels.directory.as_mut() {
            if view.network == network {
                view.refresh_pending = false;
                view.error = Some("directory-refresh-failed");
            }
        }
        push_directory(state, ui, false);
    }
}

/// Mirrors the open directory into the UI; `open` also shows its pane (and
/// the search text, which later pushes leave alone so typing isn't
/// overwritten by an answer to an earlier query). Nothing is pushed when no
/// directory is open.
fn push_directory(state: &WorkerState, ui: &slint::Weak<AppWindow>, open: bool) {
    let Some(view) = state.panels.directory.as_ref() else {
        return;
    };
    let network = view.network.clone();
    let sort = view.sort;
    let query = view.query.clone();
    let error = view.error.unwrap_or("");
    let refresh_pending = view.refresh_pending;
    let failed_reason = view.failed_reason.clone().unwrap_or_default();
    let (rows, status, total, captured_at, captured_epoch, has_more) = match &view.page {
        Some(page) => (
            directory_rows(page, &network, &state.windows.window_states),
            page.status.clone(),
            page.total.to_string(),
            page.captured_at
                .as_deref()
                .map(format_iso_timestamp)
                .unwrap_or_default(),
            page.captured_at
                .as_deref()
                .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
                .map(|parsed| parsed.timestamp().to_string())
                .unwrap_or_default(),
            page.next_cursor.is_some(),
        ),
        None => (
            Vec::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            false,
        ),
    };
    let age = directory_age_seconds(&captured_epoch, chrono::Utc::now().timestamp());
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_directory_rows(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_directory_network(network.into());
        ui.set_directory_sort(sort.into());
        ui.set_directory_status(status.into());
        ui.set_directory_total(total.into());
        ui.set_directory_captured_at(captured_at.into());
        ui.set_directory_captured_epoch(captured_epoch.into());
        ui.set_directory_age_seconds(age);
        ui.set_directory_error(error.into());
        ui.set_directory_refresh_pending(refresh_pending);
        ui.set_directory_failed_reason(failed_reason.into());
        ui.set_directory_has_more(has_more);
        if open {
            ui.set_directory_query(query.into());
            ui.set_screen("connected".into());
            ui.set_directory_open(true);
        }
    });
}

/// The directory page as UI rows: the topic with its mIRC formatting
/// stripped, and `joined` from the network's window states.
fn directory_rows(
    page: &DirectoryPage,
    network: &str,
    window_states: &HashMap<(String, String), ChannelWindowState>,
) -> Vec<DirectoryRow> {
    page.entries
        .iter()
        .map(|entry| {
            let topic: String = entry
                .topic
                .as_deref()
                .map(|topic| {
                    cordiale_core::formatting::parse_mirc_text(topic)
                        .into_iter()
                        .map(|segment| segment.text)
                        .collect()
                })
                .unwrap_or_default();
            DirectoryRow {
                name: entry.name.clone().into(),
                users: entry.user_count.to_string().into(),
                topic: topic.into(),
                featured: entry.featured,
                joined: window_states.get(&window_state_key(network, &entry.name))
                    == Some(&ChannelWindowState::Joined),
            }
        })
        .collect()
}

/// Local-time rendering of an ISO-8601 timestamp; an unparsable value is
/// shown as sent.
fn format_iso_timestamp(raw: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|parsed| dates::render_date_time(&parsed.with_timezone(&chrono::Local), false))
        .unwrap_or_else(|_| raw.to_string())
}

/// File extension Slint's image loader needs, from the avatar's
/// `Content-Type`; `None` for formats it can't decode.
fn avatar_extension(content_type: Option<&str>) -> Option<&'static str> {
    let mime = content_type?.split(';').next()?.trim();
    match mime {
        "image/png" => Some("png"),
        "image/jpeg" | "image/jpg" => Some("jpg"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/bmp" | "image/x-ms-bmp" => Some("bmp"),
        _ => None,
    }
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

/// Common channel prefixes, used only to tell a channel argument from a mode
/// letter in `/banlist`. `+` is left out on purpose: `/banlist +e` means the
/// exception list, not a modeless `+e` channel.
fn looks_like_channel(name: &str) -> bool {
    name.starts_with(['#', '&', '!'])
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

enum QueryTopicResolution<'a> {
    Active(&'a QueryWindow),
    Stale,
    Untracked,
}

/// First protocol version where a nick change moves nothing server-side: a
/// renamed peer's next message opens a new query window and the old one
/// keeps its history, so there is no rename to infer.
const NICK_CHANGE_MOVES_NOTHING_PROTOCOL: u32 = 37;

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

/// Shows the passkey origin saved for `server_url` in the origin field.
fn load_passkey_origin_field(ui: &AppWindow, server_url: &str) {
    let saved = persistence::load_passkey_origin_override(server_url).unwrap_or_default();
    ui.set_passkey_origin(saved.into());
    ui.set_passkey_origin_saved(false);
}

/// Saves what the origin field holds for `server_url` when signing in, so
/// the passkey ceremony that may follow uses it. An invalid entry is left
/// out: the connect screen doesn't let it through.
fn save_passkey_origin_field(ui: &AppWindow, server_url: &str) {
    let _ = persistence::save_passkey_origin_override(
        server_url,
        &check_override(&ui.get_passkey_origin()),
    );
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

/// Anonymous visitor bearers are kept apart from account profiles. This
/// lets a returning guest reclaim the same nickname without adding a guest
/// to `servers.json` or replacing an account credential with the same name.
fn guest_bearer_service(server_url: &str) -> String {
    format!("{server_url}#guest-bearer")
}

fn remember_guest_bearer(server_url: &str, identifier: &str, bearer: &str) {
    if identifier.is_empty() || bearer.is_empty() {
        return;
    }
    let stored = resolve_credential_store()
        .and_then(|store| store.set_secret(&guest_bearer_service(server_url), identifier, bearer))
        .is_ok();
    if !stored {
        persistence::log_line(
            "guest bearer could not be persisted; reconnect may require a new nickname",
        );
    }
}

fn remembered_guest_bearer(server_url: &str, identifier: &str) -> Option<String> {
    if identifier.is_empty() {
        return None;
    }
    resolve_credential_store()
        .ok()?
        .get_secret(&guest_bearer_service(server_url), identifier)
        .ok()
        .flatten()
        .filter(|bearer| !bearer.is_empty())
}

fn forget_guest_bearer(server_url: &str, identifier: &str) {
    if identifier.is_empty() {
        return;
    }
    if let Ok(store) = resolve_credential_store() {
        let _ = store.delete_secret(&guest_bearer_service(server_url), identifier);
    }
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
        // Only reached without a TOTP challenge: a passkey is the account's
        // only second factor, and this platform can't run the ceremony.
        BootstrapError::Login(LoginError::TwoFactorRequired(_)) => {
            ui.set_status_kind("two-factor-passkey-only".into());
        }
        BootstrapError::TwoFactor(err) => {
            ui.set_status_kind(totp_error_key(err).into());
        }
        BootstrapError::Recovery(err) => {
            ui.set_status_kind(recovery_error_key(err).into());
        }
        BootstrapError::ShareToken(err) => {
            ui.set_status_kind(share_consume_error_key(err).into());
        }
        BootstrapError::Login(LoginError::TooManyAttempts) => {
            ui.set_status_kind("too-many-attempts".into());
        }
        BootstrapError::Login(LoginError::Refused {
            code: Some(code),
            retry_after,
            ..
        }) if login_refusal_kind(code).is_some() => {
            let kind = if code == "anon_collision" && retry_after.is_some_and(|secs| secs >= 3600) {
                "guest-nick-taken-hours"
            } else {
                login_refusal_kind(code).unwrap_or("login-failed")
            };
            ui.set_status_message(
                retry_after
                    .map(|secs| {
                        if kind == "guest-nick-taken-hours" {
                            secs.div_ceil(3600).to_string()
                        } else {
                            secs.to_string()
                        }
                    })
                    .unwrap_or_default()
                    .into(),
            );
            ui.set_status_kind(kind.into());
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

/// The status key for a login refusal Grappa names in its `error` field,
/// for the codes a guest sign-in can run into.
fn login_refusal_kind(code: &str) -> Option<&'static str> {
    match code {
        "anon_collision" => Some("guest-nick-taken"),
        "nick_in_use" => Some("guest-nick-in-use"),
        "malformed_nick" => Some("guest-nick-invalid"),
        "captcha_required" => Some("guest-captcha-required"),
        "too_many_sessions" | "ip_cap_exceeded" => Some("guest-too-many-sessions"),
        _ => None,
    }
}

/// Only terminal proof failures invalidate a visitor bearer. A rate limit,
/// session cap, server error or transport failure must leave it available
/// for a later retry of the same nickname.
fn stale_guest_bearer(error: &BootstrapError) -> bool {
    match error {
        BootstrapError::Login(LoginError::InvalidCredentials) => true,
        BootstrapError::Login(LoginError::Refused { status, code, .. }) => {
            status.as_u16() == 409 && code.as_deref() == Some("anon_collision")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
