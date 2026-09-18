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

use std::collections::HashMap;
use std::rc::Rc;
use std::thread;

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
    SendMessage {
        body: String,
    },
    ComposeTextChanged(String),
    ToggleTheme,
    SaveDisplayPrefs(DisplayPrefs),
    Disconnect,
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

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
            let empty_channels = Rc::new(slint::VecModel::from(Vec::<ChannelEntry>::new()));
            ui.set_channel_list(empty_channels.into());
            let empty_messages = Rc::new(slint::VecModel::from(Vec::<slint::SharedString>::new()));
            ui.set_chat_messages(empty_messages.into());
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
    current_channel: Option<(String, String)>,
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
            current_channel: None,
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
                    }
                    Some(WorkerCommand::SelectChannel { network, channel }) => {
                        handle_select_channel(&mut state, &ui, network, channel).await;
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
                    Some(SessionEvent::Disconnected) => {
                        persistence::log_line("session disconnected");
                        let _ = ui.upgrade_in_event_loop(|ui| {
                            ui.set_status_kind("disconnected".into());
                        });
                    }
                    Some(SessionEvent::Reconnecting) => {
                        persistence::log_line("session reconnecting");
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
    // Never log `password`: it may be a real password or a per-client
    // token, and either way it's a secret — see MEMORY.md §3.6.
    persistence::log_line(&format!(
        "connect attempt: server={server_url} identifier={identifier}"
    ));
    remember_server_url(&server_url);

    let client = GrappaClient::new(server_url.clone());
    let request = LoginRequest {
        identifier: identifier.clone(),
        password: password.clone(),
    };
    let result = bootstrap(&client, &request).await;

    match result {
        Ok(outcome) => {
            persistence::log_line(&format!("connect succeeded: server={server_url}"));
            remember_profile(&server_url, &identifier, &password);

            let entries = channel_entries_from_boot(&outcome);
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
            let network_count = entries
                .iter()
                .map(|(network, _, _)| network.clone())
                .collect::<std::collections::HashSet<_>>()
                .len();
            let channel_count = entries.len();
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_connecting(false);
                ui.set_is_admin(is_admin);
                ui.set_known_servers(known_servers_model());
                ui.set_screen("connected".into());
                ui.set_status_kind("signed-in".into());
                ui.set_status_network_count(network_count as i32);
                ui.set_status_channel_count(channel_count as i32);
                let model: Vec<ChannelEntry> = entries
                    .into_iter()
                    .map(|(network, channel, label)| ChannelEntry {
                        network: network.into(),
                        channel: channel.into(),
                        label: label.into(),
                    })
                    .collect();
                ui.set_channel_list(Rc::new(slint::VecModel::from(model)).into());
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

    let label = format!("{network} — {channel}");
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_channel_label(label.into());
        ui.set_has_selected_channel(true);
        ui.set_compose_text(draft.into());
        let model: Vec<slint::SharedString> = lines.into_iter().map(Into::into).collect();
        ui.set_chat_messages(Rc::new(slint::VecModel::from(model)).into());
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
    let Some((network, channel)) = channel_from_topic(&frame.topic) else {
        return;
    };
    if frame.event == "phx_reply" {
        return;
    }

    let line = render_frame(&frame);
    let key = (network.clone(), channel.clone());
    state.messages.entry(key.clone()).or_default().push(line);

    if state.current_channel.as_ref() == Some(&key) {
        let lines = state.messages[&key].clone();
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            let model: Vec<slint::SharedString> = lines.into_iter().map(Into::into).collect();
            ui.set_chat_messages(Rc::new(slint::VecModel::from(model)).into());
        });
    }
}

fn render_frame(frame: &cordiale_core::phoenix::PhoenixMessage) -> String {
    let nick = frame
        .payload
        .get("from")
        .or_else(|| frame.payload.get("nick"))
        .and_then(|v| v.as_str());
    let body = frame
        .payload
        .get("body")
        .or_else(|| frame.payload.get("message"))
        .and_then(|v| v.as_str());

    match (nick, body) {
        (Some(nick), Some(body)) => format!("<{nick}> {body}"),
        (None, Some(body)) => body.to_string(),
        _ => format!("{}: {}", frame.event, frame.payload),
    }
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
/// placeholder rather than guessing further.
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
            let label = format!("{network} — {channel}");
            entries.push((network.clone(), channel, label));
        }
    }
    entries
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
