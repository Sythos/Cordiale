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

use std::thread;

use cordiale_core::bootstrap::{bootstrap, BootstrapError};
use cordiale_core::client::{GrappaClient, LoginError};
use cordiale_core::persistence;
use cordiale_core::rest::LoginRequest;

/// The default server offered on first launch, per MEMORY.md §3.3.
const DEFAULT_SERVER_URL: &str = "https://irc.sindro.me";

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

    let remembered_server_url = load_remembered_server_url();
    ui.set_server_url(remembered_server_url.into());

    if persistence::load_settings()
        .unwrap_or_default()
        .language
        .is_none()
    {
        ui.set_screen("language".into());
    }

    let weak_for_language = ui.as_weak();
    ui.on_language_selected(move |code| {
        if let Some(language) = language_from_code(&code) {
            let mut settings = persistence::load_settings().unwrap_or_default();
            settings.language = Some(language);
            let _ = persistence::save_settings(&settings);
        }
        if let Some(ui) = weak_for_language.upgrade() {
            ui.set_screen("connect".into());
        }
    });

    let weak = ui.as_weak();
    ui.on_connect_requested(move |server_url, identifier, password| {
        let server_url = server_url.to_string();
        let identifier = identifier.to_string();
        let password = password.to_string();

        if let Some(ui) = weak.upgrade() {
            ui.set_connecting(true);
            ui.set_status_message("".into());
        }
        remember_server_url(&server_url);

        let weak_for_thread = weak.clone();
        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("failed to start network runtime");
            runtime.block_on(async move {
                let client = GrappaClient::new(server_url.clone());
                let request = LoginRequest {
                    identifier,
                    password,
                };
                let result = bootstrap(&client, &request).await;

                let _ = weak_for_thread.upgrade_in_event_loop(move |ui| {
                    ui.set_connecting(false);
                    match result {
                        Ok(outcome) => {
                            let networks = network_names(&outcome);
                            ui.set_screen("connected".into());
                            ui.set_status_message(
                                format!(
                                    "Signed in. {} network(s) on this account.",
                                    networks.len()
                                )
                                .into(),
                            );
                            let model = std::rc::Rc::new(slint::VecModel::from(
                                networks
                                    .into_iter()
                                    .map(Into::into)
                                    .collect::<Vec<slint::SharedString>>(),
                            ));
                            ui.set_networks(model.into());
                        }
                        Err(err) => {
                            ui.set_status_message(describe_bootstrap_error(&err).into());
                        }
                    }
                });
            });
        });
    });

    ui.run()
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

/// Reads a display name out of each opaque `boot.networks` entry.
///
/// The exact field names aren't confirmed by the client protocol (see
/// `docs/protocol-notes.md` §4), so this tries the plausible candidates and
/// falls back to a positional placeholder rather than guessing further.
fn network_names(outcome: &cordiale_core::bootstrap::BootstrapOutcome) -> Vec<String> {
    outcome
        .boot
        .networks
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .get("slug")
                .or_else(|| value.get("name"))
                .and_then(|field| field.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("network #{}", index + 1))
        })
        .collect()
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

fn describe_bootstrap_error(err: &BootstrapError) -> String {
    match err {
        BootstrapError::IncompatibleServer(compat) => format!(
            "This server's protocol version ({}) is too old for Cordiale.",
            compat.protocol_version
        ),
        BootstrapError::Config(_) => {
            "Couldn't reach the server. Check the URL and try again.".to_string()
        }
        BootstrapError::Login(LoginError::InvalidCredentials) => {
            "Wrong username or password/token.".to_string()
        }
        BootstrapError::Login(LoginError::TwoFactorRequired) => {
            "This account has two-factor authentication enabled. Sign in from a browser instead."
                .to_string()
        }
        BootstrapError::Login(LoginError::TooManyAttempts) => {
            "Too many attempts. Wait a bit before trying again.".to_string()
        }
        BootstrapError::Login(_) => "Login failed.".to_string(),
        BootstrapError::Boot(_) | BootstrapError::Me(_) => {
            "Signed in, but couldn't load account data.".to_string()
        }
    }
}
