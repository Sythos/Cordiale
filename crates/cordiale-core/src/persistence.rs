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

//! Local persistence under `~/.cordiale/`.
//!
//! No `localStorage`, no single monolithic file: non-sensitive preferences
//! live in `settings.json`, servers/profiles/selection live in
//! `servers.json`. Actual credentials never land in either file — see
//! `CredentialStore` (Phase 1, item 3).

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::domain::{Profile, Server};

const CONFIG_DIR_NAME: &str = ".cordiale";
const SETTINGS_FILE_NAME: &str = "settings.json";
const SERVERS_FILE_NAME: &str = "servers.json";
const LOG_FILE_NAME: &str = "cordiale.log";

/// One of the languages Cordiale ships translations for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    En,
    It,
    Fr,
    De,
    Es,
}

/// A GUI theme, backed by Slint design tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Light,
    Dark,
}

/// Non-sensitive user preferences, persisted to `settings.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Schema version, for future migrations.
    #[serde(default = "current_settings_schema_version")]
    pub schema_version: u32,
    /// `None` means the user hasn't picked a language yet: the GUI must ask
    /// on first launch and persist the answer here.
    #[serde(default)]
    pub language: Option<Language>,
    #[serde(default)]
    pub theme: Theme,
}

fn current_settings_schema_version() -> u32 {
    1
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            schema_version: current_settings_schema_version(),
            language: None,
            theme: Theme::default(),
        }
    }
}

/// Servers, profiles and the current selection, persisted to
/// `servers.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServersFile {
    #[serde(default = "current_servers_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub servers: Vec<Server>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    /// `base_url` of the currently selected `Server`, if any.
    #[serde(default)]
    pub selected_server_base_url: Option<String>,
    /// `identifier` of the currently selected `Profile`, if any.
    #[serde(default)]
    pub selected_profile_identifier: Option<String>,
}

fn current_servers_schema_version() -> u32 {
    1
}

impl Default for ServersFile {
    fn default() -> Self {
        ServersFile {
            schema_version: current_servers_schema_version(),
            servers: Vec::new(),
            profiles: Vec::new(),
            selected_server_base_url: None,
            selected_profile_identifier: None,
        }
    }
}

/// Error returned when reading or writing a persistence file fails.
#[derive(Debug)]
pub enum PersistenceError {
    NoConfigDir,
    Io(io::Error),
    Json(serde_json::Error),
}

impl From<io::Error> for PersistenceError {
    fn from(err: io::Error) -> Self {
        PersistenceError::Io(err)
    }
}

impl From<serde_json::Error> for PersistenceError {
    fn from(err: serde_json::Error) -> Self {
        PersistenceError::Json(err)
    }
}

/// `~/.cordiale/`, Cordiale's local config directory.
pub fn config_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(CONFIG_DIR_NAME))
}

fn load_json<T: Default + for<'de> Deserialize<'de>>(
    file_name: &str,
) -> Result<T, PersistenceError> {
    let dir = config_dir().ok_or(PersistenceError::NoConfigDir)?;
    let path = dir.join(file_name);

    if !path.exists() {
        return Ok(T::default());
    }

    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn save_json<T: Serialize>(file_name: &str, value: &T) -> Result<(), PersistenceError> {
    let dir = config_dir().ok_or(PersistenceError::NoConfigDir)?;
    fs::create_dir_all(&dir)?;
    let path = dir.join(file_name);
    let contents = serde_json::to_string_pretty(value)?;
    fs::write(path, contents)?;
    Ok(())
}

pub fn load_settings() -> Result<Settings, PersistenceError> {
    load_json(SETTINGS_FILE_NAME)
}

pub fn save_settings(settings: &Settings) -> Result<(), PersistenceError> {
    save_json(SETTINGS_FILE_NAME, settings)
}

pub fn load_servers_file() -> Result<ServersFile, PersistenceError> {
    load_json(SERVERS_FILE_NAME)
}

pub fn save_servers_file(servers_file: &ServersFile) -> Result<(), PersistenceError> {
    save_json(SERVERS_FILE_NAME, servers_file)
}

/// Appends one line to `~/.cordiale/cordiale.log`, prefixed with a Unix
/// timestamp — a plain-text trail a field tester can attach to a bug
/// report. Best-effort like every other write in this module: a failure
/// here is silently swallowed rather than surfaced, since diagnostics must
/// never be the reason the app itself breaks.
pub fn log_line(message: &str) {
    if let Some(dir) = config_dir() {
        log_line_to(&dir.join(LOG_FILE_NAME), message);
    }
}

fn log_line_to(path: &std::path::Path, message: &str) {
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let message = redact_secrets(message);
    let _ = writeln!(file, "[{timestamp}] {message}");
}

/// Keys whose value is redacted wherever they appear as `key<punctuation>value`
/// (covers `password=`, `password: "..."`, `"password":"..."` — query-string,
/// Rust `Debug`-derive and JSON shapes alike).
const SECRET_KEY_MARKERS: &[&str] = &["password", "token", "secret"];
/// Fixed strings redacted verbatim, for shapes no key/value split covers —
/// the Phoenix WS bearer subprotocol (`base64url.bearer.phx.<token>`) and a
/// plain HTTP `Authorization: Bearer <token>` header.
const SECRET_LITERAL_MARKERS: &[&str] = &["bearer.phx.", "bearer "];

/// Masks every password/token/secret value found in `message` before it's
/// written to disk. A backstop, not the only line of defense: every call
/// site already avoids interpolating a secret directly (see
/// `docs/protocol-notes.md` and the comments at each `log_line` call), but
/// this makes it structurally true instead of relying on every caller,
/// forever, getting that right — a `Debug`-derived struct or a future
/// dependency's error type echoing a credential back would otherwise slip
/// straight into a file field testers are asked to share for bug reports.
fn redact_secrets(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    let mut result = String::with_capacity(message.len());
    let mut cursor = 0;

    while cursor < message.len() {
        let literal_hit = SECRET_LITERAL_MARKERS.iter().filter_map(|marker| {
            lower[cursor..]
                .find(*marker)
                .map(|pos| (cursor + pos, cursor + pos + marker.len()))
        });
        let key_hit = SECRET_KEY_MARKERS.iter().filter_map(|marker| {
            lower[cursor..].find(*marker).map(|pos| {
                let key_end = cursor + pos + marker.len();
                let value_start = message[key_end..]
                    .find(|c: char| !matches!(c, ':' | '=' | '"' | '\'' | ' '))
                    .map(|offset| key_end + offset)
                    .unwrap_or(message.len());
                (cursor + pos, value_start)
            })
        });

        let Some((_, value_start)) = literal_hit.chain(key_hit).min_by_key(|(pos, _)| *pos)
        else {
            result.push_str(&message[cursor..]);
            break;
        };

        result.push_str(&message[cursor..value_start]);
        result.push_str("[redacted]");

        let value_end = message[value_start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '}' | '&'))
            .map(|offset| value_start + offset)
            .unwrap_or(message.len());
        cursor = value_end;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_has_no_language_and_light_theme() {
        let settings = Settings::default();
        assert_eq!(settings.language, None);
        assert_eq!(settings.theme, Theme::Light);
    }

    #[test]
    fn settings_round_trip_through_json_preserves_chosen_language() {
        let settings = Settings {
            schema_version: 1,
            language: Some(Language::It),
            theme: Theme::Dark,
        };

        let json = serde_json::to_string(&settings).expect("serialize");
        let decoded: Settings = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(settings, decoded);
    }

    #[test]
    fn servers_file_default_is_empty() {
        let servers_file = ServersFile::default();
        assert!(servers_file.servers.is_empty());
        assert!(servers_file.profiles.is_empty());
        assert_eq!(servers_file.selected_server_base_url, None);
    }

    #[test]
    fn missing_settings_field_falls_back_to_default_via_serde() {
        // Simulates an older settings.json written before a field existed.
        let decoded: Settings = serde_json::from_str("{}").expect("deserialize");
        assert_eq!(decoded, Settings::default());
    }

    #[test]
    fn log_line_to_appends_a_timestamped_line() {
        let path = std::env::temp_dir().join("cordiale-test-log-line-appends.log");
        let _ = fs::remove_file(&path);

        log_line_to(&path, "first line");
        log_line_to(&path, "second line");

        let contents = fs::read_to_string(&path).expect("read log file");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("] first line"));
        assert!(lines[1].ends_with("] second line"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn redact_secrets_masks_the_ws_bearer_subprotocol() {
        let message = "connect failed: base64url.bearer.phx.abcDEF123-_.xyz stuff";
        assert_eq!(
            redact_secrets(message),
            "connect failed: base64url.bearer.phx.[redacted] stuff"
        );
    }

    #[test]
    fn redact_secrets_masks_an_authorization_header() {
        assert_eq!(
            redact_secrets("sent Authorization: Bearer abc123.def456"),
            "sent Authorization: Bearer [redacted]"
        );
    }

    #[test]
    fn redact_secrets_masks_a_debug_derived_password_field() {
        let message = r#"LoginRequest { identifier: "vjt", password: "hunter2" }"#;
        assert_eq!(
            redact_secrets(message),
            r#"LoginRequest { identifier: "vjt", password: "[redacted]" }"#
        );
    }

    #[test]
    fn redact_secrets_masks_a_compact_json_token_field() {
        assert_eq!(
            redact_secrets(r#"{"token":"abc123","subject":{}}"#),
            r#"{"token":"[redacted]","subject":{}}"#
        );
    }

    #[test]
    fn redact_secrets_masks_a_query_string_secret() {
        assert_eq!(
            redact_secrets("GET /x?password=hunter2&next=1"),
            "GET /x?password=[redacted]&next=1"
        );
    }

    #[test]
    fn redact_secrets_leaves_an_unrelated_message_untouched() {
        let message = "connect succeeded: server=https://irc.sindro.me";
        assert_eq!(redact_secrets(message), message);
    }

    #[test]
    fn redact_secrets_masks_every_occurrence() {
        let message = "token=aaa retry token=bbb";
        assert_eq!(redact_secrets(message), "token=[redacted] retry token=[redacted]");
    }
}
