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

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::domain::{Profile, Server};
use crate::passkey_origin::{passkey_origin, OverrideCheck};

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
    /// Local display text scale, relative to Cordiale's default (50–150%).
    #[serde(default = "default_font_size_percent")]
    pub font_size_percent: u8,
    /// `(network, channel)` last selected before quitting or disconnecting
    /// — re-selected automatically on the next successful connect, so the
    /// app doesn't drop back to the bare network overview every time.
    #[serde(default)]
    pub last_channel: Option<(String, String)>,
    /// Sign in automatically at launch with the remembered profile. A
    /// manual disconnect turns it off (so another account can be used) and
    /// the next successful sign-in turns it back on.
    #[serde(default = "default_auto_connect")]
    pub auto_connect: bool,
    /// Color theme in use: `None` for the classic light/dark look,
    /// `"builtin:<name>"` for a built-in palette, `"server"` to follow the
    /// account's active theme on Grappa.
    #[serde(default)]
    pub color_theme: Option<String>,
    /// Radio stations the user added, next to the built-in ones. Kept on
    /// this device only, never sent to Grappa.
    #[serde(default)]
    pub radio_stations: Vec<CustomRadioStation>,
    /// Radio volume, 0 to 100.
    #[serde(default = "default_radio_volume")]
    pub radio_volume: u8,
}

/// A radio station added in Settings > Radio.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomRadioStation {
    pub name: String,
    /// The stream (or `.pls`/`.m3u` playlist) URL.
    pub url: String,
    /// `"mp3"`, `"vorbis"` or `"flac"`.
    pub codec: String,
}

fn default_radio_volume() -> u8 {
    80
}

fn default_font_size_percent() -> u8 {
    100
}

fn current_settings_schema_version() -> u32 {
    1
}

fn default_auto_connect() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            schema_version: current_settings_schema_version(),
            language: None,
            theme: Theme::default(),
            font_size_percent: default_font_size_percent(),
            last_channel: None,
            auto_connect: default_auto_connect(),
            color_theme: None,
            radio_stations: Vec::new(),
            radio_volume: default_radio_volume(),
        }
    }
}

impl Settings {
    /// Keep hand-edited or older settings within the supported UI range.
    pub fn effective_font_size_percent(&self) -> u8 {
        self.font_size_percent.clamp(50, 150)
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
    /// Per-server WebAuthn origin the user set because the server asserts
    /// another one than its URL (`GRAPPA_PASSKEY_ORIGIN`). Keyed by the
    /// origin rebuilt from the server URL, so `irc.example.com`,
    /// `https://irc.example.com/` and `https://IRC.example.com:443` share
    /// one entry. Local only, never sent to Grappa.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub passkey_origins: BTreeMap<String, String>,
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
            passkey_origins: BTreeMap::new(),
        }
    }
}

impl ServersFile {
    /// The passkey origin override saved for `server_url`, if any.
    pub fn passkey_origin_override(&self, server_url: &str) -> Option<&str> {
        self.passkey_origins
            .get(&passkey_origin(server_url, None))
            .map(String::as_str)
    }

    /// Saves (`Valid`) or clears (`Unset`) the override for `server_url`.
    /// An `Invalid` one changes nothing and returns false.
    pub fn set_passkey_origin_override(&mut self, server_url: &str, check: &OverrideCheck) -> bool {
        let key = passkey_origin(server_url, None);
        match check {
            OverrideCheck::Valid(origin) => {
                self.passkey_origins.insert(key, origin.clone());
                true
            }
            OverrideCheck::Unset => {
                self.passkey_origins.remove(&key);
                true
            }
            OverrideCheck::Invalid => false,
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

/// `config_dir()` as shown to the user and put in bug reports: the home
/// folder is written `~`, so the user name never appears.
pub fn config_dir_display() -> String {
    format!("~/{CONFIG_DIR_NAME}")
}

/// The log file's location, written like `config_dir_display()`.
pub fn log_file_display() -> String {
    format!("~/{CONFIG_DIR_NAME}/{LOG_FILE_NAME}")
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

/// The passkey origin override saved for `server_url`.
pub fn load_passkey_origin_override(server_url: &str) -> Option<String> {
    load_servers_file()
        .ok()?
        .passkey_origin_override(server_url)
        .map(str::to_string)
}

/// The origin to use for a passkey ceremony with `server_url`: its saved
/// override, else the one rebuilt from the URL.
pub fn effective_passkey_origin(server_url: &str) -> String {
    passkey_origin(
        server_url,
        load_passkey_origin_override(server_url).as_deref(),
    )
}

/// Saves or clears the passkey origin override for `server_url` (see
/// `ServersFile::set_passkey_origin_override`). Nothing is written for an
/// invalid one, or when the file already holds that value.
pub fn save_passkey_origin_override(
    server_url: &str,
    check: &OverrideCheck,
) -> Result<(), PersistenceError> {
    let mut file = load_servers_file()?;
    let before = file.passkey_origins.clone();
    if file.set_passkey_origin_override(server_url, check) && file.passkey_origins != before {
        save_servers_file(&file)?;
    }
    Ok(())
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

        let Some((_, value_start)) = literal_hit.chain(key_hit).min_by_key(|(pos, _)| *pos) else {
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
        assert_eq!(settings.font_size_percent, 100);
    }

    #[test]
    fn font_size_is_limited_to_half_and_one_and_a_half() {
        let mut settings = Settings {
            font_size_percent: 0,
            ..Settings::default()
        };
        assert_eq!(settings.effective_font_size_percent(), 50);
        settings.font_size_percent = 150;
        assert_eq!(settings.effective_font_size_percent(), 150);
        settings.font_size_percent = 255;
        assert_eq!(settings.effective_font_size_percent(), 150);
    }

    #[test]
    fn settings_without_auto_connect_default_to_signing_in() {
        let decoded: Settings =
            serde_json::from_str(r#"{"schema_version":1,"theme":"light"}"#).expect("deserialize");
        assert!(decoded.auto_connect);
        assert!(Settings::default().auto_connect);
        assert_eq!(decoded.font_size_percent, 100);
    }

    #[test]
    fn settings_round_trip_through_json_preserves_chosen_language() {
        let settings = Settings {
            schema_version: 1,
            language: Some(Language::It),
            theme: Theme::Dark,
            font_size_percent: 125,
            last_channel: Some(("libera".to_string(), "#rust".to_string())),
            auto_connect: false,
            color_theme: Some("builtin:sux".to_string()),
            radio_stations: vec![CustomRadioStation {
                name: "Local".to_string(),
                url: "https://radio.example/stream.ogg".to_string(),
                codec: "vorbis".to_string(),
            }],
            radio_volume: 55,
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
    fn passkey_origin_overrides_are_keyed_by_the_rebuilt_origin() {
        let mut file = ServersFile::default();
        let valid = OverrideCheck::Valid("http://localhost:5173".to_string());
        assert!(file.set_passkey_origin_override("irc.example.com", &valid));
        for spelling in [
            "irc.example.com",
            "https://irc.example.com/",
            "HTTPS://IRC.example.com:443",
            "https://irc.example.com/app",
        ] {
            assert_eq!(
                file.passkey_origin_override(spelling),
                Some("http://localhost:5173"),
                "{spelling}"
            );
        }
        assert_eq!(file.passkey_origin_override("https://other.example"), None);
        assert_eq!(
            file.passkey_origin_override("https://irc.example.com:8443"),
            None
        );
    }

    #[test]
    fn unset_clears_an_override_and_invalid_leaves_it_alone() {
        let mut file = ServersFile::default();
        let server = "https://irc.example.com";
        let valid = OverrideCheck::Valid("https://auth.example.com".to_string());
        assert!(file.set_passkey_origin_override(server, &valid));
        assert!(!file.set_passkey_origin_override(server, &OverrideCheck::Invalid));
        assert_eq!(
            file.passkey_origin_override(server),
            Some("https://auth.example.com")
        );
        assert!(file.set_passkey_origin_override(server, &OverrideCheck::Unset));
        assert_eq!(file.passkey_origin_override(server), None);
        assert!(file.passkey_origins.is_empty());
    }

    #[test]
    fn passkey_origin_overrides_round_trip_and_old_files_still_load() {
        let mut file = ServersFile::default();
        let valid = OverrideCheck::Valid("https://auth.example.com".to_string());
        file.set_passkey_origin_override("https://irc.example.com", &valid);
        let json = serde_json::to_string(&file).expect("serialize");
        let decoded: ServersFile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, file);

        let older: ServersFile = serde_json::from_str(r#"{"servers":[],"profiles":[]}"#)
            .expect("an older servers.json loads");
        assert!(older.passkey_origins.is_empty());
        let empty = serde_json::to_string(&older).expect("serialize");
        assert!(!empty.contains("passkey_origins"), "{empty}");
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
    fn displayed_locations_spell_the_home_folder_as_a_tilde() {
        assert_eq!(config_dir_display(), "~/.cordiale");
        assert_eq!(log_file_display(), "~/.cordiale/cordiale.log");
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
        assert_eq!(
            redact_secrets(message),
            "token=[redacted] retry token=[redacted]"
        );
    }
}
