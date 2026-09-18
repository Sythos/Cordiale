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
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::domain::{Profile, Server};

const CONFIG_DIR_NAME: &str = ".cordiale";
const SETTINGS_FILE_NAME: &str = "settings.json";
const SERVERS_FILE_NAME: &str = "servers.json";

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
}
