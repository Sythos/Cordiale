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

//! Local persistence in each platform's standard folders (see `Layout`).
//!
//! No `localStorage`, no single monolithic file: non-sensitive preferences
//! live in `settings.json`, servers/profiles/selection live in
//! `servers.json`. Actual credentials never land in either file — see
//! `CredentialStore` (Phase 1, item 3).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ban::BanType;
use crate::domain::{Profile, Server};
use crate::passkey_origin::{passkey_origin, OverrideCheck};
use crate::presence::PresencePref;

/// The folder every version before the standard-folders change used, in the
/// home directory.
const LEGACY_DIR_NAME: &str = ".cordiale";
const SETTINGS_FILE_NAME: &str = "settings.json";
const SERVERS_FILE_NAME: &str = "servers.json";
const LOG_FILE_NAME: &str = "cordiale.log";
/// The log is rotated once it passes this size; with the previous file kept
/// (`cordiale.log.1`) the two stay under about twice this.
const LOG_MAX_BYTES: u64 = 1024 * 1024;
/// The log's size is checked on the first write of a run, then once every
/// this many writes, not on every line.
const LOG_CHECK_EVERY: u64 = 50;
/// Appended to the log's name for the file rotation moves it to.
const PREVIOUS_LOG_SUFFIX: &str = ".1";

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
    /// Channels where the user chose to hide or show join/part/quit/nick/
    /// mode lines (Denoise), keyed like Grappa's `presence_filter`:
    /// `"<network> <channel>"`, the channel ASCII-lowercased. A channel
    /// without an entry follows its size.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub presence_pins: BTreeMap<String, PresencePref>,
    /// The keys of `presence_pins` whose upload to Grappa is not confirmed
    /// yet: sent again at the next sign-in instead of being overwritten by
    /// the server's older value.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub presence_unsynced: BTreeSet<String>,
    /// When the user muted a conversation from this device, as unix
    /// seconds, keyed like Grappa's `muted_targets`. Grappa keeps only the
    /// `until` of a mute and drops any other field, so the "muted at" time
    /// shown above the compose box lives here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mute_since: BTreeMap<String, i64>,
    /// Ban form used by `/kb` and `/kickban`. Kept on this device only:
    /// Grappa has no account-level field for it.
    #[serde(default)]
    pub default_ban_type: BanType,
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
            presence_pins: BTreeMap::new(),
            presence_unsynced: BTreeSet::new(),
            mute_since: BTreeMap::new(),
            default_ban_type: BanType::default(),
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

/// The platforms Cordiale picks standard folders for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Linux,
    Windows,
    MacOs,
}

impl Platform {
    fn current() -> Self {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        }
    }

    /// The name of Cordiale's folder inside each base folder, spelled the way
    /// the platform does it.
    fn app_folder(self) -> &'static str {
        match self {
            Platform::Linux => "cordiale",
            Platform::Windows | Platform::MacOs => "Cordiale",
        }
    }
}

/// The base folders the standard locations hang off. They come from the
/// system in `Bases::from_system`, and from a scratch folder in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Bases {
    home: PathBuf,
    /// Settings and servers: `$XDG_CONFIG_HOME` on Linux, `%APPDATA%` on
    /// Windows, `~/Library/Application Support` on macOS.
    config: PathBuf,
    /// Per-machine data that must not roam: `$XDG_DATA_HOME` on Linux,
    /// `%LOCALAPPDATA%` on Windows, `~/Library/Application Support` on macOS.
    data_local: PathBuf,
    /// `$XDG_STATE_HOME`; only Linux has one.
    state: Option<PathBuf>,
}

impl Bases {
    fn from_system() -> Option<Self> {
        Some(Bases {
            home: dirs::home_dir()?,
            config: dirs::config_dir()?,
            data_local: dirs::data_local_dir()?,
            state: dirs::state_dir(),
        })
    }
}

/// The three folders Cordiale writes to. This is the only place that decides
/// where they are.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Layout {
    /// `settings.json` and `servers.json`.
    config: PathBuf,
    /// The credentials fallback.
    data: PathBuf,
    /// `cordiale.log` and `cordiale.log.1`.
    log: PathBuf,
}

/// Which of the `Layout` folders a file belongs in.
#[derive(Debug, Clone, Copy)]
enum Place {
    Config,
    Data,
    Log,
}

impl Layout {
    /// The platform's standard folders:
    ///
    /// | | config | credentials fallback | log |
    /// |-|-|-|-|
    /// | Linux | `~/.config/cordiale` | `~/.local/share/cordiale` | `~/.local/state/cordiale` |
    /// | Windows | `%APPDATA%\Cordiale` | `%LOCALAPPDATA%\Cordiale` | `%LOCALAPPDATA%\Cordiale` |
    /// | macOS | `~/Library/Application Support/Cordiale` | same | `~/Library/Logs/Cordiale` |
    fn standard(platform: Platform, bases: &Bases) -> Self {
        let folder = platform.app_folder();
        let log_base = match platform {
            Platform::MacOs => bases.home.join("Library").join("Logs"),
            Platform::Linux | Platform::Windows => bases
                .state
                .clone()
                .unwrap_or_else(|| bases.data_local.clone()),
        };
        Layout {
            config: bases.config.join(folder),
            data: bases.data_local.join(folder),
            log: log_base.join(folder),
        }
    }

    /// Everything in one folder: the old `~/.cordiale`, still used when its
    /// files could not be moved.
    fn single(dir: PathBuf) -> Self {
        Layout {
            config: dir.clone(),
            data: dir.clone(),
            log: dir,
        }
    }

    fn dir(&self, place: Place) -> &Path {
        match place {
            Place::Config => &self.config,
            Place::Data => &self.data,
            Place::Log => &self.log,
        }
    }
}

/// What the old folder held that is worth moving, and where each file goes.
const MIGRATED_FILES: &[(&str, Place)] = &[
    (SETTINGS_FILE_NAME, Place::Config),
    (SERVERS_FILE_NAME, Place::Config),
    ("settings.json.corrupt", Place::Config),
    ("servers.json.corrupt", Place::Config),
    ("credentials.json", Place::Data),
    (LOG_FILE_NAME, Place::Log),
];

/// What `migrate_legacy` did.
#[derive(Debug, Default, PartialEq, Eq)]
struct MigrationSummary {
    /// Files written to their new place.
    copied: usize,
    /// Old files deleted after their copy was checked.
    removed: usize,
    /// Old files left where they were, because the new place already holds a
    /// different file of the same name.
    kept: usize,
}

impl MigrationSummary {
    /// The line for the log, or `None` when nothing happened.
    fn log_message(&self) -> Option<String> {
        (self.copied > 0 || self.removed > 0).then(|| {
            format!(
                "moved files from ~/{LEGACY_DIR_NAME} to the standard folders: {} copied, {} old copies removed, {} left in place",
                self.copied, self.removed, self.kept
            )
        })
    }
}

/// Moves what the old folder `old` holds into the folders of `target`. Every
/// file is copied and read back first; only when all of them are in place are
/// the old ones deleted, so a failure leaves `old` as it was (the copies made
/// in this run are removed again). It can be run again after a crash: a file
/// whose copy is already there and identical is just deleted from `old`, and
/// one that differs from the new place's file is left alone.
fn migrate_legacy(old: &Path, target: &Layout) -> Result<MigrationSummary, String> {
    let mut summary = MigrationSummary::default();
    let mut created = Vec::new();
    let mut verified = Vec::new();
    if let Err(reason) = copy_legacy_files(old, target, &mut summary, &mut created, &mut verified) {
        for path in &created {
            let _ = fs::remove_file(path);
        }
        return Err(reason);
    }
    for path in &verified {
        if fs::remove_file(path).is_ok() {
            summary.removed += 1;
        }
    }
    // Only goes through when nothing else is left in it.
    let _ = fs::remove_dir(old);
    Ok(summary)
}

/// First half of `migrate_legacy`. `created` gets the new files written and
/// `verified` the old files whose copy is known to be complete.
fn copy_legacy_files(
    old: &Path,
    target: &Layout,
    summary: &mut MigrationSummary,
    created: &mut Vec<PathBuf>,
    verified: &mut Vec<PathBuf>,
) -> Result<(), String> {
    for &(name, place) in MIGRATED_FILES {
        let from = old.join(name);
        let contents = match fs::read(&from) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("{name} could not be read: {err}")),
        };
        let dir = target.dir(place);
        let to = dir.join(name);
        match fs::read(&to) {
            Ok(existing) if existing == contents => verified.push(from),
            Ok(_) => summary.kept += 1,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                create_private_dir_all(dir)
                    .map_err(|err| format!("the folder for {name} could not be created: {err}"))?;
                write_atomic(&to, &contents)
                    .map_err(|err| format!("{name} could not be copied: {err}"))?;
                created.push(to.clone());
                match fs::read(&to) {
                    Ok(copy) if copy == contents => {}
                    Ok(_) => return Err(format!("the copy of {name} differs from the original")),
                    Err(err) => return Err(format!("the copy of {name} could not be read: {err}")),
                }
                summary.copied += 1;
                verified.push(from);
            }
            Err(err) => return Err(format!("{name} could not be checked: {err}")),
        }
    }
    Ok(())
}

/// Where the files are, decided once per run.
struct Storage {
    platform: Platform,
    bases: Bases,
    layout: Layout,
    /// The old `~/.cordiale`, read from when a file is missing in its new
    /// place; `None` when it is the folder in use.
    legacy: Option<PathBuf>,
    /// Shown on the Debug page when the old folder could not be moved.
    note: Option<String>,
}

impl Storage {
    fn log_file(&self) -> PathBuf {
        self.layout.log.join(LOG_FILE_NAME)
    }

    fn legacy_file(&self, name: &str) -> Option<PathBuf> {
        self.legacy.as_ref().map(|dir| dir.join(name))
    }

    fn display(&self, path: &Path) -> String {
        display_path(self.platform, &self.bases, path)
    }

    /// Every folder Cordiale keeps files in, each once, the old one included
    /// while it is around.
    #[cfg(unix)]
    fn dirs_to_tighten(&self) -> Vec<&Path> {
        let mut dirs: Vec<&Path> = Vec::new();
        let in_use = [
            self.layout.config.as_path(),
            self.layout.data.as_path(),
            self.layout.log.as_path(),
        ];
        for dir in in_use.into_iter().chain(self.legacy.as_deref()) {
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
        dirs
    }
}

/// Picks the folders to use and, when the old `~/.cordiale` exists, moves its
/// files into them. If that fails the old folder stays in use, so nothing
/// starts from scratch, and the reason is kept for the Debug page. The
/// outcome goes to the log (the one in the folders in use).
fn resolve(platform: Platform, bases: Bases) -> Storage {
    let mut layout = Layout::standard(platform, &bases);
    let old = bases.home.join(LEGACY_DIR_NAME);
    let mut legacy = None;
    let mut note = None;
    if old.is_dir() {
        match migrate_legacy(&old, &layout) {
            Ok(summary) => {
                if let Some(message) = summary.log_message() {
                    write_log_line(&layout.log.join(LOG_FILE_NAME), &message, None);
                }
                legacy = Some(old);
            }
            Err(reason) => {
                let shown = display_path(platform, &bases, &old);
                layout = Layout::single(old);
                write_log_line(
                    &layout.log.join(LOG_FILE_NAME),
                    &format!(
                        "could not move {shown} to the standard folders: {reason}; still using it"
                    ),
                    None,
                );
                note = Some(format!(
                    "Could not move {shown} to the standard folders ({reason}); Cordiale keeps using it."
                ));
            }
        }
    }
    Storage {
        platform,
        bases,
        layout,
        legacy,
        note,
    }
}

/// The folders in use. The first call settles them (and may move the old
/// folder's files), so it must not log through `log_line`.
fn storage() -> Option<&'static Storage> {
    static STORAGE: OnceLock<Option<Storage>> = OnceLock::new();
    STORAGE
        .get_or_init(|| Bases::from_system().map(|bases| resolve(Platform::current(), bases)))
        .as_ref()
}

/// `path` as shown to the user and put in bug reports: the home folder is
/// written `~` (and `%APPDATA%`, `%LOCALAPPDATA%` on Windows), so the user
/// name never appears. A path outside all of them is shown as it is.
fn display_path(platform: Platform, bases: &Bases, path: &Path) -> String {
    if platform == Platform::Windows {
        let windows_bases = [
            ("%APPDATA%", &bases.config),
            ("%LOCALAPPDATA%", &bases.data_local),
        ];
        for (name, base) in windows_bases {
            if let Some(shown) = shown_under(name, "\\", base, path) {
                return shown;
            }
        }
    }
    shown_under("~", "/", &bases.home, path).unwrap_or_else(|| path.display().to_string())
}

/// `path` with `base` replaced by `name`, parts joined by `separator`.
fn shown_under(name: &str, separator: &str, base: &Path, path: &Path) -> Option<String> {
    let rest = path.strip_prefix(base).ok()?;
    let mut shown = name.to_string();
    for part in rest.components() {
        shown.push_str(separator);
        shown.push_str(&part.as_os_str().to_string_lossy());
    }
    Some(shown)
}

/// Where `settings.json` and `servers.json` live: Cordiale's config folder.
pub fn config_dir() -> Option<PathBuf> {
    storage().map(|storage| storage.layout.config.clone())
}

/// Where the credentials fallback lives: a folder that never roams.
pub(crate) fn data_dir() -> Option<PathBuf> {
    storage().map(|storage| storage.layout.data.clone())
}

/// `name` in the old `~/.cordiale`, when that is not the folder in use.
pub(crate) fn legacy_file(name: &str) -> Option<PathBuf> {
    storage()?.legacy_file(name)
}

/// The file to read: `primary`, or `fallback` (the same file in the old
/// folder) when only that one exists.
pub(crate) fn read_path(primary: &Path, fallback: Option<&Path>) -> PathBuf {
    match fallback {
        Some(old) if !primary.exists() && old.exists() => old.to_path_buf(),
        _ => primary.to_path_buf(),
    }
}

/// `config_dir()` as shown to the user and put in bug reports.
pub fn config_dir_display() -> String {
    storage()
        .map(|storage| storage.display(&storage.layout.config))
        .unwrap_or_default()
}

/// The log file's location, written like `config_dir_display()`.
pub fn log_file_display() -> String {
    storage()
        .map(|storage| storage.display(&storage.log_file()))
        .unwrap_or_default()
}

/// The previous log (`cordiale.log.1`), written like `log_file_display()`.
pub fn previous_log_file_display() -> String {
    storage()
        .map(|storage| {
            storage.display(&sibling_with_suffix(
                &storage.log_file(),
                PREVIOUS_LOG_SUFFIX,
            ))
        })
        .unwrap_or_default()
}

/// A problem with where the files are kept, for the Debug page: the old
/// folder could not be moved and is still in use.
pub fn storage_note() -> Option<String> {
    storage()?.note.clone()
}

/// Creates `dir` and its missing parents. On Unix the new directories are
/// private (0700); on Windows they inherit the user profile's ACLs.
pub(crate) fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(dir)
}

/// A sibling of `path` that no other writer, thread or process uses.
fn temp_path_for(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(".{name}.{}-{serial}.tmp", std::process::id()))
}

/// Writes `contents` to a new file at `path` (0600 on Unix) and flushes it to
/// disk.
fn write_synced(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn rename_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

/// Replaces the file at `path` with `contents` all at once: a reader, or a
/// crash, sees the old file or the new one, never a half-written one. The
/// data goes to a temp file in the same directory (so the rename stays on one
/// filesystem), is synced, then renamed over the target; on any failure the
/// target is left as it was and the temp file is removed. On Unix the result
/// is private (0600), also when the target already existed with another mode.
pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    write_atomic_with(path, contents, rename_file)
}

fn write_atomic_with(
    path: &Path,
    contents: &[u8],
    rename: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    let temp = temp_path_for(path);
    let result = write_synced(&temp, contents).and_then(|()| rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Settles where the files live (moving an old `~/.cordiale` folder's files
/// to the standard folders, see `migrate_legacy`) and, on Unix, tightens what
/// an older version created with the default umask: each folder to 0700 and
/// the files in it to 0600. Best-effort, like every other write here: a
/// failure is logged and never stops the app. Nothing to tighten on Windows,
/// where the folders inherit the user profile's ACLs.
#[cfg(unix)]
pub fn init_storage() {
    let Some(storage) = storage() else {
        return;
    };
    for dir in storage.dirs_to_tighten() {
        for failure in tighten_permissions_in(dir) {
            log_line(&failure);
        }
    }
}

#[cfg(not(unix))]
pub fn init_storage() {
    let _ = storage();
}

/// Sets `dir` to 0700 and each regular file directly in it to 0600 (links
/// are not followed). Returns one message per failure, without file contents.
#[cfg(unix)]
fn tighten_permissions_in(dir: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return failures,
        Err(err) => {
            failures.push(format!("a folder was not tightened: {err}"));
            return failures;
        }
    };
    if let Err(err) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
        failures.push(format!("a folder was not tightened: {err}"));
    }
    for entry in entries.flatten() {
        let is_file = entry.file_type().is_ok_and(|kind| kind.is_file());
        if !is_file {
            continue;
        }
        if let Err(err) = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600)) {
            failures.push(format!(
                "{} not tightened: {err}",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    failures
}

fn load_json_from<T: Default + for<'de> Deserialize<'de>>(
    path: &Path,
) -> Result<T, PersistenceError> {
    if !path.exists() {
        return Ok(T::default());
    }

    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

/// `path` with `suffix` added to the file name, in the same folder.
fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// Moves a file that no longer parses aside as `<name>.corrupt` (replacing an
/// older one), so the default the callers fall back to is not saved over the
/// only copy of the user's settings or servers.
fn quarantine_corrupt(path: &Path) -> io::Result<PathBuf> {
    let kept = sibling_with_suffix(path, ".corrupt");
    fs::rename(path, &kept)?;
    Ok(kept)
}

/// Reads a config file, from the old `~/.cordiale` when it is missing in the
/// config folder (a downgrade or a half-finished move must not look like a
/// fresh start). When it can't be parsed it is set aside with
/// `quarantine_corrupt` and the error is returned; the next load then finds
/// no file and yields the default.
fn load_json<T: Default + for<'de> Deserialize<'de>>(
    file_name: &str,
) -> Result<T, PersistenceError> {
    let dir = config_dir().ok_or(PersistenceError::NoConfigDir)?;
    let path = read_path(&dir.join(file_name), legacy_file(file_name).as_deref());

    let result = load_json_from(&path);
    if let Err(PersistenceError::Json(err)) = &result {
        // Only where the parse failed: the message could quote the content.
        let (line, column) = (err.line(), err.column());
        match quarantine_corrupt(&path) {
            Ok(_) => log_line(&format!(
                "{file_name} is not valid JSON (line {line}, column {column}), kept as {file_name}.corrupt"
            )),
            Err(io_err) => log_line(&format!(
                "{file_name} is not valid JSON (line {line}, column {column}) and could not be set aside: {io_err}"
            )),
        }
    }
    result
}

fn save_json<T: Serialize>(file_name: &str, value: &T) -> Result<(), PersistenceError> {
    let dir = config_dir().ok_or(PersistenceError::NoConfigDir)?;
    create_private_dir_all(&dir)?;
    let contents = serde_json::to_string_pretty(value)?;
    write_atomic(&dir.join(file_name), contents.as_bytes())?;
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

/// Appends one line to `cordiale.log` in the log folder, prefixed with a Unix
/// timestamp — a plain-text trail a field tester can attach to a bug
/// report. The log is bounded: past `LOG_MAX_BYTES` it moves to
/// `cordiale.log.1` (replacing the previous one) and a new one starts.
/// Best-effort like every other write in this module: a failure here is
/// silently swallowed rather than surfaced, since diagnostics must never be
/// the reason the app itself breaks.
pub fn log_line(message: &str) {
    if let Some(storage) = storage() {
        log_line_to(&storage.log_file(), message);
    }
}

fn log_line_to(path: &Path, message: &str) {
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let check_size = size_check_due(WRITES.fetch_add(1, Ordering::Relaxed));
    write_log_line(path, message, check_size.then_some(LOG_MAX_BYTES));
}

/// Whether the write numbered `writes_before` (from 0 in each run) checks the
/// log's size: the first one, then every `LOG_CHECK_EVERY`.
fn size_check_due(writes_before: u64) -> bool {
    writes_before.is_multiple_of(LOG_CHECK_EVERY)
}

/// Writes the line, first rotating the log when `rotate_over` is a size it
/// has grown past.
fn write_log_line(path: &Path, message: &str, rotate_over: Option<u64>) {
    if let Some(parent) = path.parent() {
        if create_private_dir_all(parent).is_err() {
            return;
        }
    }
    if let Some(max_bytes) = rotate_over {
        rotate_log_if_over(path, max_bytes);
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let Ok(mut file) = options.open(path) else {
        return;
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let message = redact_secrets(message);
    let _ = writeln!(file, "[{timestamp}] {message}");
}

/// Moves the log to `<name>.1`, replacing the previous one, when it is bigger
/// than `max_bytes`. The next write starts a new file.
fn rotate_log_if_over(path: &Path, max_bytes: u64) {
    let too_big = fs::metadata(path).is_ok_and(|meta| meta.len() > max_bytes);
    if too_big {
        let _ = fs::rename(path, sibling_with_suffix(path, PREVIOUS_LOG_SUFFIX));
    }
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
            presence_pins: BTreeMap::from([("libera #rust".to_string(), PresencePref::Hide)]),
            presence_unsynced: BTreeSet::from(["libera #rust".to_string()]),
            mute_since: BTreeMap::from([("libera #rust".to_string(), 1_700_000_000)]),
            default_ban_type: BanType::UserHost,
        };

        let json = serde_json::to_string(&settings).expect("serialize");
        let decoded: Settings = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(settings, decoded);
    }

    #[test]
    fn settings_without_denoise_choices_default_to_none() {
        let decoded: Settings =
            serde_json::from_str(r#"{"schema_version":1,"theme":"light"}"#).expect("deserialize");
        assert!(decoded.presence_pins.is_empty());
        assert!(decoded.presence_unsynced.is_empty());
        let json = serde_json::to_value(Settings::default()).expect("serialize");
        assert!(json.get("presence_pins").is_none());
    }

    #[test]
    fn settings_without_a_ban_type_default_to_host() {
        let decoded: Settings =
            serde_json::from_str(r#"{"schema_version":1,"theme":"light"}"#).expect("deserialize");
        assert_eq!(decoded.default_ban_type, BanType::Host);
        let decoded: Settings =
            serde_json::from_str(r#"{"default_ban_type":"user_host"}"#).expect("deserialize");
        assert_eq!(decoded.default_ban_type, BanType::UserHost);
    }

    #[test]
    fn settings_without_mute_times_default_to_none() {
        let decoded: Settings =
            serde_json::from_str(r#"{"schema_version":1,"theme":"light"}"#).expect("deserialize");
        assert!(decoded.mute_since.is_empty());
        let json = serde_json::to_value(Settings::default()).expect("serialize");
        assert!(json.get("mute_since").is_none());
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

    /// An empty, uniquely named folder under the system temp dir.
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cordiale-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn write_atomic_creates_then_replaces_a_file_without_leftovers() {
        let dir = scratch_dir("atomic-replace");
        let path = dir.join("settings.json");

        write_atomic(&path, b"one").expect("first write");
        assert_eq!(fs::read_to_string(&path).expect("read"), "one");
        write_atomic(&path, b"two").expect("second write");
        assert_eq!(fs::read_to_string(&path).expect("read"), "two");
        assert_eq!(entry_names(&dir), ["settings.json"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_keeps_the_old_file_when_the_rename_fails() {
        let dir = scratch_dir("atomic-rename-fails");
        let path = dir.join("servers.json");
        fs::write(&path, "old").expect("seed file");

        let result = write_atomic_with(&path, b"new", |_, _| {
            Err(io::Error::other("rename refused"))
        });

        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).expect("read"), "old");
        assert_eq!(entry_names(&dir), ["servers.json"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_removes_its_temp_file_when_the_target_cannot_be_replaced() {
        let dir = scratch_dir("atomic-target-is-dir");
        let path = dir.join("settings.json");
        fs::create_dir(&path).expect("directory in the way");

        assert!(write_atomic(&path, b"data").is_err());
        assert!(path.is_dir());
        assert_eq!(entry_names(&dir), ["settings.json"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_makes_the_file_private_even_over_a_looser_one() {
        let dir = scratch_dir("atomic-mode");
        let path = dir.join("credentials.json");
        fs::write(&path, "old").expect("seed file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");

        write_atomic(&path, b"new").expect("write");

        assert_eq!(mode_of(&path), 0o600);
        let fresh = dir.join("fresh.json");
        write_atomic(&fresh, b"data").expect("write new file");
        assert_eq!(mode_of(&fresh), 0o600);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn create_private_dir_all_makes_every_new_level_private() {
        let dir = scratch_dir("private-dir");
        let nested = dir.join("a").join("b");

        create_private_dir_all(&nested).expect("create");
        create_private_dir_all(&nested).expect("create again");

        assert_eq!(mode_of(&dir.join("a")), 0o700);
        assert_eq!(mode_of(&nested), 0o700);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn log_line_to_creates_a_private_log_file() {
        let dir = scratch_dir("private-log");
        let path = dir.join("cordiale.log");

        log_line_to(&path, "hello");

        assert_eq!(mode_of(&path), 0o600);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn tighten_permissions_in_fixes_an_existing_folder_and_its_files() {
        let dir = scratch_dir("tighten");
        let file = dir.join("credentials.json");
        fs::write(&file, "{}").expect("seed file");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("loosen file");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("loosen dir");

        let failures = tighten_permissions_in(&dir);

        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(mode_of(&dir), 0o700);
        assert_eq!(mode_of(&file), 0o600);
        assert!(tighten_permissions_in(&dir.join("missing")).is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_file_is_set_aside_instead_of_being_lost() {
        let dir = scratch_dir("corrupt");
        let path = dir.join("settings.json");
        fs::write(&path, "{\"theme\": \"da").expect("seed a truncated file");

        assert!(matches!(
            load_json_from::<Settings>(&path),
            Err(PersistenceError::Json(_))
        ));
        let kept = quarantine_corrupt(&path).expect("set aside");

        assert_eq!(kept, dir.join("settings.json.corrupt"));
        assert_eq!(fs::read_to_string(&kept).expect("read"), "{\"theme\": \"da");
        assert_eq!(
            load_json_from::<Settings>(&path).expect("default"),
            Settings::default()
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Base folders shaped like Linux's, under a fake home that is never touched.
    fn linux_bases() -> Bases {
        Bases {
            home: PathBuf::from("/home/alice"),
            config: PathBuf::from("/home/alice/.config"),
            data_local: PathBuf::from("/home/alice/.local/share"),
            state: Some(PathBuf::from("/home/alice/.local/state")),
        }
    }

    fn windows_bases() -> Bases {
        Bases {
            home: PathBuf::from("/home/alice"),
            config: PathBuf::from("/home/alice/AppData/Roaming"),
            data_local: PathBuf::from("/home/alice/AppData/Local"),
            state: None,
        }
    }

    fn macos_bases() -> Bases {
        Bases {
            home: PathBuf::from("/home/alice"),
            config: PathBuf::from("/home/alice/Library/Application Support"),
            data_local: PathBuf::from("/home/alice/Library/Application Support"),
            state: None,
        }
    }

    #[test]
    fn linux_keeps_config_data_and_state_apart_in_lowercase_folders() {
        let layout = Layout::standard(Platform::Linux, &linux_bases());
        assert_eq!(layout.config, PathBuf::from("/home/alice/.config/cordiale"));
        assert_eq!(
            layout.data,
            PathBuf::from("/home/alice/.local/share/cordiale")
        );
        assert_eq!(
            layout.log,
            PathBuf::from("/home/alice/.local/state/cordiale")
        );
    }

    #[test]
    fn linux_follows_the_xdg_overrides_it_is_given() {
        let bases = Bases {
            home: PathBuf::from("/home/alice"),
            config: PathBuf::from("/srv/cfg"),
            data_local: PathBuf::from("/srv/data"),
            state: Some(PathBuf::from("/srv/state")),
        };
        let layout = Layout::standard(Platform::Linux, &bases);
        assert_eq!(layout.config, PathBuf::from("/srv/cfg/cordiale"));
        assert_eq!(layout.data, PathBuf::from("/srv/data/cordiale"));
        assert_eq!(layout.log, PathBuf::from("/srv/state/cordiale"));
        // Outside the home folder there is nothing to abbreviate.
        assert_eq!(
            display_path(Platform::Linux, &bases, &layout.config),
            layout.config.display().to_string()
        );
    }

    #[test]
    fn windows_puts_the_credentials_and_the_log_in_the_local_folder() {
        let layout = Layout::standard(Platform::Windows, &windows_bases());
        assert_eq!(
            layout.config,
            PathBuf::from("/home/alice/AppData/Roaming/Cordiale")
        );
        assert_eq!(
            layout.data,
            PathBuf::from("/home/alice/AppData/Local/Cordiale")
        );
        assert_eq!(layout.log, layout.data);
    }

    #[test]
    fn macos_logs_go_to_library_logs() {
        let layout = Layout::standard(Platform::MacOs, &macos_bases());
        let support = PathBuf::from("/home/alice/Library/Application Support/Cordiale");
        assert_eq!(layout.config, support);
        assert_eq!(layout.data, support);
        assert_eq!(
            layout.log,
            PathBuf::from("/home/alice/Library/Logs/Cordiale")
        );
    }

    #[test]
    fn displayed_locations_hide_the_user_name_on_every_platform() {
        let cases = [
            (
                Platform::Linux,
                linux_bases(),
                "~/.config/cordiale",
                "~/.local/state/cordiale/cordiale.log",
            ),
            (
                Platform::Windows,
                windows_bases(),
                "%APPDATA%\\Cordiale",
                "%LOCALAPPDATA%\\Cordiale\\cordiale.log",
            ),
            (
                Platform::MacOs,
                macos_bases(),
                "~/Library/Application Support/Cordiale",
                "~/Library/Logs/Cordiale/cordiale.log",
            ),
        ];
        for (platform, bases, config, log) in cases {
            let layout = Layout::standard(platform, &bases);
            let shown_config = display_path(platform, &bases, &layout.config);
            let shown_log = display_path(platform, &bases, &layout.log.join(LOG_FILE_NAME));
            assert_eq!(shown_config, config);
            assert_eq!(shown_log, log);
            assert!(!shown_config.contains("alice") && !shown_log.contains("alice"));
        }
    }

    #[test]
    fn the_old_folder_is_still_written_with_a_tilde() {
        let bases = windows_bases();
        let old = bases.home.join(LEGACY_DIR_NAME).join(LOG_FILE_NAME);
        assert_eq!(
            display_path(Platform::Windows, &bases, &old),
            "~/.cordiale/cordiale.log"
        );
    }

    /// A scratch home with an old `.cordiale` folder in it, and Linux-style
    /// bases hanging off that home. Returns the scratch root to clean up.
    fn scratch_home(name: &str) -> (PathBuf, Bases) {
        let root = scratch_dir(name);
        let home = root.join("home");
        let bases = Bases {
            home: home.clone(),
            config: home.join(".config"),
            data_local: home.join(".local").join("share"),
            state: Some(home.join(".local").join("state")),
        };
        fs::create_dir_all(home.join(LEGACY_DIR_NAME)).expect("create old folder");
        (root, bases)
    }

    fn write_files(dir: &Path, files: &[(&str, &str)]) {
        fs::create_dir_all(dir).expect("create folder");
        for (name, body) in files {
            fs::write(dir.join(name), body).expect("write file");
        }
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).expect("read file")
    }

    #[test]
    fn the_old_folder_moves_to_the_standard_folders() {
        let (root, bases) = scratch_home("migrate-clean");
        let old = bases.home.join(LEGACY_DIR_NAME);
        write_files(
            &old,
            &[
                ("settings.json", r#"{"theme":"dark"}"#),
                ("servers.json", r#"{"servers":[]}"#),
                ("credentials.json", "{}"),
                ("cordiale.log", "[1] an old line\n"),
            ],
        );

        let storage = resolve(Platform::Linux, bases.clone());

        let standard = Layout::standard(Platform::Linux, &bases);
        assert_eq!(storage.layout, standard);
        assert_eq!(storage.note, None);
        assert_eq!(
            read(&standard.config.join("settings.json")),
            r#"{"theme":"dark"}"#
        );
        assert_eq!(
            read(&standard.config.join("servers.json")),
            r#"{"servers":[]}"#
        );
        assert_eq!(read(&standard.data.join("credentials.json")), "{}");
        let log = read(&standard.log.join(LOG_FILE_NAME));
        assert!(log.contains("an old line"), "{log}");
        assert!(log.contains("moved files from ~/.cordiale"), "{log}");
        assert!(!old.exists(), "the emptied old folder is removed");
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&standard.config), 0o700);
            assert_eq!(mode_of(&standard.config.join("settings.json")), 0o600);
            assert_eq!(mode_of(&standard.data.join("credentials.json")), 0o600);
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_half_finished_move_is_completed() {
        let (root, bases) = scratch_home("migrate-half");
        let old = bases.home.join(LEGACY_DIR_NAME);
        let standard = Layout::standard(Platform::Linux, &bases);
        write_files(&old, &[("settings.json", "S"), ("servers.json", "V")]);
        // An earlier run got as far as copying the settings.
        write_files(&standard.config, &[("settings.json", "S")]);

        let storage = resolve(Platform::Linux, bases);

        assert_eq!(storage.layout, standard);
        assert_eq!(read(&standard.config.join("settings.json")), "S");
        assert_eq!(read(&standard.config.join("servers.json")), "V");
        assert!(!old.exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_newer_file_in_the_new_folder_is_never_overwritten() {
        let (root, bases) = scratch_home("migrate-newer");
        let old = bases.home.join(LEGACY_DIR_NAME);
        let standard = Layout::standard(Platform::Linux, &bases);
        write_files(&old, &[("settings.json", "older"), ("servers.json", "V")]);
        write_files(&standard.config, &[("settings.json", "newer")]);

        let storage = resolve(Platform::Linux, bases);

        assert_eq!(storage.layout, standard);
        assert_eq!(read(&standard.config.join("settings.json")), "newer");
        assert_eq!(read(&standard.config.join("servers.json")), "V");
        assert_eq!(read(&old.join("settings.json")), "older");
        assert!(!old.join("servers.json").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_move_keeps_the_old_folder_in_use_and_undoes_its_copies() {
        let (root, bases) = scratch_home("migrate-fails");
        let old = bases.home.join(LEGACY_DIR_NAME);
        write_files(
            &old,
            &[("settings.json", "S"), ("credentials.json", "secret")],
        );
        // A file where the credentials folder has to go: that copy fails
        // after the settings were already copied.
        write_files(&bases.data_local, &[("cordiale", "in the way")]);

        let storage = resolve(Platform::Linux, bases.clone());

        assert_eq!(storage.layout, Layout::single(old.clone()));
        assert_eq!(storage.legacy, None);
        let note = storage.note.expect("the Debug page is told");
        assert!(note.contains("~/.cordiale"), "{note}");
        assert!(note.contains("keeps using it"), "{note}");
        assert_eq!(read(&old.join("settings.json")), "S");
        assert_eq!(read(&old.join("credentials.json")), "secret");
        let standard = Layout::standard(Platform::Linux, &bases);
        assert!(!standard.config.join("settings.json").exists());
        assert!(read(&old.join(LOG_FILE_NAME)).contains("could not move"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nothing_to_move_changes_nothing() {
        let (root, bases) = scratch_home("migrate-nothing");
        let standard = Layout::standard(Platform::Linux, &bases);

        let storage = resolve(Platform::Linux, bases);

        assert_eq!(storage.layout, standard);
        assert_eq!(storage.note, None);
        assert!(!standard.config.exists());
        assert_eq!(MigrationSummary::default().log_message(), None);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_missing_in_the_new_folder_is_read_from_the_old_one() {
        let dir = scratch_dir("read-fallback");
        let new = dir.join("new.json");
        let old = dir.join("old.json");
        fs::write(&old, "old").expect("seed old file");

        assert_eq!(read_path(&new, Some(&old)), old);
        assert_eq!(read_path(&new, None), new);
        fs::write(&new, "new").expect("seed new file");
        assert_eq!(read_path(&new, Some(&old)), new);
        fs::remove_file(&old).expect("remove old file");
        assert_eq!(read_path(&new, Some(&old)), new);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_moves_a_log_past_the_limit_and_replaces_the_previous_one() {
        let dir = scratch_dir("log-rotate");
        let log = dir.join("cordiale.log");
        let previous = dir.join("cordiale.log.1");
        fs::write(&previous, "ancient").expect("seed previous log");
        fs::write(&log, "0123456789").expect("seed log");

        rotate_log_if_over(&log, 10);
        assert_eq!(read(&log), "0123456789", "at the limit is not past it");
        assert_eq!(read(&previous), "ancient");

        rotate_log_if_over(&log, 9);
        assert!(!log.exists());
        assert_eq!(read(&previous), "0123456789");
        rotate_log_if_over(&log, 9);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_log_stays_bounded_and_keeps_the_newest_lines() {
        let dir = scratch_dir("log-bounded");
        let log = dir.join("cordiale.log");
        let previous = dir.join("cordiale.log.1");

        for index in 0..40 {
            write_log_line(&log, &format!("line {index:02}"), Some(100));
        }

        let (current, before) = (read(&log), read(&previous));
        assert!(current.contains("line 39"), "{current}");
        assert!(!format!("{before}{current}").contains("line 00"));
        for contents in [&current, &before] {
            // The limit plus the one line that tipped it over.
            assert!(contents.len() <= 100 + 30, "{}", contents.len());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_write_that_does_not_check_the_size_never_rotates() {
        let dir = scratch_dir("log-unchecked");
        let log = dir.join("cordiale.log");
        fs::write(&log, "x".repeat(500)).expect("seed log");

        write_log_line(&log, "one more", None);

        assert!(!dir.join("cordiale.log.1").exists());
        assert!(read(&log).ends_with("one more\n"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_size_is_checked_first_and_then_once_every_so_many_writes() {
        assert!(size_check_due(0));
        assert!(!size_check_due(1));
        assert!(!size_check_due(LOG_CHECK_EVERY - 1));
        assert!(size_check_due(LOG_CHECK_EVERY));
        assert!(!size_check_due(LOG_CHECK_EVERY + 1));
    }

    #[cfg(unix)]
    #[test]
    fn a_rotated_log_and_its_replacement_are_both_private() {
        let dir = scratch_dir("log-rotate-private");
        let log = dir.join("cordiale.log");

        write_log_line(&log, "first", Some(1));
        write_log_line(&log, "second", Some(1));

        assert_eq!(mode_of(&log), 0o600);
        assert_eq!(mode_of(&dir.join("cordiale.log.1")), 0o600);

        let _ = fs::remove_dir_all(&dir);
    }
}
