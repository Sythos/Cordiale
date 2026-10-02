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

//! Credential storage: native OS keychains via the `keyring` crate, with an
//! explicitly insecure fallback for environments where no native backend is
//! reachable (see [`ObfuscatedCredentialStore`]).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::persistence::{create_private_dir_all, data_dir, legacy_file, read_path, write_atomic};

const CREDENTIALS_FILE_NAME: &str = "credentials.json";
const PROBE_SERVICE: &str = "cordiale-probe";
const PROBE_USERNAME: &str = "cordiale-probe";

#[derive(Debug)]
pub enum CredentialError {
    /// The native backend (or the fallback's own I/O) reported a failure.
    Backend(String),
    NoConfigDir,
    Io(io::Error),
    Json(serde_json::Error),
}

impl From<io::Error> for CredentialError {
    fn from(err: io::Error) -> Self {
        CredentialError::Io(err)
    }
}

impl From<serde_json::Error> for CredentialError {
    fn from(err: serde_json::Error) -> Self {
        CredentialError::Json(err)
    }
}

/// Stores and retrieves secrets keyed by `(service, username)`.
///
/// Cordiale uses a server's `base_url` as `service` and a profile's
/// `identifier` as `username`. A missing entry is `Ok(None)` from
/// `get_secret`, never an error; deleting a missing entry is also `Ok(())`.
pub trait CredentialStore {
    fn set_secret(
        &self,
        service: &str,
        username: &str,
        secret: &str,
    ) -> Result<(), CredentialError>;
    fn get_secret(&self, service: &str, username: &str) -> Result<Option<String>, CredentialError>;
    fn delete_secret(&self, service: &str, username: &str) -> Result<(), CredentialError>;
}

/// Native backend: Windows Credential Manager (DPAPI) or Linux Secret
/// Service, via `keyring::v1::Entry`.
pub struct KeyringCredentialStore;

impl KeyringCredentialStore {
    fn entry(service: &str, username: &str) -> Result<keyring::v1::Entry, CredentialError> {
        keyring::v1::Entry::new(service, username)
            .map_err(|err| CredentialError::Backend(err.to_string()))
    }

    /// Whether a native backend is actually reachable on this machine.
    ///
    /// `NoEntry` still counts as "available": the backend answered, it just
    /// found nothing for a throwaway probe key that is never written.
    /// Anything else (`NoStorageAccess`, `PlatformFailure`, ...) means there
    /// is no usable native backend here — e.g. a headless Linux CI runner
    /// with no Secret Service daemon on the session bus — and callers
    /// should use the fallback instead.
    pub fn is_available() -> bool {
        match keyring::v1::Entry::new(PROBE_SERVICE, PROBE_USERNAME) {
            Ok(entry) => matches!(
                entry.get_password(),
                Ok(_) | Err(keyring::v1::Error::NoEntry)
            ),
            Err(_) => false,
        }
    }
}

impl CredentialStore for KeyringCredentialStore {
    fn set_secret(
        &self,
        service: &str,
        username: &str,
        secret: &str,
    ) -> Result<(), CredentialError> {
        Self::entry(service, username)?
            .set_password(secret)
            .map_err(|err| CredentialError::Backend(err.to_string()))
    }

    fn get_secret(&self, service: &str, username: &str) -> Result<Option<String>, CredentialError> {
        match Self::entry(service, username)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::v1::Error::NoEntry) => Ok(None),
            Err(err) => Err(CredentialError::Backend(err.to_string())),
        }
    }

    fn delete_secret(&self, service: &str, username: &str) -> Result<(), CredentialError> {
        match Self::entry(service, username)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::v1::Error::NoEntry) => Ok(()),
            Err(err) => Err(CredentialError::Backend(err.to_string())),
        }
    }
}

/// Fallback used only when no native backend is reachable.
///
/// This is **not** real security: it obfuscates secrets with a fixed,
/// publicly-known XOR pattern purely to avoid storing them as plain
/// readable text, protecting against nothing beyond a casual glance.
/// Anyone with read access to `credentials.json` and the Cordiale source
/// can recover every secret. Stored separately from `settings.json`, in the
/// local data folder (never a roaming one), in a file only its owner can read
/// (Unix) and replaced atomically on every save.
pub struct ObfuscatedCredentialStore {
    file_path: PathBuf,
    /// The same file in the old `~/.cordiale`, read when the new one is
    /// missing.
    fallback_path: Option<PathBuf>,
}

type ObfuscatedMap = HashMap<String, Vec<u8>>;

const OBFUSCATION_PATTERN: &[u8] = b"cordiale-non-secret-obfuscation-pattern";

fn credential_key(service: &str, username: &str) -> String {
    format!("{service}\u{0}{username}")
}

fn obfuscate(secret: &str) -> Vec<u8> {
    secret
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ OBFUSCATION_PATTERN[i % OBFUSCATION_PATTERN.len()])
        .collect()
}

fn deobfuscate(bytes: &[u8]) -> Result<String, CredentialError> {
    let plain: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ OBFUSCATION_PATTERN[i % OBFUSCATION_PATTERN.len()])
        .collect();
    String::from_utf8(plain)
        .map_err(|_| CredentialError::Backend("corrupted fallback credential".to_string()))
}

impl ObfuscatedCredentialStore {
    pub fn new() -> Result<Self, CredentialError> {
        let dir = data_dir().ok_or(CredentialError::NoConfigDir)?;
        Ok(ObfuscatedCredentialStore {
            file_path: dir.join(CREDENTIALS_FILE_NAME),
            fallback_path: legacy_file(CREDENTIALS_FILE_NAME),
        })
    }

    #[cfg(test)]
    fn with_file_path(file_path: PathBuf) -> Self {
        ObfuscatedCredentialStore {
            file_path,
            fallback_path: None,
        }
    }

    fn load(&self) -> Result<ObfuscatedMap, CredentialError> {
        let path = read_path(&self.file_path, self.fallback_path.as_deref());
        if !path.exists() {
            return Ok(ObfuscatedMap::new());
        }
        let contents = fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&contents)?)
    }

    fn save(&self, map: &ObfuscatedMap) -> Result<(), CredentialError> {
        if let Some(parent) = self.file_path.parent() {
            create_private_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(map)?;
        write_atomic(&self.file_path, contents.as_bytes())?;
        Ok(())
    }
}

impl CredentialStore for ObfuscatedCredentialStore {
    fn set_secret(
        &self,
        service: &str,
        username: &str,
        secret: &str,
    ) -> Result<(), CredentialError> {
        let mut map = self.load()?;
        map.insert(credential_key(service, username), obfuscate(secret));
        self.save(&map)
    }

    fn get_secret(&self, service: &str, username: &str) -> Result<Option<String>, CredentialError> {
        let map = self.load()?;
        match map.get(&credential_key(service, username)) {
            Some(bytes) => Ok(Some(deobfuscate(bytes)?)),
            None => Ok(None),
        }
    }

    fn delete_secret(&self, service: &str, username: &str) -> Result<(), CredentialError> {
        let mut map = self.load()?;
        map.remove(&credential_key(service, username));
        self.save(&map)
    }
}

/// Picks the native backend when reachable, the obfuscated fallback
/// otherwise.
pub fn resolve_credential_store() -> Result<Box<dyn CredentialStore>, CredentialError> {
    if KeyringCredentialStore::is_available() {
        Ok(Box::new(KeyringCredentialStore))
    } else {
        Ok(Box::new(ObfuscatedCredentialStore::new()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate_round_trips_a_secret() {
        let secret = "correct horse battery staple";
        let obfuscated = obfuscate(secret);
        assert_ne!(obfuscated, secret.as_bytes());
        assert_eq!(deobfuscate(&obfuscated).expect("deobfuscate"), secret);
    }

    #[test]
    fn obfuscated_store_round_trips_through_a_file() {
        let path = std::env::temp_dir().join("cordiale-test-credentials-round-trip.json");
        let _ = fs::remove_file(&path);
        let store = ObfuscatedCredentialStore::with_file_path(path.clone());

        assert_eq!(
            store.get_secret("https://irc.sindro.me", "vjt").unwrap(),
            None
        );

        store
            .set_secret("https://irc.sindro.me", "vjt", "s3cr3t")
            .unwrap();
        assert_eq!(
            store.get_secret("https://irc.sindro.me", "vjt").unwrap(),
            Some("s3cr3t".to_string())
        );

        store.delete_secret("https://irc.sindro.me", "vjt").unwrap();
        assert_eq!(
            store.get_secret("https://irc.sindro.me", "vjt").unwrap(),
            None
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn obfuscated_store_keeps_service_and_username_distinct() {
        let path = std::env::temp_dir().join("cordiale-test-credentials-distinct-keys.json");
        let _ = fs::remove_file(&path);
        let store = ObfuscatedCredentialStore::with_file_path(path.clone());

        store.set_secret("server-a", "alice", "one").unwrap();
        store.set_secret("server-b", "alice", "two").unwrap();

        assert_eq!(
            store.get_secret("server-a", "alice").unwrap(),
            Some("one".to_string())
        );
        assert_eq!(
            store.get_secret("server-b", "alice").unwrap(),
            Some("two".to_string())
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn obfuscated_store_reads_the_old_folder_until_it_saves_to_the_new_one() {
        let dir = std::env::temp_dir().join(format!(
            "cordiale-test-credentials-fallback-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let old = dir.join("old").join("credentials.json");
        let new = dir.join("new").join("credentials.json");
        let seed = ObfuscatedCredentialStore::with_file_path(old.clone());
        seed.set_secret("server-a", "alice", "one").unwrap();

        let store = ObfuscatedCredentialStore {
            file_path: new.clone(),
            fallback_path: Some(old.clone()),
        };
        assert_eq!(
            store.get_secret("server-a", "alice").unwrap(),
            Some("one".to_string())
        );

        store.set_secret("server-b", "alice", "two").unwrap();
        assert!(new.exists());
        assert_eq!(
            store.get_secret("server-a", "alice").unwrap(),
            Some("one".to_string())
        );
        assert_eq!(
            store.get_secret("server-b", "alice").unwrap(),
            Some("two".to_string())
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn obfuscated_store_file_is_private_and_leaves_no_temp_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "cordiale-test-credentials-private-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("credentials.json");
        let store = ObfuscatedCredentialStore::with_file_path(path.clone());

        store.set_secret("server-a", "alice", "one").unwrap();
        store.set_secret("server-a", "alice", "two").unwrap();

        let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
