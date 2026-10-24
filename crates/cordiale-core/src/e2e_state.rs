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

//! Encrypted local state of the E2E device: the Olm account and sessions.
//!
//! One file holds the Olm account and the Olm sessions. The file is sealed
//! with XChaCha20-Poly1305. The Olm pickles are also encrypted with the same
//! key. The key comes from an `E2eKeyProvider`. When the provider has no
//! secure place for the key (no OS keyring), the store does not open and E2E
//! stays off: the store never uses the obfuscated fallback of
//! `credentials.rs` and never asks for a passphrase.
//!
//! The file header holds the schema version (`CORDIALE-E2E-STATE-2`) and a
//! short check value of the key. A wrong key gives `WrongKey`. A damaged or
//! changed seal gives `Corrupted`. A changed check value reads as a wrong key.
//!
//! A file of the first schema (`CORDIALE-E2E-STATE-1`) is converted in memory
//! on open. The new file goes to a staging file and is read back. Only then it
//! replaces the old file. A failed step keeps the old file.
//!
//! Every change is written to a new file first and then renamed over the
//! old one. A failed write keeps the old state in the file and in memory. A
//! file that does not open is an error: it is never replaced by an empty
//! state, so a damaged file never gives a new identity without notice.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Generate, Key, KeyInit, Nonce, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};
use zeroize::Zeroize;

use crate::e2e_store::{E2eKeyProvider, E2eStoreError};
use crate::persistence::{create_private_dir_all, write_atomic};

const KEY_LEN: usize = 32;
/// File header of the first schema; read only, for the migration.
const MAGIC_V1: &[u8] = b"CORDIALE-E2E-STATE-1";
/// File header of the current schema; also bound to the sealed state.
const MAGIC: &[u8] = b"CORDIALE-E2E-STATE-2";
const NONCE_LEN: usize = 24;
/// Length of the key check value after the header.
const CHECK_LEN: usize = 16;
/// Domain text of the key check value.
const CHECK_DOMAIN: &[u8] = b"cordiale-e2e-state-key-check";
/// Suffix of the staging file of a migration.
const STAGING_SUFFIX: &str = ".migrating";

/// What the file holds. The secret fields are overwritten on drop.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct StateData {
    /// Encrypted pickle of the Olm account.
    account: Option<String>,
    /// Encrypted pickles of the Olm sessions, by session id.
    sessions: BTreeMap<String, String>,
}

impl Drop for StateData {
    fn drop(&mut self) {
        if let Some(text) = self.account.as_mut() {
            text.zeroize();
        }
        for text in self.sessions.values_mut() {
            text.zeroize();
        }
    }
}

type Writer = fn(&Path, &[u8]) -> io::Result<()>;

/// The sealed E2E device state. An exclusive lock on a sidecar file keeps a
/// second handle or process from writing the same state.
pub struct E2eStateStore {
    path: PathBuf,
    /// Held for the life of the store; dropping it releases the lock.
    _lock: File,
    key: [u8; KEY_LEN],
    data: StateData,
    writer: Writer,
}

impl E2eStateStore {
    /// Opens (or starts empty) the state at `path`. A file that does not
    /// open is an error: it is never replaced by an empty state. Another
    /// open handle on the same path gives `InUse`. A file of the first
    /// schema is converted; see the module text.
    pub fn open(path: PathBuf, provider: &dyn E2eKeyProvider) -> Result<Self, E2eStoreError> {
        Self::open_with_writer(path, provider, write_atomic)
    }

    fn open_with_writer(
        path: PathBuf,
        provider: &dyn E2eKeyProvider,
        writer: Writer,
    ) -> Result<Self, E2eStoreError> {
        if let Some(parent) = path.parent() {
            create_private_dir_all(parent)?;
        }
        let mut lock_path = path.clone().into_os_string();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(lock_path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return Err(E2eStoreError::InUse),
            Err(fs::TryLockError::Error(err)) => return Err(err.into()),
        }
        // Take the key only under the state lock, so that two openers of
        // the same path never create the key in parallel.
        let key = provider.load_or_create_key()?;
        let mut store = E2eStateStore {
            path,
            _lock: lock,
            key,
            data: StateData::default(),
            writer,
        };
        if store.path.exists() {
            let (data, legacy) = store.unseal(&fs::read(&store.path)?)?;
            store.data = data;
            if legacy {
                store.migrate()?;
            }
        }
        Ok(store)
    }

    /// The Olm account, or `None` when the device has none yet.
    pub fn account(&self) -> Result<Option<Account>, E2eStoreError> {
        let Some(text) = self.data.account.as_deref() else {
            return Ok(None);
        };
        let pickle =
            AccountPickle::from_encrypted(text, &self.key).map_err(|_| E2eStoreError::Corrupted)?;
        Ok(Some(Account::from_pickle(pickle)))
    }

    /// Saves the Olm account.
    pub fn set_account(&mut self, account: &Account) -> Result<(), E2eStoreError> {
        let text = account.pickle().encrypt(&self.key);
        self.commit(|data| data.account = Some(text))
    }

    /// The Olm session with this id, or `None`.
    pub fn session(&self, id: &str) -> Result<Option<Session>, E2eStoreError> {
        let Some(text) = self.data.sessions.get(id) else {
            return Ok(None);
        };
        let pickle =
            SessionPickle::from_encrypted(text, &self.key).map_err(|_| E2eStoreError::Corrupted)?;
        Ok(Some(Session::from_pickle(pickle)))
    }

    /// Saves the state of one Olm session; call it after each use.
    pub fn set_session(&mut self, id: &str, session: &Session) -> Result<(), E2eStoreError> {
        let text = session.pickle().encrypt(&self.key);
        let id = id.to_string();
        self.commit(|data| {
            data.sessions.insert(id, text);
        })
    }

    /// Applies `change` to a copy, writes the copy, and only then keeps it.
    /// A failed write leaves the old state in the file and in memory.
    fn commit(&mut self, change: impl FnOnce(&mut StateData)) -> Result<(), E2eStoreError> {
        let mut next = self.data.clone();
        change(&mut next);
        let sealed = self.seal(&next)?;
        (self.writer)(&self.path, &sealed)?;
        self.data = next;
        Ok(())
    }

    /// Writes the current state in the current schema to a staging file,
    /// reads it back, and only then renames it over the old file. A failed
    /// step removes the staging file and keeps the old file.
    fn migrate(&self) -> Result<(), E2eStoreError> {
        let mut staging = self.path.clone().into_os_string();
        staging.push(STAGING_SUFFIX);
        let staging = PathBuf::from(staging);
        let result = self
            .write_checked(&staging)
            .and_then(|()| fs::rename(&staging, &self.path).map_err(E2eStoreError::from));
        if result.is_err() {
            let _ = fs::remove_file(&staging);
        }
        result
    }

    fn write_checked(&self, staging: &Path) -> Result<(), E2eStoreError> {
        (self.writer)(staging, &self.seal(&self.data)?)?;
        match self.unseal(&fs::read(staging)?)? {
            (back, false) if back == self.data => Ok(()),
            _ => Err(E2eStoreError::Corrupted),
        }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::<XChaCha20Poly1305>::from(self.key))
    }

    /// A short value that tells the key of a file without opening it. It is
    /// a one-way hash of the key with a domain text.
    fn key_check(&self) -> [u8; CHECK_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(CHECK_DOMAIN);
        hasher.update(self.key);
        let mut check = [0u8; CHECK_LEN];
        check.copy_from_slice(&hasher.finalize()[..CHECK_LEN]);
        check
    }

    /// Builds `[magic][key check][nonce][ciphertext]`. The header is bound
    /// to the ciphertext as associated data.
    fn seal(&self, data: &StateData) -> Result<Vec<u8>, E2eStoreError> {
        let mut plain = serde_json::to_vec(data).map_err(io::Error::other)?;
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&self.key_check());
        let nonce = Nonce::<XChaCha20Poly1305>::generate();
        let sealed = self.cipher().encrypt(
            &nonce,
            Payload {
                msg: &plain,
                aad: &header,
            },
        );
        plain.zeroize();
        let sealed = sealed.map_err(|_| E2eStoreError::Corrupted)?;
        let mut out = header;
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Opens the bytes of a file. The flag is true when the file was of the
    /// first schema and was converted in memory.
    fn unseal(&self, raw: &[u8]) -> Result<(StateData, bool), E2eStoreError> {
        if raw.starts_with(MAGIC_V1) {
            let plain = self.open_sealed(&raw[MAGIC_V1.len()..], MAGIC_V1)?;
            // The first schema holds the same two fields as the current one.
            return Ok((parse(plain)?, true));
        }
        let header_len = MAGIC.len() + CHECK_LEN;
        if !raw.starts_with(MAGIC) || raw.len() < header_len + NONCE_LEN {
            return Err(E2eStoreError::Corrupted);
        }
        if raw[MAGIC.len()..header_len] != self.key_check() {
            return Err(E2eStoreError::WrongKey);
        }
        let plain = self.open_sealed(&raw[header_len..], &raw[..header_len])?;
        Ok((parse(plain)?, false))
    }

    /// Decrypts `[nonce][ciphertext]` with `aad` as associated data.
    fn open_sealed(&self, body: &[u8], aad: &[u8]) -> Result<Vec<u8>, E2eStoreError> {
        let corrupted = || E2eStoreError::Corrupted;
        if body.len() < NONCE_LEN {
            return Err(corrupted());
        }
        let nonce =
            Nonce::<XChaCha20Poly1305>::try_from(&body[..NONCE_LEN]).map_err(|_| corrupted())?;
        self.cipher()
            .decrypt(
                &nonce,
                Payload {
                    msg: &body[NONCE_LEN..],
                    aad,
                },
            )
            .map_err(|_| corrupted())
    }
}

/// Parses the decrypted JSON and overwrites the text.
fn parse(mut plain: Vec<u8>) -> Result<StateData, E2eStoreError> {
    let parsed = serde_json::from_slice(&plain).map_err(|_| E2eStoreError::Corrupted);
    plain.zeroize();
    parsed
}

impl Drop for E2eStateStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FixedKey([u8; KEY_LEN]);

    impl E2eKeyProvider for FixedKey {
        fn load_or_create_key(&self) -> Result<[u8; KEY_LEN], E2eStoreError> {
            Ok(self.0)
        }
    }

    struct NoKeyring;

    impl E2eKeyProvider for NoKeyring {
        fn load_or_create_key(&self) -> Result<[u8; KEY_LEN], E2eStoreError> {
            Err(E2eStoreError::SecureStorageUnavailable)
        }
    }

    /// A random key for one test; no key is written in the source.
    fn fresh_key() -> FixedKey {
        let key = Key::<XChaCha20Poly1305>::generate();
        FixedKey(<[u8; KEY_LEN]>::try_from(key.as_slice()).expect("key length"))
    }

    fn scratch_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "cordiale-e2e-state-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn failing_writer(_: &Path, _: &[u8]) -> io::Result<()> {
        Err(io::Error::other("write interrupted"))
    }

    /// A write that stops half way and leaves a cut file in place.
    fn cutting_writer(path: &Path, contents: &[u8]) -> io::Result<()> {
        fs::write(path, &contents[..contents.len() / 2])?;
        Err(io::Error::other("write interrupted"))
    }

    fn outbound_session(account: &Account) -> Session {
        let mut peer = Account::new();
        peer.generate_one_time_keys(1);
        let one_time = *peer.one_time_keys().values().next().expect("one-time key");
        account
            .create_outbound_session(
                vodozemac::olm::SessionConfig::version_1(),
                peer.identity_keys().curve25519,
                one_time,
            )
            .expect("outbound session")
    }

    #[test]
    fn account_and_session_survive_a_restart() {
        let dir = scratch_dir("roundtrip");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let account = Account::new();
        let session = outbound_session(&account);
        {
            let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
            assert!(store.account().expect("account").is_none());
            store.set_account(&account).expect("account");
            store.set_session("peer-1", &session).expect("session");
        }
        let store = E2eStateStore::open(path, &provider).expect("reopen");
        let loaded = store.account().expect("account").expect("present");
        assert_eq!(loaded.identity_keys(), account.identity_keys());
        let loaded = store.session("peer-1").expect("session").expect("present");
        assert_eq!(loaded.session_id(), session.session_id());
        assert!(store.session("other").expect("session").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_bytes_do_not_show_secrets() {
        let dir = scratch_dir("at-rest");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let account = Account::new();
        let pickle = account.pickle().encrypt(&provider.0);
        let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
        store.set_account(&account).expect("account");
        let raw = String::from_utf8_lossy(&fs::read(&path).expect("read")).into_owned();
        assert!(!raw.contains(&pickle));
        assert!(!raw.contains(&account.identity_keys().ed25519.to_base64()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_secure_storage_fails_closed() {
        let dir = scratch_dir("closed");
        let path = dir.join("state.bin");
        let result = E2eStateStore::open(path.clone(), &NoKeyring);
        assert!(matches!(
            result,
            Err(E2eStoreError::SecureStorageUnavailable)
        ));
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrong_key_is_an_error_and_keeps_the_file() {
        let dir = scratch_dir("wrong-key");
        let path = dir.join("state.bin");
        let mut store = E2eStateStore::open(path.clone(), &fresh_key()).expect("open");
        store.set_account(&Account::new()).expect("account");
        drop(store);
        let before = fs::read(&path).expect("read");
        let result = E2eStateStore::open(path.clone(), &fresh_key());
        assert!(matches!(result, Err(E2eStoreError::WrongKey)));
        assert_eq!(fs::read(&path).expect("read"), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cut_or_damaged_file_is_an_error_and_keeps_the_file() {
        let dir = scratch_dir("damaged");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
        store.set_account(&Account::new()).expect("account");
        drop(store);
        let whole = fs::read(&path).expect("read");
        let mut flipped = whole.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        for damaged in [
            whole[..whole.len() / 2].to_vec(),
            whole[..MAGIC.len() + 3].to_vec(),
            flipped,
            b"not a state file".to_vec(),
        ] {
            fs::write(&path, &damaged).expect("damage");
            let result = E2eStateStore::open(path.clone(), &provider);
            assert!(matches!(result, Err(E2eStoreError::Corrupted)));
            assert_eq!(fs::read(&path).expect("read"), damaged);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_save_keeps_the_old_account_in_file_and_memory() {
        let dir = scratch_dir("failed-save");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let account = Account::new();
        let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
        store.set_account(&account).expect("account");
        let before = fs::read(&path).expect("read");
        store.writer = failing_writer;
        let result = store.set_account(&Account::new());
        assert!(matches!(result, Err(E2eStoreError::Io(_))));
        let kept = store.account().expect("account").expect("present");
        assert_eq!(kept.identity_keys(), account.identity_keys());
        assert_eq!(fs::read(&path).expect("read"), before);
        drop(store);
        let store = E2eStateStore::open(path, &provider).expect("reopen");
        let loaded = store.account().expect("account").expect("present");
        assert_eq!(loaded.identity_keys(), account.identity_keys());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_interrupted_first_write_never_gives_a_new_identity() {
        let dir = scratch_dir("interrupted");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
        store.writer = cutting_writer;
        assert!(store.set_account(&Account::new()).is_err());
        assert!(store.account().expect("account").is_none());
        drop(store);
        // The cut file is an error, not an empty state.
        let result = E2eStateStore::open(path, &provider);
        assert!(matches!(result, Err(E2eStoreError::Corrupted)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_handle_on_the_same_state_is_refused() {
        let dir = scratch_dir("lock");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let first = E2eStateStore::open(path.clone(), &provider).expect("open");
        let second = E2eStateStore::open(path.clone(), &provider);
        assert!(matches!(second, Err(E2eStoreError::InUse)));
        drop(first);
        assert!(E2eStateStore::open(path, &provider).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A file as the first schema wrote it.
    fn legacy_file(key: &[u8; KEY_LEN], account: &Account, session: (&str, &Session)) -> Vec<u8> {
        let sessions = BTreeMap::from([(session.0, session.1.pickle().encrypt(key))]);
        let plain = serde_json::to_vec(&serde_json::json!({
            "account": account.pickle().encrypt(key),
            "sessions": sessions,
        }))
        .expect("json");
        let nonce = Nonce::<XChaCha20Poly1305>::generate();
        let sealed = XChaCha20Poly1305::new(&Key::<XChaCha20Poly1305>::from(*key))
            .encrypt(
                &nonce,
                Payload {
                    msg: &plain,
                    aad: MAGIC_V1,
                },
            )
            .expect("seal");
        let mut out = MAGIC_V1.to_vec();
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&sealed);
        out
    }

    fn staging_of(path: &Path) -> PathBuf {
        let mut staging = path.to_path_buf().into_os_string();
        staging.push(STAGING_SUFFIX);
        PathBuf::from(staging)
    }

    #[test]
    fn a_first_schema_file_keeps_its_account_and_sessions() {
        let dir = scratch_dir("migrate");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let account = Account::new();
        let session = outbound_session(&account);
        let old = legacy_file(&provider.0, &account, ("peer-1", &session));
        fs::write(&path, old).expect("write");
        let store = E2eStateStore::open(path.clone(), &provider).expect("open");
        let loaded = store.account().expect("account").expect("present");
        assert_eq!(loaded.identity_keys(), account.identity_keys());
        let loaded = store.session("peer-1").expect("session").expect("present");
        assert_eq!(loaded.session_id(), session.session_id());
        drop(store);
        assert!(fs::read(&path).expect("read").starts_with(MAGIC));
        assert!(!staging_of(&path).exists());
        let store = E2eStateStore::open(path, &provider).expect("reopen");
        let loaded = store.account().expect("account").expect("present");
        assert_eq!(loaded.identity_keys(), account.identity_keys());
        assert!(store.session("peer-1").expect("session").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_migration_keeps_the_first_schema_file() {
        let dir = scratch_dir("migrate-fail");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let account = Account::new();
        let session = outbound_session(&account);
        let old = legacy_file(&provider.0, &account, ("peer-1", &session));
        fs::write(&path, &old).expect("write");
        for writer in [failing_writer as Writer, cutting_writer as Writer] {
            let result = E2eStateStore::open_with_writer(path.clone(), &provider, writer);
            assert!(matches!(result, Err(E2eStoreError::Io(_))));
            assert_eq!(fs::read(&path).expect("read"), old);
            assert!(!staging_of(&path).exists());
        }
        // The old file still opens and converts.
        assert!(E2eStateStore::open(path, &provider).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_first_schema_file_with_a_wrong_key_is_an_error_and_keeps_the_file() {
        let dir = scratch_dir("migrate-key");
        let path = dir.join("state.bin");
        let account = Account::new();
        let session = outbound_session(&account);
        let old = legacy_file(&fresh_key().0, &account, ("peer-1", &session));
        fs::write(&path, &old).expect("write");
        let result = E2eStateStore::open(path.clone(), &fresh_key());
        assert!(matches!(result, Err(E2eStoreError::Corrupted)));
        assert_eq!(fs::read(&path).expect("read"), old);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_changed_byte_is_an_error_at_every_offset() {
        let dir = scratch_dir("every-byte");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
        store.set_account(&Account::new()).expect("account");
        drop(store);
        let whole = fs::read(&path).expect("read");
        for offset in 0..whole.len() {
            let mut changed = whole.clone();
            changed[offset] ^= 1;
            fs::write(&path, &changed).expect("damage");
            assert!(E2eStateStore::open(path.clone(), &provider).is_err());
            assert_eq!(fs::read(&path).expect("read"), changed);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
