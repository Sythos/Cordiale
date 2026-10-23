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
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};
use zeroize::Zeroize;

use crate::e2e_store::{E2eKeyProvider, E2eStoreError};
use crate::persistence::{create_private_dir_all, write_atomic};

const KEY_LEN: usize = 32;
/// File header; also bound to the sealed state as associated data.
const MAGIC: &[u8] = b"CORDIALE-E2E-STATE-1";
const NONCE_LEN: usize = 24;

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
    /// open handle on the same path gives `InUse`.
    pub fn open(path: PathBuf, provider: &dyn E2eKeyProvider) -> Result<Self, E2eStoreError> {
        let key = provider.load_or_create_key()?;
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
        let mut store = E2eStateStore {
            path,
            _lock: lock,
            key,
            data: StateData::default(),
            writer: write_atomic,
        };
        if store.path.exists() {
            store.data = store.read_file()?;
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
        self.write_file(&next)?;
        self.data = next;
        Ok(())
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::<XChaCha20Poly1305>::from(self.key))
    }

    /// Writes `[magic][nonce][ciphertext]`.
    fn write_file(&self, data: &StateData) -> Result<(), E2eStoreError> {
        let mut plain = serde_json::to_vec(data).map_err(io::Error::other)?;
        let nonce = Nonce::<XChaCha20Poly1305>::generate();
        let sealed = self.cipher().encrypt(
            &nonce,
            Payload {
                msg: &plain,
                aad: MAGIC,
            },
        );
        plain.zeroize();
        let sealed = sealed.map_err(|_| E2eStoreError::Corrupted)?;
        let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + sealed.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&sealed);
        (self.writer)(&self.path, &out)?;
        Ok(())
    }

    fn read_file(&self) -> Result<StateData, E2eStoreError> {
        let corrupted = || E2eStoreError::Corrupted;
        let raw = fs::read(&self.path)?;
        if !raw.starts_with(MAGIC) || raw.len() < MAGIC.len() + NONCE_LEN {
            return Err(corrupted());
        }
        let body = &raw[MAGIC.len()..];
        let nonce =
            Nonce::<XChaCha20Poly1305>::try_from(&body[..NONCE_LEN]).map_err(|_| corrupted())?;
        let mut plain = self
            .cipher()
            .decrypt(
                &nonce,
                Payload {
                    msg: &body[NONCE_LEN..],
                    aad: MAGIC,
                },
            )
            .map_err(|_| corrupted())?;
        let parsed = serde_json::from_slice(&plain).map_err(|_| corrupted());
        plain.zeroize();
        parsed
    }
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
                vodozemac::olm::SessionConfig::version_2(),
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
        assert!(matches!(result, Err(E2eStoreError::Corrupted)));
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
}
