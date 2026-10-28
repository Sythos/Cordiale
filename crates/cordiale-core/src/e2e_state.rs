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
//! One file holds the Olm account, the Olm sessions, the master key, the own
//! signed device list, the peer trust state and one slot for pending pairing
//! state. The file is sealed
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
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Generate, Key, KeyInit, Nonce, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};
use zeroize::Zeroize;

use crate::e2e_device::VersionedDeviceCertificate;
use crate::e2e_manage::SignedList;
use crate::e2e_peer::{peer_device_key, ReplayState};
use crate::e2e_store::{E2eKeyProvider, E2eStoreError};
use crate::e2e_trust::PeerTrust;
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
    /// Encrypted pickle of the master key account.
    #[serde(default)]
    master: Option<String>,
    /// The own signed device list (public values and the master signature).
    #[serde(default)]
    signed_list: Option<SignedList>,
    /// True while the own signed list waits for its upload. Cleared only
    /// after the server answered 2xx to the put.
    #[serde(default)]
    list_pending: bool,
    /// The certificate of this device: the master signature for the first
    /// list version that holds the device (public values).
    #[serde(default)]
    device_certificate: Option<VersionedDeviceCertificate>,
    /// Trust state of the peers, with the revoked devices (public values).
    #[serde(default)]
    trust: PeerTrust,
    /// Opaque state of a pairing that is not finished.
    #[serde(default)]
    pending_pairing: Option<String>,
    /// First-message and new-session ids already accepted (public values).
    #[serde(default)]
    replay: ReplayState,
}

impl Drop for StateData {
    fn drop(&mut self) {
        if let Some(text) = self.account.as_mut() {
            text.zeroize();
        }
        for text in self.sessions.values_mut() {
            text.zeroize();
        }
        if let Some(text) = self.master.as_mut() {
            text.zeroize();
        }
        if let Some(text) = self.pending_pairing.as_mut() {
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

    /// The Olm session with one remote device, or `None`. The key is the
    /// network, the nick and the `did`: one session for each device.
    pub fn peer_session(
        &self,
        network: &str,
        nick: &str,
        did: &str,
    ) -> Result<Option<Session>, E2eStoreError> {
        self.session(&peer_device_key(network, nick, did))
    }

    /// Saves the session with one remote device. It replaces the session
    /// that the same device had and never touches another device.
    pub fn set_peer_session(
        &mut self,
        network: &str,
        nick: &str,
        did: &str,
        session: &Session,
    ) -> Result<(), E2eStoreError> {
        self.set_session(&peer_device_key(network, nick, did), session)
    }

    /// The replay state. It is empty when none was saved.
    pub fn replay(&self) -> ReplayState {
        self.data.replay.clone()
    }

    /// Saves the replay state.
    pub fn set_replay(&mut self, replay: &ReplayState) -> Result<(), E2eStoreError> {
        let replay = replay.clone();
        self.commit(|data| data.replay = replay)
    }

    /// The master key, or `None` when the device has none yet.
    pub fn master_key(&self) -> Result<Option<Account>, E2eStoreError> {
        let Some(text) = self.data.master.as_deref() else {
            return Ok(None);
        };
        let pickle =
            AccountPickle::from_encrypted(text, &self.key).map_err(|_| E2eStoreError::Corrupted)?;
        Ok(Some(Account::from_pickle(pickle)))
    }

    /// Saves the master key as an encrypted pickle.
    pub fn set_master_key(&mut self, master: &Account) -> Result<(), E2eStoreError> {
        let text = master.pickle().encrypt(&self.key);
        self.commit(|data| data.master = Some(text))
    }

    /// The own signed device list, or `None`.
    pub fn signed_list(&self) -> Option<SignedList> {
        self.data.signed_list.clone()
    }

    /// Saves the own signed device list.
    pub fn set_signed_list(&mut self, list: &SignedList) -> Result<(), E2eStoreError> {
        let list = list.clone();
        self.commit(|data| data.signed_list = Some(list))
    }

    /// True while the own signed list waits for publication: after a first
    /// list, or after the migration of a list that has the old key order.
    pub fn list_pending(&self) -> bool {
        self.data.list_pending
    }

    /// Saves the own signed list and marks it as waiting for publication, in
    /// one write. `set_signed_list` leaves the mark as it is.
    pub fn set_signed_list_pending(&mut self, list: &SignedList) -> Result<(), E2eStoreError> {
        let list = list.clone();
        self.commit(|data| {
            data.signed_list = Some(list);
            data.list_pending = true;
        })
    }

    /// Clears the mark after the server accepted the list.
    pub fn clear_list_pending(&mut self) -> Result<(), E2eStoreError> {
        if !self.data.list_pending {
            return Ok(());
        }
        self.commit(|data| data.list_pending = false)
    }

    /// The certificate of this device, or `None`.
    pub fn device_certificate(&self) -> Option<VersionedDeviceCertificate> {
        self.data.device_certificate.clone()
    }

    /// Saves the certificate of this device.
    pub fn set_device_certificate(
        &mut self,
        certificate: &VersionedDeviceCertificate,
    ) -> Result<(), E2eStoreError> {
        let certificate = certificate.clone();
        self.commit(|data| data.device_certificate = Some(certificate))
    }

    /// The trust state of the peers, with the revoked devices. It is empty
    /// when none was saved.
    pub fn trust(&self) -> PeerTrust {
        self.data.trust.clone()
    }

    /// Saves the trust state of the peers.
    pub fn set_trust(&mut self, trust: &PeerTrust) -> Result<(), E2eStoreError> {
        let trust = trust.clone();
        self.commit(|data| data.trust = trust)
    }

    /// The pending pairing state, or `None` when no pairing is open.
    pub fn pending_pairing(&self) -> Option<&str> {
        self.data.pending_pairing.as_deref()
    }

    /// Saves the pending pairing state in the one slot. It replaces the
    /// state that the slot held.
    pub fn set_pending_pairing(&mut self, state: &str) -> Result<(), E2eStoreError> {
        let state = state.to_string();
        self.commit(|data| data.pending_pairing = Some(state))
    }

    /// Empties the pending pairing slot.
    pub fn clear_pending_pairing(&mut self) -> Result<(), E2eStoreError> {
        if self.data.pending_pairing.is_none() {
            return Ok(());
        }
        self.commit(|data| data.pending_pairing = None)
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
            // The first schema holds the account and the sessions only. The
            // other fields start empty.
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

/// Shows what the store holds, never a key or a pickle.
impl fmt::Debug for E2eStateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("E2eStateStore")
            .field("path", &self.path)
            .field("has_account", &self.data.account.is_some())
            .field("sessions", &self.data.sessions.len())
            .field("has_master", &self.data.master.is_some())
            .field("has_signed_list", &self.data.signed_list.is_some())
            .field("list_pending", &self.data.list_pending)
            .field("has_pending_pairing", &self.data.pending_pairing.is_some())
            .finish_non_exhaustive()
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

    fn sample_list(master: &Account, version: u32, keys: &[String]) -> SignedList {
        let signature = crate::e2e_device::build_signed_list_signature(version, keys, |text| {
            master.sign(text).to_base64()
        })
        .expect("signature");
        SignedList {
            version,
            keys: keys.to_vec(),
            signature,
        }
    }

    fn ed25519_of(account: &Account) -> String {
        account.identity_keys().ed25519.to_base64()
    }

    /// A trust state with one peer and one revoked device.
    fn trust_with_revoked(master: &Account, kept: &str, dropped: &str) -> PeerTrust {
        let master_key = ed25519_of(master);
        let mut trust = PeerTrust::default();
        trust
            .observe_master("net", "alice", &master_key)
            .expect("observe");
        for (version, keys) in [
            (1, vec![kept.to_string(), dropped.to_string()]),
            (2, vec![kept.to_string()]),
        ] {
            let list = sample_list(master, version, &keys);
            trust
                .accept_list("net", "alice", &master_key, version, &keys, &list.signature)
                .expect("list");
        }
        assert!(trust.is_revoked("net", "alice", dropped, None));
        trust
    }

    #[test]
    fn master_list_trust_and_pairing_survive_a_restart() {
        let dir = scratch_dir("full-state");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let master = Account::new();
        let kept = ed25519_of(&Account::new());
        let dropped = ed25519_of(&Account::new());
        let list = sample_list(&master, 3, std::slice::from_ref(&kept));
        let trust = trust_with_revoked(&master, &kept, &dropped);
        {
            let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
            assert!(store.master_key().expect("master").is_none());
            assert!(store.signed_list().is_none());
            assert!(store.pending_pairing().is_none());
            store.set_master_key(&master).expect("master");
            store.set_signed_list(&list).expect("list");
            store.set_trust(&trust).expect("trust");
            store.set_pending_pairing("pairing-state").expect("pairing");
        }
        let mut store = E2eStateStore::open(path.clone(), &provider).expect("reopen");
        let loaded = store.master_key().expect("master").expect("present");
        assert_eq!(loaded.identity_keys(), master.identity_keys());
        assert_eq!(store.signed_list(), Some(list));
        assert_eq!(store.trust(), trust);
        assert!(store.trust().is_revoked("net", "alice", &dropped, None));
        assert_eq!(store.pending_pairing(), Some("pairing-state"));
        store.clear_pending_pairing().expect("clear");
        drop(store);
        let store = E2eStateStore::open(path, &provider).expect("reopen");
        assert!(store.pending_pairing().is_none());
        assert_eq!(store.trust(), trust);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_sessions_and_replay_state_survive_a_restart() {
        let dir = scratch_dir("peer-sessions");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let account = Account::new();
        let (first, second) = (outbound_session(&account), outbound_session(&account));
        let mut replay = ReplayState::default();
        replay
            .accept_first_message("net", "alice", "d1", "m1")
            .unwrap();
        replay
            .accept_new_session("net", "alice", "d1", "s1")
            .unwrap();
        {
            let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
            store
                .set_peer_session("net", "alice", "d1", &first)
                .unwrap();
            store
                .set_peer_session("net", "alice", "d2", &second)
                .unwrap();
            // The second query entry of the same peer reuses the session.
            store
                .set_peer_session("net", "alice", "d1", &first)
                .unwrap();
            store.set_replay(&replay).expect("replay");
            assert_eq!(store.data.sessions.len(), 2);
        }
        let store = E2eStateStore::open(path, &provider).expect("reopen");
        let one = store.peer_session("net", "alice", "d1").unwrap().unwrap();
        let two = store.peer_session("net", "alice", "d2").unwrap().unwrap();
        assert_eq!(one.session_id(), first.session_id());
        assert_eq!(two.session_id(), second.session_id());
        assert!(store.peer_session("net", "bob", "d1").unwrap().is_none());
        assert_eq!(store.replay(), replay);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sessions_of_nicks_that_name_object_members_stay_apart() {
        let dir = scratch_dir("member-nicks");
        let provider = fresh_key();
        let account = Account::new();
        let mut store = E2eStateStore::open(dir.join("state.bin"), &provider).expect("open");
        let mut expected = Vec::new();
        for nick in ["constructor", "__proto__", "toString"] {
            let session = outbound_session(&account);
            store.set_peer_session("net", nick, "d1", &session).unwrap();
            expected.push((nick, session.session_id()));
        }
        for (nick, id) in expected {
            let loaded = store.peer_session("net", nick, "d1").unwrap().unwrap();
            assert_eq!(loaded.session_id(), id);
        }
        assert!(store
            .peer_session("net", "valueOf", "d1")
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_save_keeps_the_old_master_list_trust_and_pairing() {
        let dir = scratch_dir("failed-full");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let master = Account::new();
        let kept = ed25519_of(&Account::new());
        let dropped = ed25519_of(&Account::new());
        let list = sample_list(&master, 3, std::slice::from_ref(&kept));
        let trust = trust_with_revoked(&master, &kept, &dropped);
        let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
        store.set_master_key(&master).expect("master");
        store.set_signed_list(&list).expect("list");
        store.set_trust(&trust).expect("trust");
        store.set_pending_pairing("first").expect("pairing");
        let before = fs::read(&path).expect("read");
        store.writer = failing_writer;
        let newer = sample_list(&master, 4, std::slice::from_ref(&kept));
        assert!(store.set_master_key(&Account::new()).is_err());
        assert!(store.set_signed_list(&newer).is_err());
        assert!(store.set_trust(&PeerTrust::default()).is_err());
        assert!(store.set_pending_pairing("second").is_err());
        assert!(store.clear_pending_pairing().is_err());
        let kept_master = store.master_key().expect("master").expect("present");
        assert_eq!(kept_master.identity_keys(), master.identity_keys());
        assert_eq!(store.signed_list(), Some(list));
        assert_eq!(store.trust(), trust);
        assert_eq!(store.pending_pairing(), Some("first"));
        assert_eq!(fs::read(&path).expect("read"), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_pending_list_mark_and_the_certificate_survive_a_restart() {
        let dir = scratch_dir("pending-list");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let master = Account::new();
        let device = ed25519_of(&Account::new());
        let list = sample_list(&master, 1, std::slice::from_ref(&device));
        let certificate =
            crate::e2e_device::build_device_certificate(1, &device, &ed25519_of(&master), |text| {
                master.sign(text).to_base64()
            })
            .expect("certificate");
        {
            let mut store = E2eStateStore::open(path.clone(), &provider).expect("open");
            assert!(!store.list_pending());
            assert!(store.device_certificate().is_none());
            store.set_signed_list_pending(&list).expect("list");
            store.set_device_certificate(&certificate).expect("cert");
        }
        let mut store = E2eStateStore::open(path.clone(), &provider).expect("reopen");
        assert!(store.list_pending());
        assert_eq!(store.signed_list(), Some(list.clone()));
        assert_eq!(store.device_certificate(), Some(certificate));
        store.writer = failing_writer;
        assert!(store.clear_list_pending().is_err());
        assert!(store.list_pending());
        store.writer = write_atomic;
        store.clear_list_pending().expect("clear");
        drop(store);
        let store = E2eStateStore::open(path, &provider).expect("reopen");
        assert!(!store.list_pending());
        assert_eq!(store.signed_list(), Some(list));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_first_schema_file_starts_with_empty_new_fields() {
        let dir = scratch_dir("migrate-empty");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let account = Account::new();
        let session = outbound_session(&account);
        fs::write(&path, legacy_file(&provider.0, &account, ("p", &session))).expect("write");
        let store = E2eStateStore::open(path, &provider).expect("open");
        assert!(store.master_key().expect("master").is_none());
        assert!(store.signed_list().is_none());
        assert_eq!(store.trust(), PeerTrust::default());
        assert!(store.pending_pairing().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_output_shows_no_key_and_no_pickle() {
        let dir = scratch_dir("debug");
        let path = dir.join("state.bin");
        let provider = fresh_key();
        let account = Account::new();
        let master = Account::new();
        let mut store = E2eStateStore::open(path, &provider).expect("open");
        store.set_account(&account).expect("account");
        store.set_master_key(&master).expect("master");
        store
            .set_pending_pairing("secret-pairing")
            .expect("pairing");
        let text = format!("{store:?}");
        assert!(text.contains("E2eStateStore"));
        assert!(!text.contains(&format!("{:?}", provider.0)));
        assert!(!text.contains(&account.pickle().encrypt(&provider.0)));
        assert!(!text.contains(&master.pickle().encrypt(&provider.0)));
        assert!(!text.contains("secret-pairing"));
        assert!(!text.contains(&ed25519_of(&account)));
        let _ = fs::remove_dir_all(&dir);
    }
}
