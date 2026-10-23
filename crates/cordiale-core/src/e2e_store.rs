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

//! Encrypted local history of E2E conversations.
//!
//! The history lives in one file of sealed records, one for each row, with
//! XChaCha20-Poly1305. An append writes one record. The key
//! comes from the native OS keyring only: the store never uses the
//! obfuscated fallback of `credentials.rs`, and it fails closed when no
//! keyring is reachable. Search runs on the decrypted rows in memory; no
//! index, cache or temporary copy of the clear text goes to disk. This file
//! is kept apart from `settings.json` and from the normal history.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Generate, Key, KeyInit, Nonce, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::credentials::{CredentialStore, KeyringCredentialStore};
use crate::persistence::{create_private_dir_all, data_dir, write_atomic};

const HISTORY_FILE_NAME: &str = "e2e_history.bin";
const KEY_SERVICE: &str = "cordiale-e2e";
const KEY_USERNAME: &str = "history-key";
const KEY_LOCK_FILE_NAME: &str = "e2e_key.lock";
const KEY_LEN: usize = 32;
/// File header; also bound to every record as associated data, with the
/// index of the record.
const MAGIC: &[u8] = b"CORDIALE-E2E-HISTORY-1";
const NONCE_LEN: usize = 24;
/// Size of the length field in front of each record.
const LEN_FIELD: usize = 4;

#[derive(Debug)]
pub enum E2eStoreError {
    /// No secure place for the key: the store refuses to work.
    SecureStorageUnavailable,
    /// The key store answered with a failure.
    Key(String),
    NoDataDir,
    /// Another handle or process has this history open.
    InUse,
    /// The history file does not open with the key (damaged or wrong key,
    /// or a record cut short by a crash).
    Corrupted,
    Io(io::Error),
}

impl From<io::Error> for E2eStoreError {
    fn from(err: io::Error) -> Self {
        E2eStoreError::Io(err)
    }
}

/// Gives the 32-byte history key. The store never writes the key to a file
/// it owns.
pub trait E2eKeyProvider {
    fn load_or_create_key(&self) -> Result<[u8; KEY_LEN], E2eStoreError>;
}

/// The key is a secret of the native keyring.
pub struct KeyringKeyProvider;

impl E2eKeyProvider for KeyringKeyProvider {
    fn load_or_create_key(&self) -> Result<[u8; KEY_LEN], E2eStoreError> {
        if !KeyringCredentialStore::is_available() {
            return Err(E2eStoreError::SecureStorageUnavailable);
        }
        let dir = data_dir().ok_or(E2eStoreError::NoDataDir)?;
        create_private_dir_all(&dir)?;
        let username = key_username(&dir.canonicalize()?);
        load_or_create_locked(
            &dir.join(KEY_LOCK_FILE_NAME),
            &username,
            &KeyringCredentialStore,
        )
    }
}

/// The keyring user name of the key for one data folder. The keyring is
/// shared by every process of the user, so the folder is part of the name:
/// two data folders never share a key or need a common lock. The name holds
/// a hash, so the path (and the user name in it) never reaches the keyring.
fn key_username(dir: &Path) -> String {
    let hash = Sha256::digest(dir.as_os_str().as_encoded_bytes());
    let mut name = format!("{KEY_USERNAME}-");
    for byte in &hash[..16] {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// Reads the key `username`, or creates and stores it, while an exclusive
/// lock on `lock_path` is held. The entry and the lock belong to one data
/// folder (see `key_username`), not to a history file.
fn load_or_create_locked(
    lock_path: &Path,
    username: &str,
    store: &dyn CredentialStore,
) -> Result<[u8; KEY_LEN], E2eStoreError> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)?;
    lock.lock()?;
    let stored = store
        .get_secret(KEY_SERVICE, username)
        .map_err(|err| E2eStoreError::Key(format!("{err:?}")))?;
    if let Some(text) = stored {
        return decode_key(&text);
    }
    let key = Key::<XChaCha20Poly1305>::generate();
    let mut bytes =
        <[u8; KEY_LEN]>::try_from(key.as_slice()).map_err(|_| E2eStoreError::Corrupted)?;
    let mut text = STANDARD_NO_PAD.encode(bytes);
    let result = store
        .set_secret(KEY_SERVICE, username, &text)
        .map_err(|err| E2eStoreError::Key(format!("{err:?}")));
    text.zeroize();
    // The lock is released when `lock` drops at the end of the function.
    match result {
        Ok(()) => Ok(bytes),
        Err(err) => {
            bytes.zeroize();
            Err(err)
        }
    }
}

fn decode_key(text: &str) -> Result<[u8; KEY_LEN], E2eStoreError> {
    let mut raw = STANDARD_NO_PAD
        .decode(text)
        .map_err(|_| E2eStoreError::Corrupted)?;
    let result = <[u8; KEY_LEN]>::try_from(raw.as_slice()).map_err(|_| E2eStoreError::Corrupted);
    raw.zeroize();
    result
}

/// One decrypted row. `conversation_id` is an opaque id chosen by the
/// caller; it is never a nickname alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_device: String,
    pub sent_at: i64,
    pub text: String,
}

/// The sealed history. The decrypted rows stay in memory until `close` or
/// drop, which overwrite the texts. An exclusive lock on a sidecar file
/// keeps a second handle or process from writing the same history.
pub struct E2eHistoryStore {
    path: PathBuf,
    /// Held for the life of the store; dropping it releases the lock.
    _lock: File,
    key: [u8; KEY_LEN],
    /// Rows in order of `sent_at`.
    messages: Vec<E2eMessage>,
    /// Number of records in the file; the next record gets this index.
    records: u64,
}

impl E2eHistoryStore {
    /// Opens the history in the data folder with the keyring key.
    pub fn open_default() -> Result<Self, E2eStoreError> {
        let path = data_dir()
            .ok_or(E2eStoreError::NoDataDir)?
            .join(HISTORY_FILE_NAME);
        Self::open(path, &KeyringKeyProvider)
    }

    /// Opens (or starts empty) the history at `path`. A file that does not
    /// open is an error: it is never replaced by an empty history. Another
    /// open handle on the same path gives `InUse`.
    pub fn open(path: PathBuf, provider: &dyn E2eKeyProvider) -> Result<Self, E2eStoreError> {
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
        // This lock only stops a second handle on the same file. The key
        // provider has its own lock for the key creation.
        let key = provider.load_or_create_key()?;
        let mut store = E2eHistoryStore {
            path,
            _lock: lock,
            key,
            messages: Vec::new(),
            records: 0,
        };
        if store.path.exists() {
            let (rows, records) = store.read_file()?;
            store.messages = rows;
            store.records = records;
        }
        Ok(store)
    }

    /// Adds one row as one new record. On a write failure the row is not
    /// kept.
    pub fn append(&mut self, message: E2eMessage) -> Result<(), E2eStoreError> {
        let record = match self.seal_record(&message, self.records) {
            Ok(record) => record,
            Err(err) => {
                wipe(vec![message]);
                return Err(err);
            }
        };
        if let Err(err) = self.append_record(&record) {
            wipe(vec![message]);
            return Err(err);
        }
        self.records += 1;
        let at = self
            .messages
            .partition_point(|row| row.sent_at <= message.sent_at);
        self.messages.insert(at, message);
        Ok(())
    }

    /// The rows of one conversation, oldest first.
    pub fn messages(&self, conversation_id: &str) -> Vec<&E2eMessage> {
        self.messages
            .iter()
            .filter(|message| message.conversation_id == conversation_id)
            .collect()
    }

    /// Case-insensitive search in memory, oldest first. `None` searches
    /// every E2E conversation; normal IRC history is never part of it.
    pub fn search(&self, conversation_id: Option<&str>, needle: &str) -> Vec<&E2eMessage> {
        let needle = fold_case(needle);
        if needle.is_empty() {
            return Vec::new();
        }
        self.messages
            .iter()
            .filter(|message| conversation_id.is_none_or(|id| message.conversation_id == id))
            .filter(|message| fold_case(&message.text).contains(&needle))
            .collect()
    }

    /// Ids of the conversations that have rows, in order of first row.
    pub fn conversation_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        for message in &self.messages {
            if !ids.contains(&message.conversation_id) {
                ids.push(message.conversation_id.clone());
            }
        }
        ids
    }

    /// Removes the rows of one conversation. The caller asks the user to
    /// confirm first.
    pub fn delete_conversation(&mut self, conversation_id: &str) -> Result<(), E2eStoreError> {
        let kept: Vec<E2eMessage> = self
            .messages
            .iter()
            .filter(|message| message.conversation_id != conversation_id)
            .cloned()
            .collect();
        if let Err(err) = self.rewrite_file(&kept) {
            wipe(kept);
            return Err(err);
        }
        self.records = kept.len() as u64;
        wipe(std::mem::replace(&mut self.messages, kept));
        Ok(())
    }

    /// Removes the whole history file. The caller asks the user to confirm
    /// first.
    pub fn delete_all(&mut self) -> Result<(), E2eStoreError> {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        self.records = 0;
        wipe(std::mem::take(&mut self.messages));
        Ok(())
    }

    /// Overwrites the decrypted rows in memory.
    pub fn close(mut self) {
        wipe(std::mem::take(&mut self.messages));
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::<XChaCha20Poly1305>::from(self.key))
    }

    /// Seals one row as `[length][nonce][ciphertext]`. The record index is
    /// part of the associated data, so records cannot be swapped.
    fn seal_record(&self, message: &E2eMessage, index: u64) -> Result<Vec<u8>, E2eStoreError> {
        let mut plain = serde_json::to_vec(message).map_err(io::Error::other)?;
        let nonce = Nonce::<XChaCha20Poly1305>::generate();
        let sealed = self.cipher().encrypt(
            &nonce,
            Payload {
                msg: &plain,
                aad: &record_aad(index),
            },
        );
        plain.zeroize();
        let sealed = sealed.map_err(|_| E2eStoreError::Corrupted)?;
        let len = u32::try_from(sealed.len()).map_err(|_| E2eStoreError::Corrupted)?;
        let mut out = Vec::with_capacity(LEN_FIELD + NONCE_LEN + sealed.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn read_file(&self) -> Result<(Vec<E2eMessage>, u64), E2eStoreError> {
        let data = fs::read(&self.path)?;
        let mut rows = Vec::new();
        if let Err(err) = self.read_records(&data, &mut rows) {
            wipe(rows);
            return Err(err);
        }
        let records = rows.len() as u64;
        rows.sort_by_key(|row| row.sent_at);
        Ok((rows, records))
    }

    fn read_records(&self, data: &[u8], rows: &mut Vec<E2eMessage>) -> Result<(), E2eStoreError> {
        let corrupted = || E2eStoreError::Corrupted;
        if !data.starts_with(MAGIC) {
            return Err(corrupted());
        }
        let cipher = self.cipher();
        let mut rest = &data[MAGIC.len()..];
        while !rest.is_empty() {
            if rest.len() < LEN_FIELD + NONCE_LEN {
                return Err(corrupted());
            }
            let len = u32::from_le_bytes(
                <[u8; LEN_FIELD]>::try_from(&rest[..LEN_FIELD]).map_err(|_| corrupted())?,
            ) as usize;
            let body = &rest[LEN_FIELD..];
            if body.len() - NONCE_LEN < len {
                return Err(corrupted());
            }
            let nonce = Nonce::<XChaCha20Poly1305>::try_from(&body[..NONCE_LEN])
                .map_err(|_| corrupted())?;
            let sealed = &body[NONCE_LEN..NONCE_LEN + len];
            let mut plain = cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: sealed,
                        aad: &record_aad(rows.len() as u64),
                    },
                )
                .map_err(|_| corrupted())?;
            let parsed = serde_json::from_slice(&plain).map_err(|_| corrupted());
            plain.zeroize();
            rows.push(parsed?);
            rest = &body[NONCE_LEN + len..];
        }
        Ok(())
    }

    /// Writes one record at the end of the file. A failed write cuts the
    /// file back to its old length.
    fn append_record(&self, record: &[u8]) -> Result<(), E2eStoreError> {
        if !self.path.exists() {
            write_atomic(&self.path, MAGIC)?;
        }
        let mut file = OpenOptions::new().write(true).open(&self.path)?;
        let old_len = file.seek(SeekFrom::End(0))?;
        let written = file.write_all(record).and_then(|()| file.sync_data());
        if let Err(err) = written {
            let _ = file.set_len(old_len);
            return Err(err.into());
        }
        Ok(())
    }

    /// Replaces the file with one record for each of `rows`.
    fn rewrite_file(&self, rows: &[E2eMessage]) -> Result<(), E2eStoreError> {
        let mut out = MAGIC.to_vec();
        for (index, row) in rows.iter().enumerate() {
            out.extend_from_slice(&self.seal_record(row, index as u64)?);
        }
        write_atomic(&self.path, &out)?;
        Ok(())
    }
}

/// Unicode default full case folding, so that `Straße` and `STRASSE`
/// compare equal.
fn fold_case(text: &str) -> String {
    caseless::default_case_fold_str(text)
}

fn record_aad(index: u64) -> Vec<u8> {
    let mut aad = MAGIC.to_vec();
    aad.extend_from_slice(&index.to_le_bytes());
    aad
}

impl Drop for E2eHistoryStore {
    fn drop(&mut self) {
        self.key.zeroize();
        wipe(std::mem::take(&mut self.messages));
    }
}

fn wipe(messages: Vec<E2eMessage>) {
    for mut message in messages {
        message.text.zeroize();
    }
}

/// The path of the history file, for the delete prompt.
pub fn history_file_path() -> Option<PathBuf> {
    data_dir().map(|dir| dir.join(HISTORY_FILE_NAME))
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
            "cordiale-e2e-store-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn message_at(id: &str, conversation: &str, text: &str, sent_at: i64) -> E2eMessage {
        E2eMessage {
            id: id.to_string(),
            conversation_id: conversation.to_string(),
            sender_device: "device-a".to_string(),
            sent_at,
            text: text.to_string(),
        }
    }

    fn message(id: &str, conversation: &str, text: &str) -> E2eMessage {
        message_at(id, conversation, text, 1)
    }

    #[test]
    fn history_is_encrypted_at_rest_and_reloads() {
        let dir = scratch_dir("roundtrip");
        let path = dir.join("history.bin");
        let provider = fresh_key();
        let mut store = E2eHistoryStore::open(path.clone(), &provider).expect("open");
        store
            .append(message("1", "conv-1", "needle-in-clear"))
            .expect("append");
        let raw = fs::read(&path).expect("read file");
        assert!(!String::from_utf8_lossy(&raw).contains("needle-in-clear"));
        assert!(!String::from_utf8_lossy(&raw).contains("conv-1"));
        store.close();

        let store = E2eHistoryStore::open(path, &provider).expect("reopen");
        assert_eq!(store.messages("conv-1").len(), 1);
        assert_eq!(store.messages("conv-1")[0].text, "needle-in-clear");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_store_starts_empty() {
        let dir = scratch_dir("empty");
        let store = E2eHistoryStore::open(dir.join("history.bin"), &fresh_key()).expect("open");
        assert!(store.conversation_ids().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_secure_storage_fails_closed() {
        let dir = scratch_dir("closed");
        let path = dir.join("history.bin");
        let result = E2eHistoryStore::open(path.clone(), &NoKeyring);
        assert!(matches!(
            result,
            Err(E2eStoreError::SecureStorageUnavailable)
        ));
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrong_key_or_damaged_file_is_an_error_and_keeps_the_file() {
        let dir = scratch_dir("wrong-key");
        let path = dir.join("history.bin");
        let provider = fresh_key();
        let mut store = E2eHistoryStore::open(path.clone(), &provider).expect("open");
        store.append(message("1", "c", "secret")).expect("append");
        store.close();
        let before = fs::read(&path).expect("read");

        let wrong = E2eHistoryStore::open(path.clone(), &fresh_key());
        assert!(matches!(wrong, Err(E2eStoreError::Corrupted)));
        assert_eq!(fs::read(&path).expect("read"), before);

        let mut damaged = before.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 0xff;
        fs::write(&path, damaged).expect("write");
        let result = E2eHistoryStore::open(path, &provider);
        assert!(matches!(result, Err(E2eStoreError::Corrupted)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_cut_short_is_an_error() {
        let dir = scratch_dir("cut-short");
        let path = dir.join("history.bin");
        let provider = fresh_key();
        let mut store = E2eHistoryStore::open(path.clone(), &provider).expect("open");
        store.append(message("1", "c", "one")).expect("append");
        store.close();
        let mut data = fs::read(&path).expect("read");
        data.truncate(data.len() - 3);
        fs::write(&path, data).expect("write");
        let result = E2eHistoryStore::open(path, &provider);
        assert!(matches!(result, Err(E2eStoreError::Corrupted)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_write_does_not_keep_the_row() {
        let dir = scratch_dir("write-fails");
        let path = dir.join("history.bin");
        let mut store = E2eHistoryStore::open(path.clone(), &fresh_key()).expect("open");
        fs::create_dir(&path).expect("directory in the way");
        assert!(store.append(message("1", "c", "text")).is_err());
        assert!(store.messages("c").is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_runs_in_memory_over_one_or_all_conversations() {
        let dir = scratch_dir("search");
        let mut store = E2eHistoryStore::open(dir.join("history.bin"), &fresh_key()).expect("open");
        store.append(message("1", "a", "Hello World")).expect("a");
        store.append(message("2", "b", "world peace")).expect("b");
        assert_eq!(store.search(None, "WORLD").len(), 2);
        assert_eq!(store.search(Some("a"), "world").len(), 1);
        assert!(store.search(None, "").is_empty());
        assert!(store.search(None, "absent").is_empty());
        let mut names: Vec<String> = fs::read_dir(&dir)
            .expect("list")
            .map(|entry| entry.expect("entry").file_name().to_string_lossy().into())
            .collect();
        names.sort();
        assert_eq!(names, ["history.bin", "history.bin.lock"]);
        // The lock is held, and Windows refuses to read a locked file: check
        // the length from the metadata.
        let lock_len = fs::metadata(dir.join("history.bin.lock"))
            .expect("lock metadata")
            .len();
        assert_eq!(lock_len, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_folds_case_beyond_lowercase() {
        let dir = scratch_dir("fold");
        let mut store = E2eHistoryStore::open(dir.join("history.bin"), &fresh_key()).expect("open");
        store.append(message("1", "a", "Die Straße")).expect("a");
        assert_eq!(store.search(None, "STRASSE").len(), 1);
        assert_eq!(store.search(None, "straße").len(), 1);
        store.append(message("2", "a", "a ﬀ b")).expect("b");
        assert_eq!(store.search(None, "A FF B").len(), 1);
        store.append(message("3", "a", "micro µ")).expect("c");
        assert_eq!(store.search(None, "MICRO Μ").len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rows_come_back_in_order_of_sent_at() {
        let dir = scratch_dir("order");
        let path = dir.join("history.bin");
        let provider = fresh_key();
        let mut store = E2eHistoryStore::open(path.clone(), &provider).expect("open");
        store
            .append(message_at("late", "c", "second", 2))
            .expect("late");
        store
            .append(message_at("early", "c", "first", 1))
            .expect("early");
        let ids: Vec<&str> = store.messages("c").iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, ["early", "late"]);
        store.close();

        let store = E2eHistoryStore::open(path, &provider).expect("reopen");
        let ids: Vec<&str> = store.messages("c").iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, ["early", "late"]);
        let found: Vec<&str> = store
            .search(None, "s")
            .iter()
            .map(|m| m.id.as_str())
            .collect();
        assert_eq!(found, ["early", "late"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_handle_on_the_same_history_is_refused() {
        let dir = scratch_dir("in-use");
        let path = dir.join("history.bin");
        let provider = fresh_key();
        let store = E2eHistoryStore::open(path.clone(), &provider).expect("open");
        let second = E2eHistoryStore::open(path.clone(), &provider);
        assert!(matches!(second, Err(E2eStoreError::InUse)));
        store.close();
        E2eHistoryStore::open(path, &provider).expect("open after close");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn many_appends_survive_a_reopen_and_each_adds_one_record() {
        let dir = scratch_dir("appends");
        let path = dir.join("history.bin");
        let provider = fresh_key();
        let mut store = E2eHistoryStore::open(path.clone(), &provider).expect("open");
        store.append(message("1", "a", "one")).expect("one");
        let first_size = fs::metadata(&path).expect("size").len();
        store.append(message("2", "a", "two")).expect("two");
        store.append(message("3", "b", "three")).expect("three");
        let size = fs::metadata(&path).expect("size").len();
        assert!(size > first_size);
        store.close();

        let store = E2eHistoryStore::open(path, &provider).expect("reopen");
        assert_eq!(store.messages("a").len(), 2);
        assert_eq!(store.messages("b").len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_conversation_removes_only_that_conversation() {
        let dir = scratch_dir("delete-one");
        let path = dir.join("history.bin");
        let provider = fresh_key();
        let mut store = E2eHistoryStore::open(path.clone(), &provider).expect("open");
        store.append(message("1", "a", "one")).expect("a");
        store.append(message("2", "b", "two")).expect("b");
        store.delete_conversation("a").expect("delete");
        store.append(message("3", "b", "three")).expect("b again");
        store.close();
        let store = E2eHistoryStore::open(path, &provider).expect("reopen");
        assert_eq!(store.conversation_ids(), ["b"]);
        assert_eq!(store.messages("b").len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A store that is slow between the read and the write.
    struct SlowStore(std::sync::Mutex<Option<String>>);

    impl CredentialStore for SlowStore {
        fn set_secret(
            &self,
            _service: &str,
            _username: &str,
            secret: &str,
        ) -> Result<(), crate::credentials::CredentialError> {
            *self.0.lock().expect("store") = Some(secret.to_string());
            Ok(())
        }

        fn get_secret(
            &self,
            _service: &str,
            _username: &str,
        ) -> Result<Option<String>, crate::credentials::CredentialError> {
            let value = self.0.lock().expect("store").clone();
            std::thread::sleep(std::time::Duration::from_millis(100));
            Ok(value)
        }

        fn delete_secret(
            &self,
            _service: &str,
            _username: &str,
        ) -> Result<(), crate::credentials::CredentialError> {
            Ok(())
        }
    }

    #[test]
    fn concurrent_key_creation_gives_one_key() {
        let dir = scratch_dir("keylock");
        let lock_path = dir.join("key.lock");
        let store = SlowStore(std::sync::Mutex::new(None));
        let (first, second) = std::thread::scope(|scope| {
            let a = scope.spawn(|| load_or_create_locked(&lock_path, "user", &store));
            let b = scope.spawn(|| load_or_create_locked(&lock_path, "user", &store));
            (a.join().expect("a"), b.join().expect("b"))
        });
        assert_eq!(first.expect("first"), second.expect("second"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_username_depends_on_the_folder_only() {
        let first = key_username(Path::new("data-a"));
        assert_eq!(first, key_username(Path::new("data-a")));
        assert_ne!(first, key_username(Path::new("data-b")));
        assert!(first.starts_with(KEY_USERNAME));
        assert!(!first.contains("data-a"));
    }

    #[test]
    fn delete_all_removes_the_file() {
        let dir = scratch_dir("delete-all");
        let path = dir.join("history.bin");
        let mut store = E2eHistoryStore::open(path.clone(), &fresh_key()).expect("open");
        store.append(message("1", "a", "one")).expect("a");
        store.delete_all().expect("delete");
        assert!(!path.exists());
        assert!(store.conversation_ids().is_empty());
        store.delete_all().expect("delete again");
        let _ = fs::remove_dir_all(&dir);
    }
}
