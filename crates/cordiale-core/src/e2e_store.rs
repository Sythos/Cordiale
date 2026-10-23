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
//! The history lives in one file, sealed with XChaCha20-Poly1305. The key
//! comes from the native OS keyring only: the store never uses the
//! obfuscated fallback of `credentials.rs`, and it fails closed when no
//! keyring is reachable. Search runs on the decrypted rows in memory; no
//! index, cache or temporary copy of the clear text goes to disk. This file
//! is kept apart from `settings.json` and from the normal history.

use std::fs;
use std::io;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Generate, Key, KeyInit, Nonce, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::credentials::{CredentialStore, KeyringCredentialStore};
use crate::persistence::{create_private_dir_all, data_dir, write_atomic};

const HISTORY_FILE_NAME: &str = "e2e_history.bin";
const KEY_SERVICE: &str = "cordiale-e2e";
const KEY_USERNAME: &str = "history-key";
const KEY_LEN: usize = 32;
/// File header; also bound to every ciphertext as associated data.
const MAGIC: &[u8] = b"CORDIALE-E2E-HISTORY-1";
const NONCE_LEN: usize = 24;

#[derive(Debug)]
pub enum E2eStoreError {
    /// No secure place for the key: the store refuses to work.
    SecureStorageUnavailable,
    /// The key store answered with a failure.
    Key(String),
    NoDataDir,
    /// The history file does not open with the key (damaged or wrong key).
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
        let keyring = KeyringCredentialStore;
        let stored = keyring
            .get_secret(KEY_SERVICE, KEY_USERNAME)
            .map_err(|err| E2eStoreError::Key(format!("{err:?}")))?;
        if let Some(text) = stored {
            return decode_key(&text);
        }
        let key = Key::<XChaCha20Poly1305>::generate();
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(key.as_slice());
        let mut text = STANDARD_NO_PAD.encode(bytes);
        let result = keyring
            .set_secret(KEY_SERVICE, KEY_USERNAME, &text)
            .map_err(|err| E2eStoreError::Key(format!("{err:?}")));
        text.zeroize();
        match result {
            Ok(()) => Ok(bytes),
            Err(err) => {
                bytes.zeroize();
                Err(err)
            }
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
/// drop, which overwrite the texts.
pub struct E2eHistoryStore {
    path: PathBuf,
    key: [u8; KEY_LEN],
    messages: Vec<E2eMessage>,
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
    /// open is an error: it is never replaced by an empty history.
    pub fn open(path: PathBuf, provider: &dyn E2eKeyProvider) -> Result<Self, E2eStoreError> {
        let key = provider.load_or_create_key()?;
        let mut store = E2eHistoryStore {
            path,
            key,
            messages: Vec::new(),
        };
        if store.path.exists() {
            store.messages = store.read_file()?;
        }
        Ok(store)
    }

    /// Adds one row and writes the sealed file. On a write failure the
    /// row is not kept.
    pub fn append(&mut self, message: E2eMessage) -> Result<(), E2eStoreError> {
        self.messages.push(message);
        if let Err(err) = self.write_file() {
            if let Some(mut dropped) = self.messages.pop() {
                dropped.text.zeroize();
            }
            return Err(err);
        }
        Ok(())
    }

    /// The rows of one conversation, oldest first.
    pub fn messages(&self, conversation_id: &str) -> Vec<&E2eMessage> {
        self.messages
            .iter()
            .filter(|message| message.conversation_id == conversation_id)
            .collect()
    }

    /// Case-insensitive search in memory. `None` searches every E2E
    /// conversation; normal IRC history is never part of it.
    pub fn search(&self, conversation_id: Option<&str>, needle: &str) -> Vec<&E2eMessage> {
        let needle = needle.to_lowercase();
        if needle.is_empty() {
            return Vec::new();
        }
        self.messages
            .iter()
            .filter(|message| conversation_id.is_none_or(|id| message.conversation_id == id))
            .filter(|message| message.text.to_lowercase().contains(&needle))
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
        let old = std::mem::replace(&mut self.messages, kept);
        if let Err(err) = self.write_file() {
            self.messages = old;
            return Err(err);
        }
        wipe(old);
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

    fn read_file(&self) -> Result<Vec<E2eMessage>, E2eStoreError> {
        let data = fs::read(&self.path)?;
        if data.len() < MAGIC.len() + NONCE_LEN || !data.starts_with(MAGIC) {
            return Err(E2eStoreError::Corrupted);
        }
        let (nonce, sealed) = data[MAGIC.len()..].split_at(NONCE_LEN);
        let nonce =
            Nonce::<XChaCha20Poly1305>::try_from(nonce).map_err(|_| E2eStoreError::Corrupted)?;
        let mut plain = self
            .cipher()
            .decrypt(
                &nonce,
                Payload {
                    msg: sealed,
                    aad: MAGIC,
                },
            )
            .map_err(|_| E2eStoreError::Corrupted)?;
        let parsed = serde_json::from_slice(&plain).map_err(|_| E2eStoreError::Corrupted);
        plain.zeroize();
        parsed
    }

    fn write_file(&self) -> Result<(), E2eStoreError> {
        let mut plain = serde_json::to_vec(&self.messages).map_err(io::Error::other)?;
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
        if let Some(parent) = self.path.parent() {
            create_private_dir_all(parent)?;
        }
        write_atomic(&self.path, &out)?;
        Ok(())
    }
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

    fn message(id: &str, conversation: &str, text: &str) -> E2eMessage {
        E2eMessage {
            id: id.to_string(),
            conversation_id: conversation.to_string(),
            sender_device: "device-a".to_string(),
            sent_at: 1,
            text: text.to_string(),
        }
    }

    #[test]
    fn history_is_encrypted_at_rest_and_reloads() {
        let dir = scratch_dir("roundtrip");
        let path = dir.join("history.bin");
        let provider = FixedKey([7; KEY_LEN]);
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
        let store =
            E2eHistoryStore::open(dir.join("history.bin"), &FixedKey([1; KEY_LEN])).expect("open");
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
        let mut store = E2eHistoryStore::open(path.clone(), &FixedKey([2; KEY_LEN])).expect("open");
        store.append(message("1", "c", "secret")).expect("append");
        store.close();
        let before = fs::read(&path).expect("read");

        let wrong = E2eHistoryStore::open(path.clone(), &FixedKey([3; KEY_LEN]));
        assert!(matches!(wrong, Err(E2eStoreError::Corrupted)));
        assert_eq!(fs::read(&path).expect("read"), before);

        let mut damaged = before.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 0xff;
        fs::write(&path, damaged).expect("write");
        let result = E2eHistoryStore::open(path, &FixedKey([2; KEY_LEN]));
        assert!(matches!(result, Err(E2eStoreError::Corrupted)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_write_does_not_keep_the_row() {
        let dir = scratch_dir("write-fails");
        let path = dir.join("history.bin");
        let mut store = E2eHistoryStore::open(path.clone(), &FixedKey([4; KEY_LEN])).expect("open");
        fs::create_dir(&path).expect("directory in the way");
        assert!(store.append(message("1", "c", "text")).is_err());
        assert!(store.messages("c").is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_runs_in_memory_over_one_or_all_conversations() {
        let dir = scratch_dir("search");
        let mut store =
            E2eHistoryStore::open(dir.join("history.bin"), &FixedKey([5; KEY_LEN])).expect("open");
        store.append(message("1", "a", "Hello World")).expect("a");
        store.append(message("2", "b", "world peace")).expect("b");
        assert_eq!(store.search(None, "WORLD").len(), 2);
        assert_eq!(store.search(Some("a"), "world").len(), 1);
        assert!(store.search(None, "").is_empty());
        assert!(store.search(None, "absent").is_empty());
        let names: Vec<String> = fs::read_dir(&dir)
            .expect("list")
            .map(|entry| entry.expect("entry").file_name().to_string_lossy().into())
            .collect();
        assert_eq!(names, ["history.bin"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_conversation_removes_only_that_conversation() {
        let dir = scratch_dir("delete-one");
        let path = dir.join("history.bin");
        let provider = FixedKey([6; KEY_LEN]);
        let mut store = E2eHistoryStore::open(path.clone(), &provider).expect("open");
        store.append(message("1", "a", "one")).expect("a");
        store.append(message("2", "b", "two")).expect("b");
        store.delete_conversation("a").expect("delete");
        store.close();
        let store = E2eHistoryStore::open(path, &provider).expect("reopen");
        assert_eq!(store.conversation_ids(), ["b"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_all_removes_the_file() {
        let dir = scratch_dir("delete-all");
        let path = dir.join("history.bin");
        let mut store = E2eHistoryStore::open(path.clone(), &FixedKey([8; KEY_LEN])).expect("open");
        store.append(message("1", "a", "one")).expect("a");
        store.delete_all().expect("delete");
        assert!(!path.exists());
        assert!(store.conversation_ids().is_empty());
        store.delete_all().expect("delete again");
        let _ = fs::remove_dir_all(&dir);
    }
}
