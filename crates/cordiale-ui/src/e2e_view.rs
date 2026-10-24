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

//! Data for the E2E views: the state of one message, local history search
//! and the delete confirmation. This module reads the sealed history of
//! the core and holds no crypto and no wire rule. The Slint views and the
//! worker commands use it; the store calls run on the worker thread, never
//! on the Slint event thread.

// The views and the worker commands that call this module are a later step.
#![allow(dead_code)]

use cordiale_core::e2e_store::{E2eHistoryStore, E2eMessage, E2eStoreError};

/// What the user sees for one E2E message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageState {
    /// Decrypted and checked.
    Encrypted,
    /// Waiting for a key or a device list.
    Pending,
    /// Decryption or a check failed.
    Failed,
    /// The text is not on this device.
    Unavailable,
}

impl MessageState {
    /// The `status-kind` style key that selects the translated label.
    pub fn key(self) -> &'static str {
        match self {
            MessageState::Encrypted => "e2e-state-encrypted",
            MessageState::Pending => "e2e-state-pending",
            MessageState::Failed => "e2e-state-failed",
            MessageState::Unavailable => "e2e-state-unavailable",
        }
    }

    /// Parses a key from `key`; any other text is `None`.
    pub fn from_key(key: &str) -> Option<MessageState> {
        [
            MessageState::Encrypted,
            MessageState::Pending,
            MessageState::Failed,
            MessageState::Unavailable,
        ]
        .into_iter()
        .find(|state| state.key() == key)
    }

    /// Only an encrypted message shows its text.
    pub fn shows_text(self) -> bool {
        self == MessageState::Encrypted
    }
}

/// The local data a delete removes. The view shows it before the user
/// confirms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletePlan {
    /// `Some` for one conversation, `None` for the whole E2E history.
    pub conversation_id: Option<String>,
    pub conversations: usize,
    pub messages: usize,
}

/// Counts what `delete_conversation` (or `delete_all` when `conversation_id`
/// is `None`) would remove. It changes nothing.
pub fn delete_plan(store: &E2eHistoryStore, conversation_id: Option<&str>) -> DeletePlan {
    match conversation_id {
        Some(id) => {
            let messages = store.messages(id).len();
            DeletePlan {
                conversation_id: Some(id.to_string()),
                conversations: usize::from(messages > 0),
                messages,
            }
        }
        None => {
            let ids = store.conversation_ids();
            let messages = ids.iter().map(|id| store.messages(id).len()).sum();
            DeletePlan {
                conversation_id: None,
                conversations: ids.len(),
                messages,
            }
        }
    }
}

/// Runs a confirmed delete. `confirmed` is false until the user accepts the
/// plan, and then nothing is removed. Only the named data goes.
pub fn delete_confirmed(
    store: &mut E2eHistoryStore,
    plan: &DeletePlan,
    confirmed: bool,
) -> Result<bool, E2eStoreError> {
    if !confirmed {
        return Ok(false);
    }
    match &plan.conversation_id {
        Some(id) => store.delete_conversation(id)?,
        None => store.delete_all()?,
    }
    Ok(true)
}

/// Local search for the history view. The core folds the case, so the
/// result follows its Unicode rules. Nothing leaves the device.
pub fn search_history<'a>(
    store: &'a E2eHistoryStore,
    conversation_id: Option<&str>,
    needle: &str,
) -> Vec<&'a E2eMessage> {
    store.search(conversation_id, needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{Generate, Key};
    use chacha20poly1305::XChaCha20Poly1305;
    use cordiale_core::e2e_store::E2eKeyProvider;

    struct FixedKey([u8; 32]);

    impl E2eKeyProvider for FixedKey {
        fn load_or_create_key(&self) -> Result<[u8; 32], E2eStoreError> {
            Ok(self.0)
        }
    }

    /// A random key for one test; no key is written in the source.
    fn fresh_key() -> FixedKey {
        let key = Key::<XChaCha20Poly1305>::generate();
        FixedKey(<[u8; 32]>::try_from(key.as_slice()).expect("key length"))
    }

    fn row(id: &str, conversation: &str, at: i64, text: &str) -> E2eMessage {
        E2eMessage {
            id: id.into(),
            conversation_id: conversation.into(),
            sender_device: "device".into(),
            sent_at: at,
            text: text.into(),
        }
    }

    fn open(dir: &tempfile::TempDir) -> E2eHistoryStore {
        E2eHistoryStore::open(dir.path().join("history.bin"), &fresh_key()).expect("open")
    }

    #[test]
    fn message_states_have_distinct_keys_and_only_encrypted_shows_text() {
        let all = [
            MessageState::Encrypted,
            MessageState::Pending,
            MessageState::Failed,
            MessageState::Unavailable,
        ];
        for state in all {
            assert_eq!(MessageState::from_key(state.key()), Some(state));
            assert_eq!(state.shows_text(), state == MessageState::Encrypted);
        }
        let mut keys: Vec<&str> = all.iter().map(|state| state.key()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), all.len());
        assert_eq!(MessageState::from_key("other"), None);
    }

    #[test]
    fn delete_plan_counts_only_the_named_data() {
        let dir = tempfile::tempdir().expect("dir");
        let mut store = open(&dir);
        store.append(row("1", "a", 1, "one")).expect("append");
        store.append(row("2", "a", 2, "two")).expect("append");
        store.append(row("3", "b", 3, "three")).expect("append");

        let one = delete_plan(&store, Some("a"));
        assert_eq!((one.conversations, one.messages), (1, 2));
        let all = delete_plan(&store, None);
        assert_eq!((all.conversations, all.messages), (2, 3));
        let none = delete_plan(&store, Some("missing"));
        assert_eq!((none.conversations, none.messages), (0, 0));
    }

    #[test]
    fn delete_needs_confirmation_and_keeps_other_conversations() {
        let dir = tempfile::tempdir().expect("dir");
        let mut store = open(&dir);
        store.append(row("1", "a", 1, "one")).expect("append");
        store.append(row("2", "b", 2, "two")).expect("append");
        let plan = delete_plan(&store, Some("a"));

        assert!(!delete_confirmed(&mut store, &plan, false).expect("declined"));
        assert_eq!(store.messages("a").len(), 1);

        assert!(delete_confirmed(&mut store, &plan, true).expect("confirmed"));
        assert!(store.messages("a").is_empty());
        assert_eq!(store.messages("b").len(), 1);
    }

    #[test]
    fn search_is_local_and_ignores_case() {
        let dir = tempfile::tempdir().expect("dir");
        let mut store = open(&dir);
        store
            .append(row("1", "a", 1, "Hello World"))
            .expect("append");
        store.append(row("2", "b", 2, "other")).expect("append");
        assert_eq!(search_history(&store, None, "hello").len(), 1);
        assert!(search_history(&store, Some("b"), "hello").is_empty());
        assert!(search_history(&store, None, "").is_empty());
    }
}
