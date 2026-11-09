// Copyright (c) 2026 Sythos. MIT License.

//! Per-channel input history for the compose box: Up and Down recall the
//! last submitted entries. The history lives in client memory only and is
//! separate from the unsent drafts.

use std::collections::HashMap;

/// The most entries kept for one `(network, channel)`.
pub(crate) const INPUT_HISTORY_LIMIT: usize = 8;

#[derive(Default)]
struct ChannelHistory {
    /// Submitted entries, oldest first.
    entries: Vec<String>,
    /// Index of the recalled entry while the user navigates.
    cursor: Option<usize>,
    /// The unsent text from before the first recall.
    saved: String,
}

#[derive(Default)]
pub(crate) struct InputHistory {
    channels: HashMap<(String, String), ChannelHistory>,
}

impl InputHistory {
    /// Adds a submitted entry. An empty entry is ignored.
    pub(crate) fn record(&mut self, key: &(String, String), text: &str) {
        if text.trim().is_empty() {
            return;
        }
        let history = self.channels.entry(key.clone()).or_default();
        history.entries.push(text.to_string());
        if history.entries.len() > INPUT_HISTORY_LIMIT {
            history.entries.remove(0);
        }
        history.cursor = None;
        history.saved.clear();
    }

    /// Returns the text to show after Up (`older`) or Down, or `None` when
    /// the field must stay as it is. `current` is the text in the field.
    pub(crate) fn navigate(
        &mut self,
        key: &(String, String),
        older: bool,
        current: &str,
    ) -> Option<String> {
        let history = self.channels.get_mut(key)?;
        // The field no longer shows the recalled entry: the user edited it
        // (or the window changed), so navigation ends and the text is the
        // current draft.
        if let Some(cursor) = history.cursor {
            if history.entries.get(cursor).map(String::as_str) != Some(current) {
                history.cursor = None;
            }
        }
        match (history.cursor, older) {
            (None, true) => {
                let last = history.entries.len().checked_sub(1)?;
                history.saved = current.to_string();
                history.cursor = Some(last);
                Some(history.entries[last].clone())
            }
            (Some(cursor), true) => {
                let older_index = cursor.checked_sub(1)?;
                history.cursor = Some(older_index);
                Some(history.entries[older_index].clone())
            }
            (Some(cursor), false) if cursor + 1 < history.entries.len() => {
                history.cursor = Some(cursor + 1);
                Some(history.entries[cursor + 1].clone())
            }
            (Some(_), false) => {
                history.cursor = None;
                Some(std::mem::take(&mut history.saved))
            }
            (None, false) => None,
        }
    }
}
