//! Keeps read-cursor updates that the server has not confirmed yet.
//!
//! The local cursor moves at once. The server copy moves only after the POST
//! succeeds or a matching `read_cursor_set` push arrives. A failed or
//! ambiguous POST leaves the update pending, and a later flush sends it
//! again. All updates are forward-only, so a repeated send is safe.

use std::collections::HashMap;
use std::time::Duration;

/// Sends for one window before the retry task stops. The next flush starts a
/// new task, so a reconnect or a new read resumes the work.
pub(crate) const MAX_SEND_ATTEMPTS: u32 = 5;

/// Longest wait between two sends of the same cursor.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Window key: network slug and ASCII-folded target.
pub(crate) type WindowKey = (String, String);

/// A cursor that the server has not confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingReadCursor {
    /// Target as the server needs it in the request path.
    pub(crate) target: String,
    pub(crate) message_id: i64,
    /// True while one task owns the sending of this window.
    pub(crate) in_flight: bool,
}

/// One send job for a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadCursorSend {
    pub(crate) network: String,
    pub(crate) target: String,
    pub(crate) message_id: i64,
}

#[derive(Debug, Default)]
pub(crate) struct ReadCursorSync {
    pending: HashMap<WindowKey, PendingReadCursor>,
}

/// Delay before send number `attempt` (1 is the first retry): 1 s, 2 s, 4 s,
/// and so on, up to 30 s.
pub(crate) fn retry_delay(attempt: u32) -> Duration {
    let seconds = 1u64 << attempt.saturating_sub(1).min(5);
    Duration::from_secs(seconds).min(MAX_RETRY_DELAY)
}

impl ReadCursorSync {
    /// Records an update for a window. A pending update keeps the newest ID,
    /// so a lower ID never replaces a higher one.
    pub(crate) fn queue(&mut self, key: WindowKey, target: &str, message_id: i64) {
        match self.pending.get_mut(&key) {
            Some(entry) => {
                if message_id > entry.message_id {
                    entry.message_id = message_id;
                    entry.target = target.to_string();
                }
            }
            None => {
                self.pending.insert(
                    key,
                    PendingReadCursor {
                        target: target.to_string(),
                        message_id,
                        in_flight: false,
                    },
                );
            }
        }
    }

    /// Takes the windows that have a pending update and no running task. The
    /// caller starts one task for each returned key.
    pub(crate) fn take_idle(&mut self) -> Vec<WindowKey> {
        let mut keys = Vec::new();
        for (key, entry) in &mut self.pending {
            if !entry.in_flight {
                entry.in_flight = true;
                keys.push(key.clone());
            }
        }
        keys.sort();
        keys
    }

    /// The update to send now for a window, or `None` when nothing is
    /// pending. Then the task owner stops and the window becomes idle.
    pub(crate) fn next_send(&self, key: &WindowKey) -> Option<ReadCursorSend> {
        let entry = self.pending.get(key)?;
        Some(ReadCursorSend {
            network: key.0.clone(),
            target: entry.target.clone(),
            message_id: entry.message_id,
        })
    }

    /// The server answered the POST with its stored cursor. The pending
    /// update ends when the stored cursor reaches it. A newer pending ID
    /// stays. Returns true when the window has no more pending update.
    pub(crate) fn sent_ok(&mut self, key: &WindowKey, sent_id: i64, stored_id: i64) -> bool {
        let confirmed = sent_id.max(stored_id);
        self.confirm(key, confirmed);
        !self.pending.contains_key(key)
    }

    /// A matching push or response confirms a cursor. The pending update ends
    /// only when the confirmed ID is not lower than the pending ID.
    pub(crate) fn confirm(&mut self, key: &WindowKey, confirmed_id: i64) {
        if self
            .pending
            .get(key)
            .is_some_and(|entry| entry.message_id <= confirmed_id)
        {
            self.pending.remove(key);
        }
    }

    /// The task for a window stops without confirmation. A later flush starts
    /// a new task.
    pub(crate) fn release(&mut self, key: &WindowKey) {
        if let Some(entry) = self.pending.get_mut(key) {
            entry.in_flight = false;
        }
    }

    /// The pending ID of a window, if any.
    pub(crate) fn pending_id(&self, key: &WindowKey) -> Option<i64> {
        self.pending.get(key).map(|entry| entry.message_id)
    }

    /// Compares the pending updates with a fresh server snapshot. An update
    /// that the snapshot already covers ends. Returns the windows that stay
    /// pending with their IDs, so the caller keeps the local cursor there.
    pub(crate) fn reconcile(&mut self, server: &HashMap<WindowKey, i64>) -> Vec<(WindowKey, i64)> {
        self.pending.retain(|key, entry| {
            server
                .get(key)
                .is_none_or(|&cursor| cursor < entry.message_id)
        });
        let mut left: Vec<(WindowKey, i64)> = self
            .pending
            .iter()
            .map(|(key, entry)| (key.clone(), entry.message_id))
            .collect();
        left.sort();
        left
    }

    /// Forgets every pending update (identity change).
    pub(crate) fn clear(&mut self) {
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(network: &str, target: &str) -> WindowKey {
        (network.to_string(), target.to_string())
    }

    #[test]
    fn failed_post_leaves_a_pending_update_and_retry_confirms_it() {
        let mut sync = ReadCursorSync::default();
        let window = key("net", "#a");
        sync.queue(window.clone(), "#A", 10);
        assert_eq!(sync.take_idle(), vec![window.clone()]);
        let send = sync.next_send(&window).expect("pending send");
        assert_eq!(send.message_id, 10);
        assert_eq!(send.target, "#A");
        // The POST fails: nothing changes, the update stays.
        assert_eq!(sync.pending_id(&window), Some(10));
        // The retry succeeds.
        assert!(sync.sent_ok(&window, 10, 10));
        assert_eq!(sync.pending_id(&window), None);
        assert!(sync.next_send(&window).is_none());
    }

    #[test]
    fn ambiguous_timeout_stays_pending_until_a_matching_push() {
        let mut sync = ReadCursorSync::default();
        let window = key("net", "#a");
        sync.queue(window.clone(), "#a", 7);
        sync.release(&window);
        // A push for a lower ID does not confirm.
        sync.confirm(&window, 6);
        assert_eq!(sync.pending_id(&window), Some(7));
        sync.confirm(&window, 7);
        assert_eq!(sync.pending_id(&window), None);
    }

    #[test]
    fn duplicate_id_is_kept_and_sent_again_while_unconfirmed() {
        let mut sync = ReadCursorSync::default();
        let window = key("net", "#a");
        sync.queue(window.clone(), "#a", 5);
        assert_eq!(sync.take_idle().len(), 1);
        sync.release(&window);
        sync.queue(window.clone(), "#a", 5);
        assert_eq!(sync.take_idle(), vec![window.clone()]);
        assert_eq!(sync.next_send(&window).map(|send| send.message_id), Some(5));
    }

    #[test]
    fn pending_update_is_forward_only_and_out_of_order_replies_are_safe() {
        let mut sync = ReadCursorSync::default();
        let window = key("net", "#a");
        sync.queue(window.clone(), "#a", 9);
        sync.queue(window.clone(), "#a", 4);
        assert_eq!(sync.pending_id(&window), Some(9));
        // A late reply for an older ID does not end the newer update.
        assert!(!sync.sent_ok(&window, 4, 4));
        assert_eq!(sync.pending_id(&window), Some(9));
        // A newer ID that arrives during a send stays after the old reply.
        sync.queue(window.clone(), "#a", 12);
        assert!(!sync.sent_ok(&window, 9, 9));
        assert_eq!(sync.pending_id(&window), Some(12));
        assert!(sync.sent_ok(&window, 12, 12));
    }

    #[test]
    fn windows_are_isolated() {
        let mut sync = ReadCursorSync::default();
        let channel = key("net", "#a");
        let query = key("net", "bob");
        let other_network = key("other", "#a");
        sync.queue(channel.clone(), "#a", 3);
        sync.queue(query.clone(), "bob", 8);
        sync.queue(other_network.clone(), "#a", 3);
        sync.confirm(&channel, 3);
        assert_eq!(sync.pending_id(&channel), None);
        assert_eq!(sync.pending_id(&query), Some(8));
        assert_eq!(sync.pending_id(&other_network), Some(3));
    }

    #[test]
    fn one_task_owns_a_window_so_flushes_do_not_start_a_storm() {
        let mut sync = ReadCursorSync::default();
        let window = key("net", "#a");
        sync.queue(window.clone(), "#a", 1);
        assert_eq!(sync.take_idle().len(), 1);
        sync.queue(window.clone(), "#a", 2);
        assert!(sync.take_idle().is_empty());
        sync.release(&window);
        assert_eq!(sync.take_idle().len(), 1);
    }

    #[test]
    fn reconnect_snapshot_keeps_unconfirmed_updates_only() {
        let mut sync = ReadCursorSync::default();
        let covered = key("net", "#a");
        let behind = key("net", "#b");
        sync.queue(covered.clone(), "#a", 5);
        sync.queue(behind.clone(), "#b", 9);
        let mut server = HashMap::new();
        server.insert(covered.clone(), 5);
        server.insert(behind.clone(), 2);
        assert_eq!(sync.reconcile(&server), vec![(behind.clone(), 9)]);
        assert_eq!(sync.pending_id(&covered), None);
        sync.release(&behind);
        assert_eq!(sync.take_idle(), vec![behind]);
    }

    #[test]
    fn retry_delay_is_bounded() {
        assert_eq!(retry_delay(1), Duration::from_secs(1));
        assert_eq!(retry_delay(2), Duration::from_secs(2));
        assert_eq!(retry_delay(3), Duration::from_secs(4));
        assert_eq!(retry_delay(100), Duration::from_secs(30));
    }
}
