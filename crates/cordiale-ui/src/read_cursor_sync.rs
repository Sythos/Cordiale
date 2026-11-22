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
    /// The ticket of the task that owns the sending of a window. The owner
    /// stays when a confirmation removes the pending update, so a new update
    /// for the same window never starts a second task.
    owners: HashMap<WindowKey, u64>,
    next_ticket: u64,
}

/// Whether the server refused a send because the query window is closed
/// (`422 no_query_window`). Such a refusal is final: a retry gets the same
/// answer.
pub(crate) fn is_closed_query_error(err: &cordiale_core::client::GrappaClientError) -> bool {
    err.status().map(|status| status.as_u16()) == Some(422) && err.code() == Some("no_query_window")
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
                    },
                );
            }
        }
    }

    /// Takes the windows that have a pending update and no owner task. Each
    /// window gets a new ticket. The caller starts one task for each returned
    /// key and ticket.
    pub(crate) fn take_idle(&mut self) -> Vec<(WindowKey, u64)> {
        let mut keys: Vec<WindowKey> = self
            .pending
            .keys()
            .filter(|key| !self.owners.contains_key(*key))
            .cloned()
            .collect();
        keys.sort();
        let mut taken = Vec::new();
        for key in keys {
            self.next_ticket += 1;
            self.owners.insert(key.clone(), self.next_ticket);
            taken.push((key, self.next_ticket));
        }
        taken
    }

    /// The update to send now for a window, or `None` when the ticket does
    /// not own the window or nothing is pending. With nothing pending, the
    /// owner ends in the same call, so a new update cannot be lost.
    pub(crate) fn next_send(&mut self, key: &WindowKey, ticket: u64) -> Option<ReadCursorSend> {
        if self.owners.get(key) != Some(&ticket) {
            return None;
        }
        let Some(entry) = self.pending.get(key) else {
            self.owners.remove(key);
            return None;
        };
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

    /// The server refused a send because the query window no longer exists.
    /// The pending update ends only when its ID is not newer than the sent
    /// ID. A newer pending ID stays. Returns true when an update ended.
    pub(crate) fn reject(&mut self, key: &WindowKey, sent_id: i64) -> bool {
        if self
            .pending
            .get(key)
            .is_some_and(|entry| entry.message_id <= sent_id)
        {
            self.pending.remove(key);
            return true;
        }
        false
    }

    /// The window is closed: its pending update ends, whatever its ID.
    pub(crate) fn retire(&mut self, key: &WindowKey) {
        self.pending.remove(key);
    }

    /// The task for a window stops without confirmation. A later flush starts
    /// a new task. A task with an old ticket changes nothing.
    pub(crate) fn release(&mut self, key: &WindowKey, ticket: u64) {
        if self.owners.get(key) == Some(&ticket) {
            self.owners.remove(key);
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

    /// Forgets every pending update and owner (identity change). A task of
    /// the old identity gets `None` and stops.
    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.owners.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(network: &str, target: &str) -> WindowKey {
        (network.to_string(), target.to_string())
    }

    #[test]
    fn closed_query_refusal_ends_only_the_matching_update() {
        let mut sync = ReadCursorSync::default();
        let closed = key("net", "alice");
        let other = key("net", "bob");
        let channel = key("net", "#a");
        sync.queue(closed.clone(), "alice", 10);
        sync.queue(other.clone(), "bob", 7);
        sync.queue(channel.clone(), "#a", 5);
        // A newer value arrived while the send of 10 was in flight.
        sync.queue(closed.clone(), "alice", 12);
        assert!(!sync.reject(&closed, 10));
        assert_eq!(sync.pending_id(&closed), Some(12));
        // The refusal of the newer value ends it.
        assert!(sync.reject(&closed, 12));
        assert_eq!(sync.pending_id(&closed), None);
        assert_eq!(sync.pending_id(&other), Some(7));
        assert_eq!(sync.pending_id(&channel), Some(5));
    }

    #[test]
    fn rejected_cursor_does_not_return_after_reconnect() {
        let mut sync = ReadCursorSync::default();
        let closed = key("net", "alice");
        let other = key("net", "bob");
        sync.queue(closed.clone(), "alice", 10);
        sync.queue(other.clone(), "bob", 7);
        assert!(sync.reject(&closed, 10));
        // The server snapshot has no cursor for the closed query.
        let server = HashMap::from([(other.clone(), 3)]);
        assert_eq!(sync.reconcile(&server), vec![(other, 7)]);
        assert_eq!(sync.pending_id(&closed), None);
    }

    #[test]
    fn retire_drops_the_update_of_a_closed_window_only() {
        let mut sync = ReadCursorSync::default();
        let closed = key("net", "alice");
        let other = key("net", "bob");
        sync.queue(closed.clone(), "alice", 10);
        sync.queue(other.clone(), "bob", 7);
        let idle = sync.take_idle();
        let ticket = idle.iter().find(|(k, _)| *k == closed).map(|(_, t)| *t);
        sync.retire(&closed);
        // The task of the closed window finds nothing to send and ends.
        assert_eq!(sync.next_send(&closed, ticket.expect("ticket")), None);
        assert_eq!(sync.pending_id(&other), Some(7));
    }

    #[test]
    fn only_422_no_query_window_is_final() {
        use cordiale_core::client::GrappaClientError;
        let rejected = |status: u16, code: Option<&str>| GrappaClientError::Rejected {
            status: cordiale_core::client::StatusCode::from_u16(status).expect("status"),
            code: code.map(str::to_string),
            retry_after: None,
        };
        assert!(is_closed_query_error(&rejected(
            422,
            Some("no_query_window")
        )));
        assert!(!is_closed_query_error(&rejected(422, Some("other"))));
        assert!(!is_closed_query_error(&rejected(503, None)));
        assert!(!is_closed_query_error(&GrappaClientError::InvalidUrl(
            String::new()
        )));
    }

    #[test]
    fn failed_post_leaves_a_pending_update_and_retry_confirms_it() {
        let mut sync = ReadCursorSync::default();
        let window = key("net", "#a");
        sync.queue(window.clone(), "#A", 10);
        let taken = sync.take_idle();
        assert_eq!(taken.len(), 1);
        let ticket = taken[0].1;
        let send = sync.next_send(&window, ticket).expect("pending send");
        assert_eq!(send.message_id, 10);
        assert_eq!(send.target, "#A");
        // The POST fails: nothing changes, the update stays.
        assert_eq!(sync.pending_id(&window), Some(10));
        // The retry succeeds.
        assert!(sync.next_send(&window, ticket).is_some());
        assert!(sync.sent_ok(&window, 10, 10));
        assert_eq!(sync.pending_id(&window), None);
        assert!(sync.next_send(&window, ticket).is_none());
        // The owner ended with the last call, so a new update gets a task.
        sync.queue(window.clone(), "#A", 11);
        assert_eq!(sync.take_idle().len(), 1);
    }

    #[test]
    fn ambiguous_timeout_stays_pending_until_a_matching_push() {
        let mut sync = ReadCursorSync::default();
        let window = key("net", "#a");
        sync.queue(window.clone(), "#a", 7);
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
        let (_, first) = sync.take_idle().remove(0);
        sync.release(&window, first);
        sync.queue(window.clone(), "#a", 5);
        let taken = sync.take_idle();
        assert_eq!(taken.len(), 1);
        assert_eq!(
            sync.next_send(&window, taken[0].1)
                .map(|send| send.message_id),
            Some(5)
        );
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
        let (_, ticket) = sync.take_idle().remove(0);
        sync.queue(window.clone(), "#a", 2);
        assert!(sync.take_idle().is_empty());
        // A stale ticket cannot release the owner.
        sync.release(&window, ticket + 100);
        assert!(sync.take_idle().is_empty());
        sync.release(&window, ticket);
        assert_eq!(sync.take_idle().len(), 1);
    }

    #[test]
    fn push_confirmation_keeps_the_owner_so_no_second_task_starts() {
        let mut sync = ReadCursorSync::default();
        let window = key("net", "#a");
        sync.queue(window.clone(), "#a", 1);
        let (_, ticket) = sync.take_idle().remove(0);
        // A push confirms the update before the POST answers.
        sync.confirm(&window, 1);
        assert_eq!(sync.pending_id(&window), None);
        // The next read queues a new ID: the old task still owns the window.
        sync.queue(window.clone(), "#a", 2);
        assert!(sync.take_idle().is_empty());
        let send = sync.next_send(&window, ticket).expect("new ID");
        assert_eq!(send.message_id, 2);
        // A task with another ticket gets nothing.
        assert!(sync.next_send(&window, ticket + 1).is_none());
    }

    #[test]
    fn clear_stops_the_task_of_the_old_identity() {
        let mut sync = ReadCursorSync::default();
        let window = key("net", "#a");
        sync.queue(window.clone(), "#a", 1);
        let (_, ticket) = sync.take_idle().remove(0);
        sync.clear();
        assert!(sync.next_send(&window, ticket).is_none());
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
        let taken = sync.take_idle();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0, behind);
    }

    #[test]
    fn retry_delay_is_bounded() {
        assert_eq!(retry_delay(1), Duration::from_secs(1));
        assert_eq!(retry_delay(2), Duration::from_secs(2));
        assert_eq!(retry_delay(3), Duration::from_secs(4));
        assert_eq!(retry_delay(100), Duration::from_secs(30));
    }
}
