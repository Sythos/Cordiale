// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)

//! The keyword watchlist follows the server: each `add`, `del` and `list`
//! push is tracked, and only an `ok` reply changes the local patterns. A
//! request without a reply expires, and its late reply is ignored.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::*;

/// How long a `watchlist` push waits for its reply.
pub(crate) const WATCHLIST_REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// Why the server did not confirm a watchlist request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WatchlistFailure {
    NoReply,
    ConnectionLost,
    Refused,
}

impl WatchlistFailure {
    /// The key of the message in the watchlist settings.
    fn panel_key(self) -> &'static str {
        match self {
            Self::NoReply => "no-reply",
            Self::ConnectionLost => "connection-lost",
            Self::Refused => "refused",
        }
    }
}

/// What a `phx_reply` to a watchlist request means.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WatchlistReply {
    /// The list of the server after the request.
    Accepted(Vec<String>),
    /// An error, or a reply without a list: the local list stays.
    Refused,
    /// The request expired, or a newer reply is already applied.
    Ignored,
}

struct PendingRequest {
    /// Send order, so an older list never replaces a newer one.
    order: u64,
    deadline: Instant,
}

/// The watchlist requests of one session, keyed by their push ref.
#[derive(Default)]
pub(crate) struct WatchlistRequests {
    pending: HashMap<String, PendingRequest>,
    /// Refs that expired: their late replies are dropped.
    expired: HashSet<String>,
    sent: u64,
    applied: u64,
    /// A dropped connection lost a request, and the status bar does not
    /// say it yet.
    unreported_loss: bool,
}

impl WatchlistRequests {
    pub(crate) fn track(&mut self, message_ref: String, now: Instant) {
        self.sent += 1;
        self.pending.insert(
            message_ref,
            PendingRequest {
                order: self.sent,
                deadline: now + WATCHLIST_REPLY_TIMEOUT,
            },
        );
    }

    /// Reads the reply with `message_ref`. `None` when the ref is not a
    /// watchlist request.
    pub(crate) fn take_reply(
        &mut self,
        message_ref: &str,
        payload: &Value,
    ) -> Option<WatchlistReply> {
        if self.expired.remove(message_ref) {
            return Some(WatchlistReply::Ignored);
        }
        let request = self.pending.remove(message_ref)?;
        let Some(patterns) = watch_patterns_from_reply(payload) else {
            return Some(WatchlistReply::Refused);
        };
        if request.order <= self.applied {
            return Some(WatchlistReply::Ignored);
        }
        self.applied = request.order;
        Some(WatchlistReply::Accepted(patterns))
    }

    /// When the oldest pending request expires.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.pending.values().map(|request| request.deadline).min()
    }

    /// Drops the requests whose deadline passed. Returns whether any did.
    pub(crate) fn expire(&mut self, now: Instant) -> bool {
        let due: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, request)| request.deadline <= now)
            .map(|(message_ref, _)| message_ref.clone())
            .collect();
        for message_ref in &due {
            self.pending.remove(message_ref);
        }
        let any = !due.is_empty();
        self.expired.extend(due);
        any
    }

    /// Drops every pending request after a lost connection. Returns whether
    /// there was one.
    pub(crate) fn lose_connection(&mut self) -> bool {
        let any = !self.pending.is_empty();
        self.expired
            .extend(self.pending.drain().map(|(message_ref, _)| message_ref));
        self.unreported_loss |= any;
        any
    }

    /// Whether a lost request still needs its status message; true once.
    pub(crate) fn take_unreported_loss(&mut self) -> bool {
        std::mem::take(&mut self.unreported_loss)
    }
}

/// Shows `failure` in the watchlist settings, or clears the message.
pub(crate) fn show_watchlist_error(ui: &slint::Weak<AppWindow>, failure: Option<WatchlistFailure>) {
    let key = failure.map_or("", WatchlistFailure::panel_key);
    let _ = ui.upgrade_in_event_loop(move |ui| ui.set_settings_watch_error(key.into()));
}

/// Pushes a `watchlist` request on the user topic and tracks its reply.
pub(crate) fn send_watchlist_request(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    payload: Value,
) {
    let (Some(session), Some(identifier)) = (&state.conn.session, &state.conn.identifier) else {
        show_watchlist_error(ui, Some(WatchlistFailure::ConnectionLost));
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_status_kind("watchlist-connection-lost".into());
        });
        return;
    };
    let message_ref =
        session.send_tracked_command(format!("grappa:user:{identifier}"), "watchlist", payload);
    state.prefs.watchlist.track(message_ref, Instant::now());
}

/// Reports the requests that got no reply in time.
pub(crate) fn expire_watchlist_requests(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    now: Instant,
) {
    if state.prefs.watchlist.expire(now) {
        persistence::log_line("watchlist request got no reply in time");
        show_watchlist_error(ui, Some(WatchlistFailure::NoReply));
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_status_kind("watchlist-no-reply".into());
        });
    }
}

/// Gives up the pending requests when the socket drops. The status bar keeps
/// the reconnect message; `report_lost_watchlist_requests` follows it.
pub(crate) fn lose_watchlist_requests(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    if state.prefs.watchlist.lose_connection() {
        persistence::log_line("watchlist request lost with the connection");
        show_watchlist_error(ui, Some(WatchlistFailure::ConnectionLost));
    }
}

/// After a reconnect, says in the status bar that a request was lost.
pub(crate) fn report_lost_watchlist_requests(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    if state.prefs.watchlist.take_unreported_loss() {
        let _ = ui.upgrade_in_event_loop(|ui| {
            // The status change handler can miss the "signed-in" value set
            // just before, so clear the connection indicator here too.
            ui.set_connection_status_kind("".into());
            ui.set_status_kind("watchlist-connection-lost".into());
        });
    }
}

#[cfg(test)]
mod tests {
    use cordiale_core::phoenix::PhoenixMessage;
    use cordiale_core::slash::SlashCommand;

    use super::*;

    /// A state with the patterns `["old"]` and a session. The session task
    /// never runs, and the runtime stays alive for the whole test.
    fn watch_state() -> (tokio::runtime::Runtime, WorkerState) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let (handle, _events) = {
            let _guard = runtime.enter();
            spawn_session(
                "ws://127.0.0.1:1/socket".to_string(),
                "test-token".to_string(),
                "alice".to_string(),
            )
        };
        let mut state = WorkerState::new();
        state.conn.client = Some(GrappaClient::new("http://127.0.0.1:1"));
        state.conn.token = Some("test-token".to_string());
        state.conn.identifier = Some("alice".to_string());
        state.conn.session = Some(handle);
        state.prefs.watch_patterns = vec!["old".to_string()];
        (runtime, state)
    }

    fn ok(patterns: &[&str]) -> Value {
        serde_json::json!({"status": "ok", "response": {"patterns": patterns}})
    }

    fn refused() -> Value {
        serde_json::json!({"status": "error", "response": {"error": "save_failed"}})
    }

    /// Delivers the reply to the push with `message_ref`. The first tracked
    /// ref of a session is `t1`.
    fn reply(
        runtime: &tokio::runtime::Runtime,
        state: &mut WorkerState,
        message_ref: &str,
        payload: Value,
    ) {
        let ui = slint::Weak::<AppWindow>::default();
        let frame = PhoenixMessage {
            join_ref: Some("1".to_string()),
            message_ref: Some(message_ref.to_string()),
            topic: "grappa:user:alice".to_string(),
            event: "phx_reply".to_string(),
            payload,
        };
        runtime.block_on(handle_frame(state, &ui, frame));
    }

    #[test]
    fn an_add_changes_the_list_only_with_the_reply() {
        let (runtime, mut state) = watch_state();
        let ui = slint::Weak::<AppWindow>::default();
        run_watch_pattern_add(&mut state, &ui, "rust".to_string());
        assert_eq!(state.prefs.watch_patterns, ["old"]);
        reply(&runtime, &mut state, "t1", ok(&["rust", "old"]));
        assert_eq!(state.prefs.watch_patterns, ["rust", "old"]);
        assert_eq!(state.prefs.watchlist.next_deadline(), None);
    }

    #[test]
    fn a_delete_changes_the_list_only_with_the_reply() {
        let (runtime, mut state) = watch_state();
        let ui = slint::Weak::<AppWindow>::default();
        run_watch_pattern_remove(&mut state, &ui, "old".to_string());
        assert_eq!(state.prefs.watch_patterns, ["old"]);
        reply(&runtime, &mut state, "t1", ok(&[]));
        assert!(state.prefs.watch_patterns.is_empty());
    }

    #[test]
    fn the_highlight_command_waits_for_the_reply() {
        let (runtime, mut state) = watch_state();
        let ui = slint::Weak::<AppWindow>::default();
        for (add, pattern) in [(true, "rust"), (false, "old")] {
            runtime.block_on(run_slash_command(
                &mut state,
                &ui,
                "libera".to_string(),
                "#rust".to_string(),
                SlashCommand::Highlight {
                    add,
                    pattern: pattern.to_string(),
                },
                "/hilight".to_string(),
            ));
        }
        assert_eq!(state.prefs.watch_patterns, ["old"]);
        reply(&runtime, &mut state, "t1", ok(&["rust", "old"]));
        reply(&runtime, &mut state, "t2", ok(&["rust"]));
        assert_eq!(state.prefs.watch_patterns, ["rust"]);
    }

    #[test]
    fn the_list_request_takes_the_server_list() {
        let (runtime, mut state) = watch_state();
        let ui = slint::Weak::<AppWindow>::default();
        request_watch_patterns(&mut state, &ui);
        reply(&runtime, &mut state, "t1", ok(&["server"]));
        assert_eq!(state.prefs.watch_patterns, ["server"]);
    }

    #[test]
    fn a_refused_change_keeps_the_list() {
        let (runtime, mut state) = watch_state();
        let ui = slint::Weak::<AppWindow>::default();
        run_watch_pattern_add(&mut state, &ui, "rust".to_string());
        run_watch_pattern_remove(&mut state, &ui, "old".to_string());
        reply(&runtime, &mut state, "t1", refused());
        reply(&runtime, &mut state, "t2", refused());
        assert_eq!(state.prefs.watch_patterns, ["old"]);
        assert_eq!(state.prefs.watchlist.next_deadline(), None);
    }

    #[test]
    fn a_missing_reply_expires_and_the_late_one_is_ignored() {
        let (runtime, mut state) = watch_state();
        let ui = slint::Weak::<AppWindow>::default();
        run_watch_pattern_add(&mut state, &ui, "rust".to_string());
        let deadline = state.prefs.watchlist.next_deadline().expect("pending");
        expire_watchlist_requests(&mut state, &ui, deadline);
        assert_eq!(state.prefs.watchlist.next_deadline(), None);
        reply(&runtime, &mut state, "t1", ok(&["rust", "old"]));
        assert_eq!(state.prefs.watch_patterns, ["old"]);
    }

    #[test]
    fn a_disconnect_drops_the_pending_requests() {
        let (runtime, mut state) = watch_state();
        let ui = slint::Weak::<AppWindow>::default();
        run_watch_pattern_add(&mut state, &ui, "rust".to_string());
        lose_watchlist_requests(&mut state, &ui);
        assert_eq!(state.prefs.watchlist.next_deadline(), None);
        assert!(state.prefs.watchlist.take_unreported_loss());
        assert!(!state.prefs.watchlist.take_unreported_loss());
        reply(&runtime, &mut state, "t1", ok(&["rust", "old"]));
        assert_eq!(state.prefs.watch_patterns, ["old"]);
    }

    #[test]
    fn an_older_reply_never_replaces_a_newer_list() {
        let now = Instant::now();
        let mut requests = WatchlistRequests::default();
        requests.track("t1".to_string(), now);
        requests.track("t2".to_string(), now);
        assert_eq!(
            requests.take_reply("t2", &ok(&["new"])),
            Some(WatchlistReply::Accepted(vec!["new".to_string()]))
        );
        assert_eq!(
            requests.take_reply("t1", &ok(&["old"])),
            Some(WatchlistReply::Ignored)
        );
        assert_eq!(requests.take_reply("t9", &ok(&[])), None);
    }

    #[test]
    fn only_the_due_requests_expire() {
        let start = Instant::now();
        let later = start + Duration::from_secs(1);
        let mut requests = WatchlistRequests::default();
        requests.track("t1".to_string(), start);
        requests.track("t2".to_string(), later);
        assert!(!requests.expire(start));
        assert!(requests.expire(start + WATCHLIST_REPLY_TIMEOUT));
        assert_eq!(
            requests.next_deadline(),
            Some(later + WATCHLIST_REPLY_TIMEOUT)
        );
    }
}
