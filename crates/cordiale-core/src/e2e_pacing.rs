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

//! Pure E2E pacing and send-status rules.
//!
//! Every rule takes `now` as a monotonic [`Duration`] since a fixed start, so
//! tests inject the clock and a wall-clock change cannot extend a window. The
//! four states stay separate: KEYS answer pacing, the fake-lag bank (a
//! constant that no pacer here uses), KEYS reassembly and send status.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::isupport::CaseMapping;

/// Minimum time between two KEYS answers to the same nickname.
pub const KEYS_ANSWER_INTERVAL: Duration = Duration::from_secs(15);

/// Fake-lag bank of the relay. It is not a pacing interval of the client.
pub const FAKE_LAG_BANK: Duration = Duration::from_secs(22);

/// Minimum time between two one-time key requests to the same nickname.
pub const ONE_TIME_KEY_INTERVAL: Duration = Duration::from_secs(60);

/// A send must arrive at least this long before its deadline.
pub const SEND_SAFETY_MARGIN: Duration = Duration::from_secs(2);

/// Monotonic clock for production code. Tests pass a [`Duration`] directly.
#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock {
    start: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn now(&self) -> Duration {
        self.start.elapsed()
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Nicknames are folded with the casemapping of the network. The caller
/// passes the current mapping of that network on every call.
fn nick_key(nick: &str, casemapping: CaseMapping) -> String {
    casemapping.fold(nick)
}

/// Per-nickname limit: one event in each interval. The exact end of the
/// interval is allowed.
#[derive(Debug, Clone)]
pub struct IntervalLimiter {
    interval: Duration,
    last: HashMap<String, Duration>,
}

impl IntervalLimiter {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: HashMap::new(),
        }
    }

    /// Record the event and return `true` when the interval has passed.
    /// A refused event does not start a new interval.
    pub fn try_acquire(&mut self, nick: &str, casemapping: CaseMapping, now: Duration) -> bool {
        let key = nick_key(nick, casemapping);
        if let Some(last) = self.last.get(&key) {
            if now.saturating_sub(*last) < self.interval {
                return false;
            }
        }
        self.last.insert(key, now);
        true
    }

    pub fn forget(&mut self, nick: &str, casemapping: CaseMapping) {
        self.last.remove(&nick_key(nick, casemapping));
    }
}

/// Limiter for KEYS answers: one answer for each nickname in 15 seconds.
pub fn keys_answer_limiter() -> IntervalLimiter {
    IntervalLimiter::new(KEYS_ANSWER_INTERVAL)
}

/// How to get a key for a nickname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyChoice {
    /// Ask for a one-time key.
    OneTime,
    /// The one-time key window is closed: use the approved fallback key.
    Fallback,
}

/// Decides between a one-time key and the fallback, per nickname.
#[derive(Debug, Clone)]
pub struct OneTimeKeyPacer {
    limiter: IntervalLimiter,
}

impl OneTimeKeyPacer {
    pub fn new() -> Self {
        Self {
            limiter: IntervalLimiter::new(ONE_TIME_KEY_INTERVAL),
        }
    }

    pub fn choose(&mut self, nick: &str, casemapping: CaseMapping, now: Duration) -> KeyChoice {
        if self.limiter.try_acquire(nick, casemapping, now) {
            KeyChoice::OneTime
        } else {
            KeyChoice::Fallback
        }
    }
}

impl Default for OneTimeKeyPacer {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks KEYS reassembly per nickname and per message id. A KEYREQ is
/// blocked while any reassembly of the nickname is active. Each new fragment
/// restarts the timer of its own message only.
#[derive(Debug, Clone)]
pub struct ReassemblyGate {
    timeout: Duration,
    last_fragment: HashMap<String, HashMap<String, Duration>>,
}

impl ReassemblyGate {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            last_fragment: HashMap::new(),
        }
    }

    /// A KEYS fragment of message `msgid` arrived: start or restart its timer.
    pub fn note_fragment(
        &mut self,
        nick: &str,
        msgid: &str,
        casemapping: CaseMapping,
        now: Duration,
    ) {
        let timeout = self.timeout;
        let messages = self
            .last_fragment
            .entry(nick_key(nick, casemapping))
            .or_default();
        messages.retain(|_, last| now.saturating_sub(*last) < timeout);
        messages.insert(msgid.to_string(), now);
    }

    /// The reassembly of message `msgid` ended (complete, failed or
    /// cancelled). Other messages of the nickname stay active.
    pub fn finish(&mut self, nick: &str, msgid: &str, casemapping: CaseMapping) {
        let key = nick_key(nick, casemapping);
        if let Some(messages) = self.last_fragment.get_mut(&key) {
            messages.remove(msgid);
            if messages.is_empty() {
                self.last_fragment.remove(&key);
            }
        }
    }

    /// A reassembly is active until `timeout` has passed since its last
    /// fragment. At exactly `timeout` it is no longer active.
    pub fn is_active(&self, nick: &str, casemapping: CaseMapping, now: Duration) -> bool {
        self.last_fragment
            .get(&nick_key(nick, casemapping))
            .is_some_and(|messages| {
                messages
                    .values()
                    .any(|last| now.saturating_sub(*last) < self.timeout)
            })
    }

    pub fn may_send_keyreq(&self, nick: &str, casemapping: CaseMapping, now: Duration) -> bool {
        !self.is_active(nick, casemapping, now)
    }
}

/// Result of the deadline check before a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendDecision {
    Go,
    /// The send cannot arrive before the deadline minus the safety margin.
    TooLate,
}

/// A send goes only when `now + margin` is before the deadline. At exactly
/// the margin the send is too late.
pub fn check_send_deadline(now: Duration, deadline: Duration) -> SendDecision {
    if now + SEND_SAFETY_MARGIN < deadline {
        SendDecision::Go
    } else {
        SendDecision::TooLate
    }
}

/// Failure of a send request, from the HTTP answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFailure {
    /// HTTP 422 `too_late`.
    TooLate,
    /// HTTP 400 `bad_request`.
    BadRequest,
}

/// Distinct client state for each HTTP answer to a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendResponse {
    /// HTTP 202: the relay accepted the message for processing. This is not
    /// a delivery.
    Accepted,
    Failed(SendFailure),
    /// Any other status: not part of the send contract.
    Unexpected(u16),
}

pub fn classify_send_response(status: u16, error: Option<&str>) -> SendResponse {
    match (status, error) {
        (202, _) => SendResponse::Accepted,
        (422, Some("too_late")) => SendResponse::Failed(SendFailure::TooLate),
        (400, Some("bad_request")) => SendResponse::Failed(SendFailure::BadRequest),
        _ => SendResponse::Unexpected(status),
    }
}

/// Reason of an `e2e_send_dropped` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Late,
    SendFailed,
    SessionEnded,
}

impl DropReason {
    pub fn from_wire(text: &str) -> Option<Self> {
        match text {
            "late" => Some(Self::Late),
            "send_failed" => Some(Self::SendFailed),
            "session_ended" => Some(Self::SessionEnded),
            _ => None,
        }
    }
}

/// Local status of one send. No variant means "delivered": the relay gives no
/// such proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendStatus {
    Pending,
    Accepted,
    Failed(SendFailure),
    Dropped(DropReason),
}

/// Local send status by send id. A final state changes only once.
#[derive(Debug, Clone, Default)]
pub struct SendTracker {
    sends: HashMap<String, SendStatus>,
}

impl SendTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self, id: &str) {
        self.sends
            .entry(id.to_string())
            .or_insert(SendStatus::Pending);
    }

    pub fn status(&self, id: &str) -> Option<SendStatus> {
        self.sends.get(id).copied()
    }

    /// Apply an HTTP answer to a pending send. Return `true` when the status
    /// changed.
    pub fn apply_response(&mut self, id: &str, response: SendResponse) -> bool {
        let next = match response {
            SendResponse::Accepted => SendStatus::Accepted,
            SendResponse::Failed(failure) => SendStatus::Failed(failure),
            SendResponse::Unexpected(_) => return false,
        };
        match self.sends.get_mut(id) {
            Some(status @ SendStatus::Pending) => {
                *status = next;
                true
            }
            _ => false,
        }
    }

    /// Apply an `e2e_send_dropped` event. It changes a pending or accepted
    /// send once. A duplicate or an unknown id changes nothing.
    pub fn apply_dropped(&mut self, id: &str, reason: DropReason) -> bool {
        match self.sends.get_mut(id) {
            Some(status @ (SendStatus::Pending | SendStatus::Accepted)) => {
                *status = SendStatus::Dropped(reason);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    const ASCII: CaseMapping = CaseMapping::Ascii;
    const RFC: CaseMapping = CaseMapping::Rfc1459;

    #[test]
    fn keys_answer_interval_is_not_the_fake_lag_bank() {
        assert_eq!(KEYS_ANSWER_INTERVAL, secs(15));
        assert_eq!(FAKE_LAG_BANK, secs(22));
        let mut limiter = keys_answer_limiter();
        assert!(limiter.try_acquire("Bob", ASCII, secs(0)));
        assert!(limiter.try_acquire("bob", ASCII, secs(15)));
    }

    #[test]
    fn keys_answer_boundary_and_per_nick() {
        let mut limiter = keys_answer_limiter();
        assert!(limiter.try_acquire("bob", ASCII, secs(100)));
        assert!(!limiter.try_acquire("BOB", ASCII, secs(114)));
        assert!(limiter.try_acquire("carol", ASCII, secs(114)));
        // The refused try did not restart the window.
        assert!(limiter.try_acquire("bob", ASCII, secs(115)));
    }

    #[test]
    fn keys_answer_folds_rfc1459_nicks() {
        let mut limiter = keys_answer_limiter();
        assert!(limiter.try_acquire("[bob]", RFC, secs(0)));
        assert!(!limiter.try_acquire("{bob}", RFC, secs(14)));
        assert!(limiter.try_acquire("{bob}", RFC, secs(15)));
    }

    #[test]
    fn ascii_keeps_bracket_nicks_apart() {
        let mut limiter = keys_answer_limiter();
        assert!(limiter.try_acquire("[bob]", ASCII, secs(0)));
        assert!(limiter.try_acquire("{bob}", ASCII, secs(1)));
    }

    #[test]
    fn tilde_folds_only_under_rfc1459() {
        let mut limiter = keys_answer_limiter();
        assert!(limiter.try_acquire("bob~", RFC, secs(0)));
        assert!(!limiter.try_acquire("bob^", RFC, secs(1)));
        let strict = CaseMapping::Rfc1459Strict;
        assert!(limiter.try_acquire("amy~", strict, secs(0)));
        assert!(limiter.try_acquire("amy^", strict, secs(1)));
    }

    #[test]
    fn one_time_key_once_per_minute() {
        let mut pacer = OneTimeKeyPacer::new();
        assert_eq!(pacer.choose("bob", ASCII, secs(0)), KeyChoice::OneTime);
        assert_eq!(pacer.choose("bob", ASCII, secs(59)), KeyChoice::Fallback);
        assert_eq!(pacer.choose("carol", ASCII, secs(59)), KeyChoice::OneTime);
        assert_eq!(pacer.choose("bob", ASCII, secs(60)), KeyChoice::OneTime);
    }

    #[test]
    fn one_time_key_folds_rfc1459_nicks() {
        let mut pacer = OneTimeKeyPacer::new();
        assert_eq!(pacer.choose("[bob]", RFC, secs(0)), KeyChoice::OneTime);
        assert_eq!(pacer.choose("{bob}", RFC, secs(30)), KeyChoice::Fallback);
    }

    #[test]
    fn keyreq_blocked_during_reassembly() {
        let mut gate = ReassemblyGate::new(secs(10));
        assert!(gate.may_send_keyreq("bob", ASCII, secs(0)));
        gate.note_fragment("bob", "A", ASCII, secs(0));
        assert!(!gate.may_send_keyreq("bob", ASCII, secs(9)));
        assert!(gate.may_send_keyreq("alice", ASCII, secs(9)));
        assert!(gate.may_send_keyreq("bob", ASCII, secs(10)));
    }

    #[test]
    fn reassembly_gate_folds_rfc1459_nicks() {
        let mut gate = ReassemblyGate::new(secs(10));
        gate.note_fragment("[bob]", "A", RFC, secs(0));
        assert!(!gate.may_send_keyreq("{bob}", RFC, secs(5)));

        let mut ascii_gate = ReassemblyGate::new(secs(10));
        ascii_gate.note_fragment("[bob]", "A", ASCII, secs(0));
        assert!(ascii_gate.may_send_keyreq("{bob}", ASCII, secs(5)));
        assert!(!ascii_gate.may_send_keyreq("[bob]", ASCII, secs(5)));
    }

    #[test]
    fn new_fragment_restarts_the_timer() {
        let mut gate = ReassemblyGate::new(secs(10));
        gate.note_fragment("bob", "A", ASCII, secs(0));
        gate.note_fragment("bob", "A", ASCII, secs(8));
        assert!(gate.is_active("bob", ASCII, secs(17)));
        assert!(!gate.is_active("bob", ASCII, secs(18)));
    }

    #[test]
    fn finish_cancels_reassembly() {
        let mut gate = ReassemblyGate::new(secs(10));
        gate.note_fragment("bob", "A", ASCII, secs(0));
        gate.finish("bob", "A", ASCII);
        assert!(gate.may_send_keyreq("bob", ASCII, secs(1)));
    }

    #[test]
    fn overlapping_reassemblies_keep_the_gate_closed() {
        let mut gate = ReassemblyGate::new(secs(10));
        gate.note_fragment("bob", "A", ASCII, secs(0));
        gate.note_fragment("bob", "B", ASCII, secs(1));
        gate.finish("bob", "A", ASCII);
        assert!(!gate.may_send_keyreq("bob", ASCII, secs(2)));
        gate.finish("bob", "B", ASCII);
        assert!(gate.may_send_keyreq("bob", ASCII, secs(2)));
    }

    #[test]
    fn expired_reassembly_does_not_hide_an_active_one() {
        let mut gate = ReassemblyGate::new(secs(10));
        gate.note_fragment("bob", "A", ASCII, secs(0));
        gate.note_fragment("bob", "B", ASCII, secs(8));
        assert!(gate.is_active("bob", ASCII, secs(12)));
        assert!(!gate.is_active("bob", ASCII, secs(18)));
    }

    #[test]
    fn deadline_margin_edges() {
        let deadline = secs(100);
        assert_eq!(check_send_deadline(secs(97), deadline), SendDecision::Go);
        assert_eq!(
            check_send_deadline(secs(98), deadline),
            SendDecision::TooLate
        );
        assert_eq!(
            check_send_deadline(secs(99), deadline),
            SendDecision::TooLate
        );
        assert_eq!(
            check_send_deadline(secs(100), deadline),
            SendDecision::TooLate
        );
        assert_eq!(
            check_send_deadline(secs(200), deadline),
            SendDecision::TooLate
        );
    }

    #[test]
    fn http_answers_are_distinct() {
        assert_eq!(classify_send_response(202, None), SendResponse::Accepted);
        assert_eq!(
            classify_send_response(422, Some("too_late")),
            SendResponse::Failed(SendFailure::TooLate)
        );
        assert_eq!(
            classify_send_response(400, Some("bad_request")),
            SendResponse::Failed(SendFailure::BadRequest)
        );
        assert_eq!(
            classify_send_response(422, Some("other")),
            SendResponse::Unexpected(422)
        );
        assert_eq!(
            classify_send_response(500, None),
            SendResponse::Unexpected(500)
        );
    }

    #[test]
    fn drop_reasons_parse() {
        assert_eq!(DropReason::from_wire("late"), Some(DropReason::Late));
        assert_eq!(
            DropReason::from_wire("send_failed"),
            Some(DropReason::SendFailed)
        );
        assert_eq!(
            DropReason::from_wire("session_ended"),
            Some(DropReason::SessionEnded)
        );
        assert_eq!(DropReason::from_wire("x"), None);
    }

    #[test]
    fn accepted_is_not_final_and_drop_applies_once() {
        let mut tracker = SendTracker::new();
        tracker.start("m1");
        assert!(tracker.apply_response("m1", SendResponse::Accepted));
        assert_eq!(tracker.status("m1"), Some(SendStatus::Accepted));
        assert!(tracker.apply_dropped("m1", DropReason::Late));
        assert!(!tracker.apply_dropped("m1", DropReason::SendFailed));
        assert_eq!(
            tracker.status("m1"),
            Some(SendStatus::Dropped(DropReason::Late))
        );
    }

    #[test]
    fn dropped_send_is_not_reported_as_accepted_later() {
        let mut tracker = SendTracker::new();
        tracker.start("m1");
        assert!(tracker.apply_dropped("m1", DropReason::SessionEnded));
        assert!(!tracker.apply_response("m1", SendResponse::Accepted));
        assert_eq!(
            tracker.status("m1"),
            Some(SendStatus::Dropped(DropReason::SessionEnded))
        );
    }

    #[test]
    fn drop_updates_only_its_own_send() {
        let mut tracker = SendTracker::new();
        tracker.start("m1");
        tracker.start("m2");
        assert!(tracker.apply_dropped("m2", DropReason::SendFailed));
        assert_eq!(tracker.status("m1"), Some(SendStatus::Pending));
        assert!(!tracker.apply_dropped("unknown", DropReason::Late));
    }

    #[test]
    fn failed_response_is_final() {
        let mut tracker = SendTracker::new();
        tracker.start("m1");
        assert!(tracker.apply_response("m1", SendResponse::Failed(SendFailure::TooLate)));
        assert!(!tracker.apply_dropped("m1", DropReason::Late));
        assert_eq!(
            tracker.status("m1"),
            Some(SendStatus::Failed(SendFailure::TooLate))
        );
    }

    #[test]
    fn monotonic_clock_does_not_go_back() {
        let clock = MonotonicClock::new();
        let a = clock.now();
        assert!(clock.now() >= a);
    }
}
