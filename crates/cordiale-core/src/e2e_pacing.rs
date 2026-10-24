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

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::e2e_wire::{as_object, required_str, WireError};
use crate::isupport::CaseMapping;

/// Minimum time between two KEYS answers to the same nickname.
pub const KEYS_ANSWER_INTERVAL: Duration = Duration::from_secs(15);

/// Fake-lag bank of the relay. It is not a pacing interval of the client.
pub const FAKE_LAG_BANK: Duration = Duration::from_secs(22);

/// Minimum time between two KEYREQ to the same nickname (protocol 46).
pub const KEYREQ_INTERVAL: Duration = Duration::from_secs(30);

/// Pacing values of the MD-3 candidate (irc-olm PR #4). They are not final.
/// Update path: change only this module when the candidate is merged or
/// changes, and check the tests that name a value.
pub mod md3_candidate {
    use std::time::Duration;

    /// Minimum time between two re-key requests to the same nickname.
    pub const REKEY_INTERVAL: Duration = Duration::from_secs(60);

    /// An outgoing message that waits longer than this is dropped.
    pub const OUTGOING_QUEUE_TTL: Duration = Duration::from_secs(90);

    /// Minimum time between two one-time key requests to the same nickname.
    pub const ONE_TIME_KEY_INTERVAL: Duration = Duration::from_secs(60);

    /// Most one-time key requests to all nicknames in `ONE_TIME_KEY_WINDOW`.
    pub const ONE_TIME_KEY_GLOBAL_LIMIT: usize = 30;

    /// Window of the global one-time key limit.
    pub const ONE_TIME_KEY_WINDOW: Duration = Duration::from_secs(3600);
}

/// Minimum time between two one-time key requests to the same nickname.
pub const ONE_TIME_KEY_INTERVAL: Duration = md3_candidate::ONE_TIME_KEY_INTERVAL;

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
    casemapping: Option<CaseMapping>,
    last: HashMap<String, Duration>,
}

impl IntervalLimiter {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            casemapping: None,
            last: HashMap::new(),
        }
    }

    /// Clear the state when the casemapping differs from the one of the
    /// stored keys. Old keys cannot be folded again with the new mapping.
    fn sync_casemapping(&mut self, casemapping: CaseMapping) {
        if self.casemapping != Some(casemapping) {
            self.last.clear();
            self.casemapping = Some(casemapping);
        }
    }

    /// Record the event and return `true` when the interval has passed.
    /// A refused event does not start a new interval. A changed casemapping
    /// clears all intervals first.
    pub fn try_acquire(&mut self, nick: &str, casemapping: CaseMapping, now: Duration) -> bool {
        self.sync_casemapping(casemapping);
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
        self.sync_casemapping(casemapping);
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

/// Global limit: at most `limit` events in any window of `window`.
#[derive(Debug, Clone)]
pub struct WindowLimiter {
    limit: usize,
    window: Duration,
    events: VecDeque<Duration>,
}

impl WindowLimiter {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            events: VecDeque::new(),
        }
    }

    /// Whether `try_acquire` would succeed. It records nothing.
    pub fn is_ready(&mut self, now: Duration) -> bool {
        while self
            .events
            .front()
            .is_some_and(|first| now.saturating_sub(*first) >= self.window)
        {
            self.events.pop_front();
        }
        self.events.len() < self.limit
    }

    pub fn try_acquire(&mut self, now: Duration) -> bool {
        if !self.is_ready(now) {
            return false;
        }
        self.events.push_back(now);
        true
    }
}

/// Decides between a one-time key and the fallback. The limit of one request
/// for each nickname and the global hourly limit both apply. A refused
/// request does not use any limit.
#[derive(Debug, Clone)]
pub struct OneTimeKeyPacer {
    limiter: IntervalLimiter,
    global: WindowLimiter,
}

impl OneTimeKeyPacer {
    pub fn new() -> Self {
        Self {
            limiter: IntervalLimiter::new(ONE_TIME_KEY_INTERVAL),
            global: WindowLimiter::new(
                md3_candidate::ONE_TIME_KEY_GLOBAL_LIMIT,
                md3_candidate::ONE_TIME_KEY_WINDOW,
            ),
        }
    }

    pub fn choose(&mut self, nick: &str, casemapping: CaseMapping, now: Duration) -> KeyChoice {
        if self.global.is_ready(now)
            && self.limiter.try_acquire(nick, casemapping, now)
            && self.global.try_acquire(now)
        {
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
    casemapping: Option<CaseMapping>,
    last_fragment: HashMap<String, HashMap<String, Duration>>,
}

impl ReassemblyGate {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            casemapping: None,
            last_fragment: HashMap::new(),
        }
    }

    /// Clear the state when the casemapping differs from the one of the
    /// stored keys. Old keys cannot be folded again with the new mapping.
    fn sync_casemapping(&mut self, casemapping: CaseMapping) {
        if self.casemapping != Some(casemapping) {
            self.last_fragment.clear();
            self.casemapping = Some(casemapping);
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
        self.sync_casemapping(casemapping);
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
        self.sync_casemapping(casemapping);
        let key = nick_key(nick, casemapping);
        if let Some(messages) = self.last_fragment.get_mut(&key) {
            messages.remove(msgid);
            if messages.is_empty() {
                self.last_fragment.remove(&key);
            }
        }
    }

    /// A reassembly is active until `timeout` has passed since its last
    /// fragment. At exactly `timeout` it is no longer active. A different
    /// casemapping clears the state of the old one.
    pub fn is_active(&mut self, nick: &str, casemapping: CaseMapping, now: Duration) -> bool {
        self.sync_casemapping(casemapping);
        self.last_fragment
            .get(&nick_key(nick, casemapping))
            .is_some_and(|messages| {
                messages
                    .values()
                    .any(|last| now.saturating_sub(*last) < self.timeout)
            })
    }

    pub fn may_send_keyreq(&mut self, nick: &str, casemapping: CaseMapping, now: Duration) -> bool {
        !self.is_active(nick, casemapping, now)
    }
}

/// Why a KEYREQ may not go out now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyReqRefusal {
    /// A fragmented KEYS answer of the nickname is being reassembled.
    Reassembling,
    /// The last KEYREQ to the nickname is less than 30 seconds old.
    Interval,
}

/// KEYREQ pacing: one request for each nickname in 30 seconds, and none while
/// a KEYS answer of that nickname is in reassembly.
///
/// The reassembly timeout is a parameter. It must equal the timeout that the
/// server uses for a fragmented KEYS answer (Grappa, protocol 46). This
/// repository has no copy of that rule, so the caller owns the value.
#[derive(Debug, Clone)]
pub struct KeyReqPacer {
    limiter: IntervalLimiter,
    gate: ReassemblyGate,
}

impl KeyReqPacer {
    pub fn new(reassembly_timeout: Duration) -> Self {
        Self {
            limiter: IntervalLimiter::new(KEYREQ_INTERVAL),
            gate: ReassemblyGate::new(reassembly_timeout),
        }
    }

    /// A changed casemapping clears both the interval and the reassembly
    /// state. Every public call starts here, so the two halves never differ.
    fn sync_casemapping(&mut self, casemapping: CaseMapping) {
        self.limiter.sync_casemapping(casemapping);
        self.gate.sync_casemapping(casemapping);
    }

    /// A KEYS fragment arrived: the timer of its message restarts.
    pub fn note_fragment(
        &mut self,
        nick: &str,
        msgid: &str,
        casemapping: CaseMapping,
        now: Duration,
    ) {
        self.sync_casemapping(casemapping);
        self.gate.note_fragment(nick, msgid, casemapping, now);
    }

    /// The reassembly of a KEYS answer ended.
    pub fn finish(&mut self, nick: &str, msgid: &str, casemapping: CaseMapping) {
        self.sync_casemapping(casemapping);
        self.gate.finish(nick, msgid, casemapping);
    }

    /// Ask to send a KEYREQ. A refusal uses no interval.
    pub fn try_send(
        &mut self,
        nick: &str,
        casemapping: CaseMapping,
        now: Duration,
    ) -> Result<(), KeyReqRefusal> {
        self.sync_casemapping(casemapping);
        if !self.gate.may_send_keyreq(nick, casemapping, now) {
            return Err(KeyReqRefusal::Reassembling);
        }
        if self.limiter.try_acquire(nick, casemapping, now) {
            Ok(())
        } else {
            Err(KeyReqRefusal::Interval)
        }
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

/// Typed `e2e_send_dropped` event (protocol 46).
///
/// Candidate shape: `id` (send id) and `reason`. Unknown fields are ignored,
/// because events are additive. A missing or wrongly typed field, or an
/// unknown reason, is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendDropped {
    pub id: String,
    pub reason: DropReason,
}

impl SendDropped {
    pub fn from_value(value: &Value) -> Result<Self, WireError> {
        let map = as_object(value)?;
        let id = required_str(map, "id")?;
        if id.is_empty() {
            return Err(WireError::MissingField);
        }
        let reason =
            DropReason::from_wire(required_str(map, "reason")?).ok_or(WireError::BadFieldType)?;
        Ok(Self {
            id: id.to_string(),
            reason,
        })
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

    /// Remove a send and return its last status. The caller does this after
    /// it saves the status. An unknown id returns `None`.
    pub fn remove(&mut self, id: &str) -> Option<SendStatus> {
        self.sends.remove(id)
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

    /// Parse an `e2e_send_dropped` payload and apply it. Return `true` when
    /// the status of a known send changed. A malformed payload is an error
    /// and changes nothing.
    pub fn apply_dropped_event(&mut self, payload: &Value) -> Result<bool, WireError> {
        let event = SendDropped::from_value(payload)?;
        Ok(self.apply_dropped(&event.id, event.reason))
    }
}

/// Wire name of the drop event, as in the `kind` field of the payload.
pub const SEND_DROPPED_KIND: &str = "e2e_send_dropped";

/// Identity of one send: network, target and message id. Two sends match
/// only when all three are equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SendKey {
    pub network: String,
    pub target: String,
    pub message_id: String,
}

impl SendKey {
    pub fn new(network: &str, target: &str, message_id: &str) -> Self {
        Self {
            network: network.to_string(),
            target: target.to_string(),
            message_id: message_id.to_string(),
        }
    }
}

/// A parsed `e2e_send_dropped` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendDropped {
    pub key: SendKey,
    pub reason: DropReason,
}

impl SendDropped {
    /// Read the event payload. Return `None` when the kind is another one,
    /// a field is missing or not a string, or the reason is not known. The
    /// field names `network`, `target`, `message_id` and `reason` are an
    /// assumption: check them against the protocol 47 contract.
    pub fn from_payload(payload: &Value) -> Option<Self> {
        if payload.get("kind")?.as_str()? != SEND_DROPPED_KIND {
            return None;
        }
        Some(Self {
            key: SendKey::new(
                payload.get("network")?.as_str()?,
                payload.get("target")?.as_str()?,
                payload.get("message_id")?.as_str()?,
            ),
            reason: DropReason::from_wire(payload.get("reason")?.as_str()?)?,
        })
    }
}

/// Local status of every send, by [`SendKey`]. It routes a response or a
/// drop event to the matching send only.
#[derive(Debug, Clone, Default)]
pub struct SendBook {
    sends: HashMap<SendKey, SendStatus>,
}

impl SendBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a send as pending. A known send keeps its status.
    pub fn start(&mut self, key: SendKey) {
        self.sends.entry(key).or_insert(SendStatus::Pending);
    }

    pub fn status(&self, key: &SendKey) -> Option<SendStatus> {
        self.sends.get(key).copied()
    }

    pub fn remove(&mut self, key: &SendKey) -> Option<SendStatus> {
        self.sends.remove(key)
    }

    /// Apply an HTTP answer to the matching pending send. Return `true`
    /// when the status changed.
    pub fn apply_response(&mut self, key: &SendKey, response: SendResponse) -> bool {
        let next = match response {
            SendResponse::Accepted => SendStatus::Accepted,
            SendResponse::Failed(failure) => SendStatus::Failed(failure),
            SendResponse::Unexpected(_) => return false,
        };
        match self.sends.get_mut(key) {
            Some(status @ SendStatus::Pending) => {
                *status = next;
                true
            }
            _ => false,
        }
    }

    /// Apply a drop event to the matching pending or accepted send. An
    /// unknown or final send changes nothing.
    pub fn apply_dropped(&mut self, event: &SendDropped) -> bool {
        match self.sends.get_mut(&event.key) {
            Some(status @ (SendStatus::Pending | SendStatus::Accepted)) => {
                *status = SendStatus::Dropped(event.reason);
                true
            }
            _ => false,
        }
    }

    /// Route one event payload. Return the event when it is a drop event
    /// that changed a send.
    pub fn apply_payload(&mut self, payload: &Value) -> Option<SendDropped> {
        let event = SendDropped::from_payload(payload)?;
        self.apply_dropped(&event).then_some(event)
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
    fn send_dropped_fixtures() {
        let cases: Value =
            serde_json::from_str(include_str!("../tests/fixtures/e2e/send_dropped.json"))
                .expect("fixture is JSON");
        for case in cases["valid"].as_array().expect("valid cases") {
            let event = SendDropped::from_value(&case["event"]).expect("valid event");
            assert_eq!(
                event.id,
                case["id"].as_str().expect("id"),
                "{}",
                case["case"]
            );
            let reason = DropReason::from_wire(case["reason"].as_str().expect("reason"));
            assert_eq!(Some(event.reason), reason, "{}", case["case"]);
        }
        for case in cases["invalid"].as_array().expect("invalid cases") {
            let error = SendDropped::from_value(&case["event"]).expect_err("invalid event");
            assert_eq!(
                format!("{error:?}"),
                case["error"].as_str().expect("error"),
                "{}",
                case["case"]
            );
        }
    }

    #[test]
    fn dropped_event_reaches_the_tracker_through_the_router() {
        let cases: Value =
            serde_json::from_str(include_str!("../tests/fixtures/e2e/send_dropped.json"))
                .expect("fixture is JSON");
        let valid = &cases["valid"][0]["event"];
        assert_eq!(
            crate::wire_event::ClientEventKind::from_payload(valid),
            Some(crate::wire_event::ClientEventKind::E2eSendDropped)
        );
        let mut tracker = SendTracker::new();
        tracker.start("s1");
        assert_eq!(tracker.apply_dropped_event(valid), Ok(true));
        assert_eq!(
            tracker.status("s1"),
            Some(SendStatus::Dropped(DropReason::Late))
        );
        // A duplicate event changes nothing.
        assert_eq!(tracker.apply_dropped_event(valid), Ok(false));
    }

    #[test]
    fn invalid_dropped_event_leaves_the_tracker_unchanged() {
        let cases: Value =
            serde_json::from_str(include_str!("../tests/fixtures/e2e/send_dropped.json"))
                .expect("fixture is JSON");
        let mut tracker = SendTracker::new();
        tracker.start("s1");
        for case in cases["invalid"].as_array().expect("invalid cases") {
            assert!(
                tracker.apply_dropped_event(&case["event"]).is_err(),
                "{}",
                case["case"]
            );
            assert_eq!(tracker.status("s1"), Some(SendStatus::Pending));
        }
    }

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

    fn key(id: &str) -> SendKey {
        SendKey::new("libera", "bob", id)
    }

    fn dropped_payload(network: &str, target: &str, id: &str, reason: &str) -> Value {
        serde_json::json!({
            "kind": "e2e_send_dropped",
            "network": network,
            "target": target,
            "message_id": id,
            "reason": reason,
        })
    }

    #[test]
    fn dropped_event_parses_and_rejects_bad_payloads() {
        let event = SendDropped::from_payload(&dropped_payload("libera", "bob", "m1", "late"))
            .expect("event");
        assert_eq!(event.key, key("m1"));
        assert_eq!(event.reason, DropReason::Late);
        assert_eq!(
            SendDropped::from_payload(&dropped_payload("libera", "bob", "m1", "other")),
            None
        );
        let mut other_kind = dropped_payload("libera", "bob", "m1", "late");
        other_kind["kind"] = Value::from("message");
        assert_eq!(SendDropped::from_payload(&other_kind), None);
        let mut missing = dropped_payload("libera", "bob", "m1", "late");
        missing.as_object_mut().expect("object").remove("target");
        assert_eq!(SendDropped::from_payload(&missing), None);
    }

    #[test]
    fn book_accepted_response_is_not_delivered() {
        let mut book = SendBook::new();
        book.start(key("m1"));
        assert!(book.apply_response(&key("m1"), SendResponse::Accepted));
        assert_eq!(book.status(&key("m1")), Some(SendStatus::Accepted));
        // A repeated answer changes nothing.
        assert!(!book.apply_response(&key("m1"), SendResponse::Accepted));
    }

    #[test]
    fn book_too_late_expires_only_the_matching_send() {
        let mut book = SendBook::new();
        book.start(key("m1"));
        book.start(key("m2"));
        let too_late = classify_send_response(422, Some("too_late"));
        assert!(book.apply_response(&key("m1"), too_late));
        assert_eq!(
            book.status(&key("m1")),
            Some(SendStatus::Failed(SendFailure::TooLate))
        );
        assert_eq!(book.status(&key("m2")), Some(SendStatus::Pending));
    }

    #[test]
    fn book_each_drop_reason_updates_only_its_send() {
        for reason in ["late", "send_failed", "session_ended"] {
            let mut book = SendBook::new();
            book.start(key("m1"));
            book.start(key("m2"));
            let payload = dropped_payload("libera", "bob", "m2", reason);
            let event = book.apply_payload(&payload).expect("applied");
            assert_eq!(Some(event.reason), DropReason::from_wire(reason));
            assert_eq!(book.status(&key("m1")), Some(SendStatus::Pending));
            assert_eq!(
                book.status(&key("m2")),
                Some(SendStatus::Dropped(event.reason))
            );
        }
    }

    #[test]
    fn book_matches_network_and_target_too() {
        let mut book = SendBook::new();
        book.start(key("m1"));
        assert!(book
            .apply_payload(&dropped_payload("other", "bob", "m1", "late"))
            .is_none());
        assert!(book
            .apply_payload(&dropped_payload("libera", "carol", "m1", "late"))
            .is_none());
        assert_eq!(book.status(&key("m1")), Some(SendStatus::Pending));
    }

    #[test]
    fn book_duplicate_unknown_and_late_events_change_nothing() {
        let mut book = SendBook::new();
        book.start(key("m1"));
        let payload = dropped_payload("libera", "bob", "m1", "late");
        assert!(book.apply_payload(&payload).is_some());
        // Duplicate, then a different reason for the same final send.
        assert!(book.apply_payload(&payload).is_none());
        let other = dropped_payload("libera", "bob", "m1", "send_failed");
        assert!(book.apply_payload(&other).is_none());
        // Unknown send.
        let unknown = dropped_payload("libera", "bob", "zz", "late");
        assert!(book.apply_payload(&unknown).is_none());
        assert_eq!(book.status(&key("zz")), None);
        // A late event does not touch a later send: the old one is removed.
        book.remove(&key("m1"));
        book.start(key("m3"));
        assert!(book.apply_payload(&payload).is_none());
        assert_eq!(book.status(&key("m3")), Some(SendStatus::Pending));
    }

    #[test]
    fn book_out_of_order_answer_after_drop_is_ignored() {
        let mut book = SendBook::new();
        book.start(key("m1"));
        let payload = dropped_payload("libera", "bob", "m1", "session_ended");
        assert!(book.apply_payload(&payload).is_some());
        assert!(!book.apply_response(&key("m1"), SendResponse::Accepted));
        assert_eq!(
            book.status(&key("m1")),
            Some(SendStatus::Dropped(DropReason::SessionEnded))
        );
    }

    #[test]
    fn book_drop_before_accepted_answer_then_unexpected_status() {
        let mut book = SendBook::new();
        book.start(key("m1"));
        assert!(!book.apply_response(&key("m1"), SendResponse::Unexpected(500)));
        assert_eq!(book.status(&key("m1")), Some(SendStatus::Pending));
        assert!(book.apply_response(&key("m1"), SendResponse::Accepted));
        let payload = dropped_payload("libera", "bob", "m1", "send_failed");
        assert!(book.apply_payload(&payload).is_some());
        assert_eq!(
            book.status(&key("m1")),
            Some(SendStatus::Dropped(DropReason::SendFailed))
        );
    }

    #[test]
    fn limiter_clears_state_when_casemapping_changes() {
        let mut limiter = keys_answer_limiter();
        assert!(limiter.try_acquire("[bob]", ASCII, secs(0)));
        assert!(limiter.try_acquire("{bob}", RFC, secs(1)));
        assert!(!limiter.try_acquire("[bob]", RFC, secs(2)));
    }

    #[test]
    fn gate_clears_state_when_casemapping_changes() {
        let mut gate = ReassemblyGate::new(secs(10));
        gate.note_fragment("[bob]", "A", ASCII, secs(0));
        assert!(gate.is_active("[bob]", ASCII, secs(1)));
        assert!(!gate.is_active("[bob]", RFC, secs(1)));
        gate.note_fragment("{bob}", "B", RFC, secs(2));
        assert!(gate.is_active("[bob]", RFC, secs(3)));
        gate.finish("{bob}", "B", RFC);
        assert!(gate.may_send_keyreq("[bob]", RFC, secs(3)));
    }

    #[test]
    fn gate_read_clears_state_when_casemapping_changes() {
        let mut gate = ReassemblyGate::new(secs(10));
        gate.note_fragment("[bob]", "A", ASCII, secs(0));
        assert!(!gate.is_active("[bob]", RFC, secs(1)));
        assert!(!gate.is_active("[bob]", ASCII, secs(2)));
        assert!(gate.may_send_keyreq("[bob]", ASCII, secs(2)));
    }

    #[test]
    fn keyreq_pacer_clears_both_halves_when_fragment_changes_casemapping() {
        let mut pacer = KeyReqPacer::new(secs(10));
        assert_eq!(pacer.try_send("[bob]", ASCII, secs(0)), Ok(()));
        pacer.note_fragment("[bob]", "A", RFC, secs(1));
        pacer.finish("[bob]", "A", RFC);
        assert_eq!(pacer.try_send("[bob]", ASCII, secs(2)), Ok(()));
    }

    #[test]
    fn keyreq_pacer_clears_fragment_state_when_casemapping_returns() {
        let mut pacer = KeyReqPacer::new(secs(10));
        assert_eq!(pacer.try_send("[bob]", ASCII, secs(0)), Ok(()));
        pacer.note_fragment("[bob]", "A", RFC, secs(1));
        assert_eq!(pacer.try_send("[bob]", ASCII, secs(2)), Ok(()));
    }

    #[test]
    fn remove_drops_a_send_entry() {
        let mut tracker = SendTracker::new();
        tracker.start("m1");
        assert!(tracker.apply_response("m1", SendResponse::Accepted));
        assert_eq!(tracker.remove("m1"), Some(SendStatus::Accepted));
        assert_eq!(tracker.status("m1"), None);
        assert_eq!(tracker.remove("m1"), None);
    }

    #[test]
    fn monotonic_clock_does_not_go_back() {
        let clock = MonotonicClock::new();
        let a = clock.now();
        assert!(clock.now() >= a);
    }

    #[test]
    fn keyreq_once_per_nick_every_30_seconds() {
        let mut pacer = KeyReqPacer::new(secs(10));
        assert_eq!(pacer.try_send("bob", ASCII, secs(0)), Ok(()));
        assert_eq!(
            pacer.try_send("BOB", ASCII, secs(29)),
            Err(KeyReqRefusal::Interval)
        );
        assert_eq!(pacer.try_send("carol", ASCII, secs(29)), Ok(()));
        assert_eq!(pacer.try_send("bob", ASCII, secs(30)), Ok(()));
    }

    #[test]
    fn keyreq_waits_for_reassembly_and_keeps_its_interval() {
        let mut pacer = KeyReqPacer::new(secs(10));
        pacer.note_fragment("bob", "A", ASCII, secs(0));
        assert_eq!(
            pacer.try_send("bob", ASCII, secs(5)),
            Err(KeyReqRefusal::Reassembling)
        );
        // A new fragment restarts the timer.
        pacer.note_fragment("bob", "A", ASCII, secs(8));
        assert_eq!(
            pacer.try_send("bob", ASCII, secs(17)),
            Err(KeyReqRefusal::Reassembling)
        );
        // A refusal used no interval: the first send goes at once.
        assert_eq!(pacer.try_send("bob", ASCII, secs(18)), Ok(()));
        assert_eq!(
            pacer.try_send("bob", ASCII, secs(40)),
            Err(KeyReqRefusal::Interval)
        );
        pacer.note_fragment("bob", "B", ASCII, secs(48));
        pacer.finish("bob", "B", ASCII);
        assert_eq!(pacer.try_send("bob", ASCII, secs(48)), Ok(()));
    }

    #[test]
    fn keys_interval_and_fake_lag_bank_are_separate_values() {
        let mut limiter = keys_answer_limiter();
        assert!(limiter.try_acquire("bob", ASCII, secs(0)));
        assert!(!limiter.try_acquire("bob", ASCII, secs(14)));
        // 15 seconds is enough, although the bank is 22 seconds.
        assert!(limiter.try_acquire("bob", ASCII, secs(15)));
        assert!(KEYS_ANSWER_INTERVAL < FAKE_LAG_BANK);
    }

    #[test]
    fn one_time_key_global_limit_per_hour() {
        let mut pacer = OneTimeKeyPacer::new();
        for i in 0..30u64 {
            let nick = format!("nick{i}");
            assert_eq!(pacer.choose(&nick, ASCII, secs(i)), KeyChoice::OneTime);
        }
        assert_eq!(pacer.choose("extra", ASCII, secs(30)), KeyChoice::Fallback);
        // A refused request used no per-nick interval.
        assert_eq!(pacer.choose("extra", ASCII, secs(3600)), KeyChoice::OneTime);
        // The first grant has left the window at 3600 seconds.
        assert_eq!(pacer.choose("later", ASCII, secs(3601)), KeyChoice::OneTime);
    }

    #[test]
    fn candidate_values_are_the_md3_numbers() {
        assert_eq!(md3_candidate::REKEY_INTERVAL, secs(60));
        assert_eq!(md3_candidate::OUTGOING_QUEUE_TTL, secs(90));
        assert_eq!(md3_candidate::ONE_TIME_KEY_INTERVAL, secs(60));
        assert_eq!(md3_candidate::ONE_TIME_KEY_GLOBAL_LIMIT, 30);
        assert_eq!(md3_candidate::ONE_TIME_KEY_WINDOW, secs(3600));
    }
}
