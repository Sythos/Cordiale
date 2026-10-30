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

//! Checks the shared lifecycle fixtures: revocation, replay and sessions, and
//! expiry. The fixture file is plain JSON, so another implementation can read
//! the same cases. The keys in it are throw-away test keys.

use std::collections::HashSet;

use cordiale_core::e2e_peer::{ReplayState, REPLAY_WINDOW};
use cordiale_core::e2e_selfcopy::{
    drain_inbox, inbox_accepts, is_expired, CopyCipher, CopyState, DeliveryTracker, DrainOutcome,
    InboxItem,
};
use cordiale_core::e2e_trust::PeerTrust;
use cordiale_core::e2e_wire::{
    INBOX_ENTRY_COST_BYTES, INBOX_EXPIRY_SECS, INBOX_MAX_BYTES, INBOX_SENDER_MAX_BYTES,
};
use serde_json::Value;

const NET: &str = "net";
const NICK: &str = "alice";

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/e2e/lifecycle_v1.json"))
        .expect("fixture file is JSON")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_else(|| panic!("field {key}"))
}

fn number(value: &Value, key: &str) -> u64 {
    value[key].as_u64().unwrap_or_else(|| panic!("field {key}"))
}

fn flag(value: &Value, key: &str) -> bool {
    value[key]
        .as_bool()
        .unwrap_or_else(|| panic!("field {key}"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().expect("text").to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn every_fixture_file_has_the_revision_of_the_interop_report() {
    let files = [
        (include_str!("fixtures/e2e/wire_v2.json"), 4),
        (include_str!("fixtures/e2e/send_request.json"), 3),
        (include_str!("fixtures/e2e/send_dropped.json"), 3),
        (include_str!("fixtures/e2e/pairing_v1.json"), 1),
        (include_str!("fixtures/e2e/irc_olm_v2.json"), 1),
        (include_str!("fixtures/e2e/lifecycle_v1.json"), 1),
    ];
    for (file, revision) in files {
        let value: Value = serde_json::from_str(file).expect("fixture file is JSON");
        assert_eq!(value["fixture_revision"], revision);
    }
}

#[test]
fn fixture_limits_equal_the_constants_of_the_core() {
    let all = fixtures();
    assert_eq!(all["fixture_revision"], 1);
    assert_eq!(number(&all["expiry"], "lifetime_secs"), INBOX_EXPIRY_SECS);
    let limits = &all["expiry"]["inbox_limits"];
    assert_eq!(number(limits, "total"), INBOX_MAX_BYTES as u64);
    assert_eq!(number(limits, "per_sender"), INBOX_SENDER_MAX_BYTES as u64);
    assert_eq!(number(limits, "entry_cost"), INBOX_ENTRY_COST_BYTES as u64);
    assert_eq!(number(&all["sessions"], "window"), REPLAY_WINDOW as u64);
}

#[test]
fn fixture_revocation_steps_run_in_order() {
    let mut trust = PeerTrust::default();
    for step in fixtures()["revocation"].as_array().expect("steps") {
        let case = text(step, "case");
        let version = u32::try_from(number(step, "version")).expect("version");
        let result = trust.accept_list(
            NET,
            NICK,
            text(step, "master"),
            version,
            &strings(step, "keys"),
            text(step, "signature"),
        );
        let name = match result {
            Ok(decision) => format!("{decision:?}"),
            Err(err) => format!("{err:?}"),
        };
        assert_eq!(name, text(step, "result"), "{case}");
        for key in strings(step, "revoked") {
            assert!(trust.is_revoked(NET, NICK, &key, None), "{case}");
        }
        for key in strings(step, "not_revoked") {
            assert!(!trust.is_revoked(NET, NICK, &key, None), "{case}");
        }
    }
}

#[test]
fn fixture_revoked_device_is_found_again_by_its_did() {
    let all = fixtures();
    let mut trust = PeerTrust::default();
    for step in all["revocation"].as_array().expect("steps").iter().take(3) {
        let version = u32::try_from(number(step, "version")).expect("version");
        let _ = trust.accept_list(
            NET,
            NICK,
            text(step, "master"),
            version,
            &strings(step, "keys"),
            text(step, "signature"),
        );
    }
    // The second device of the fixture is the one that list 2 dropped.
    let devices = all["keys"]["devices"].as_array().expect("devices");
    let dropped = text(&devices[1], "did");
    let kept = text(&devices[0], "did");
    assert!(trust.is_did_revoked(NET, NICK, dropped));
    assert!(!trust.is_did_revoked(NET, NICK, kept));
    assert!(trust.has_revoked_devices(NET, NICK));
}

#[test]
fn fixture_replay_cases_run_in_order() {
    let all = fixtures();
    let mut replay = ReplayState::default();
    for case in all["sessions"]["first_messages"].as_array().expect("cases") {
        let result = replay.accept_first_message(NET, NICK, text(case, "did"), text(case, "id"));
        assert_eq!(
            outcome_name(result),
            text(case, "result"),
            "{}",
            text(case, "case")
        );
    }
    for case in all["sessions"]["new_sessions"].as_array().expect("cases") {
        let result = replay.accept_new_session(NET, NICK, text(case, "did"), text(case, "id"));
        assert_eq!(
            outcome_name(result),
            text(case, "result"),
            "{}",
            text(case, "case")
        );
    }
}

fn outcome_name<E: std::fmt::Debug>(result: Result<(), E>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(err) => format!("{err:?}"),
    }
}

#[test]
fn fixture_replay_window_forgets_only_the_oldest_id() {
    let did = text(&fixtures()["keys"]["devices"][0], "did").to_string();
    let mut replay = ReplayState::default();
    for n in 0..=REPLAY_WINDOW {
        replay
            .accept_first_message(NET, NICK, &did, &format!("id{n}"))
            .expect("new id");
    }
    // The window holds the last ids: the first one is accepted again, the
    // newest one is still a replay.
    assert!(replay
        .accept_first_message(NET, NICK, &did, &format!("id{REPLAY_WINDOW}"))
        .is_err());
    assert!(replay.accept_first_message(NET, NICK, &did, "id0").is_ok());
}

#[test]
fn fixture_expiry_follows_the_inbox_lifetime() {
    for case in fixtures()["expiry"]["is_expired"]
        .as_array()
        .expect("cases")
    {
        assert_eq!(
            is_expired(number(case, "created_at"), number(case, "now")),
            flag(case, "expired"),
            "{}",
            text(case, "case")
        );
    }
}

fn state_name(state: Option<CopyState>) -> &'static str {
    match state {
        None => "none",
        Some(CopyState::Queued { .. }) => "Queued",
        Some(CopyState::Delivered) => "Delivered",
        Some(CopyState::Expired) => "Expired",
        Some(CopyState::Missing) => "Missing",
    }
}

#[test]
fn fixture_copy_states_follow_acknowledgements_and_expiry() {
    for case in fixtures()["expiry"]["copy_states"]
        .as_array()
        .expect("cases")
    {
        let mut tracker = DeliveryTracker::default();
        for step in case["steps"].as_array().expect("steps") {
            match text(step, "do") {
                "queued" => tracker.queued("item", "did", number(step, "created_at")),
                "ack" => tracker.acknowledged("item", "did"),
                "missing" => tracker.missing("item", "did"),
                "expire" => tracker.expire(number(step, "now")),
                other => panic!("unknown step {other}"),
            }
        }
        let expected = case["state"].as_str().unwrap_or("none");
        assert_eq!(
            state_name(tracker.state("item", "did")),
            expected,
            "{}",
            text(case, "case")
        );
        // Only an acknowledgement makes a copy delivered.
        assert_eq!(
            tracker.is_delivered("item", "did"),
            expected == "Delivered",
            "{}",
            text(case, "case")
        );
    }
}

#[test]
fn fixture_inbox_limits_are_exact() {
    let limits = &fixtures()["expiry"]["inbox_limits"];
    for case in limits["cases"].as_array().expect("cases") {
        let size = |key: &str| usize::try_from(number(case, key)).expect("size");
        assert_eq!(
            inbox_accepts(size("total_bytes"), size("sender_bytes"), size("next_len")),
            flag(case, "accepts"),
            "{}",
            text(case, "case")
        );
    }
}

/// Reads the text `ok` and refuses any other ciphertext.
struct Reader;

impl CopyCipher for Reader {
    fn encrypt(&mut self, _target_did: &str, _plaintext: &[u8]) -> Option<String> {
        None
    }

    fn decrypt(&mut self, _sender_did: &str, ciphertext: &str) -> Option<Vec<u8>> {
        (ciphertext == "ok").then(|| b"plain".to_vec())
    }
}

fn outcome_label(outcome: DrainOutcome) -> &'static str {
    match outcome {
        DrainOutcome::Stored => "Stored",
        DrainOutcome::Duplicate => "Duplicate",
        DrainOutcome::Expired => "Expired",
        DrainOutcome::BeforePairing => "BeforePairing",
        DrainOutcome::Undecryptable => "Undecryptable",
        DrainOutcome::StoreFailed => "StoreFailed",
    }
}

#[test]
fn fixture_drain_gives_one_outcome_for_each_item() {
    let all = fixtures();
    let drain = &all["expiry"]["drain"];
    let cases = drain["items"].as_array().expect("items");
    let items: Vec<InboxItem> = cases
        .iter()
        .map(|case| InboxItem {
            id: text(case, "id").to_string(),
            sender_did: text(case, "sender_did").to_string(),
            created_at: number(case, "created_at"),
            ciphertext: text(case, "ciphertext").to_string(),
        })
        .collect();
    let mut seen = HashSet::new();
    let mut stored = Vec::new();
    let outcomes = drain_inbox(
        &items,
        number(drain, "now"),
        number(drain, "paired_at"),
        &mut seen,
        &mut Reader,
        |item, _plain| -> Result<(), ()> {
            stored.push(item.id.clone());
            Ok(())
        },
    );
    assert_eq!(outcomes.len(), cases.len());
    for ((id, outcome), case) in outcomes.iter().zip(cases) {
        assert_eq!(id, text(case, "id"));
        assert_eq!(
            outcome_label(*outcome),
            text(case, "outcome"),
            "{}",
            text(case, "case")
        );
        // The caller acknowledges every item that is not a store failure.
        assert!(outcome.acknowledge(), "{}", text(case, "case"));
    }
    // Only the readable item reached the sink, and only once.
    assert_eq!(stored, vec!["i1".to_string()]);
}
