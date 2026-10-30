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

//! S1 copies between the devices of one account (protocol 50): the pure
//! rules for the per-device inbox.
//!
//! The contract is the one of Grappa protocol 50. After Grappa answers 202
//! for the original text, the sending device claims one key of each sibling
//! device (`claim`, body `{"from_did"}`, answer `{"keys"}` in the KEYS wire
//! shape). It encrypts one `copy` for each sibling and queues it through the
//! `copies` route. A copy never goes over IRC. The own verified signed list
//! names the siblings. A server KEYS list can remove a sibling and never adds
//! one. The calls are in `E2eEngine::send_copies`.
//!
//! A device reads the inbox rows with `own` set through a separate path,
//! `E2eEngine::receive_copy`. It does not use the identity checks of peer
//! messages. A copy shows as a sent row in the locked E2E query of its peer,
//! also when the device never opened that query. The plain query gets no row.
//! A repeated push or drain gives one row.
//!
//! Refusals of the relay: `same_device`, `keyless_device`, `key_taken`,
//! `removed_device` and `inbox_full`. Each one ends the copy for that sibling.
//! Only `key_taken` asks for a new key, once.
//!
//! Accepted case: Grappa accepts the original with 202 and Cordiale queues the
//! copy. Then Grappa drops the original unsent. The sibling shows a sent row
//! and the sender shows a failed row. A copy never proves delivery to the
//! peer.
//!
//! This module holds the rules that do not depend on the routes: the copy
//! plan, the inbox limits, the delivery states and the drain with its
//! acknowledgements. The Olm engine plugs in through [`CopyCipher`]. Types
//! carry ciphertext only: plaintext goes to the caller through a sink and
//! never into a value that can be logged.

use std::collections::{HashMap, HashSet};

use crate::e2e_wire::{
    INBOX_ENTRY_COST_BYTES, INBOX_EXPIRY_SECS, INBOX_MAX_BYTES, INBOX_SENDER_MAX_BYTES,
};

/// The Olm operations that S1 needs. The engine of the pairing phase
/// implements it.
pub trait CopyCipher {
    /// Encrypts for one device. `None` means that no session is usable.
    fn encrypt(&mut self, target_did: &str, plaintext: &[u8]) -> Option<String>;
    /// Decrypts a copy from one device. `None` means that it is not readable.
    fn decrypt(&mut self, sender_did: &str, ciphertext: &str) -> Option<Vec<u8>>;
}

/// One encrypted copy for the inbox of one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingCopy {
    pub target_did: String,
    pub item_id: String,
    pub ciphertext: String,
}

/// The result of the copy plan for one sent message.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CopyPlan {
    pub copies: Vec<OutgoingCopy>,
    /// Devices that get no copy: no session, or the copy is too large.
    pub failed: Vec<String>,
}

/// Makes one copy for each device in `peer_dids` except `own_did`.
///
/// Only the message being sent is encrypted, so a new device never gets
/// earlier history from this function.
pub fn build_copies(
    own_did: &str,
    peer_dids: &[&str],
    msgid: &str,
    plaintext: &[u8],
    cipher: &mut dyn CopyCipher,
) -> CopyPlan {
    let mut plan = CopyPlan::default();
    let mut seen = HashSet::new();
    for did in peer_dids.iter().copied().filter(|d| *d != own_did) {
        if !seen.insert(did) {
            continue;
        }
        match cipher.encrypt(did, plaintext) {
            Some(ciphertext) if inbox_accepts(0, 0, ciphertext.len()) => {
                plan.copies.push(OutgoingCopy {
                    target_did: did.to_owned(),
                    item_id: format!("{msgid}.{did}"),
                    ciphertext,
                });
            }
            _ => plan.failed.push(did.to_owned()),
        }
    }
    plan
}

/// True when an inbox can take one more copy.
///
/// `total_bytes` is the size of the whole inbox. `sender_bytes` is the size
/// of the items of the same sender. A self-copy counts as a sender. Count
/// each stored entry as its payload size plus `INBOX_ENTRY_COST_BYTES`. The
/// new copy counts the same way: `next_len` plus `INBOX_ENTRY_COST_BYTES`.
pub fn inbox_accepts(total_bytes: usize, sender_bytes: usize, next_len: usize) -> bool {
    let Some(cost) = next_len.checked_add(INBOX_ENTRY_COST_BYTES) else {
        return false;
    };
    total_bytes
        .checked_add(cost)
        .is_some_and(|sum| sum <= INBOX_MAX_BYTES)
        && sender_bytes
            .checked_add(cost)
            .is_some_and(|sum| sum <= INBOX_SENDER_MAX_BYTES)
}

/// True when a copy created at `created_at` (Unix seconds) is expired.
pub fn is_expired(created_at: u64, now: u64) -> bool {
    now >= created_at.saturating_add(INBOX_EXPIRY_SECS)
}

/// The state of one copy for one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyState {
    /// The relay accepted the copy. The device did not confirm it.
    Queued { created_at: u64 },
    /// The device acknowledged the copy.
    Delivered,
    /// The copy expired before the device acknowledged it.
    Expired,
    /// The relay reports that the copy is gone.
    Missing,
}

/// Tracks the copies of sent messages. Only an acknowledgement from the
/// device makes a copy [`CopyState::Delivered`].
#[derive(Debug, Default)]
pub struct DeliveryTracker {
    states: HashMap<(String, String), CopyState>,
}

impl DeliveryTracker {
    pub fn queued(&mut self, item_id: &str, target_did: &str, created_at: u64) {
        self.states.insert(
            (item_id.to_owned(), target_did.to_owned()),
            CopyState::Queued { created_at },
        );
    }

    /// A late or repeated acknowledgement does not change an expired or
    /// missing copy.
    pub fn acknowledged(&mut self, item_id: &str, target_did: &str) {
        self.settle(item_id, target_did, CopyState::Delivered);
    }

    pub fn missing(&mut self, item_id: &str, target_did: &str) {
        self.settle(item_id, target_did, CopyState::Missing);
    }

    fn settle(&mut self, item_id: &str, target_did: &str, next: CopyState) {
        if let Some(state) = self
            .states
            .get_mut(&(item_id.to_owned(), target_did.to_owned()))
        {
            if matches!(state, CopyState::Queued { .. }) {
                *state = next;
            }
        }
    }

    /// Moves every queued copy past its lifetime to [`CopyState::Expired`].
    pub fn expire(&mut self, now: u64) {
        for state in self.states.values_mut() {
            if let CopyState::Queued { created_at } = *state {
                if is_expired(created_at, now) {
                    *state = CopyState::Expired;
                }
            }
        }
    }

    pub fn state(&self, item_id: &str, target_did: &str) -> Option<CopyState> {
        self.states
            .get(&(item_id.to_owned(), target_did.to_owned()))
            .copied()
    }

    pub fn is_delivered(&self, item_id: &str, target_did: &str) -> bool {
        self.state(item_id, target_did) == Some(CopyState::Delivered)
    }
}

/// One item read from the inbox of this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxItem {
    pub id: String,
    pub sender_did: String,
    pub created_at: u64,
    pub ciphertext: String,
}

/// What the drain did with one item. The caller acknowledges every outcome
/// except [`DrainOutcome::StoreFailed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    Stored,
    Duplicate,
    Expired,
    /// The copy is older than the pairing of this device: no old history.
    BeforePairing,
    Undecryptable,
    /// The sink could not write the copy. The item is not marked as seen.
    /// Do not acknowledge it: it stays in the inbox for the next drain.
    StoreFailed,
}

impl DrainOutcome {
    /// True when the caller acknowledges the item.
    pub fn acknowledge(self) -> bool {
        self != DrainOutcome::StoreFailed
    }
}

/// Processes the items of the inbox of one device.
///
/// `seen` holds the ids already stored by this device. `paired_at` is the
/// time at which this device joined the account. The sink gets the plaintext
/// of each item and writes it to the encrypted history. An item is marked as
/// seen only when the sink succeeds. The returned list has one entry for each
/// item, in order: the caller acknowledges the ids for which
/// [`DrainOutcome::acknowledge`] is true, also the ids of items that it did
/// not store. The error of the sink is dropped, so the outcome holds no
/// detail of the store.
pub fn drain_inbox<E>(
    items: &[InboxItem],
    now: u64,
    paired_at: u64,
    seen: &mut HashSet<String>,
    cipher: &mut dyn CopyCipher,
    mut sink: impl FnMut(&InboxItem, Vec<u8>) -> Result<(), E>,
) -> Vec<(String, DrainOutcome)> {
    items
        .iter()
        .map(|item| {
            let outcome = if seen.contains(&item.id) {
                DrainOutcome::Duplicate
            } else if is_expired(item.created_at, now) {
                DrainOutcome::Expired
            } else if item.created_at < paired_at {
                DrainOutcome::BeforePairing
            } else if let Some(plain) = cipher.decrypt(&item.sender_did, &item.ciphertext) {
                if sink(item, plain).is_ok() {
                    seen.insert(item.id.clone());
                    DrainOutcome::Stored
                } else {
                    DrainOutcome::StoreFailed
                }
            } else {
                DrainOutcome::Undecryptable
            };
            (item.id.clone(), outcome)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test cipher: reverses the text and marks it. It refuses the devices
    /// in `offline`.
    #[derive(Default)]
    struct FakeCipher {
        offline: Vec<String>,
    }

    impl CopyCipher for FakeCipher {
        fn encrypt(&mut self, target_did: &str, plaintext: &[u8]) -> Option<String> {
            if self.offline.iter().any(|d| d == target_did) {
                return None;
            }
            let mut bytes = plaintext.to_vec();
            bytes.reverse();
            Some(format!("ct:{}", String::from_utf8(bytes).ok()?))
        }

        fn decrypt(&mut self, _sender_did: &str, ciphertext: &str) -> Option<Vec<u8>> {
            let body = ciphertext.strip_prefix("ct:")?;
            let mut bytes = body.as_bytes().to_vec();
            bytes.reverse();
            Some(bytes)
        }
    }

    fn item(id: &str, created_at: u64, ciphertext: &str) -> InboxItem {
        InboxItem {
            id: id.to_owned(),
            sender_did: "dev-a".to_owned(),
            created_at,
            ciphertext: ciphertext.to_owned(),
        }
    }

    #[test]
    fn one_copy_for_each_other_device() {
        let mut cipher = FakeCipher::default();
        let plan = build_copies(
            "dev-a",
            &["dev-a", "dev-b", "dev-c", "dev-b"],
            "m1",
            b"secret text",
            &mut cipher,
        );
        let targets: Vec<&str> = plan.copies.iter().map(|c| c.target_did.as_str()).collect();
        assert_eq!(targets, ["dev-b", "dev-c"]);
        assert!(plan.failed.is_empty());
        assert_eq!(plan.copies[0].item_id, "m1.dev-b");
    }

    #[test]
    fn copies_hold_ciphertext_only() {
        let mut cipher = FakeCipher::default();
        let plan = build_copies("dev-a", &["dev-b"], "m1", b"secret text", &mut cipher);
        assert!(!format!("{plan:?}").contains("secret text"));
    }

    #[test]
    fn offline_device_is_reported_and_not_delivered() {
        let mut cipher = FakeCipher {
            offline: vec!["dev-c".to_owned()],
        };
        let plan = build_copies("dev-a", &["dev-b", "dev-c"], "m1", b"hi", &mut cipher);
        assert_eq!(plan.copies.len(), 1);
        assert_eq!(plan.failed, ["dev-c"]);
        let mut tracker = DeliveryTracker::default();
        tracker.queued("m1.dev-b", "dev-b", 100);
        assert_eq!(tracker.state("m1.dev-c", "dev-c"), None);
        assert!(!tracker.is_delivered("m1.dev-c", "dev-c"));
    }

    #[test]
    fn too_large_copy_is_not_sent() {
        struct Big;
        impl CopyCipher for Big {
            fn encrypt(&mut self, _: &str, _: &[u8]) -> Option<String> {
                Some("x".repeat(INBOX_SENDER_MAX_BYTES + 1))
            }
            fn decrypt(&mut self, _: &str, _: &str) -> Option<Vec<u8>> {
                None
            }
        }
        let plan = build_copies("dev-a", &["dev-b"], "m1", b"hi", &mut Big);
        assert!(plan.copies.is_empty());
        assert_eq!(plan.failed, ["dev-b"]);
    }

    #[test]
    fn inbox_limits_apply() {
        let room = INBOX_SENDER_MAX_BYTES - INBOX_ENTRY_COST_BYTES;
        assert!(inbox_accepts(0, 0, room));
        assert!(!inbox_accepts(0, 0, room + 1));
        assert!(!inbox_accepts(0, 1, room));
        assert!(!inbox_accepts(
            INBOX_MAX_BYTES - INBOX_ENTRY_COST_BYTES - 9,
            0,
            10
        ));
        assert!(inbox_accepts(
            INBOX_MAX_BYTES - INBOX_ENTRY_COST_BYTES - 10,
            0,
            10
        ));
        assert!(!inbox_accepts(usize::MAX, 0, 1));
        assert!(!inbox_accepts(0, 0, usize::MAX));
    }

    #[test]
    fn each_inbox_entry_costs_256_bytes_more() {
        assert_eq!(INBOX_ENTRY_COST_BYTES, 256);
        // An empty copy still takes the entry cost.
        assert!(!inbox_accepts(
            INBOX_MAX_BYTES - INBOX_ENTRY_COST_BYTES + 1,
            0,
            0
        ));
        assert!(inbox_accepts(
            INBOX_MAX_BYTES - INBOX_ENTRY_COST_BYTES,
            0,
            0
        ));
    }

    #[test]
    fn expiry_is_seven_days() {
        assert!(!is_expired(1000, 1000 + INBOX_EXPIRY_SECS - 1));
        assert!(is_expired(1000, 1000 + INBOX_EXPIRY_SECS));
    }

    #[test]
    fn only_an_acknowledgement_delivers() {
        let mut tracker = DeliveryTracker::default();
        tracker.queued("m1.dev-b", "dev-b", 100);
        assert!(!tracker.is_delivered("m1.dev-b", "dev-b"));
        tracker.acknowledged("m1.dev-b", "dev-b");
        assert!(tracker.is_delivered("m1.dev-b", "dev-b"));
        tracker.acknowledged("m1.dev-b", "dev-b");
        assert!(tracker.is_delivered("m1.dev-b", "dev-b"));
    }

    #[test]
    fn expired_or_missing_copy_is_never_delivered() {
        let mut tracker = DeliveryTracker::default();
        tracker.queued("m1.dev-b", "dev-b", 100);
        tracker.queued("m1.dev-c", "dev-c", 100);
        tracker.missing("m1.dev-c", "dev-c");
        tracker.expire(100 + INBOX_EXPIRY_SECS);
        tracker.acknowledged("m1.dev-b", "dev-b");
        tracker.acknowledged("m1.dev-c", "dev-c");
        assert_eq!(tracker.state("m1.dev-b", "dev-b"), Some(CopyState::Expired));
        assert_eq!(tracker.state("m1.dev-c", "dev-c"), Some(CopyState::Missing));
        assert!(!tracker.is_delivered("m1.dev-b", "dev-b"));
        assert!(!tracker.is_delivered("m1.dev-c", "dev-c"));
    }

    #[test]
    fn one_device_acknowledgement_does_not_deliver_another() {
        let mut tracker = DeliveryTracker::default();
        tracker.queued("m1.dev-b", "dev-b", 100);
        tracker.queued("m1.dev-c", "dev-c", 100);
        tracker.acknowledged("m1.dev-b", "dev-b");
        assert!(tracker.is_delivered("m1.dev-b", "dev-b"));
        assert!(!tracker.is_delivered("m1.dev-c", "dev-c"));
    }

    #[test]
    fn drain_stores_and_acknowledges_each_item() {
        let mut cipher = FakeCipher::default();
        let mut seen = HashSet::new();
        let mut stored = Vec::new();
        let items = [item("a", 500, "ct:olleh")];
        let out = drain_inbox(&items, 600, 0, &mut seen, &mut cipher, |i, plain| {
            stored.push((i.id.clone(), plain));
            Ok::<(), ()>(())
        });
        assert_eq!(out, [("a".to_owned(), DrainOutcome::Stored)]);
        assert_eq!(stored, [("a".to_owned(), b"hello".to_vec())]);
    }

    #[test]
    fn duplicate_delivery_is_stored_once_and_acknowledged() {
        let mut cipher = FakeCipher::default();
        let mut seen = HashSet::new();
        let mut count = 0;
        let items = [item("a", 500, "ct:x"), item("a", 500, "ct:x")];
        let out = drain_inbox(&items, 600, 0, &mut seen, &mut cipher, |_, _| {
            count += 1;
            Ok::<(), ()>(())
        });
        assert_eq!(count, 1);
        assert_eq!(out[1], ("a".to_owned(), DrainOutcome::Duplicate));
    }

    #[test]
    fn expired_and_unreadable_items_are_acknowledged_not_stored() {
        let mut cipher = FakeCipher::default();
        let mut seen = HashSet::new();
        let mut count = 0;
        let now = 10 + INBOX_EXPIRY_SECS;
        let items = [item("old", 10, "ct:x"), item("bad", now, "garbage")];
        let out = drain_inbox(&items, now, 0, &mut seen, &mut cipher, |_, _| {
            count += 1;
            Ok::<(), ()>(())
        });
        assert_eq!(count, 0);
        assert_eq!(out[0].1, DrainOutcome::Expired);
        assert_eq!(out[1].1, DrainOutcome::Undecryptable);
    }

    #[test]
    fn new_device_gets_no_earlier_history() {
        let mut cipher = FakeCipher::default();
        let mut seen = HashSet::new();
        let mut ids = Vec::new();
        let items = [item("before", 100, "ct:x"), item("after", 300, "ct:x")];
        let out = drain_inbox(&items, 400, 200, &mut seen, &mut cipher, |i, _| {
            ids.push(i.id.clone());
            Ok::<(), ()>(())
        });
        assert_eq!(out[0].1, DrainOutcome::BeforePairing);
        assert_eq!(ids, ["after"]);
    }

    #[test]
    fn failed_write_keeps_the_item_for_the_next_drain() {
        let mut cipher = FakeCipher::default();
        let mut seen = HashSet::new();
        let mut rows = Vec::new();
        let mut calls = 0;
        let items = [item("a", 500, "ct:x")];
        let mut sink = |i: &InboxItem, plain: Vec<u8>| {
            calls += 1;
            if calls == 1 {
                return Err(());
            }
            rows.push((i.id.clone(), plain));
            Ok(())
        };
        let first = drain_inbox(&items, 600, 0, &mut seen, &mut cipher, &mut sink);
        assert_eq!(first[0].1, DrainOutcome::StoreFailed);
        assert!(!first[0].1.acknowledge());
        assert!(seen.is_empty());
        let second = drain_inbox(&items, 600, 0, &mut seen, &mut cipher, &mut sink);
        assert_eq!(second[0].1, DrainOutcome::Stored);
        assert!(second[0].1.acknowledge());
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn inboxes_drain_independently() {
        let mut cipher = FakeCipher::default();
        let mut seen_b = HashSet::new();
        let mut seen_c = HashSet::new();
        let items_b = [item("m1.dev-b", 500, "ct:x")];
        let items_c = [item("m1.dev-c", 500, "ct:x")];
        let out_b = drain_inbox(&items_b, 600, 0, &mut seen_b, &mut cipher, |_, _| {
            Ok::<(), ()>(())
        });
        assert_eq!(out_b.len(), 1);
        assert!(seen_c.is_empty());
        let out_c = drain_inbox(&items_c, 600, 0, &mut seen_c, &mut cipher, |_, _| {
            Ok::<(), ()>(())
        });
        assert_eq!(out_c[0].1, DrainOutcome::Stored);
        assert!(seen_b.contains("m1.dev-b") && !seen_b.contains("m1.dev-c"));
    }
}
