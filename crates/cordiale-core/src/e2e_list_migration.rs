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

//! Check for device lists that an older build signed over the raw byte order
//! of the keys.
//!
//! The current order is ascending plain text (`sort_list_keys`). An older
//! build ordered the keys by their raw 32 bytes. Where such a signature can
//! exist:
//!
//! - The sealed local state holds no signed list, so it cannot hold one.
//! - The peer trust state (`PeerTrust`) and the peer directory keep the
//!   version and the keys of a list, never its signature.
//! - The own list on the server can hold an old-order signature.
//!
//! This module only tells the caller that a list has the old order. It never
//! accepts a list. The certificate text holds one key, so the key order does
//! not apply to it.

use crate::e2e_device::{verify_signature, verify_signed_list, E2eError};
use crate::e2e_wire::legacy_raw_order_list_signed_text;

/// True when the signature verifies over the old raw byte order but not over
/// the current order. The caller uses it to mark a peer, never to accept the
/// list.
pub(crate) fn has_legacy_order(
    version: u32,
    keys: &[String],
    master_ed25519: &str,
    signature: &str,
) -> bool {
    if verify_signed_list(version, keys, master_ed25519, signature) != Err(E2eError::BadSignature) {
        return false;
    }
    legacy_raw_order_list_signed_text(version, keys)
        .is_ok_and(|text| verify_signature(master_ed25519, signature, &text).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_device::build_signed_list_signature;
    use crate::e2e_wire::signed_list_signed_text;
    use vodozemac::olm::Account;

    fn key_of(account: &Account) -> String {
        account.identity_keys().ed25519.to_base64()
    }

    /// Four device keys whose raw byte order differs from the text order.
    fn keys_in_two_orders() -> Vec<String> {
        loop {
            let keys: Vec<String> = (0..4).map(|_| key_of(&Account::new())).collect();
            let current = signed_list_signed_text(1, &keys).unwrap();
            if current != legacy_raw_order_list_signed_text(1, &keys).unwrap() {
                return keys;
            }
        }
    }

    #[test]
    fn only_a_list_in_the_old_order_is_found() {
        let master = Account::new();
        let master_key = key_of(&master);
        let keys = keys_in_two_orders();
        let text = legacy_raw_order_list_signed_text(2, &keys).unwrap();
        let old = master.sign(&text).to_base64();
        let new = build_signed_list_signature(2, &keys, |t| master.sign(t).to_base64()).unwrap();
        assert!(has_legacy_order(2, &keys, &master_key, &old));
        assert!(!has_legacy_order(2, &keys, &master_key, &new));
        assert!(!has_legacy_order(3, &keys, &master_key, &old));
        let foreign = Account::new().sign(&text).to_base64();
        assert!(!has_legacy_order(2, &keys, &master_key, &foreign));
    }
}
