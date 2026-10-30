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

use vodozemac::olm::Account;

use crate::e2e_device::{
    build_signed_list_signature, verify_signature, verify_signed_list, E2eError,
};
use crate::e2e_manage::SignedList;
use crate::e2e_wire::legacy_raw_order_list_signed_text;

/// The key order over which a signature verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListOrder {
    /// Ascending plain text, the current order.
    Current,
    /// The raw byte order of an older build.
    Legacy,
}

/// The order over which the signature verifies, or `BadSignature` when it
/// verifies in no order.
pub(crate) fn list_order(
    version: u32,
    keys: &[String],
    master_ed25519: &str,
    signature: &str,
) -> Result<ListOrder, E2eError> {
    match verify_signed_list(version, keys, master_ed25519, signature) {
        Ok(()) => Ok(ListOrder::Current),
        Err(E2eError::BadSignature) => {
            if has_legacy_order(version, keys, master_ed25519, signature) {
                Ok(ListOrder::Legacy)
            } else {
                Err(E2eError::BadSignature)
            }
        }
        Err(err) => Err(err),
    }
}

/// Signs the own list again with the master key when it verifies only in the
/// old order. The version and the keys stay the same.
///
/// Returns `None` when the list has the current order. Returns an error and
/// signs nothing when the list verifies in no order, for example when another
/// key signed it.
pub(crate) fn migrate_own_list(
    master: &Account,
    list: &SignedList,
) -> Result<Option<SignedList>, E2eError> {
    let master_key = master.identity_keys().ed25519.to_base64();
    match list_order(list.version, &list.keys, &master_key, &list.signature)? {
        ListOrder::Current => Ok(None),
        ListOrder::Legacy => {
            let signature = build_signed_list_signature(list.version, &list.keys, |text| {
                master.sign(text).to_base64()
            })?;
            Ok(Some(SignedList {
                version: list.version,
                keys: list.keys.clone(),
                signature,
            }))
        }
    }
}

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

    fn legacy_list(master: &Account, version: u32, keys: &[String]) -> SignedList {
        let text = legacy_raw_order_list_signed_text(version, keys).unwrap();
        SignedList {
            version,
            keys: keys.to_vec(),
            signature: master.sign(&text).to_base64(),
        }
    }

    #[test]
    fn list_order_tells_the_three_cases_apart() {
        let master = Account::new();
        let master_key = key_of(&master);
        let keys = keys_in_two_orders();
        let old = legacy_list(&master, 2, &keys);
        let new = build_signed_list_signature(2, &keys, |t| master.sign(t).to_base64()).unwrap();
        let order = |sig: &str| list_order(2, &keys, &master_key, sig);
        assert_eq!(order(&old.signature), Ok(ListOrder::Legacy));
        assert_eq!(order(&new), Ok(ListOrder::Current));
        assert_eq!(
            order(&Account::new().sign("x").to_base64()),
            Err(E2eError::BadSignature)
        );
    }

    #[test]
    fn an_old_order_own_list_is_signed_again_with_the_same_version_and_keys() {
        let master = Account::new();
        let keys = keys_in_two_orders();
        let old = legacy_list(&master, 4, &keys);
        let next = migrate_own_list(&master, &old).unwrap().expect("migrated");
        assert_eq!((next.version, &next.keys), (4, &keys));
        verify_signed_list(4, &keys, &key_of(&master), &next.signature).expect("current order");
        assert_eq!(migrate_own_list(&master, &next), Ok(None));
    }

    #[test]
    fn an_own_list_in_no_order_or_under_another_key_is_an_error() {
        let master = Account::new();
        let keys = keys_in_two_orders();
        let other = Account::new();
        let foreign = legacy_list(&other, 2, &keys);
        assert_eq!(
            migrate_own_list(&master, &foreign),
            Err(E2eError::BadSignature)
        );
        let mut wrong_version = legacy_list(&master, 2, &keys);
        wrong_version.version = 3;
        assert_eq!(
            migrate_own_list(&master, &wrong_version),
            Err(E2eError::BadSignature)
        );
    }
}
