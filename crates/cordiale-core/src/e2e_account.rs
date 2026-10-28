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

//! Local Olm accounts of the E2E engine, one for each network and device.
//!
//! An account is made on the device that uses it and never leaves it. The
//! private keys stay inside the [`LocalAccount`]: it has no accessor for them
//! and its `Debug` text hides them. This module holds the account and its
//! one-time keys.
//!
//! Not in this module: the public bundle, the master signing key, the
//! encrypted storage of the account, the REST upload and the Olm sessions.

use std::collections::HashMap;
use std::fmt;

use vodozemac::olm::Account;

/// Why an account step fails.
#[derive(Debug, PartialEq, Eq)]
pub enum AccountError {
    /// The network or the device name is empty.
    BadId,
    /// An account for this network and device exists already.
    Exists,
    /// No account for this network and device.
    Missing,
}

/// The pair that owns one account: a network and a local device name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId {
    network: String,
    device: String,
}

impl AccountId {
    pub fn new(network: &str, device: &str) -> Result<Self, AccountError> {
        if network.is_empty() || device.is_empty() {
            return Err(AccountError::BadId);
        }
        Ok(Self {
            network: network.to_string(),
            device: device.to_string(),
        })
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn device(&self) -> &str {
        &self.device
    }
}

/// The Olm account of one network and device pair.
pub struct LocalAccount {
    id: AccountId,
    account: Account,
}

impl LocalAccount {
    pub fn create(id: AccountId) -> Self {
        Self {
            id,
            account: Account::new(),
        }
    }

    /// Wraps an account that the sealed store gave back.
    pub fn from_account(id: AccountId, account: Account) -> Self {
        Self { id, account }
    }

    /// The Olm account, for the sealed store only.
    pub(crate) fn account(&self) -> &Account {
        &self.account
    }

    /// Signs with the Ed25519 key of the device. The signature is unpadded
    /// standard base64.
    pub fn sign(&self, message: &[u8]) -> String {
        self.account.sign(message).to_base64()
    }

    /// Makes `count` new one-time keys, without a look at the keys that
    /// the account holds already. The caller counts what the server holds.
    pub fn generate_one_time_keys(&mut self, count: usize) {
        if count > 0 {
            self.account.generate_one_time_keys(count);
        }
    }

    pub fn id(&self) -> &AccountId {
        &self.id
    }

    /// The public device key (Curve25519) as unpadded standard base64.
    pub fn curve25519(&self) -> String {
        self.account.identity_keys().curve25519.to_base64()
    }

    /// The public device signing key (Ed25519) as unpadded standard base64.
    pub fn ed25519(&self) -> String {
        self.account.identity_keys().ed25519.to_base64()
    }

    /// Makes new one-time keys until the account holds `target`, at most the
    /// limit of the Olm account. Returns how many keys it made.
    pub fn replenish_one_time_keys(&mut self, target: usize) -> usize {
        let target = target.min(self.account.max_number_of_one_time_keys());
        let missing = target.saturating_sub(self.account.stored_one_time_key_count());
        if missing > 0 {
            self.account.generate_one_time_keys(missing);
        }
        missing
    }

    /// The number of one-time keys that the account holds.
    pub fn one_time_key_count(&self) -> usize {
        self.account.stored_one_time_key_count()
    }

    /// The public one-time keys not yet published, sorted.
    pub fn unpublished_one_time_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .account
            .one_time_keys()
            .values()
            .map(|key| key.to_base64())
            .collect();
        keys.sort();
        keys
    }

    /// Makes a new fallback key. The key before it stays for late messages.
    /// The key before that one is forgotten.
    pub fn rotate_fallback_key(&mut self) {
        self.account.forget_fallback_key();
        self.account.generate_fallback_key();
    }

    /// The public fallback key not yet published.
    pub fn unpublished_fallback_key(&self) -> Option<String> {
        self.account
            .fallback_key()
            .values()
            .next()
            .map(|key| key.to_base64())
    }

    /// Marks the current one-time and fallback keys as published, after the
    /// upload works.
    pub fn mark_published(&mut self) {
        self.account.mark_keys_as_published();
    }
}

impl fmt::Debug for LocalAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalAccount")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The accounts of this device, one for each network. A lookup needs the
/// exact pair, so one pair cannot reach the account of another.
#[derive(Debug, Default)]
pub struct AccountStore {
    accounts: HashMap<AccountId, LocalAccount>,
}

impl AccountStore {
    /// Makes the account for a pair. It fails when the pair has one already.
    pub fn create(&mut self, id: AccountId) -> Result<&mut LocalAccount, AccountError> {
        if self.accounts.contains_key(&id) {
            return Err(AccountError::Exists);
        }
        Ok(self
            .accounts
            .entry(id.clone())
            .or_insert_with(|| LocalAccount::create(id)))
    }

    pub fn get(&self, id: &AccountId) -> Result<&LocalAccount, AccountError> {
        self.accounts.get(id).ok_or(AccountError::Missing)
    }

    pub fn get_mut(&mut self, id: &AccountId) -> Result<&mut LocalAccount, AccountError> {
        self.accounts.get_mut(id).ok_or(AccountError::Missing)
    }

    pub fn remove(&mut self, id: &AccountId) -> Option<LocalAccount> {
        self.accounts.remove(id)
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(network: &str, device: &str) -> AccountId {
        AccountId::new(network, device).unwrap()
    }

    /// An account with one-time keys, as the private state to compare.
    fn state(account: &mut LocalAccount) -> (String, String, Vec<String>) {
        account.replenish_one_time_keys(3);
        (
            account.curve25519(),
            account.ed25519(),
            account.unpublished_one_time_keys(),
        )
    }

    #[test]
    fn empty_names_are_rejected() {
        assert_eq!(AccountId::new("", "d"), Err(AccountError::BadId));
        assert_eq!(AccountId::new("n", ""), Err(AccountError::BadId));
    }

    #[test]
    fn two_devices_on_one_network_have_different_accounts() {
        let mut store = AccountStore::default();
        store.create(id("net", "laptop")).unwrap();
        store.create(id("net", "phone")).unwrap();
        let a = state(store.get_mut(&id("net", "laptop")).unwrap());
        let b = state(store.get_mut(&id("net", "phone")).unwrap());
        assert_ne!(a.0, b.0);
        assert_ne!(a.1, b.1);
        assert!(a.2.iter().all(|key| !b.2.contains(key)));
    }

    #[test]
    fn two_networks_on_one_device_have_different_accounts() {
        let mut store = AccountStore::default();
        store.create(id("one", "laptop")).unwrap();
        store.create(id("two", "laptop")).unwrap();
        let a = state(store.get_mut(&id("one", "laptop")).unwrap());
        let b = state(store.get_mut(&id("two", "laptop")).unwrap());
        assert_ne!(a.0, b.0);
        assert_ne!(a.1, b.1);
        assert!(a.2.iter().all(|key| !b.2.contains(key)));
    }

    #[test]
    fn store_needs_the_exact_pair() {
        let mut store = AccountStore::default();
        store.create(id("one", "laptop")).unwrap();
        assert_eq!(
            store.create(id("one", "laptop")).err(),
            Some(AccountError::Exists)
        );
        assert_eq!(
            store.get(&id("one", "phone")).err(),
            Some(AccountError::Missing)
        );
        assert_eq!(
            store.get(&id("two", "laptop")).err(),
            Some(AccountError::Missing)
        );
        assert_eq!(store.len(), 1);
        assert!(store.remove(&id("one", "laptop")).is_some());
        assert!(store.is_empty());
    }

    #[test]
    fn one_time_keys_fill_up_to_the_target() {
        let mut account = LocalAccount::create(id("net", "laptop"));
        assert_eq!(account.replenish_one_time_keys(10), 10);
        assert_eq!(account.replenish_one_time_keys(10), 0);
        assert_eq!(account.replenish_one_time_keys(12), 2);
        assert_eq!(account.one_time_key_count(), 12);
        let limit = Account::new().max_number_of_one_time_keys();
        account.replenish_one_time_keys(limit + 100);
        assert_eq!(account.one_time_key_count(), limit);
    }

    #[test]
    fn published_keys_leave_the_unpublished_list() {
        let mut account = LocalAccount::create(id("net", "laptop"));
        account.replenish_one_time_keys(5);
        account.rotate_fallback_key();
        let first = account.unpublished_one_time_keys();
        assert_eq!(first.len(), 5);
        assert!(account.unpublished_fallback_key().is_some());
        account.mark_published();
        assert!(account.unpublished_one_time_keys().is_empty());
        assert!(account.unpublished_fallback_key().is_none());
        assert_eq!(account.one_time_key_count(), 5);
        account.replenish_one_time_keys(7);
        let third = account.unpublished_one_time_keys();
        assert_eq!(third.len(), 2);
        assert!(third.iter().all(|key| !first.contains(key)));
    }

    #[test]
    fn debug_text_hides_account_keys() {
        let account = LocalAccount::create(id("net", "laptop"));
        let text = format!("{account:?}");
        assert!(!text.contains(&account.ed25519()));
        assert!(!text.contains(&account.curve25519()));
    }
}
