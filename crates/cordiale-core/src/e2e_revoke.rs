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

//! Revoke of an own device and reset of the own E2E identity.
//!
//! A revoke signs a new device list with the master key. The list has a
//! higher version and lacks the revoked device. The steps are:
//!
//! 1. The revoked key goes to the trust state of the own nick and to the
//!    sealed store. From then on no key request, copy, inbox row or session
//!    uses the device, and an older list never restores it.
//! 2. The new list and the pending revoke go to the sealed store in one write.
//! 3. The list goes to the server. A stale answer reads the held list and
//!    signs again above it, without any revoked key.
//! 4. The server drops the device (`DELETE /e2e/devices/:did`). A device that
//!    the server forgot already (404) counts as dropped.
//!
//! A failed step keeps the pending revoke. [`finish_pending_revoke`] repeats
//! the steps that are not done, also after a restart.
//!
//! A reset needs a [`ResetConfirmation`]. It marks the reset in the store,
//! drops the identity on the server (`DELETE /e2e/keys`) and only then removes
//! the private state. A failed call keeps the private state, so a retry
//! finishes the reset. After a reset the device has no identity, so the locked
//! query cannot send. There is no clear-text path in this module. The history
//! store is not touched.

use crate::client::GrappaClient;
use crate::e2e_device::{verify_signed_list, E2eError};
use crate::e2e_identity_routes::ListRequest;
use crate::e2e_protocol::E2eOperation;
use crate::e2e_provision::sign_list;
use crate::e2e_refusal::{E2eRefusal, E2eRouteError};
use crate::e2e_state::{E2eStateStore, PendingRevoke};
use crate::e2e_store::E2eStoreError;
use crate::e2e_wire::{did_from_key_text, WireError};

/// The server and the account that a revoke or a reset talks to.
pub struct OwnRoutes<'a> {
    pub client: &'a GrappaClient,
    pub token: &'a str,
    /// The network id, also the network of the trust state.
    pub network: &'a str,
    /// The own nick, under which the own devices are stored as peers.
    pub own_nick: &'a str,
    pub server_protocol: Option<u32>,
}

/// Why a revoke or a reset stops.
#[derive(Debug)]
pub enum RevokeError {
    Store(E2eStoreError),
    Route(E2eRouteError),
    Wire(WireError),
    Crypto(E2eError),
    /// This device holds no master key, so it cannot sign a list.
    NeedsMaster,
    /// The device has no own list yet.
    NoList,
    /// The `did` is not in the own list.
    UnknownDevice,
    /// The device is this device. Reset the identity instead.
    OwnDevice,
    /// Another revoke is not finished. Finish it first.
    OtherPending,
    /// A reset is not finished.
    ResetPending,
    /// The list on the server has another master.
    MasterMismatch,
    /// The revoke would leave a list without a device.
    EmptyList,
}

impl From<E2eStoreError> for RevokeError {
    fn from(err: E2eStoreError) -> Self {
        Self::Store(err)
    }
}

impl From<E2eRouteError> for RevokeError {
    fn from(err: E2eRouteError) -> Self {
        Self::Route(err)
    }
}

impl From<WireError> for RevokeError {
    fn from(err: WireError) -> Self {
        Self::Wire(err)
    }
}

impl From<E2eError> for RevokeError {
    fn from(err: E2eError) -> Self {
        Self::Crypto(err)
    }
}

/// What a finished revoke did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    /// The id of the revoked device, for the message to the user.
    pub did: String,
    /// The version of the list that does not hold the device.
    pub list_version: u32,
}

/// Proof that the user confirmed a reset. Make it only after the user
/// accepted the question in the view.
#[derive(Debug)]
pub struct ResetConfirmation(());

impl ResetConfirmation {
    pub fn user_confirmed() -> Self {
        Self(())
    }
}

fn check_routes(routes: &OwnRoutes<'_>, operations: &[E2eOperation]) -> Result<(), RevokeError> {
    if operations
        .iter()
        .any(|operation| !operation.available(routes.server_protocol))
    {
        return Err(E2eRouteError::Unavailable.into());
    }
    Ok(())
}

/// Revokes the own device `did`. See the module text for the steps.
pub async fn revoke_device(
    routes: &OwnRoutes<'_>,
    store: &mut E2eStateStore,
    did: &str,
) -> Result<Revoked, RevokeError> {
    check_routes(
        routes,
        &[
            E2eOperation::DeviceDrop,
            E2eOperation::ListPut,
            E2eOperation::ListFetch,
        ],
    )?;
    if store.reset_pending() {
        return Err(RevokeError::ResetPending);
    }
    if let Some(pending) = store.pending_revoke() {
        if pending.did != did {
            return Err(RevokeError::OtherPending);
        }
        return finish_revoke(routes, store, pending).await;
    }
    let master = store.master_key()?.ok_or(RevokeError::NeedsMaster)?;
    let list = store.signed_list().ok_or(RevokeError::NoList)?;
    let target = list
        .keys
        .iter()
        .find(|key| did_from_key_text(key).is_ok_and(|found| found == did))
        .ok_or(RevokeError::UnknownDevice)?
        .clone();
    if store.device_key()?.as_deref() == Some(target.as_str()) {
        return Err(RevokeError::OwnDevice);
    }
    let keys: Vec<String> = list
        .keys
        .iter()
        .filter(|key| **key != target)
        .cloned()
        .collect();
    if keys.is_empty() {
        return Err(RevokeError::EmptyList);
    }
    let next = sign_list(&master, list.version + 1, &keys)?;
    let pending = PendingRevoke {
        ed25519: target,
        did: did.to_string(),
    };
    stop_routing(routes, store, &pending)?;
    store.begin_revoke(&pending, &next)?;
    finish_revoke(routes, store, pending).await
}

/// Repeats the steps of a revoke that is not finished. Returns `None` when
/// no revoke is pending.
pub async fn finish_pending_revoke(
    routes: &OwnRoutes<'_>,
    store: &mut E2eStateStore,
) -> Result<Option<Revoked>, RevokeError> {
    match store.pending_revoke() {
        Some(pending) => finish_revoke(routes, store, pending).await.map(Some),
        None => Ok(None),
    }
}

/// Writes the revoke in the trust state and forgets the session, so the
/// device gets no key request, copy, inbox work or session.
fn stop_routing(
    routes: &OwnRoutes<'_>,
    store: &mut E2eStateStore,
    pending: &PendingRevoke,
) -> Result<(), RevokeError> {
    let master = store.master_key()?.ok_or(RevokeError::NeedsMaster)?;
    let master_key = master.identity_keys().ed25519.to_base64();
    let mut trust = store.trust();
    trust.revoke_device(
        routes.network,
        routes.own_nick,
        &master_key,
        &pending.ed25519,
    )?;
    store.set_trust(&trust)?;
    store.remove_peer_session(routes.network, routes.own_nick, &pending.did)?;
    Ok(())
}

async fn finish_revoke(
    routes: &OwnRoutes<'_>,
    store: &mut E2eStateStore,
    pending: PendingRevoke,
) -> Result<Revoked, RevokeError> {
    stop_routing(routes, store, &pending)?;
    if store.list_pending() {
        publish_list(routes, store).await?;
    }
    match routes
        .client
        .drop_e2e_device(
            routes.token,
            routes.network,
            &pending.did,
            routes.server_protocol,
        )
        .await
    {
        Ok(())
        | Err(E2eRouteError::Refused {
            refusal: E2eRefusal::NotFound,
            ..
        }) => {}
        Err(err) => return Err(err.into()),
    }
    store.clear_pending_revoke()?;
    let list_version = store.signed_list().ok_or(RevokeError::NoList)?.version;
    Ok(Revoked {
        did: pending.did,
        list_version,
    })
}

/// Puts the own list. A stale answer reads the held list and signs again
/// above it. The new list never holds a revoked key, so an older list of
/// the server never brings a device back.
async fn publish_list(
    routes: &OwnRoutes<'_>,
    store: &mut E2eStateStore,
) -> Result<(), RevokeError> {
    let master = store.master_key()?.ok_or(RevokeError::NeedsMaster)?;
    let master_key = master.identity_keys().ed25519.to_base64();
    for _ in 0..2 {
        let list = store.signed_list().ok_or(RevokeError::NoList)?;
        let request = ListRequest::new(&master_key, &list)?;
        match routes
            .client
            .put_e2e_list(
                routes.token,
                routes.network,
                routes.server_protocol,
                &request,
            )
            .await
        {
            Ok(_) => return Ok(store.clear_list_pending()?),
            Err(E2eRouteError::Refused {
                refusal: E2eRefusal::StaleList,
                ..
            }) => {}
            Err(err) => return Err(err.into()),
        }
        let held = routes
            .client
            .fetch_e2e_list(routes.token, routes.network, routes.server_protocol)
            .await?;
        if held.master != master_key {
            return Err(RevokeError::MasterMismatch);
        }
        verify_signed_list(
            held.list.version,
            &held.list.keys,
            &master_key,
            &held.list.signature,
        )?;
        let keys: Vec<String> = held
            .list
            .keys
            .iter()
            .filter(|key| !store.own_revoked().contains(key))
            .cloned()
            .collect();
        if keys.is_empty() {
            return Err(RevokeError::EmptyList);
        }
        if keys == held.list.keys && held.list.version >= list.version {
            // The server holds a list without the revoked device already.
            store.set_signed_list(&held.list)?;
            return Ok(store.clear_list_pending()?);
        }
        let version = held.list.version.max(list.version) + 1;
        let next = sign_list(&master, version, &keys)?;
        store.set_signed_list_pending(&next)?;
    }
    // The list rose again between the two tries. The pending mark stays and
    // a retry reads the list again.
    Err(E2eRouteError::Refused {
        refusal: E2eRefusal::StaleList,
        retry_after: None,
    }
    .into())
}

/// Resets the identity after the user confirmed it. The server drops the
/// identity first. The private state goes only after that, so a failed call
/// keeps it and a retry (or [`resume_reset`]) finishes the reset.
pub async fn reset_identity(
    routes: &OwnRoutes<'_>,
    store: &mut E2eStateStore,
    _confirmed: ResetConfirmation,
) -> Result<(), RevokeError> {
    check_routes(routes, &[E2eOperation::IdentityDelete])?;
    store.begin_reset()?;
    complete_reset(routes, store).await
}

/// Finishes a reset that the user confirmed before a failure or a restart.
/// Returns false when no reset is pending.
pub async fn resume_reset(
    routes: &OwnRoutes<'_>,
    store: &mut E2eStateStore,
) -> Result<bool, RevokeError> {
    if !store.reset_pending() {
        return Ok(false);
    }
    check_routes(routes, &[E2eOperation::IdentityDelete])?;
    complete_reset(routes, store).await?;
    Ok(true)
}

async fn complete_reset(
    routes: &OwnRoutes<'_>,
    store: &mut E2eStateStore,
) -> Result<(), RevokeError> {
    match routes
        .client
        .delete_e2e_identity(routes.token, routes.network, routes.server_protocol)
        .await
    {
        Ok(())
        | Err(E2eRouteError::Refused {
            refusal: E2eRefusal::NotFound,
            ..
        }) => {}
        Err(err) => return Err(err.into()),
    }
    Ok(store.finish_reset()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_manage::SignedList;
    use crate::e2e_store::E2eKeyProvider;
    use serde_json::{json, Value};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use vodozemac::olm::Account;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const PROTOCOL: Option<u32> = Some(49);
    const NETWORK: &str = "libera";
    const NICK: &str = "bob";

    struct TestKey([u8; 32]);

    impl E2eKeyProvider for TestKey {
        fn load_or_create_key(&self) -> Result<[u8; 32], E2eStoreError> {
            Ok(self.0)
        }
    }

    /// A random key for one test; no key is written in the source.
    fn fresh_key() -> TestKey {
        TestKey(Account::new().identity_keys().curve25519.to_bytes())
    }

    fn scratch_dir(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "cordiale-e2e-revoke-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// What the fake server holds and has seen.
    #[derive(Default)]
    struct Fake {
        list: Option<Value>,
        /// Every request answers 503.
        offline: bool,
        /// Only the drop of a device answers 503.
        fail_drop: bool,
        list_puts: usize,
        drops: Vec<String>,
        identity_deletes: usize,
    }

    type Shared = Arc<Mutex<Fake>>;

    fn unavailable() -> ResponseTemplate {
        ResponseTemplate::new(503).set_body_json(json!({"error": "db_unavailable"}))
    }

    async fn fake_server(state: &Shared) -> MockServer {
        let server = MockServer::start().await;

        let s = Arc::clone(state);
        Mock::given(method("GET"))
            .and(path("/networks/libera/e2e/list"))
            .respond_with(move |_: &Request| {
                let state = s.lock().unwrap();
                match (&state.list, state.offline) {
                    (_, true) => unavailable(),
                    (Some(list), _) => ResponseTemplate::new(200).set_body_json(list),
                    (None, _) => {
                        ResponseTemplate::new(404).set_body_json(json!({"error": "not_found"}))
                    }
                }
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("PUT"))
            .and(path("/networks/libera/e2e/list"))
            .respond_with(move |request: &Request| {
                let body: Value = serde_json::from_slice(&request.body).expect("json");
                let mut state = s.lock().unwrap();
                if state.offline {
                    return unavailable();
                }
                state.list_puts += 1;
                let held = state.list.as_ref().and_then(|list| list["ver"].as_u64());
                if held.is_some_and(|held| body["ver"].as_u64() <= Some(held)) {
                    return ResponseTemplate::new(409)
                        .set_body_json(json!({"error": "stale_list"}));
                }
                state.list = Some(body.clone());
                ResponseTemplate::new(200).set_body_json(body)
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("DELETE"))
            .and(path_regex(
                r"^/networks/libera/e2e/devices/[A-Za-z0-9_-]{11}$",
            ))
            .respond_with(move |request: &Request| {
                let mut state = s.lock().unwrap();
                if state.offline || state.fail_drop {
                    return unavailable();
                }
                let did = request.url.path().rsplit('/').next().unwrap().to_string();
                state.drops.push(did);
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("DELETE"))
            .and(path("/networks/libera/e2e/keys"))
            .respond_with(move |_: &Request| {
                let mut state = s.lock().unwrap();
                if state.offline {
                    return unavailable();
                }
                state.identity_deletes += 1;
                state.list = None;
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;
        server
    }

    fn ed25519_of(account: &Account) -> String {
        account.identity_keys().ed25519.to_base64()
    }

    fn list_json(master: &Account, list: &SignedList) -> Value {
        json!({
            "master": ed25519_of(master),
            "ver": list.version,
            "devices": list.keys,
            "sig": list.signature,
        })
    }

    /// A store with the identity of this device and a list of two devices.
    struct Setup {
        dir: PathBuf,
        provider: TestKey,
        store: E2eStateStore,
        master: Account,
        own_key: String,
        second: Account,
        second_did: String,
    }

    fn setup(name: &str) -> Setup {
        let dir = scratch_dir(name);
        let provider = fresh_key();
        let mut store = E2eStateStore::open(dir.join("state.bin"), &provider).expect("open");
        let master = Account::new();
        let device = Account::new();
        let second = Account::new();
        let own_key = ed25519_of(&device);
        let second_key = ed25519_of(&second);
        store.set_master_key(&master).expect("master");
        store.set_account(&device).expect("account");
        let list = sign_list(&master, 1, &[own_key.clone(), second_key.clone()]).expect("list");
        store.set_signed_list(&list).expect("list");
        Setup {
            dir,
            provider,
            store,
            master,
            own_key,
            second_did: did_from_key_text(&second_key).expect("did"),
            second,
        }
    }

    fn routes(client: &GrappaClient, protocol: Option<u32>) -> OwnRoutes<'_> {
        OwnRoutes {
            client,
            token: "abc123",
            network: NETWORK,
            own_nick: NICK,
            server_protocol: protocol,
        }
    }

    fn reopen(setup: &mut Setup) {
        setup.store =
            E2eStateStore::open(setup.dir.join("state.bin"), &setup.provider).expect("reopen");
    }

    /// The server holds the list of the store.
    fn hold_stored_list(setup: &Setup, state: &Shared) {
        let list = setup.store.signed_list().expect("list");
        state.lock().unwrap().list = Some(list_json(&setup.master, &list));
    }

    #[tokio::test]
    async fn a_revoke_signs_a_higher_list_without_the_device_and_drops_it() {
        let mut s = setup("success");
        let state = Shared::default();
        hold_stored_list(&s, &state);
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());

        let done = revoke_device(&routes(&client, PROTOCOL), &mut s.store, &s.second_did)
            .await
            .expect("revoke");

        assert_eq!(done.did, s.second_did);
        assert_eq!(done.list_version, 2);
        let list = s.store.signed_list().expect("list");
        assert_eq!(list.version, 2);
        assert_eq!(list.keys, vec![s.own_key.clone()]);
        verify_signed_list(2, &list.keys, &ed25519_of(&s.master), &list.signature)
            .expect("signature");
        assert!(!s.store.list_pending());
        assert!(s.store.pending_revoke().is_none());
        let fake = state.lock().unwrap();
        assert_eq!(fake.list.as_ref().unwrap()["ver"], 2);
        assert_eq!(fake.drops, vec![s.second_did.clone()]);
        drop(fake);

        // Nothing goes to the revoked device, and an older list with it is
        // refused by the trust state.
        let second_key = ed25519_of(&s.second);
        let mut trust = s.store.trust();
        assert!(trust.is_revoked(NETWORK, NICK, &second_key, None));
        assert!(trust.is_did_revoked(NETWORK, NICK, &s.second_did));
        let old = sign_list(&s.master, 9, &[s.own_key.clone(), second_key.clone()]).expect("old");
        let restored = trust.accept_list(
            NETWORK,
            NICK,
            &ed25519_of(&s.master),
            old.version,
            &old.keys,
            &old.signature,
        );
        assert!(restored.is_err());
        assert_eq!(s.store.own_revoked(), &[second_key]);
        let _ = fs::remove_dir_all(&s.dir);
    }

    #[tokio::test]
    async fn an_offline_revoke_stays_pending_through_a_restart_and_a_retry_ends_it() {
        let mut s = setup("offline");
        let state = Shared::default();
        hold_stored_list(&s, &state);
        state.lock().unwrap().offline = true;
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());

        let failed = revoke_device(&routes(&client, PROTOCOL), &mut s.store, &s.second_did).await;

        assert!(matches!(failed, Err(RevokeError::Route(_))));
        assert!(s.store.list_pending());
        assert_eq!(s.store.pending_revoke().unwrap().did, s.second_did);
        // The device is cut off at once, also while the server is away.
        assert!(s.store.trust().is_did_revoked(NETWORK, NICK, &s.second_did));

        reopen(&mut s);
        assert_eq!(s.store.pending_revoke().unwrap().did, s.second_did);
        assert_eq!(s.store.signed_list().unwrap().version, 2);

        state.lock().unwrap().offline = false;
        let done = finish_pending_revoke(&routes(&client, PROTOCOL), &mut s.store)
            .await
            .expect("retry")
            .expect("pending");
        assert_eq!(done.list_version, 2);
        assert!(s.store.pending_revoke().is_none());
        assert!(!s.store.list_pending());
        assert_eq!(state.lock().unwrap().list.as_ref().unwrap()["ver"], 2);
        let again = finish_pending_revoke(&routes(&client, PROTOCOL), &mut s.store)
            .await
            .expect("nothing");
        assert!(again.is_none());
        let _ = fs::remove_dir_all(&s.dir);
    }

    #[tokio::test]
    async fn a_stale_list_is_signed_again_above_the_held_one_without_the_device() {
        let mut s = setup("stale");
        let state = Shared::default();
        // The server holds version 5 that still names the second device.
        let newer =
            sign_list(&s.master, 5, &[s.own_key.clone(), ed25519_of(&s.second)]).expect("newer");
        state.lock().unwrap().list = Some(list_json(&s.master, &newer));
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());

        let done = revoke_device(&routes(&client, PROTOCOL), &mut s.store, &s.second_did)
            .await
            .expect("revoke");

        assert_eq!(done.list_version, 6);
        let fake = state.lock().unwrap();
        let held = fake.list.as_ref().unwrap();
        assert_eq!(held["ver"], 6);
        assert_eq!(held["devices"], json!([s.own_key.clone()]));
        assert_eq!(fake.drops, vec![s.second_did.clone()]);
        drop(fake);
        assert_eq!(s.store.signed_list().unwrap().keys, vec![s.own_key.clone()]);
        let _ = fs::remove_dir_all(&s.dir);
    }

    #[tokio::test]
    async fn a_held_list_without_the_device_is_adopted_and_not_replaced() {
        let mut s = setup("adopt");
        let state = Shared::default();
        // Another device of the master already revoked the device at version 7.
        let newer = sign_list(&s.master, 7, std::slice::from_ref(&s.own_key)).expect("newer");
        state.lock().unwrap().list = Some(list_json(&s.master, &newer));
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());

        let done = revoke_device(&routes(&client, PROTOCOL), &mut s.store, &s.second_did)
            .await
            .expect("revoke");

        assert_eq!(done.list_version, 7);
        assert_eq!(state.lock().unwrap().list.as_ref().unwrap()["ver"], 7);
        assert_eq!(s.store.signed_list().unwrap(), newer);
        let _ = fs::remove_dir_all(&s.dir);
    }

    #[tokio::test]
    async fn a_failed_drop_keeps_the_revoke_pending_and_a_retry_does_not_put_again() {
        let mut s = setup("partial");
        let state = Shared::default();
        hold_stored_list(&s, &state);
        state.lock().unwrap().fail_drop = true;
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());

        let failed = revoke_device(&routes(&client, PROTOCOL), &mut s.store, &s.second_did).await;

        assert!(matches!(failed, Err(RevokeError::Route(_))));
        assert_eq!(state.lock().unwrap().list.as_ref().unwrap()["ver"], 2);
        assert!(!s.store.list_pending());
        assert!(s.store.pending_revoke().is_some());

        reopen(&mut s);
        state.lock().unwrap().fail_drop = false;
        // The same call finishes the pending revoke.
        let done = revoke_device(&routes(&client, PROTOCOL), &mut s.store, &s.second_did)
            .await
            .expect("retry");
        assert_eq!(done.list_version, 2);
        let fake = state.lock().unwrap();
        assert_eq!(fake.list_puts, 1);
        assert_eq!(fake.drops, vec![s.second_did.clone()]);
        drop(fake);
        assert!(s.store.pending_revoke().is_none());
        let _ = fs::remove_dir_all(&s.dir);
    }

    #[tokio::test]
    async fn a_revoke_refuses_an_unknown_or_own_device_and_a_second_pending_one() {
        let mut s = setup("refused");
        let state = Shared::default();
        hold_stored_list(&s, &state);
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());
        let r = routes(&client, PROTOCOL);

        let unknown = did_from_key_text(&ed25519_of(&Account::new())).unwrap();
        assert!(matches!(
            revoke_device(&r, &mut s.store, &unknown).await,
            Err(RevokeError::UnknownDevice)
        ));
        let own = did_from_key_text(&s.own_key).unwrap();
        assert!(matches!(
            revoke_device(&r, &mut s.store, &own).await,
            Err(RevokeError::OwnDevice)
        ));
        assert!(s.store.pending_revoke().is_none());
        assert_eq!(s.store.signed_list().unwrap().version, 1);

        let next = sign_list(&s.master, 2, std::slice::from_ref(&s.own_key)).unwrap();
        let pending = PendingRevoke {
            ed25519: ed25519_of(&s.second),
            did: s.second_did.clone(),
        };
        s.store.begin_revoke(&pending, &next).unwrap();
        assert!(matches!(
            revoke_device(&r, &mut s.store, &unknown).await,
            Err(RevokeError::OtherPending)
        ));
        let _ = fs::remove_dir_all(&s.dir);
    }

    #[tokio::test]
    async fn a_server_without_the_routes_gets_no_request_and_no_state_change() {
        let mut s = setup("old-server");
        let state = Shared::default();
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());

        let failed = revoke_device(&routes(&client, None), &mut s.store, &s.second_did).await;

        assert!(matches!(
            failed,
            Err(RevokeError::Route(E2eRouteError::Unavailable))
        ));
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(s.store.pending_revoke().is_none());
        assert_eq!(s.store.signed_list().unwrap().version, 1);
        let _ = fs::remove_dir_all(&s.dir);
    }

    #[tokio::test]
    async fn a_reset_keeps_the_private_state_until_the_server_dropped_the_identity() {
        let mut s = setup("reset");
        let state = Shared::default();
        hold_stored_list(&s, &state);
        state.lock().unwrap().offline = true;
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());

        let failed = reset_identity(
            &routes(&client, PROTOCOL),
            &mut s.store,
            ResetConfirmation::user_confirmed(),
        )
        .await;

        assert!(matches!(failed, Err(RevokeError::Route(_))));
        assert!(s.store.reset_pending());
        assert!(s.store.master_key().unwrap().is_some());
        assert!(s.store.olm_identity().unwrap().is_some());

        // After a restart no identity is made while the reset is pending.
        reopen(&mut s);
        assert!(s.store.reset_pending());
        let provision = crate::e2e_provision::provision_device(
            &client,
            "abc123",
            NETWORK,
            PROTOCOL,
            &mut s.store,
        )
        .await;
        assert!(matches!(
            provision,
            Err(crate::e2e_provision::ProvisionError::ResetPending)
        ));
        assert!(matches!(
            revoke_device(&routes(&client, PROTOCOL), &mut s.store, &s.second_did).await,
            Err(RevokeError::ResetPending)
        ));

        state.lock().unwrap().offline = false;
        let resumed = resume_reset(&routes(&client, PROTOCOL), &mut s.store)
            .await
            .expect("resume");
        assert!(resumed);

        assert!(!s.store.reset_pending());
        assert!(s.store.master_key().unwrap().is_none());
        assert!(s.store.olm_identity().unwrap().is_none());
        assert!(s.store.signed_list().is_none());
        assert!(s.store.device_certificate().is_none());
        assert!(s.store.own_revoked().is_empty());
        assert_eq!(state.lock().unwrap().identity_deletes, 1);
        let again = resume_reset(&routes(&client, PROTOCOL), &mut s.store)
            .await
            .expect("nothing");
        assert!(!again);
        let _ = fs::remove_dir_all(&s.dir);
    }

    #[tokio::test]
    async fn a_reset_keeps_the_revoked_devices_revoked() {
        let mut s = setup("reset-trust");
        let state = Shared::default();
        hold_stored_list(&s, &state);
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());
        let r = routes(&client, PROTOCOL);
        revoke_device(&r, &mut s.store, &s.second_did)
            .await
            .expect("revoke");

        reset_identity(&r, &mut s.store, ResetConfirmation::user_confirmed())
            .await
            .expect("reset");

        assert!(s.store.signed_list().is_none());
        assert!(s.store.trust().is_did_revoked(NETWORK, NICK, &s.second_did));
        let _ = fs::remove_dir_all(&s.dir);
    }
}
