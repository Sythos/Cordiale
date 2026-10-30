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

//! Own device identity and public bundle of the E2E engine (protocol 49).
//!
//! [`provision_device`] makes the identity of this device on first use and
//! publishes its public bundle. The private keys stay in the sealed state
//! store (`E2eStateStore`). Only public keys and signatures leave it.
//!
//! One run does these steps, in this order:
//!
//! 1. Make the Olm account of the device (Curve25519 and Ed25519) and save it.
//!    A store that gives `WrongKey` or `Corrupted` stops the run here: a new
//!    identity is never made in its place.
//! 2. Read the list of the server. On a first start with no list, make the
//!    master key and the first signed list (version 1) and save both. A store
//!    with the master but no own list reuses the valid list of the server:
//!    version 1 is made only when neither side has a list. A list under a
//!    master that this device does not hold stops the run with `NeedsPairing`.
//! 3. Sign the own list again over the same version and keys when it
//!    verifies only in the old key order, once (`migrate_own_list`). Mark an
//!    own list that waits for publication. A list of the server that has the
//!    old key order (`e2e_list_migration`) gets a new version over the same
//!    keys, signed in the current order.
//! 4. Make the device certificate (the master signs the first list version
//!    that holds the device) and save it.
//! 5. Register the id block of the device, when the server does not hold it.
//! 6. Put the own list, when it waits for publication or the server has none.
//!    The mark goes only after a 2xx answer.
//! 7. Top up the one-time keys so that the server holds 50, make a fallback
//!    key when the server has none, save the account, and upload. The keys
//!    are marked as published only after a 2xx answer. A failed upload keeps
//!    them unpublished, and the next run uploads them again.
//!
//! A run on a device with nothing missing sends reads only.

use std::path::PathBuf;

use vodozemac::olm::Account;

use crate::client::GrappaClient;
use crate::e2e_account::{AccountError, AccountId, LocalAccount};
use crate::e2e_device::{
    build_device_certificate, build_signed_list_signature, verify_signed_list, E2eError,
};
use crate::e2e_identity_routes::{DeviceIdRequest, KeysUploadRequest, ListRequest, SignedKey};
use crate::e2e_list_migration::{has_legacy_order, migrate_own_list};
use crate::e2e_manage::SignedList;
use crate::e2e_protocol::E2eOperation;
use crate::e2e_refusal::{E2eRefusal, E2eRouteError};
use crate::e2e_state::E2eStateStore;
use crate::e2e_store::{E2eKeyProvider, E2eStoreError};
use crate::e2e_wire::{
    bundle_key_signed_text, device_id_signed_text, did_from_key_text, WireError, ONE_TIME_KEYS_MAX,
};

/// The operations that a run uses. A server that lacks one gets no request.
const REQUIRED: [E2eOperation; 6] = [
    E2eOperation::DeviceRegister,
    E2eOperation::DeviceList,
    E2eOperation::ListPut,
    E2eOperation::ListFetch,
    E2eOperation::KeysPublish,
    E2eOperation::KeysFetch,
];

/// Why a run stops.
#[derive(Debug)]
pub enum ProvisionError {
    /// The sealed store does not open or does not read. No identity is made.
    Store(E2eStoreError),
    /// A call failed, was refused, or is not in the protocol of the server.
    Route(E2eRouteError),
    Wire(WireError),
    Crypto(E2eError),
    Account(AccountError),
    /// The server holds a list under a master that this device does not
    /// hold. The device must pair with a device of that master.
    NeedsPairing,
    /// The master of the list on the server is not the stored master.
    MasterMismatch,
    /// An identity reset is not finished. No identity is made before it ends.
    ResetPending,
}

impl From<E2eStoreError> for ProvisionError {
    fn from(err: E2eStoreError) -> Self {
        Self::Store(err)
    }
}

impl From<E2eRouteError> for ProvisionError {
    fn from(err: E2eRouteError) -> Self {
        Self::Route(err)
    }
}

impl From<WireError> for ProvisionError {
    fn from(err: WireError) -> Self {
        Self::Wire(err)
    }
}

impl From<E2eError> for ProvisionError {
    fn from(err: E2eError) -> Self {
        Self::Crypto(err)
    }
}

impl From<AccountError> for ProvisionError {
    fn from(err: AccountError) -> Self {
        Self::Account(err)
    }
}

/// What a run did. It holds public values only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    pub did: String,
    /// The Olm account was made in this run.
    pub identity_created: bool,
    /// The id block was sent in this run.
    pub device_registered: bool,
    /// The own list was put in this run.
    pub list_published: bool,
    /// How many one-time keys the upload of this run carried.
    pub one_time_keys_published: usize,
    /// The upload of this run carried a fallback key.
    pub fallback_published: bool,
}

/// Opens the sealed store at `path` and runs [`provision_device`]. A store
/// that does not open ends the run before any request.
pub async fn provision_device_at(
    client: &GrappaClient,
    token: &str,
    network_id: &str,
    server_protocol: Option<u32>,
    path: PathBuf,
    provider: &(dyn E2eKeyProvider + Sync),
) -> Result<Provisioned, ProvisionError> {
    let mut store = E2eStateStore::open(path, provider)?;
    provision_device(client, token, network_id, server_protocol, &mut store).await
}

/// Makes the identity of this device on first use and publishes its bundle.
/// See the module text for the steps.
pub async fn provision_device(
    client: &GrappaClient,
    token: &str,
    network_id: &str,
    server_protocol: Option<u32>,
    store: &mut E2eStateStore,
) -> Result<Provisioned, ProvisionError> {
    if REQUIRED
        .iter()
        .any(|operation| !operation.available(server_protocol))
    {
        return Err(E2eRouteError::Unavailable.into());
    }
    if store.reset_pending() {
        return Err(ProvisionError::ResetPending);
    }

    let (account, identity_created) = match store.olm_identity()? {
        Some(account) => (account, false),
        None => {
            let account = Account::new();
            store.set_account(&account)?;
            (account, true)
        }
    };
    let ed25519 = account.identity_keys().ed25519.to_base64();
    let curve25519 = account.identity_keys().curve25519.to_base64();
    let did = did_from_key_text(&ed25519)?;
    let mut local = LocalAccount::from_account(AccountId::new(network_id, &did)?, account);

    let held = match client
        .fetch_e2e_list(token, network_id, server_protocol)
        .await
    {
        Ok(held) => Some(held),
        Err(E2eRouteError::Refused {
            refusal: E2eRefusal::NotFound,
            ..
        }) => None,
        Err(err) => return Err(err.into()),
    };

    // A device that joined by X1 pairing holds no master secret: it has the
    // certificate that the master signed for its key. Only a master holder
    // signs a list or a certificate.
    let (master, master_key): (Option<Account>, String) = match store.master_key()? {
        Some(master) => {
            let key = master.identity_keys().ed25519.to_base64();
            (Some(master), key)
        }
        None => match &held {
            Some(held) if is_paired_under(store, &held.master, &ed25519) => {
                (None, held.master.clone())
            }
            Some(_) => return Err(ProvisionError::NeedsPairing),
            None => {
                let master = Account::new();
                store.set_master_key(&master)?;
                let key = master.identity_keys().ed25519.to_base64();
                (Some(master), key)
            }
        },
    };
    if held.as_ref().is_some_and(|held| held.master != master_key) {
        return Err(ProvisionError::MasterMismatch);
    }

    let mut list = store.signed_list();
    if !store.list_migrated() {
        if let (Some(own), Some(master)) = (&list, master.as_ref()) {
            match migrate_own_list(master, own)? {
                Some(next) => {
                    store.set_migrated_list_pending(&next)?;
                    list = Some(next);
                }
                None => store.set_list_migrated()?,
            }
        }
    }
    if let (Some(held), Some(master)) = (&held, master.as_ref()) {
        let held = &held.list;
        let behind = list.as_ref().is_none_or(|own| own.version <= held.version);
        if behind && has_legacy_order(held.version, &held.keys, &master_key, &held.signature) {
            let next = sign_list(master, held.version + 1, &held.keys)?;
            store.set_signed_list_pending(&next)?;
            list = Some(next);
        }
    }
    let list = match (list, &held) {
        (Some(list), _) => list,
        // The store has the master but no own list: reuse the valid list of
        // the server, so that the next version is above it.
        (None, Some(held)) => {
            let held = &held.list;
            verify_signed_list(held.version, &held.keys, &master_key, &held.signature)?;
            if held.keys.contains(&ed25519) {
                store.set_signed_list(held)?;
                held.clone()
            } else {
                let mut keys = held.keys.clone();
                keys.push(ed25519.clone());
                let master = master.as_ref().ok_or(ProvisionError::NeedsPairing)?;
                let next = sign_list(master, held.version + 1, &keys)?;
                store.set_signed_list_pending(&next)?;
                next
            }
        }
        (None, None) => {
            let master = master.as_ref().ok_or(ProvisionError::NeedsPairing)?;
            let first = sign_list(master, 1, std::slice::from_ref(&ed25519))?;
            store.set_signed_list_pending(&first)?;
            first
        }
    };

    if store.device_certificate().is_none() {
        let master = master.as_ref().ok_or(ProvisionError::NeedsPairing)?;
        let certificate = build_device_certificate(list.version, &ed25519, &master_key, |text| {
            master.sign(text).to_base64()
        })?;
        store.set_device_certificate(&certificate)?;
    }

    let id_signature = local.sign(device_id_signed_text(&curve25519, &master_key).as_bytes());
    let id_request = DeviceIdRequest::new(&ed25519, &curve25519, &id_signature)?;
    let devices = client
        .list_e2e_devices(token, network_id, server_protocol)
        .await?;
    let device_registered = !devices
        .iter()
        .any(|device| device.did == did && device.matches(&id_request));
    if device_registered {
        let record = client
            .register_e2e_device(token, network_id, server_protocol, &id_request)
            .await?;
        if record.did != did {
            return Err(WireError::BadDid.into());
        }
    }

    let list_published = store.list_pending() || held.is_none();
    if list_published {
        let request = ListRequest::new(&master_key, &list)?;
        client
            .put_e2e_list(token, network_id, server_protocol, &request)
            .await?;
        store.clear_list_pending()?;
    }

    let server_keys = client
        .fetch_e2e_keys(token, network_id, &did, server_protocol)
        .await?;
    let wanted = ONE_TIME_KEYS_MAX.saturating_sub(server_keys.one_time_keys);
    let waiting = local.unpublished_one_time_keys().len();
    let missing = wanted.saturating_sub(waiting);
    let needs_fallback = !server_keys.fallback && local.unpublished_fallback_key().is_none();
    local.generate_one_time_keys(missing);
    if needs_fallback {
        local.rotate_fallback_key();
    }
    if missing > 0 || needs_fallback {
        // The new keys are on disk before the upload, so a failed upload
        // keeps them unpublished and the next run sends the same keys.
        store.set_account(local.account())?;
    }

    let one_time = local.unpublished_one_time_keys();
    let fallback = local.unpublished_fallback_key();
    let mut outcome = Provisioned {
        did: did.clone(),
        identity_created,
        device_registered,
        list_published,
        one_time_keys_published: 0,
        fallback_published: false,
    };
    if one_time.is_empty() && fallback.is_none() {
        return Ok(outcome);
    }
    let one_time_signed = one_time
        .iter()
        .map(|key| signed_key(&local, key))
        .collect::<Result<Vec<_>, WireError>>()?;
    let fallback_signed = fallback
        .as_deref()
        .map(|key| signed_key(&local, key))
        .transpose()?;
    let request = KeysUploadRequest::new(one_time_signed, fallback_signed)?;
    client
        .publish_e2e_keys(token, network_id, &did, server_protocol, &request)
        .await?;
    local.mark_published();
    store.set_account(local.account())?;
    outcome.one_time_keys_published = one_time.len();
    outcome.fallback_published = fallback.is_some();
    Ok(outcome)
}

/// True when the store holds the certificate that `master` signed for this
/// device key. Only a device that joined by X1 pairing has one without the
/// master secret.
fn is_paired_under(store: &E2eStateStore, master: &str, device_ed25519: &str) -> bool {
    store
        .device_certificate()
        .is_some_and(|cert| cert.master_ed25519 == master && cert.device_ed25519 == device_ed25519)
}

/// Signs a device list with the master key. The keys are sorted by the
/// builder of the signature.
pub(crate) fn sign_list(
    master: &Account,
    version: u32,
    keys: &[String],
) -> Result<SignedList, E2eError> {
    let signature =
        build_signed_list_signature(version, keys, |text| master.sign(text).to_base64())?;
    let mut sorted = keys.to_vec();
    sorted.sort();
    Ok(SignedList {
        version,
        keys: sorted,
        signature,
    })
}

/// A public key of the bundle with the device signature over
/// `irc-e2e:v1:otk:<key>`.
fn signed_key(local: &LocalAccount, key: &str) -> Result<SignedKey, WireError> {
    let text = bundle_key_signed_text(key)?;
    SignedKey::new(key, &local.sign(&text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_device::verify_signature;
    use crate::e2e_wire::{legacy_raw_order_list_signed_text, signed_list_signed_text};
    use serde_json::{json, Value};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const PROTOCOL: Option<u32> = Some(49);

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
            "cordiale-e2e-provision-{name}-{}-{}",
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
        devices: Vec<Value>,
        one_time_keys: usize,
        fallback: bool,
        fail_keys: bool,
        device_posts: usize,
        list_puts: usize,
        key_posts: Vec<Value>,
    }

    type Shared = Arc<Mutex<Fake>>;

    fn body_of(request: &Request) -> Value {
        serde_json::from_slice(&request.body).expect("json body")
    }

    /// A server that keeps the state of the account, as Grappa does.
    async fn fake_server(state: &Shared) -> MockServer {
        let server = MockServer::start().await;
        let keys_path = r"^/networks/libera/e2e/devices/[A-Za-z0-9_-]{11}/keys$";

        let s = Arc::clone(state);
        Mock::given(method("GET"))
            .and(path("/networks/libera/e2e/list"))
            .respond_with(move |_: &Request| match &s.lock().unwrap().list {
                Some(list) => ResponseTemplate::new(200).set_body_json(list),
                None => ResponseTemplate::new(404).set_body_json(json!({"error": "not_found"})),
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("PUT"))
            .and(path("/networks/libera/e2e/list"))
            .respond_with(move |request: &Request| {
                let body = body_of(request);
                let mut state = s.lock().unwrap();
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
        Mock::given(method("GET"))
            .and(path("/networks/libera/e2e/devices"))
            .respond_with(move |_: &Request| {
                let devices = s.lock().unwrap().devices.clone();
                ResponseTemplate::new(200).set_body_json(json!({"devices": devices}))
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("POST"))
            .and(path("/networks/libera/e2e/devices"))
            .respond_with(move |request: &Request| {
                let mut record = body_of(request);
                let ed25519 = record["ed25519"].clone();
                record["did"] = json!(did_from_key_text(ed25519.as_str().expect("key")).unwrap());
                let mut state = s.lock().unwrap();
                state.device_posts += 1;
                state.devices.retain(|device| device["ed25519"] != ed25519);
                state.devices.push(record.clone());
                ResponseTemplate::new(200).set_body_json(record)
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("GET"))
            .and(path_regex(keys_path))
            .respond_with(move |_: &Request| {
                let state = s.lock().unwrap();
                ResponseTemplate::new(200).set_body_json(
                    json!({"one_time_keys": state.one_time_keys, "fallback": state.fallback}),
                )
            })
            .mount(&server)
            .await;

        let s = Arc::clone(state);
        Mock::given(method("POST"))
            .and(path_regex(keys_path))
            .respond_with(move |request: &Request| {
                let mut state = s.lock().unwrap();
                if state.fail_keys {
                    return ResponseTemplate::new(503)
                        .set_body_json(json!({"error": "db_unavailable"}));
                }
                let body = body_of(request);
                state.one_time_keys += body["one_time_keys"].as_array().map_or(0, Vec::len);
                state.fallback |= body.get("fallback").is_some();
                state.key_posts.push(body);
                ResponseTemplate::new(200).set_body_json(
                    json!({"one_time_keys": state.one_time_keys, "fallback": state.fallback}),
                )
            })
            .mount(&server)
            .await;
        server
    }

    async fn run(
        server: &MockServer,
        store: &mut E2eStateStore,
        protocol: Option<u32>,
    ) -> Result<Provisioned, ProvisionError> {
        provision_device(
            &GrappaClient::new(server.uri()),
            "abc123",
            "libera",
            protocol,
            store,
        )
        .await
    }

    fn state_path(dir: &std::path::Path) -> PathBuf {
        dir.join("state.bin")
    }

    fn ed25519_of(account: &Account) -> String {
        account.identity_keys().ed25519.to_base64()
    }

    #[tokio::test]
    async fn a_first_start_makes_one_identity_and_publishes_one_bundle() {
        let dir = scratch_dir("first");
        let provider = fresh_key();
        let state = Shared::default();
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");

        let outcome = run(&server, &mut store, PROTOCOL).await.expect("run");

        let account = store.olm_identity().expect("account").expect("saved");
        let master = store.master_key().expect("master").expect("saved");
        let device_key = ed25519_of(&account);
        let master_key = ed25519_of(&master);
        assert!(outcome.identity_created && outcome.device_registered && outcome.list_published);
        assert_eq!(outcome.did, did_from_key_text(&device_key).unwrap());
        assert_eq!(outcome.did.len(), 11);
        assert_eq!(outcome.one_time_keys_published, ONE_TIME_KEYS_MAX);
        assert!(outcome.fallback_published);

        let fake = state.lock().unwrap();
        assert_eq!((fake.device_posts, fake.list_puts), (1, 1));
        assert_eq!(fake.key_posts.len(), 1);
        // The id block: the device signs the curve key under the master.
        let record = &fake.devices[0];
        assert_eq!(record["ed25519"], device_key);
        let id_text =
            device_id_signed_text(&account.identity_keys().curve25519.to_base64(), &master_key);
        verify_signature(
            &device_key,
            record["sig"].as_str().unwrap(),
            id_text.as_bytes(),
        )
        .expect("id block signature");
        // The list: version 1, the device alone, signed by the master.
        let list = fake.list.as_ref().expect("list");
        assert_eq!(
            (list["ver"].clone(), list["master"].clone()),
            (json!(1), json!(master_key))
        );
        assert_eq!(list["devices"], json!([device_key]));
        verify_signed_list(
            1,
            std::slice::from_ref(&device_key),
            &master_key,
            list["sig"].as_str().unwrap(),
        )
        .expect("list signature");
        // The bundle: 50 signed one-time keys and one signed fallback key.
        let bundle = &fake.key_posts[0];
        let otks = bundle["one_time_keys"].as_array().unwrap();
        assert_eq!(otks.len(), ONE_TIME_KEYS_MAX);
        for entry in otks.iter().chain(std::iter::once(&bundle["fallback"])) {
            let key = entry["key"].as_str().unwrap();
            verify_signature(
                &device_key,
                entry["sig"].as_str().unwrap(),
                &bundle_key_signed_text(key).unwrap(),
            )
            .expect("key signature");
        }
        // The certificate is saved: the master signed N = 1 for the device.
        let certificate = store.device_certificate().expect("certificate");
        assert_eq!(certificate.first_list_version, 1);
        crate::e2e_device::verify_device_certificate(&certificate, &[master_key])
            .expect("certificate signature");
        assert!(!store.list_pending());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn only_public_values_leave_the_device() {
        let dir = scratch_dir("public");
        let provider = fresh_key();
        let state = Shared::default();
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");
        run(&server, &mut store, PROTOCOL).await.expect("run");

        let allowed = [
            ("POST", vec!["ed25519", "curve25519", "sig"]),
            ("PUT", vec!["master", "ver", "devices", "sig"]),
        ];
        let requests = server.received_requests().await.expect("requests");
        for request in requests.iter().filter(|r| r.method.as_str() != "GET") {
            let body = body_of(request);
            let names: Vec<&str> = body
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            let is_keys = request.url.path().ends_with("/keys");
            if is_keys {
                assert!(names
                    .iter()
                    .all(|n| ["one_time_keys", "fallback"].contains(n)));
            } else {
                let expected = &allowed
                    .iter()
                    .find(|(verb, _)| *verb == request.method.as_str())
                    .expect("known verb")
                    .1;
                assert!(names.iter().all(|n| expected.contains(n)), "{names:?}");
            }
        }
        // The debug text of the store shows no key.
        let account = store.olm_identity().unwrap().unwrap();
        let text = format!("{store:?}");
        assert!(!text.contains(&ed25519_of(&account)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_restart_publishes_nothing_when_no_key_is_missing() {
        let dir = scratch_dir("restart");
        let provider = fresh_key();
        let state = Shared::default();
        let server = fake_server(&state).await;
        let (account_key, master_key) = {
            let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");
            run(&server, &mut store, PROTOCOL).await.expect("first run");
            (
                ed25519_of(&store.olm_identity().unwrap().unwrap()),
                ed25519_of(&store.master_key().unwrap().unwrap()),
            )
        };

        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("reopen");
        let outcome = run(&server, &mut store, PROTOCOL)
            .await
            .expect("second run");

        assert!(!outcome.identity_created);
        assert!(!outcome.device_registered);
        assert!(!outcome.list_published);
        assert_eq!(outcome.one_time_keys_published, 0);
        assert!(!outcome.fallback_published);
        let fake = state.lock().unwrap();
        assert_eq!(
            (fake.device_posts, fake.list_puts, fake.key_posts.len()),
            (1, 1, 1)
        );
        assert_eq!(
            ed25519_of(&store.olm_identity().unwrap().unwrap()),
            account_key
        );
        assert_eq!(
            ed25519_of(&store.master_key().unwrap().unwrap()),
            master_key
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn keys_used_up_on_the_server_are_made_again_up_to_the_limit() {
        let dir = scratch_dir("topup");
        let provider = fresh_key();
        let state = Shared::default();
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");
        run(&server, &mut store, PROTOCOL).await.expect("first run");
        state.lock().unwrap().one_time_keys -= 12;

        let outcome = run(&server, &mut store, PROTOCOL)
            .await
            .expect("second run");

        assert_eq!(outcome.one_time_keys_published, 12);
        assert!(!outcome.fallback_published);
        let fake = state.lock().unwrap();
        assert_eq!(fake.one_time_keys, ONE_TIME_KEYS_MAX);
        let second = fake.key_posts[1].as_object().unwrap();
        assert!(!second.contains_key("fallback"));
        assert_eq!(second["one_time_keys"].as_array().unwrap().len(), 12);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_failed_upload_keeps_the_keys_unpublished_and_a_retry_sends_them() {
        let dir = scratch_dir("retry");
        let provider = fresh_key();
        let state = Shared::default();
        state.lock().unwrap().fail_keys = true;
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");

        let failed = run(&server, &mut store, PROTOCOL).await;

        assert!(matches!(
            failed,
            Err(ProvisionError::Route(E2eRouteError::Refused {
                refusal: E2eRefusal::DbUnavailable,
                ..
            }))
        ));
        let kept = store.olm_identity().unwrap().unwrap();
        let kept_keys: Vec<String> = kept
            .one_time_keys()
            .values()
            .map(|key| key.to_base64())
            .collect();
        assert_eq!(kept_keys.len(), ONE_TIME_KEYS_MAX);
        assert!(!kept.fallback_key().is_empty());
        let device_key = ed25519_of(&kept);

        state.lock().unwrap().fail_keys = false;
        let outcome = run(&server, &mut store, PROTOCOL).await.expect("retry");

        assert!(!outcome.identity_created);
        assert!(!outcome.device_registered && !outcome.list_published);
        assert_eq!(outcome.one_time_keys_published, ONE_TIME_KEYS_MAX);
        assert!(outcome.fallback_published);
        let fake = state.lock().unwrap();
        assert_eq!((fake.device_posts, fake.list_puts), (1, 1));
        let sent: Vec<String> = fake.key_posts[0]["one_time_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["key"].as_str().unwrap().to_string())
            .collect();
        let mut expected = kept_keys;
        expected.sort();
        let mut sent_sorted = sent;
        sent_sorted.sort();
        assert_eq!(sent_sorted, expected);
        let after = store.olm_identity().unwrap().unwrap();
        assert_eq!(ed25519_of(&after), device_key);
        assert!(after.one_time_keys().is_empty());
        assert!(after.fallback_key().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_pending_own_list_is_published_once_and_the_mark_is_cleared() {
        let dir = scratch_dir("pending");
        let provider = fresh_key();
        let state = Shared::default();
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");
        run(&server, &mut store, PROTOCOL).await.expect("first run");

        let master = store.master_key().unwrap().unwrap();
        let device_key = ed25519_of(&store.olm_identity().unwrap().unwrap());
        let newer = sign_list(&master, 2, std::slice::from_ref(&device_key)).unwrap();
        store.set_signed_list_pending(&newer).expect("pending");
        assert!(store.list_pending());

        let outcome = run(&server, &mut store, PROTOCOL).await.expect("run");

        assert!(outcome.list_published);
        assert!(!store.list_pending());
        assert_eq!(state.lock().unwrap().list_puts, 2);
        assert_eq!(state.lock().unwrap().list.as_ref().unwrap()["ver"], 2);
        let again = run(&server, &mut store, PROTOCOL).await.expect("again");
        assert!(!again.list_published);
        assert_eq!(state.lock().unwrap().list_puts, 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_list_with_the_old_key_order_is_replaced_by_the_next_version() {
        let dir = scratch_dir("legacy");
        let provider = fresh_key();
        let state = Shared::default();
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");
        run(&server, &mut store, PROTOCOL).await.expect("first run");

        // The server holds a version 2 list that an older build signed over
        // the raw byte order of the keys.
        let master = store.master_key().unwrap().unwrap();
        let master_key = ed25519_of(&master);
        let device_key = ed25519_of(&store.olm_identity().unwrap().unwrap());
        let keys = loop {
            let keys = vec![device_key.clone(), ed25519_of(&Account::new())];
            if legacy_raw_order_list_signed_text(2, &keys).unwrap()
                != signed_list_signed_text(2, &keys).unwrap()
            {
                break keys;
            }
        };
        let old = master
            .sign(legacy_raw_order_list_signed_text(2, &keys).unwrap())
            .to_base64();
        let mut sorted = keys.clone();
        sorted.sort();
        {
            let mut fake = state.lock().unwrap();
            fake.list = Some(json!({
                "master": master_key, "ver": 2, "devices": sorted, "sig": old
            }));
        }

        let outcome = run(&server, &mut store, PROTOCOL).await.expect("run");

        assert!(outcome.list_published);
        let own = store.signed_list().expect("list");
        assert_eq!((own.version, own.keys.clone()), (3, sorted.clone()));
        verify_signed_list(3, &sorted, &master_key, &own.signature).expect("current order");
        assert!(!store.list_pending());
        assert_eq!(state.lock().unwrap().list.as_ref().unwrap()["ver"], 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_own_list_in_the_old_order_is_signed_again_once_and_published() {
        let dir = scratch_dir("own-legacy");
        let provider = fresh_key();
        let state = Shared::default();
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");
        run(&server, &mut store, PROTOCOL).await.expect("first run");

        let master = store.master_key().unwrap().unwrap();
        let master_key = ed25519_of(&master);
        let device_key = ed25519_of(&store.olm_identity().unwrap().unwrap());
        let keys = loop {
            let keys = vec![device_key.clone(), ed25519_of(&Account::new())];
            if legacy_raw_order_list_signed_text(1, &keys).unwrap()
                != signed_list_signed_text(1, &keys).unwrap()
            {
                break keys;
            }
        };
        let mut sorted = keys.clone();
        sorted.sort();
        let old = master
            .sign(legacy_raw_order_list_signed_text(1, &keys).unwrap())
            .to_base64();
        store
            .set_signed_list(&SignedList {
                version: 1,
                keys: sorted.clone(),
                signature: old,
            })
            .expect("old list");
        state.lock().unwrap().list = None;

        let outcome = run(&server, &mut store, PROTOCOL).await.expect("run");

        assert!(outcome.list_published);
        let own = store.signed_list().expect("list");
        assert_eq!((own.version, own.keys.clone()), (1, sorted.clone()));
        verify_signed_list(1, &sorted, &master_key, &own.signature).expect("current order");
        assert!(store.list_migrated());
        assert!(!store.list_pending());
        assert_eq!(state.lock().unwrap().list.as_ref().unwrap()["ver"], 1);
        drop(store);

        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("reopen");
        assert!(store.list_migrated());
        run(&server, &mut store, PROTOCOL).await.expect("restart");
        assert_eq!(store.signed_list(), Some(own));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_store_without_an_own_list_reuses_the_list_of_the_server() {
        let dir = scratch_dir("reuse");
        let provider = fresh_key();
        let state = Shared::default();
        let account = Account::new();
        let master = Account::new();
        let device_key = ed25519_of(&account);
        let held = sign_list(&master, 3, std::slice::from_ref(&device_key)).unwrap();
        state.lock().unwrap().list = Some(json!({
            "master": ed25519_of(&master), "ver": 3,
            "devices": [device_key], "sig": held.signature
        }));
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");
        store.set_account(&account).expect("account");
        store.set_master_key(&master).expect("master");

        let outcome = run(&server, &mut store, PROTOCOL).await.expect("run");

        assert!(!outcome.list_published);
        assert_eq!(store.signed_list().expect("list").version, 3);
        assert!(!store.list_pending());
        let fake = state.lock().unwrap();
        assert_eq!(fake.list_puts, 0);
        assert_eq!(fake.key_posts.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_list_under_another_master_needs_pairing_and_makes_no_master() {
        let dir = scratch_dir("pairing");
        let provider = fresh_key();
        let state = Shared::default();
        let other = Account::new();
        let other_device = ed25519_of(&Account::new());
        let signed = sign_list(&other, 4, std::slice::from_ref(&other_device)).unwrap();
        state.lock().unwrap().list = Some(json!({
            "master": ed25519_of(&other), "ver": 4,
            "devices": [other_device], "sig": signed.signature
        }));
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");

        let result = run(&server, &mut store, PROTOCOL).await;

        assert!(matches!(result, Err(ProvisionError::NeedsPairing)));
        assert!(store.master_key().unwrap().is_none());
        assert!(store.signed_list().is_none());
        let fake = state.lock().unwrap();
        assert_eq!(
            (fake.device_posts, fake.list_puts, fake.key_posts.len()),
            (0, 0, 0)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_stored_master_that_differs_from_the_list_master_stops_the_run() {
        let dir = scratch_dir("mismatch");
        let provider = fresh_key();
        let state = Shared::default();
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");
        run(&server, &mut store, PROTOCOL).await.expect("first run");
        let other = Account::new();
        let other_device = ed25519_of(&Account::new());
        let signed = sign_list(&other, 9, std::slice::from_ref(&other_device)).unwrap();
        state.lock().unwrap().list = Some(json!({
            "master": ed25519_of(&other), "ver": 9,
            "devices": [other_device], "sig": signed.signature
        }));

        let result = run(&server, &mut store, PROTOCOL).await;

        assert!(matches!(result, Err(ProvisionError::MasterMismatch)));
        assert_eq!(state.lock().unwrap().list_puts, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_server_without_the_routes_gets_no_request_and_no_identity() {
        let dir = scratch_dir("old-server");
        let provider = fresh_key();
        let state = Shared::default();
        let server = fake_server(&state).await;
        let mut store = E2eStateStore::open(state_path(&dir), &provider).expect("open");

        for protocol in [None, Some(48)] {
            let result = run(&server, &mut store, protocol).await;
            assert!(matches!(
                result,
                Err(ProvisionError::Route(E2eRouteError::Unavailable))
            ));
        }

        assert!(store.olm_identity().unwrap().is_none());
        assert!(store.master_key().unwrap().is_none());
        assert!(server.received_requests().await.unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_store_that_does_not_open_never_gives_a_new_identity() {
        let dir = scratch_dir("closed");
        let path = state_path(&dir);
        let state = Shared::default();
        let server = fake_server(&state).await;
        let client = GrappaClient::new(server.uri());
        {
            let mut store = E2eStateStore::open(path.clone(), &fresh_key()).expect("open");
            store.set_account(&Account::new()).expect("account");
        }
        let before = fs::read(&path).expect("read");

        // Another key: the store says `WrongKey` and the run stops.
        let wrong = provision_device_at(
            &client,
            "abc123",
            "libera",
            PROTOCOL,
            path.clone(),
            &fresh_key(),
        )
        .await;
        assert!(matches!(
            wrong,
            Err(ProvisionError::Store(E2eStoreError::WrongKey))
        ));

        // A damaged file: the store says `Corrupted` and the run stops.
        let provider = fresh_key();
        let damaged_dir = scratch_dir("closed-damaged");
        let damaged_path = state_path(&damaged_dir);
        fs::write(&damaged_path, b"not a state file").expect("write");
        let damaged = provision_device_at(
            &client,
            "abc123",
            "libera",
            PROTOCOL,
            damaged_path.clone(),
            &provider,
        )
        .await;
        assert!(matches!(
            damaged,
            Err(ProvisionError::Store(E2eStoreError::Corrupted))
        ));

        assert_eq!(fs::read(&path).expect("read"), before);
        assert_eq!(fs::read(&damaged_path).expect("read"), b"not a state file");
        assert!(server.received_requests().await.unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&damaged_dir);
    }
}
