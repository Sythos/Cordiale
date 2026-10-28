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

//! Models of the identity routes of protocol 49: devices, list and keys.
//!
//! The routes are below `/networks/:id`. Build each path with
//! `E2eOperation::path`; this module has no path of its own.
//!
//! - `POST /e2e/devices` takes an id block `{"ed25519", "curve25519", "sig"}`
//!   and answers the device `{"did", "ed25519", "curve25519", "sig"}`.
//! - `GET /e2e/devices` answers `{"devices": [device…]}`.
//! - `PUT` and `GET /e2e/list` use `{"master", "ver", "devices", "sig"}`.
//! - `POST /e2e/devices/:did/keys` takes `{"one_time_keys": [{"key", "sig"}…],
//!   "fallback": {"key", "sig"}}` and answers `{"one_time_keys": N,
//!   "fallback": bool}`. `GET` answers the same shape.
//!
//! Source of each field name: section 4f of `CLIENT_PROTOCOL.md` of Grappa.
//! The module holds data and pure checks. It does no network call. Answers
//! are read by name and extra fields are ignored. A request is checked before
//! it is built, so no request with a bad value leaves the client.

use serde::Serialize;
use serde_json::Value;

use crate::e2e_device::{verify_signed_list, E2eError};
use crate::e2e_manage::SignedList;
use crate::e2e_wire::{
    as_object, check_list_devices, decode_key, decode_signature, did_from_key_text, is_did_shape,
    required_str, WireError, MAX_VERSION, ONE_TIME_KEYS_MAX,
};

fn key_text(map: &serde_json::Map<String, Value>, name: &str) -> Result<String, WireError> {
    let text = required_str(map, name)?;
    decode_key(text)?;
    Ok(text.to_string())
}

fn signature_text(map: &serde_json::Map<String, Value>, name: &str) -> Result<String, WireError> {
    let text = required_str(map, name)?;
    decode_signature(text)?;
    Ok(text.to_string())
}

fn e2e_error(err: E2eError) -> WireError {
    match err {
        E2eError::Wire(wire) => wire,
        _ => WireError::BadSignature,
    }
}

/// Request body of the device register route: the id block of a device.
/// `sig` is the device signature over `irc-e2e:v2:id:<curve25519>:<master>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceIdRequest {
    ed25519: String,
    curve25519: String,
    sig: String,
}

impl DeviceIdRequest {
    /// Checks the form of the two keys and of the signature.
    pub fn new(ed25519: &str, curve25519: &str, sig: &str) -> Result<Self, WireError> {
        decode_key(ed25519)?;
        decode_key(curve25519)?;
        decode_signature(sig)?;
        Ok(Self {
            ed25519: ed25519.to_string(),
            curve25519: curve25519.to_string(),
            sig: sig.to_string(),
        })
    }

    /// The compact JSON text for the request body.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a request of plain fields serializes")
    }
}

/// A device as the server holds it. The `did` is the server's, so it is
/// checked against the `ed25519` key: a mismatch is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub did: String,
    pub ed25519: String,
    pub curve25519: String,
    pub sig: String,
}

impl DeviceRecord {
    /// Reads one device. Extra fields are ignored.
    pub fn from_value(value: &Value) -> Result<Self, WireError> {
        let map = as_object(value)?;
        let ed25519 = key_text(map, "ed25519")?;
        let did = required_str(map, "did")?;
        if !is_did_shape(did) || did_from_key_text(&ed25519)? != did {
            return Err(WireError::BadDid);
        }
        Ok(Self {
            did: did.to_string(),
            curve25519: key_text(map, "curve25519")?,
            sig: signature_text(map, "sig")?,
            ed25519,
        })
    }

    /// Reads the answer of the device list: `{"devices": [device…]}`.
    pub fn list_from_value(value: &Value) -> Result<Vec<Self>, WireError> {
        as_object(value)?
            .get("devices")
            .ok_or(WireError::MissingField)?
            .as_array()
            .ok_or(WireError::BadFieldType)?
            .iter()
            .map(Self::from_value)
            .collect()
    }

    /// True when the record is the id block of `request`.
    pub fn matches(&self, request: &DeviceIdRequest) -> bool {
        self.ed25519 == request.ed25519
            && self.curve25519 == request.curve25519
            && self.sig == request.sig
    }
}

/// Request body of the list put route. The list is checked here, with its
/// signature, so a bad list never leaves the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListRequest {
    master: String,
    ver: u32,
    devices: Vec<String>,
    sig: String,
}

impl ListRequest {
    /// The devices must be 1 to 4 keys, sorted strictly ascending as plain
    /// text. The signature must verify under `master`.
    pub fn new(master: &str, list: &SignedList) -> Result<Self, WireError> {
        decode_key(master)?;
        if !list.keys.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(WireError::BadDeviceCount);
        }
        check_list_devices(&list.keys)?;
        verify_signed_list(list.version, &list.keys, master, &list.signature).map_err(e2e_error)?;
        Ok(Self {
            master: master.to_string(),
            ver: list.version,
            devices: list.keys.clone(),
            sig: list.signature.clone(),
        })
    }

    /// The compact JSON text for the request body.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a request of plain fields serializes")
    }
}

/// The list as the server holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldList {
    pub master: String,
    pub list: SignedList,
}

impl HeldList {
    /// Reads the answer of the list routes. `ver` is a whole number from 1 to
    /// 2^31 - 1. The signature is not checked here.
    pub fn from_value(value: &Value) -> Result<Self, WireError> {
        let map = as_object(value)?;
        let ver = map
            .get("ver")
            .ok_or(WireError::MissingField)?
            .as_u64()
            .ok_or(WireError::BadFieldType)?;
        let version = u32::try_from(ver)
            .ok()
            .filter(|version| (1..=MAX_VERSION).contains(version))
            .ok_or(WireError::BadVersion)?;
        let keys = map
            .get("devices")
            .ok_or(WireError::MissingField)?
            .as_array()
            .ok_or(WireError::BadFieldType)?
            .iter()
            .map(|key| {
                let text = key.as_str().ok_or(WireError::BadFieldType)?;
                decode_key(text)?;
                Ok::<String, WireError>(text.to_string())
            })
            .collect::<Result<Vec<_>, WireError>>()?;
        check_list_devices(&keys)?;
        Ok(Self {
            master: key_text(map, "master")?,
            list: SignedList {
                version,
                keys,
                signature: signature_text(map, "sig")?,
            },
        })
    }
}

/// One public key of a bundle with the device signature over
/// `irc-e2e:v1:otk:<key>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedKey {
    key: String,
    sig: String,
}

impl SignedKey {
    /// Checks the form of the key and of the signature. The caller signed
    /// the text of `bundle_key_signed_text`.
    pub fn new(key: &str, sig: &str) -> Result<Self, WireError> {
        decode_key(key)?;
        decode_signature(sig)?;
        Ok(Self {
            key: key.to_string(),
            sig: sig.to_string(),
        })
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

/// Request body of the keys publish route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeysUploadRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    one_time_keys: Option<Vec<SignedKey>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback: Option<SignedKey>,
}

impl KeysUploadRequest {
    /// An upload with nothing in it is refused, as is one with more than
    /// `ONE_TIME_KEYS_MAX` one-time keys. An empty list of one-time keys is
    /// left out of the body.
    pub fn new(
        one_time_keys: Vec<SignedKey>,
        fallback: Option<SignedKey>,
    ) -> Result<Self, WireError> {
        if one_time_keys.len() > ONE_TIME_KEYS_MAX {
            return Err(WireError::TooManyKeys);
        }
        if one_time_keys.is_empty() && fallback.is_none() {
            return Err(WireError::BadPayload);
        }
        Ok(Self {
            one_time_keys: (!one_time_keys.is_empty()).then_some(one_time_keys),
            fallback,
        })
    }

    /// The compact JSON text for the request body.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a request of plain fields serializes")
    }
}

/// Answer of the keys routes: what the device has left to hand out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeysHeld {
    pub one_time_keys: usize,
    pub fallback: bool,
}

impl KeysHeld {
    pub fn from_value(value: &Value) -> Result<Self, WireError> {
        let map = as_object(value)?;
        let count = map
            .get("one_time_keys")
            .ok_or(WireError::MissingField)?
            .as_u64()
            .ok_or(WireError::BadFieldType)?;
        let fallback = map
            .get("fallback")
            .ok_or(WireError::MissingField)?
            .as_bool()
            .ok_or(WireError::BadFieldType)?;
        Ok(Self {
            one_time_keys: usize::try_from(count).map_err(|_| WireError::BadFieldType)?,
            fallback,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_device::build_signed_list_signature;
    use serde_json::json;
    use vodozemac::olm::Account;

    fn key_of(account: &Account) -> String {
        account.identity_keys().ed25519.to_base64()
    }

    fn sig_of(account: &Account) -> String {
        account.sign("text").to_base64()
    }

    fn signed(master: &Account, version: u32, keys: &[String]) -> SignedList {
        let mut sorted = keys.to_vec();
        sorted.sort();
        let signature =
            build_signed_list_signature(version, &sorted, |text| master.sign(text).to_base64())
                .unwrap();
        SignedList {
            version,
            keys: sorted,
            signature,
        }
    }

    #[test]
    fn device_id_request_has_the_three_fields() {
        let account = Account::new();
        let keys = account.identity_keys();
        let request = DeviceIdRequest::new(
            &key_of(&account),
            &keys.curve25519.to_base64(),
            &sig_of(&account),
        )
        .unwrap();
        let value: Value = serde_json::from_str(&request.to_json()).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["ed25519"], key_of(&account));
        assert_eq!(value["curve25519"], keys.curve25519.to_base64());
        assert_eq!(
            DeviceIdRequest::new("x", &key_of(&account), &sig_of(&account)),
            Err(WireError::BadKey)
        );
        assert_eq!(
            DeviceIdRequest::new(&key_of(&account), &key_of(&account), "x"),
            Err(WireError::BadSignature)
        );
    }

    #[test]
    fn device_record_checks_the_did_against_the_key() {
        let account = Account::new();
        let ed = key_of(&account);
        let did = did_from_key_text(&ed).unwrap();
        let value = json!({
            "did": did, "ed25519": ed, "curve25519": key_of(&Account::new()),
            "sig": sig_of(&account), "extra": 1
        });
        assert_eq!(DeviceRecord::from_value(&value).unwrap().did, did);
        for bad in [
            "AAAAAAAAAAA".to_string(),
            format!("{did}="),
            did.replace('-', "+").replace('_', "/") + "=",
            String::new(),
        ] {
            let mut wrong = value.clone();
            wrong["did"] = json!(bad);
            assert_eq!(
                DeviceRecord::from_value(&wrong),
                Err(WireError::BadDid),
                "{bad}"
            );
        }
        let page = json!({"devices": [value.clone(), value]});
        assert_eq!(DeviceRecord::list_from_value(&page).unwrap().len(), 2);
        assert_eq!(
            DeviceRecord::list_from_value(&json!({})),
            Err(WireError::MissingField)
        );
    }

    #[test]
    fn list_request_needs_a_valid_sorted_signed_list() {
        let master = Account::new();
        let devices: Vec<String> = (0..3).map(|_| key_of(&Account::new())).collect();
        let list = signed(&master, 2, &devices);
        let request = ListRequest::new(&key_of(&master), &list).unwrap();
        let value: Value = serde_json::from_str(&request.to_json()).unwrap();
        assert_eq!(value["ver"], 2);
        assert_eq!(value["master"], key_of(&master));
        assert_eq!(value["devices"], json!(list.keys));
        assert_eq!(value["sig"], list.signature);

        let mut unsorted = list.clone();
        unsorted.keys.reverse();
        assert_eq!(
            ListRequest::new(&key_of(&master), &unsorted),
            Err(WireError::BadDeviceCount)
        );
        assert_eq!(
            ListRequest::new(&key_of(&Account::new()), &list),
            Err(WireError::BadSignature)
        );
        let mut empty = list;
        empty.keys.clear();
        assert!(ListRequest::new(&key_of(&master), &empty).is_err());
    }

    #[test]
    fn held_list_reads_the_four_fields() {
        let master = Account::new();
        let devices = vec![key_of(&Account::new())];
        let list = signed(&master, 5, &devices);
        let value = json!({
            "master": key_of(&master), "ver": 5, "devices": devices,
            "sig": list.signature, "extra": true
        });
        let held = HeldList::from_value(&value).unwrap();
        assert_eq!(held.master, key_of(&master));
        assert_eq!(held.list, list);
        for (field, wrong, error) in [
            ("ver", json!(0), WireError::BadVersion),
            ("ver", json!(2147483648u64), WireError::BadVersion),
            ("ver", json!("5"), WireError::BadFieldType),
            ("devices", json!([]), WireError::BadDeviceCount),
            ("sig", json!("x"), WireError::BadSignature),
        ] {
            let mut bad = value.clone();
            bad[field] = wrong;
            assert_eq!(HeldList::from_value(&bad), Err(error), "{field}");
        }
    }

    #[test]
    fn keys_upload_leaves_out_the_empty_field() {
        let account = Account::new();
        let key = SignedKey::new(&key_of(&account), &sig_of(&account)).unwrap();
        let only_fallback = KeysUploadRequest::new(Vec::new(), Some(key.clone())).unwrap();
        let value: Value = serde_json::from_str(&only_fallback.to_json()).unwrap();
        assert!(value.get("one_time_keys").is_none());
        assert_eq!(value["fallback"]["key"], key.key());
        let only_otk = KeysUploadRequest::new(vec![key.clone()], None).unwrap();
        let value: Value = serde_json::from_str(&only_otk.to_json()).unwrap();
        assert!(value.get("fallback").is_none());
        assert_eq!(value["one_time_keys"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn keys_upload_refuses_nothing_and_too_many() {
        let account = Account::new();
        let key = SignedKey::new(&key_of(&account), &sig_of(&account)).unwrap();
        assert_eq!(
            KeysUploadRequest::new(Vec::new(), None),
            Err(WireError::BadPayload)
        );
        let full = vec![key.clone(); ONE_TIME_KEYS_MAX];
        assert!(KeysUploadRequest::new(full.clone(), None).is_ok());
        let mut over = full;
        over.push(key);
        assert_eq!(
            KeysUploadRequest::new(over, None),
            Err(WireError::TooManyKeys)
        );
        assert_eq!(SignedKey::new("x", "y"), Err(WireError::BadKey));
    }

    #[test]
    fn keys_held_reads_the_count_and_the_flag() {
        let held = KeysHeld::from_value(&json!({"one_time_keys": 7, "fallback": true})).unwrap();
        assert_eq!((held.one_time_keys, held.fallback), (7, true));
        for (value, error) in [
            (json!({"fallback": true}), WireError::MissingField),
            (json!({"one_time_keys": 1}), WireError::MissingField),
            (
                json!({"one_time_keys": -1, "fallback": true}),
                WireError::BadFieldType,
            ),
            (
                json!({"one_time_keys": 1, "fallback": "yes"}),
                WireError::BadFieldType,
            ),
        ] {
            assert_eq!(KeysHeld::from_value(&value), Err(error), "{value}");
        }
    }
}
