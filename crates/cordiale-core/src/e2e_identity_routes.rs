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
    /// Last activity that protocol 56 reports. Older servers omit it.
    pub last_seen: LastSeen,
    /// When the device was first registered (protocol 57). None when the
    /// field is absent, null or not a valid timestamp.
    pub inserted_at: Option<String>,
}

/// The optional `last_seen_at` of a device. The four cases stay apart, so a
/// view can tell "not sent" from "never seen" and from "unreadable".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LastSeen {
    /// The field is absent: the server is older than protocol 56.
    #[default]
    NotSent,
    /// The field is JSON `null`: the server never recorded activity.
    Never,
    /// The field is a valid ISO 8601 timestamp, kept as sent.
    At(String),
    /// The field has a bad type or format.
    Unreadable,
}

impl LastSeen {
    fn from_field(value: Option<&Value>) -> Self {
        match value {
            None => Self::NotSent,
            Some(Value::Null) => Self::Never,
            Some(Value::String(text)) if is_iso_timestamp(text) => Self::At(text.clone()),
            Some(_) => Self::Unreadable,
        }
    }
}

/// True for `YYYY-MM-DDTHH:MM:SS[.fraction]` followed by `Z` or `+HH:MM`.
pub fn is_iso_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    let digits = |from: usize, len: usize| -> Option<u32> {
        let part = bytes.get(from..from + len)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    let at = |index: usize, wanted: u8| bytes.get(index) == Some(&wanted);
    let (Some(year), Some(month), Some(day)) = (digits(0, 4), digits(5, 2), digits(8, 2)) else {
        return false;
    };
    let (Some(hour), Some(minute), Some(second)) = (digits(11, 2), digits(14, 2), digits(17, 2))
    else {
        return false;
    };
    if !(at(4, b'-')
        && at(7, b'-')
        && (at(10, b'T') || at(10, b't'))
        && at(13, b':')
        && at(16, b':'))
    {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > month_days || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let mut index = 19;
    if at(index, b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    match bytes.get(index) {
        Some(b'Z') | Some(b'z') => index + 1 == bytes.len(),
        Some(b'+') | Some(b'-') => {
            let (Some(zone_hour), Some(zone_minute)) = (digits(index + 1, 2), digits(index + 4, 2))
            else {
                return false;
            };
            at(index + 3, b':') && zone_hour <= 23 && zone_minute <= 59 && index + 6 == bytes.len()
        }
        _ => false,
    }
}

impl DeviceRecord {
    /// Reads one device. Extra fields are ignored. A bad `last_seen_at`
    /// marks only the activity as unreadable.
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
            last_seen: LastSeen::from_field(map.get("last_seen_at")),
            inserted_at: match map.get("inserted_at") {
                Some(Value::String(text)) if is_iso_timestamp(text) => Some(text.clone()),
                _ => None,
            },
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

    fn device_value(extra: Option<(&str, Value)>) -> Value {
        let account = Account::new();
        let keys = account.identity_keys();
        let ed = keys.ed25519.to_base64();
        let mut value = json!({
            "did": did_from_key_text(&ed).unwrap(),
            "ed25519": ed,
            "curve25519": keys.curve25519.to_base64(),
            "sig": sig_of(&account),
            "unknown_field": 7,
        });
        if let Some((name, field)) = extra {
            value[name] = field;
        }
        value
    }

    #[test]
    fn last_seen_is_absent_null_valid_or_unreadable() {
        let read = |extra| {
            DeviceRecord::from_value(&device_value(extra))
                .unwrap()
                .last_seen
        };
        assert_eq!(read(None), LastSeen::NotSent);
        assert_eq!(read(Some(("last_seen_at", Value::Null))), LastSeen::Never);
        let stamp = "2026-11-05T10:20:30.123Z";
        assert_eq!(
            read(Some(("last_seen_at", json!(stamp)))),
            LastSeen::At(stamp.to_string())
        );
        for bad in [json!("yesterday"), json!(12), json!("2026-13-05T10:20:30Z")] {
            assert_eq!(read(Some(("last_seen_at", bad))), LastSeen::Unreadable);
        }
    }

    #[test]
    fn inserted_at_is_kept_apart_from_last_seen() {
        let read = |extra| DeviceRecord::from_value(&device_value(extra)).unwrap();
        let stamp = "2026-10-01T08:00:00.5Z";
        let added = read(Some(("inserted_at", json!(stamp))));
        assert_eq!(added.inserted_at.as_deref(), Some(stamp));
        assert_eq!(added.last_seen, LastSeen::NotSent);
        assert_eq!(read(None).inserted_at, None);
        assert_eq!(read(Some(("inserted_at", Value::Null))).inserted_at, None);
        assert_eq!(read(Some(("inserted_at", json!("soon")))).inserted_at, None);
    }

    #[test]
    fn a_device_list_keeps_every_device_whatever_its_added_time() {
        let stamp = "2026-10-01T08:00:00Z";
        let valid = device_value(Some(("inserted_at", json!(stamp))));
        let missing = device_value(None);
        let nulled = device_value(Some(("inserted_at", Value::Null)));
        let page = json!({"devices": [valid.clone(), missing.clone(), nulled.clone()]});
        let list = DeviceRecord::list_from_value(&page).unwrap();
        assert_eq!(list.len(), 3);
        let dids: Vec<&str> = [&valid, &missing, &nulled]
            .iter()
            .map(|value| value["did"].as_str().unwrap())
            .collect();
        for (record, did) in list.iter().zip(dids) {
            assert_eq!(record.did, did);
        }
        assert_eq!(list[0].inserted_at.as_deref(), Some(stamp));
        assert_eq!(list[1].inserted_at, None);
        assert_eq!(list[2].inserted_at, None);
        // The identity block is unchanged, so pairing and revoke still match.
        let request =
            DeviceIdRequest::new(&list[0].ed25519, &list[0].curve25519, &list[0].sig).unwrap();
        assert!(list[0].matches(&request));
        assert!(!list[1].matches(&request));
    }

    #[test]
    fn timestamp_check_covers_zones_and_dates() {
        assert!(is_iso_timestamp("2026-11-05T10:20:30+01:00"));
        assert!(is_iso_timestamp("2024-02-29T00:00:00Z"));
        assert!(!is_iso_timestamp("2026-02-29T00:00:00Z"));
        assert!(!is_iso_timestamp("2026-11-05T10:20:30"));
        assert!(!is_iso_timestamp("2026-11-05T10:20:30.Z"));
        assert!(!is_iso_timestamp("2026-11-05 10:20:30Z"));
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
