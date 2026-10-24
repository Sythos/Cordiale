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

//! Candidate models of the per-device E2E routes of protocol 50.
//!
//! The two routes are account-level, below `/e2e/devices/:did`:
//!
//! - `POST /e2e/devices/:did/claim` takes one one-time key of device `did`.
//! - `POST /e2e/devices/:did/copies` puts one encrypted copy in the inbox of
//!   device `did`.
//!
//! The upstream contract is not in this repository. The field names below are
//! an assumption. Cordiale reads answers by name and ignores extra fields, so
//! a renamed field fails as `MissingField` and never as a wrong value. When
//! the upstream text is read, only this module changes.
//!
//! The module holds data and pure checks. It does no network call.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use serde::Serialize;
use serde_json::Value;

use crate::e2e_wire::{
    as_object, decode_key, is_did_shape, required_str, WireError, INBOX_SENDER_MAX_BYTES,
};

/// A per-device route below `/e2e/devices/:did`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRoute {
    /// `POST /e2e/devices/:did/claim`.
    Claim,
    /// `POST /e2e/devices/:did/copies`.
    Copies,
}

impl DeviceRoute {
    /// The last path segment of the route.
    pub fn segment(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Copies => "copies",
        }
    }

    /// The path for `did`. A `did` that is not url-safe base64 of the right
    /// length is refused, so it can never change the shape of the path.
    pub fn path(self, did: &str) -> Result<String, WireError> {
        if !is_did_shape(did) {
            return Err(WireError::BadDid);
        }
        Ok(format!("/e2e/devices/{did}/{}", self.segment()))
    }
}

/// Request body of the claim route. The target device is in the path, so the
/// body has no field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ClaimRequest {}

impl ClaimRequest {
    /// The compact JSON text for the request body: `{}`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("an empty request serializes")
    }
}

/// Answer of the claim route: the claimed one-time key of the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimResponse {
    did: String,
    one_time_key: String,
}

impl ClaimResponse {
    /// Reads the answer. Extra fields are ignored. The `did` must have the
    /// shape of a device id and the key must be canonical key text.
    pub fn from_value(value: &Value) -> Result<Self, WireError> {
        let map = as_object(value)?;
        let did = required_str(map, "did")?;
        if !is_did_shape(did) {
            return Err(WireError::BadDid);
        }
        let key = required_str(map, "one_time_key")?;
        decode_key(key)?;
        Ok(Self {
            did: did.to_string(),
            one_time_key: key.to_string(),
        })
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn one_time_key(&self) -> &str {
        &self.one_time_key
    }
}

/// Request body of the copies route: one copy for the device in the path.
///
/// `item_id` is the inbox item id (`<msgid>.<did>` from `build_copies`).
/// `ciphertext` is base64 text of at most `INBOX_SENDER_MAX_BYTES`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CopyRequest {
    item_id: String,
    ciphertext: String,
}

impl CopyRequest {
    /// Checks every field and builds the request.
    pub fn new(item_id: &str, ciphertext: &str) -> Result<Self, WireError> {
        if item_id.is_empty() || item_id.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err(WireError::BadMsgid);
        }
        let decodes =
            STANDARD.decode(ciphertext).is_ok() || STANDARD_NO_PAD.decode(ciphertext).is_ok();
        if ciphertext.is_empty() || ciphertext.len() > INBOX_SENDER_MAX_BYTES || !decodes {
            return Err(WireError::BadPayload);
        }
        Ok(Self {
            item_id: item_id.to_string(),
            ciphertext: ciphertext.to_string(),
        })
    }

    /// The compact JSON text for the request body.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a request of plain fields serializes")
    }
}

/// Answer of the copies route: the id of the item that the inbox holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyResponse {
    item_id: String,
}

impl CopyResponse {
    /// Reads the answer. Extra fields are ignored.
    pub fn from_value(value: &Value) -> Result<Self, WireError> {
        let map = as_object(value)?;
        let item_id = required_str(map, "item_id")?;
        if item_id.is_empty() {
            return Err(WireError::BadMsgid);
        }
        Ok(Self {
            item_id: item_id.to_string(),
        })
    }

    pub fn item_id(&self) -> &str {
        &self.item_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 11 characters of url-safe base64 that decode to 8 bytes.
    const DID: &str = "AAAAAAAAAAA";
    /// 43 characters of canonical key text.
    const KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    #[test]
    fn routes_build_the_device_path() {
        assert_eq!(
            DeviceRoute::Claim.path(DID).unwrap(),
            format!("/e2e/devices/{DID}/claim")
        );
        assert_eq!(
            DeviceRoute::Copies.path(DID).unwrap(),
            format!("/e2e/devices/{DID}/copies")
        );
    }

    #[test]
    fn routes_refuse_a_did_that_could_change_the_path() {
        for did in ["", "short", "../etc/pass", "AAAAAAAAAA/", "AAAAAAAAAAAA"] {
            assert_eq!(
                DeviceRoute::Claim.path(did),
                Err(WireError::BadDid),
                "{did}"
            );
        }
    }

    #[test]
    fn claim_request_is_an_empty_object() {
        assert_eq!(ClaimRequest::default().to_json(), "{}");
    }

    #[test]
    fn claim_response_reads_did_and_key_and_ignores_extra_fields() {
        let value = json!({"did": DID, "one_time_key": KEY, "extra": 1});
        let answer = ClaimResponse::from_value(&value).unwrap();
        assert_eq!(answer.did(), DID);
        assert_eq!(answer.one_time_key(), KEY);
    }

    #[test]
    fn claim_response_refuses_bad_values() {
        let cases = [
            (json!([]), WireError::BadFieldType),
            (json!({"one_time_key": KEY}), WireError::MissingField),
            (
                json!({"did": 1, "one_time_key": KEY}),
                WireError::BadFieldType,
            ),
            (json!({"did": "x", "one_time_key": KEY}), WireError::BadDid),
            (
                json!({"did": DID, "one_time_key": null}),
                WireError::BadFieldType,
            ),
            (
                json!({"did": DID, "one_time_key": "abc"}),
                WireError::BadKey,
            ),
        ];
        for (value, error) in cases {
            assert_eq!(ClaimResponse::from_value(&value), Err(error), "{value}");
        }
    }

    #[test]
    fn copy_request_checks_fields_and_serializes() {
        let request = CopyRequest::new("msg1.AAAAAAAAAAA", "AAEC").unwrap();
        assert_eq!(
            request.to_json(),
            r#"{"item_id":"msg1.AAAAAAAAAAA","ciphertext":"AAEC"}"#
        );
        assert_eq!(CopyRequest::new("", "AAEC"), Err(WireError::BadMsgid));
        assert_eq!(CopyRequest::new("a b", "AAEC"), Err(WireError::BadMsgid));
        assert_eq!(CopyRequest::new("a", ""), Err(WireError::BadPayload));
        assert_eq!(CopyRequest::new("a", "!!"), Err(WireError::BadPayload));
        let big = "A".repeat(INBOX_SENDER_MAX_BYTES + 4);
        assert_eq!(CopyRequest::new("a", &big), Err(WireError::BadPayload));
    }

    #[test]
    fn copy_response_reads_the_item_id() {
        let answer = CopyResponse::from_value(&json!({"item_id": "m.d", "x": true})).unwrap();
        assert_eq!(answer.item_id(), "m.d");
        assert_eq!(
            CopyResponse::from_value(&json!({})),
            Err(WireError::MissingField)
        );
        assert_eq!(
            CopyResponse::from_value(&json!({"item_id": ""})),
            Err(WireError::BadMsgid)
        );
    }
}
