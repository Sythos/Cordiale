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

//! Models of the per-device E2E routes of protocol 50.
//!
//! The routes are below `/networks/:id/e2e/devices/:did`. Build each path
//! with `E2eOperation::path`; this module has no path of its own.
//!
//! - `claim` takes one key of the sibling device `did` for the device
//!   `from_did`. Body `{"from_did"}`, answer 200 `{"keys"}`.
//! - `copies` queues one encrypted copy in the inbox of the sibling `did`.
//!   Body `{"from_did", "verb", "payload"}`, answer 202 `{"id", "msgid"}`.
//!   A 2xx answer is an acceptance. It is not a delivery.
//! - `inbox` (GET) and `inbox/ack` (POST) read and clear the inbox of `did`.
//!   Ack body `{"ids"}`, answer 204.
//!
//! Source of each field name: section 4f of `CLIENT_PROTOCOL.md` of Grappa.
//! The names `from_did`, `verb`, `payload`, `keys`, `id`, `msgid` and `ids`
//! are in the route tables and in the text of "Copies to your other devices
//! (v50)" and of the offline queue. The names of an inbox row (`kind`,
//! `network`, `id`, `from`, `from_did`, `to_did`, `verb`, `msgid`, `payload`,
//! `own`) are in the `e2e_message` example. The inbox answer is
//! `{"messages": [e2e_message…]}`.
//!
//! The module holds data and pure checks. It does no network call. Answers
//! are read by name and extra fields are ignored.

use serde::Serialize;
use serde_json::Value;

use crate::e2e_protocol::own_flag_allowed;
use crate::e2e_wire::{
    as_object, is_did_shape, parse_payload, required_str, WireError, INBOX_PAGE_MAX,
    SEND_PAYLOAD_MAX_BYTES, WILDCARD,
};

/// Largest payload of a copy, in bytes. The limit is the one of the send
/// door: `SEND_PAYLOAD_MAX_BYTES`.
pub const COPY_PAYLOAD_MAX_BYTES: usize = SEND_PAYLOAD_MAX_BYTES;

/// Checks the text of a payload or of a KEYS answer: compact JSON object
/// text in printable ASCII with no space.
pub(crate) fn check_compact_json(text: &str) -> Result<(), WireError> {
    if text.is_empty() || text.contains(' ') {
        return Err(WireError::BadPayload);
    }
    match parse_payload(text)? {
        Value::Object(_) => Ok(()),
        _ => Err(WireError::BadPayload),
    }
}

/// A positive id of the inbox, read from a JSON number.
fn read_id(value: &Value) -> Result<u64, WireError> {
    match value.as_u64() {
        Some(id) if id > 0 => Ok(id),
        Some(_) => Err(WireError::BadId),
        None => Err(WireError::BadFieldType),
    }
}

fn required_id(map: &serde_json::Map<String, Value>, key: &str) -> Result<u64, WireError> {
    read_id(map.get(key).ok_or(WireError::MissingField)?)
}

pub(crate) fn required_msgid(map: &serde_json::Map<String, Value>) -> Result<String, WireError> {
    let msgid = required_str(map, "msgid")?;
    if msgid.is_empty() || msgid.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return Err(WireError::BadMsgid);
    }
    Ok(msgid.to_string())
}

/// Request body of the claim route: the device that opens the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimRequest {
    from_did: String,
}

impl ClaimRequest {
    /// `from_did` must have the shape of a device id.
    pub fn new(from_did: &str) -> Result<Self, WireError> {
        if !is_did_shape(from_did) {
            return Err(WireError::BadDid);
        }
        Ok(Self {
            from_did: from_did.to_string(),
        })
    }

    /// The compact JSON text for the request body.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a request of plain fields serializes")
    }
}

/// Answer of the claim route: the KEYS v2 text for one sibling device, as a
/// peer's KEYREQ is answered with. The text is kept as it came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimResponse {
    keys: String,
}

impl ClaimResponse {
    /// Reads the answer. The `keys` text must be compact JSON object text.
    pub fn from_value(value: &Value) -> Result<Self, WireError> {
        let keys = required_str(as_object(value)?, "keys")?;
        check_compact_json(keys)?;
        Ok(Self {
            keys: keys.to_string(),
        })
    }

    pub fn keys(&self) -> &str {
        &self.keys
    }
}

/// Verb of a copy. Source: section 4f, "`verb` is `pkmsg` or `msg`".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CopyVerb {
    PkMsg,
    Msg,
}

/// Request body of the copies route: one copy of a message that the device
/// `from_did` sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CopyRequest {
    from_did: String,
    verb: CopyVerb,
    payload: String,
}

impl CopyRequest {
    /// Checks every field and builds the request. `payload` is the compact
    /// JSON text that the sending device encrypted to the sibling.
    pub fn new(from_did: &str, verb: CopyVerb, payload: &str) -> Result<Self, WireError> {
        if !is_did_shape(from_did) {
            return Err(WireError::BadDid);
        }
        if payload.len() > COPY_PAYLOAD_MAX_BYTES {
            return Err(WireError::BadPayload);
        }
        check_compact_json(payload)?;
        Ok(Self {
            from_did: from_did.to_string(),
            verb,
            payload: payload.to_string(),
        })
    }

    /// The compact JSON text for the request body.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a request of plain fields serializes")
    }
}

/// Answer of the copies route: the server accepted the copy. `id` is the
/// queue id in the inbox of the sibling and `msgid` is the id that the server
/// picked. It is not a proof of delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyAccepted {
    id: u64,
    msgid: String,
}

impl CopyAccepted {
    /// Reads the answer. Extra fields are ignored.
    pub fn from_value(value: &Value) -> Result<Self, WireError> {
        let map = as_object(value)?;
        Ok(Self {
            id: required_id(map, "id")?,
            msgid: required_msgid(map)?,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn msgid(&self) -> &str {
        &self.msgid
    }
}

/// Request body of the inbox ack route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboxAckRequest {
    ids: Vec<u64>,
}

impl InboxAckRequest {
    /// 1 to `INBOX_PAGE_MAX` positive ids. Any other count is refused here,
    /// so no request with a wrong count leaves the client.
    pub fn new(ids: &[u64]) -> Result<Self, WireError> {
        if ids.is_empty() || ids.len() > INBOX_PAGE_MAX {
            return Err(WireError::BadIdCount);
        }
        if ids.contains(&0) {
            return Err(WireError::BadId);
        }
        Ok(Self { ids: ids.to_vec() })
    }

    /// The compact JSON text for the request body.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a request of plain fields serializes")
    }
}

/// Verb of an inbox row. Source: section 4f, "`verb` is one of `keys`,
/// `pkmsg`, `msg`, `nack`".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxVerb {
    Keys,
    PkMsg,
    Msg,
    Nack,
}

impl InboxVerb {
    fn parse(text: &str) -> Result<Self, WireError> {
        match text {
            "keys" => Ok(Self::Keys),
            "pkmsg" => Ok(Self::PkMsg),
            "msg" => Ok(Self::Msg),
            "nack" => Ok(Self::Nack),
            _ => Err(WireError::BadVerb),
        }
    }
}

/// One row of the inbox of a device: an `e2e_message` of section 4f. The
/// `e2e_message` event on the user topic has the same fields, so it is read
/// with the same type: see [`E2eMessageEvent`].
///
/// `from` is a routing hint only. Pin a peer on its key, never on its nick.
/// `from_did` is a device id, or `*` on a `keys` row. `own` is true on a copy
/// of a message that one of your other devices sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxRow {
    pub id: u64,
    pub network: String,
    pub from: String,
    pub from_did: String,
    pub to_did: String,
    pub verb: InboxVerb,
    pub msgid: String,
    pub payload: String,
    pub own: bool,
}

/// The `e2e_message` event of section 4f. Its kind is
/// `ClientEventKind::E2eMessage`. No engine reads this event in this
/// module; a later slice connects it.
pub type E2eMessageEvent = InboxRow;

impl InboxRow {
    /// Reads one row. A missing field, a wrong type and a bad `did` are
    /// errors. Extra fields are ignored. The `own` field is read only from a
    /// server with protocol 50 or higher: from any other server a row that
    /// has `own` is refused. An absent `own` is false.
    pub fn from_value(value: &Value, server_protocol: Option<u32>) -> Result<Self, WireError> {
        let map = as_object(value)?;
        if required_str(map, "kind")? != "e2e_message" {
            return Err(WireError::BadFieldType);
        }
        let own = match map.get("own") {
            None => false,
            Some(_) if !own_flag_allowed(server_protocol) => return Err(WireError::UnknownField),
            Some(Value::Bool(own)) => *own,
            Some(_) => return Err(WireError::BadFieldType),
        };
        let verb = InboxVerb::parse(required_str(map, "verb")?)?;
        let from_did = required_str(map, "from_did")?;
        if !is_did_shape(from_did) && !(verb == InboxVerb::Keys && from_did == WILDCARD) {
            return Err(WireError::BadDid);
        }
        let to_did = required_str(map, "to_did")?;
        if !is_did_shape(to_did) {
            return Err(WireError::BadDid);
        }
        let payload = required_str(map, "payload")?;
        check_compact_json(payload)?;
        Ok(Self {
            id: required_id(map, "id")?,
            network: required_str(map, "network")?.to_string(),
            from: required_str(map, "from")?.to_string(),
            from_did: from_did.to_string(),
            to_did: to_did.to_string(),
            verb,
            msgid: required_msgid(map)?,
            payload: payload.to_string(),
            own,
        })
    }

    /// Reads the answer of the inbox fetch: `{"messages": [row…]}`.
    pub fn page_from_value(
        value: &Value,
        server_protocol: Option<u32>,
    ) -> Result<Vec<Self>, WireError> {
        let rows = as_object(value)?
            .get("messages")
            .ok_or(WireError::MissingField)?
            .as_array()
            .ok_or(WireError::BadFieldType)?;
        rows.iter()
            .map(|row| Self::from_value(row, server_protocol))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 11 characters of url-safe base64 that decode to 8 bytes.
    const DID: &str = "AAAAAAAAAAA";
    const OTHER_DID: &str = "If4x36FUomE";

    fn row() -> Value {
        json!({
            "kind": "e2e_message", "network": "azzurra", "id": 4711,
            "from": "vjt-claude", "from_did": DID, "to_did": OTHER_DID,
            "verb": "pkmsg", "msgid": "q83vEjRWeJA", "payload": "{\"v\":2}",
            "own": false
        })
    }

    #[test]
    fn claim_request_has_the_from_did_field() {
        assert_eq!(
            ClaimRequest::new(DID).unwrap().to_json(),
            r#"{"from_did":"AAAAAAAAAAA"}"#
        );
        assert_eq!(ClaimRequest::new("x"), Err(WireError::BadDid));
    }

    #[test]
    fn claim_response_reads_the_keys_text_and_ignores_extra_fields() {
        let value = json!({"keys": r#"{"ver":2}"#, "extra": 1});
        assert_eq!(
            ClaimResponse::from_value(&value).unwrap().keys(),
            r#"{"ver":2}"#
        );
    }

    #[test]
    fn claim_response_refuses_bad_values() {
        let cases = [
            (json!([]), WireError::BadFieldType),
            (json!({}), WireError::MissingField),
            (json!({"keys": null}), WireError::BadFieldType),
            (json!({"keys": ""}), WireError::BadPayload),
            (json!({"keys": "[]"}), WireError::BadPayload),
            (json!({"keys": r#"{"ver": 2}"#}), WireError::BadPayload),
            (json!({"keys": "{"}), WireError::BadJson),
        ];
        for (value, error) in cases {
            assert_eq!(ClaimResponse::from_value(&value), Err(error), "{value}");
        }
    }

    #[test]
    fn copy_request_serializes_the_three_fields() {
        let request = CopyRequest::new(DID, CopyVerb::PkMsg, r#"{"v":2}"#).unwrap();
        assert_eq!(
            request.to_json(),
            r#"{"from_did":"AAAAAAAAAAA","verb":"pkmsg","payload":"{\"v\":2}"}"#
        );
        let request = CopyRequest::new(DID, CopyVerb::Msg, "{}").unwrap();
        assert!(request.to_json().contains(r#""verb":"msg""#));
    }

    #[test]
    fn copy_request_refuses_bad_fields() {
        assert_eq!(
            CopyRequest::new("x", CopyVerb::Msg, "{}"),
            Err(WireError::BadDid)
        );
        for payload in ["", "AAEC", "{ }", "[]"] {
            assert!(
                CopyRequest::new(DID, CopyVerb::Msg, payload).is_err(),
                "{payload}"
            );
        }
        let big = format!("{{\"a\":\"{}\"}}", "A".repeat(COPY_PAYLOAD_MAX_BYTES));
        assert_eq!(
            CopyRequest::new(DID, CopyVerb::Msg, &big),
            Err(WireError::BadPayload)
        );
    }

    #[test]
    fn copy_answer_reads_id_and_msgid() {
        let answer = CopyAccepted::from_value(&json!({"id": 9, "msgid": "m1", "x": 1})).unwrap();
        assert_eq!((answer.id(), answer.msgid()), (9, "m1"));
        let cases = [
            (json!({"msgid": "m"}), WireError::MissingField),
            (json!({"id": "9", "msgid": "m"}), WireError::BadFieldType),
            (json!({"id": 0, "msgid": "m"}), WireError::BadId),
            (json!({"id": 9}), WireError::MissingField),
            (json!({"id": 9, "msgid": ""}), WireError::BadMsgid),
        ];
        for (value, error) in cases {
            assert_eq!(CopyAccepted::from_value(&value), Err(error), "{value}");
        }
    }

    #[test]
    fn ack_request_refuses_a_wrong_count_and_a_zero_id() {
        assert_eq!(
            InboxAckRequest::new(&[1, 2, 3]).unwrap().to_json(),
            r#"{"ids":[1,2,3]}"#
        );
        let full: Vec<u64> = (1..=INBOX_PAGE_MAX as u64).collect();
        assert!(InboxAckRequest::new(&full).is_ok());
        let over: Vec<u64> = (1..=INBOX_PAGE_MAX as u64 + 1).collect();
        assert_eq!(InboxAckRequest::new(&over), Err(WireError::BadIdCount));
        assert_eq!(InboxAckRequest::new(&[]), Err(WireError::BadIdCount));
        assert_eq!(InboxAckRequest::new(&[1, 0]), Err(WireError::BadId));
    }

    #[test]
    fn inbox_row_reads_every_field() {
        let read = InboxRow::from_value(&row(), Some(50)).unwrap();
        assert_eq!(read.id, 4711);
        assert_eq!(read.network, "azzurra");
        assert_eq!(read.from, "vjt-claude");
        assert_eq!(read.from_did, DID);
        assert_eq!(read.to_did, OTHER_DID);
        assert_eq!(read.verb, InboxVerb::PkMsg);
        assert_eq!(read.msgid, "q83vEjRWeJA");
        assert_eq!(read.payload, r#"{"v":2}"#);
        assert!(!read.own);
    }

    #[test]
    fn inbox_row_reads_the_own_flag_from_protocol_50() {
        let mut value = row();
        value["own"] = json!(true);
        assert!(InboxRow::from_value(&value, Some(50)).unwrap().own);
        assert_eq!(
            InboxRow::from_value(&value, Some(49)),
            Err(WireError::UnknownField)
        );
        assert_eq!(
            InboxRow::from_value(&value, None),
            Err(WireError::UnknownField)
        );
    }

    #[test]
    fn inbox_row_without_own_is_not_own_on_any_version() {
        let mut value = row();
        value.as_object_mut().unwrap().remove("own");
        for version in [Some(49), Some(50)] {
            assert!(!InboxRow::from_value(&value, version).unwrap().own);
        }
    }

    #[test]
    fn inbox_row_allows_a_wildcard_sender_only_on_keys() {
        let mut value = row();
        value["from_did"] = json!("*");
        assert_eq!(
            InboxRow::from_value(&value, Some(50)),
            Err(WireError::BadDid)
        );
        value["verb"] = json!("keys");
        assert!(InboxRow::from_value(&value, Some(50)).is_ok());
    }

    #[test]
    fn inbox_row_refuses_bad_values_and_ignores_extra_fields() {
        let cases: [(&str, Value, WireError); 8] = [
            ("from_did", json!("short"), WireError::BadDid),
            ("to_did", json!("*"), WireError::BadDid),
            ("verb", json!("hello"), WireError::BadVerb),
            ("id", json!("4711"), WireError::BadFieldType),
            ("id", json!(0), WireError::BadId),
            ("payload", json!("notjson"), WireError::BadJson),
            ("own", json!("yes"), WireError::BadFieldType),
            ("kind", json!("other"), WireError::BadFieldType),
        ];
        for (field, bad, error) in cases {
            let mut value = row();
            value[field] = bad;
            assert_eq!(
                InboxRow::from_value(&value, Some(50)),
                Err(error),
                "{field}"
            );
        }
        for field in ["network", "from", "msgid", "id", "payload", "kind"] {
            let mut value = row();
            value.as_object_mut().unwrap().remove(field);
            assert_eq!(
                InboxRow::from_value(&value, Some(50)),
                Err(WireError::MissingField),
                "{field}"
            );
        }
        let mut value = row();
        value["extra"] = json!({"a": 1});
        assert!(InboxRow::from_value(&value, Some(50)).is_ok());
    }

    #[test]
    fn inbox_page_reads_the_messages_list() {
        let page = json!({"messages": [row(), row()]});
        assert_eq!(InboxRow::page_from_value(&page, Some(50)).unwrap().len(), 2);
        assert_eq!(
            InboxRow::page_from_value(&json!({}), Some(50)),
            Err(WireError::MissingField)
        );
        assert_eq!(
            InboxRow::page_from_value(&json!({"messages": {}}), Some(50)),
            Err(WireError::BadFieldType)
        );
    }
}
