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

//! Typed models of the protocol 48 pairing relay (X1) and the pairing link.
//!
//! This module holds data only: the answers of the relay routes, the two
//! user-topic events, the pairing link of the QR code and the mapping of a
//! relay refusal to an error. It does no network call and no crypto. The
//! ECIES session, the REST calls and the signing come in later phases.
//!
//! The link and the relay payloads never appear in `Debug` output, so a log
//! line cannot leak them.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

use crate::e2e_wire::decode_key;

/// The side of a rendezvous: the device that opened it or the one that joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PairingRole {
    Creator,
    Joiner,
}

/// One rendezvous as the relay answers `POST /e2e/pairings` and `/join`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Rendezvous {
    pub id: String,
    pub role: PairingRole,
    /// ISO-8601 text from the relay.
    pub expires_at: String,
}

/// Body of the answer to `POST /e2e/pairings` and `/join`.
#[derive(Debug, Deserialize)]
pub struct RendezvousEnvelope {
    pub rendezvous: Rendezvous,
}

/// One relay message. The payload is base64 text of ciphertext.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct RelayMessage {
    pub seq: u64,
    pub from: PairingRole,
    pub payload: String,
}

impl fmt::Debug for RelayMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayMessage")
            .field("seq", &self.seq)
            .field("from", &self.from)
            .finish_non_exhaustive()
    }
}

/// Body of the answer to `POST /e2e/pairings/:id/messages`.
#[derive(Debug, Deserialize)]
pub struct MessageEnvelope {
    pub message: RelayMessage,
}

/// Body of the answer to `GET /e2e/pairings/:id/messages`.
#[derive(Debug, Deserialize)]
pub struct MessagesEnvelope {
    pub messages: Vec<RelayMessage>,
}

/// Request body of `POST /e2e/pairings/:id/messages`.
#[derive(Serialize)]
pub struct PostPayload<'a> {
    pub payload: &'a str,
}

/// Why a rendezvous ended, as the relay names it in `e2e_pairing_closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedReason {
    /// A side closed it.
    Closed,
    /// The 300-second lifetime ran out.
    Expired,
    /// A newer open of the same account replaced it.
    Replaced,
}

/// An event of the user topic about a rendezvous. It has no payload: the
/// client fetches the messages after the last sequence it took in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingPush {
    Message {
        rendezvous_id: String,
        seq: u64,
        from: PairingRole,
    },
    Closed {
        rendezvous_id: String,
        reason: ClosedReason,
    },
}

impl PairingPush {
    /// Reads `e2e_pairing_message` and `e2e_pairing_closed`. Any other
    /// event, or a wrong shape, gives `None`.
    pub fn from_value(value: &Value) -> Option<Self> {
        let rendezvous_id = value.get("rendezvous_id")?.as_str()?.to_string();
        match value.get("kind")?.as_str()? {
            "e2e_pairing_message" => Some(PairingPush::Message {
                rendezvous_id,
                seq: value.get("seq")?.as_u64()?,
                from: serde_json::from_value(value.get("from")?.clone()).ok()?,
            }),
            "e2e_pairing_closed" => {
                let reason = match value.get("reason")?.as_str()? {
                    "closed" => ClosedReason::Closed,
                    "expired" => ClosedReason::Expired,
                    "replaced" => ClosedReason::Replaced,
                    _ => return None,
                };
                Some(PairingPush::Closed {
                    rendezvous_id,
                    reason,
                })
            }
            _ => None,
        }
    }
}

/// Why a pairing call fails. No value holds a key, a link or a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingError {
    /// The text is not a pairing link or code.
    BadLink,
    /// A rendezvous id has not the shape the relay uses.
    BadId,
    /// 409 `pairing_already_joined`: another device joined first.
    AlreadyJoined,
    /// 409 `pairing_own_rendezvous`: a device cannot join its own rendezvous.
    OwnRendezvous,
    /// 409 `pairing_not_joined`: the creator posted before a joiner came.
    NotJoined,
    /// 403 `pairing_not_a_party`: a third device of the account.
    NotAParty,
    /// Any other 403: a client token or a visitor cannot pair.
    Forbidden,
    /// 404: the rendezvous is gone, or belongs to another account.
    NotFound,
    /// 413 `pairing_full` or 422: a limit of the relay.
    Rejected,
    /// 429: too many opens.
    RateLimited,
    /// Any other status.
    Unexpected(u16),
}

/// Maps a relay refusal to an error, by status and `error` code.
pub fn relay_error(status: u16, code: Option<&str>) -> PairingError {
    match (status, code) {
        (409, Some("pairing_already_joined")) => PairingError::AlreadyJoined,
        (409, Some("pairing_own_rendezvous")) => PairingError::OwnRendezvous,
        (409, Some("pairing_not_joined")) => PairingError::NotJoined,
        (403, Some("pairing_not_a_party")) => PairingError::NotAParty,
        (403, _) => PairingError::Forbidden,
        (404, _) => PairingError::NotFound,
        (413 | 422, _) => PairingError::Rejected,
        (429, _) => PairingError::RateLimited,
        (other, _) => PairingError::Unexpected(other),
    }
}

/// True when the text has the shape of a rendezvous id: 22 characters of
/// url-safe base64. The check also keeps a URL path segment safe.
pub fn is_rendezvous_id(text: &str) -> bool {
    text.len() == 22
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// What a QR code or a typed code holds: the rendezvous id and the public
/// ephemeral Curve25519 key of the creator. `Debug` prints no field.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingLink {
    rendezvous_id: String,
    ephemeral_key: String,
}

impl fmt::Debug for PairingLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingLink(..)")
    }
}

impl PairingLink {
    /// Builds a link from an id and a key in canonical text (43 characters).
    pub fn new(rendezvous_id: &str, ephemeral_key: &str) -> Result<Self, PairingError> {
        if !is_rendezvous_id(rendezvous_id) {
            return Err(PairingError::BadId);
        }
        decode_key(ephemeral_key).map_err(|_| PairingError::BadLink)?;
        Ok(Self {
            rendezvous_id: rendezvous_id.to_string(),
            ephemeral_key: ephemeral_key.to_string(),
        })
    }

    /// Reads a full URL, a fragment (`#pair=<id>.<key>`), `pair=<id>.<key>`
    /// or the bare code `<id>.<key>`.
    pub fn parse(text: &str) -> Result<Self, PairingError> {
        let text = text.trim();
        let fragment = match text.split_once('#') {
            Some((_, fragment)) => fragment,
            None => text,
        };
        let code = fragment
            .split('&')
            .find_map(|part| part.strip_prefix("pair="))
            .unwrap_or(fragment);
        let (id, key) = code.split_once('.').ok_or(PairingError::BadLink)?;
        Self::new(id, key)
    }

    pub fn rendezvous_id(&self) -> &str {
        &self.rendezvous_id
    }

    /// The public key of the creator, for the ECIES channel.
    pub fn ephemeral_key(&self) -> &str {
        &self.ephemeral_key
    }

    /// The code to type on a device with no camera: `<id>.<key>`.
    pub fn code(&self) -> String {
        format!("{}.{}", self.rendezvous_id, self.ephemeral_key)
    }

    /// The URL for the QR code: `https://<host>/pair#pair=<id>.<key>`.
    pub fn url(&self, host: &str) -> String {
        format!("https://{host}/pair#pair={}", self.code())
    }
}

/// Reads a link from `input` and clears `input` at once, also when the
/// text is not a link. The caller passes the buffer that holds the QR URL.
pub fn take_pairing_link(input: &mut String) -> Result<PairingLink, PairingError> {
    let link = PairingLink::parse(input);
    input.zeroize();
    link
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "AbCdEfGhIjKlMnOpQrStUv";
    /// 43 characters of canonical key text.
    const KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn link() -> PairingLink {
        PairingLink::new(ID, KEY).unwrap()
    }

    #[test]
    fn link_reads_url_fragment_code_and_pair_prefix() {
        let code = link().code();
        for text in [
            link().url("grappa.example"),
            format!("#pair={code}"),
            format!("pair={code}"),
            format!("  {code}  "),
            format!("https://h/pair#x=1&pair={code}"),
        ] {
            assert_eq!(PairingLink::parse(&text).unwrap(), link(), "{text}");
        }
        assert_eq!(link().rendezvous_id(), ID);
        assert_eq!(link().ephemeral_key(), KEY);
    }

    #[test]
    fn link_refuses_a_bad_id_and_a_bad_key() {
        assert_eq!(
            PairingLink::parse(&format!("short.{KEY}")),
            Err(PairingError::BadId)
        );
        assert_eq!(
            PairingLink::parse(&format!("{}/x.{KEY}", &ID[..20])),
            Err(PairingError::BadId)
        );
        assert_eq!(
            PairingLink::parse(&format!("{ID}.short")),
            Err(PairingError::BadLink)
        );
        assert_eq!(PairingLink::parse("nothing"), Err(PairingError::BadLink));
    }

    #[test]
    fn take_pairing_link_clears_the_buffer_on_success_and_on_error() {
        let mut good = link().url("grappa.example");
        assert_eq!(take_pairing_link(&mut good).unwrap(), link());
        assert!(good.is_empty());
        let mut bad = "https://grappa.example/pair#pair=broken".to_string();
        assert!(take_pairing_link(&mut bad).is_err());
        assert!(bad.is_empty());
    }

    #[test]
    fn debug_output_shows_no_link_key_or_payload() {
        let message = RelayMessage {
            seq: 1,
            from: PairingRole::Joiner,
            payload: "c2VjcmV0".to_string(),
        };
        let shown = format!("{:?} {message:?}", link());
        assert!(!shown.contains(KEY));
        assert!(!shown.contains(ID));
        assert!(!shown.contains("c2VjcmV0"));
    }

    #[test]
    fn rendezvous_id_shape_keeps_a_path_segment_safe() {
        assert!(is_rendezvous_id(ID));
        assert!(is_rendezvous_id("-_-_-_-_-_-_-_-_-_-_-_"));
        assert!(!is_rendezvous_id("../../me"));
        assert!(!is_rendezvous_id(&format!("{}/", &ID[..21])));
        assert!(!is_rendezvous_id(&ID[..21]));
    }

    #[test]
    fn relay_refusals_map_to_errors() {
        let cases = [
            (
                409,
                Some("pairing_already_joined"),
                PairingError::AlreadyJoined,
            ),
            (
                409,
                Some("pairing_own_rendezvous"),
                PairingError::OwnRendezvous,
            ),
            (409, Some("pairing_not_joined"), PairingError::NotJoined),
            (403, Some("pairing_not_a_party"), PairingError::NotAParty),
            (403, Some("client_token_scope"), PairingError::Forbidden),
            (404, None, PairingError::NotFound),
            (413, Some("pairing_full"), PairingError::Rejected),
            (422, None, PairingError::Rejected),
            (429, Some("rate_limited"), PairingError::RateLimited),
            (500, None, PairingError::Unexpected(500)),
        ];
        for (status, code, expected) in cases {
            assert_eq!(relay_error(status, code), expected);
        }
    }

    #[test]
    fn relay_models_read_the_documented_bodies() {
        let opened: RendezvousEnvelope = serde_json::from_value(serde_json::json!({
            "rendezvous": {"id": ID, "role": "creator", "expires_at": "2026-10-23T10:00:00Z"}
        }))
        .unwrap();
        assert_eq!(opened.rendezvous.role, PairingRole::Creator);
        assert_eq!(opened.rendezvous.id, ID);
        let fetched: MessagesEnvelope = serde_json::from_value(serde_json::json!({
            "messages": [{"seq": 2, "from": "joiner", "payload": "AAAA"}]
        }))
        .unwrap();
        assert_eq!(fetched.messages[0].seq, 2);
        let posted: MessageEnvelope = serde_json::from_value(serde_json::json!({
            "message": {"seq": 4, "from": "creator", "payload": "AAAA"}
        }))
        .unwrap();
        assert_eq!(posted.message.from, PairingRole::Creator);
        let body = serde_json::to_value(PostPayload { payload: "QUJD" }).unwrap();
        assert_eq!(body, serde_json::json!({"payload": "QUJD"}));
    }

    #[test]
    fn push_events_are_read_from_the_user_topic_shape() {
        let message = serde_json::json!({
            "kind": "e2e_pairing_message",
            "rendezvous_id": ID,
            "seq": 3,
            "from": "joiner",
        });
        assert_eq!(
            PairingPush::from_value(&message),
            Some(PairingPush::Message {
                rendezvous_id: ID.to_string(),
                seq: 3,
                from: PairingRole::Joiner,
            })
        );
        for (reason, expected) in [
            ("closed", ClosedReason::Closed),
            ("expired", ClosedReason::Expired),
            ("replaced", ClosedReason::Replaced),
        ] {
            let closed = serde_json::json!({
                "kind": "e2e_pairing_closed",
                "rendezvous_id": ID,
                "reason": reason,
            });
            assert_eq!(
                PairingPush::from_value(&closed),
                Some(PairingPush::Closed {
                    rendezvous_id: ID.to_string(),
                    reason: expected,
                })
            );
        }
    }

    #[test]
    fn push_events_with_a_wrong_shape_are_ignored() {
        let unknown = serde_json::json!({"kind": "other", "rendezvous_id": ID});
        assert_eq!(PairingPush::from_value(&unknown), None);
        let bad_reason = serde_json::json!({
            "kind": "e2e_pairing_closed",
            "rendezvous_id": ID,
            "reason": "boom",
        });
        assert_eq!(PairingPush::from_value(&bad_reason), None);
        let no_seq = serde_json::json!({
            "kind": "e2e_pairing_message",
            "rendezvous_id": ID,
            "from": "joiner",
        });
        assert_eq!(PairingPush::from_value(&no_seq), None);
    }
}
