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

//! Typed refusals of the E2E REST routes.
//!
//! Each known token has one HTTP status, taken from sections 4f and 4g of the
//! client protocol document. A token that arrives with another status is not
//! trusted. It maps to `Unknown`, as does a token that the table does not
//! list. `Unknown` keeps the status, so no refusal can look like a success.
//!
//! A 202 answer is an acceptance. It is not a refusal and it is not a
//! delivery, so this module never sees it.

use std::time::Duration;

use crate::client::GrappaClientError;

/// A refusal of an E2E route: the status and the token, read together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum E2eRefusal {
    BadRequest,
    InvalidLine,
    UnknownDevice,
    TooLarge,
    TooLate,
    RateLimited,
    NotFound,
    UpstreamUnreachable,
    SessionTimeout,
    DbUnavailable,
    ListedDevice,
    TooManyDevices,
    MasterMismatch,
    StaleList,
    /// The claim or the copy names the own device.
    SameDevice,
    /// The target device holds no key at all.
    KeylessDevice,
    /// The key went between the pick and the hand-out.
    KeyTaken,
    /// The target device was dropped meanwhile.
    RemovedDevice,
    /// The copy is missing on that device. Do not retry.
    InboxFull,
    PairingAlreadyJoined,
    PairingOwnRendezvous,
    PairingNotJoined,
    PairingFull,
    PairingNotAParty,
    /// A token that the table does not list, no token, or a known token with
    /// a status that the document does not give it.
    Unknown {
        status: u16,
        token: Option<String>,
    },
}

/// Every known refusal with its token and status.
static KNOWN: [(E2eRefusal, &str, u16); 24] = [
    (E2eRefusal::BadRequest, "bad_request", 400),
    (E2eRefusal::InvalidLine, "invalid_line", 400),
    (E2eRefusal::UnknownDevice, "unknown_device", 422),
    (E2eRefusal::TooLarge, "too_large", 413),
    (E2eRefusal::TooLate, "too_late", 422),
    (E2eRefusal::RateLimited, "rate_limited", 429),
    (E2eRefusal::NotFound, "not_found", 404),
    (E2eRefusal::UpstreamUnreachable, "upstream_unreachable", 502),
    (E2eRefusal::SessionTimeout, "session_timeout", 504),
    (E2eRefusal::DbUnavailable, "db_unavailable", 503),
    (E2eRefusal::ListedDevice, "listed_device", 409),
    (E2eRefusal::TooManyDevices, "too_many_devices", 409),
    (E2eRefusal::MasterMismatch, "master_mismatch", 409),
    (E2eRefusal::StaleList, "stale_list", 409),
    (E2eRefusal::SameDevice, "same_device", 409),
    (E2eRefusal::KeylessDevice, "keyless_device", 409),
    (E2eRefusal::KeyTaken, "key_taken", 409),
    (E2eRefusal::RemovedDevice, "removed_device", 409),
    (E2eRefusal::InboxFull, "inbox_full", 413),
    (
        E2eRefusal::PairingAlreadyJoined,
        "pairing_already_joined",
        409,
    ),
    (
        E2eRefusal::PairingOwnRendezvous,
        "pairing_own_rendezvous",
        409,
    ),
    (E2eRefusal::PairingNotJoined, "pairing_not_joined", 409),
    (E2eRefusal::PairingFull, "pairing_full", 413),
    (E2eRefusal::PairingNotAParty, "pairing_not_a_party", 403),
];

impl E2eRefusal {
    /// Reads a refusal from the HTTP status and the `error` token.
    pub fn from_response(status: u16, token: Option<&str>) -> Self {
        let known = token.and_then(|token| {
            KNOWN
                .iter()
                .find(|(_, name, code)| *name == token && *code == status)
        });
        match known {
            Some((refusal, _, _)) => refusal.clone(),
            None => Self::Unknown {
                status,
                token: token.map(str::to_string),
            },
        }
    }

    /// The HTTP status of the refusal.
    pub fn status(&self) -> u16 {
        match self {
            Self::Unknown { status, .. } => *status,
            known => known.entry().map_or(0, |(_, _, code)| *code),
        }
    }

    /// The `error` token, when the refusal has one.
    pub fn token(&self) -> Option<&str> {
        match self {
            Self::Unknown { token, .. } => token.as_deref(),
            known => known.entry().map(|(_, name, _)| *name),
        }
    }

    /// False for `Unknown`.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. })
    }

    fn entry(&self) -> Option<&'static (E2eRefusal, &'static str, u16)> {
        KNOWN.iter().find(|(refusal, _, _)| refusal == self)
    }
}

/// Failure of an E2E REST call: a typed refusal, or any other client error
/// (transport, URL, size).
#[derive(Debug)]
pub enum E2eRouteError {
    Refused {
        refusal: E2eRefusal,
        /// The wait the server asked for, when it gave one.
        retry_after: Option<Duration>,
    },
    Client(GrappaClientError),
}

impl From<GrappaClientError> for E2eRouteError {
    fn from(err: GrappaClientError) -> Self {
        match err {
            GrappaClientError::Rejected {
                status,
                code,
                retry_after,
            } => Self::Refused {
                refusal: E2eRefusal::from_response(status.as_u16(), code.as_deref()),
                retry_after,
            },
            other => Self::Client(other),
        }
    }
}

impl E2eRouteError {
    /// The wait the server asked for with the refusal, when it gave one.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Refused { retry_after, .. } => *retry_after,
            Self::Client(err) => err.retry_after(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unknown(status: u16, token: Option<&str>) -> E2eRefusal {
        E2eRefusal::Unknown {
            status,
            token: token.map(str::to_string),
        }
    }

    #[test]
    fn every_known_token_maps_to_its_own_value_and_status() {
        for (index, (refusal, token, status)) in KNOWN.iter().enumerate() {
            let read = E2eRefusal::from_response(*status, Some(*token));
            assert_eq!(&read, refusal, "{token}");
            assert_eq!(read.status(), *status, "{token}");
            assert_eq!(read.token(), Some(*token));
            assert!(read.is_known());
            for (other, other_token, _) in &KNOWN[index + 1..] {
                assert_ne!(refusal, other);
                assert_ne!(token, other_token);
            }
        }
    }

    #[test]
    fn the_copy_and_claim_tokens_have_the_documented_status() {
        let cases = [
            (E2eRefusal::SameDevice, 409),
            (E2eRefusal::KeylessDevice, 409),
            (E2eRefusal::KeyTaken, 409),
            (E2eRefusal::RemovedDevice, 409),
            (E2eRefusal::InboxFull, 413),
        ];
        for (refusal, status) in cases {
            assert_eq!(refusal.status(), status, "{refusal:?}");
        }
    }

    #[test]
    fn an_unknown_token_keeps_the_status() {
        let read = E2eRefusal::from_response(409, Some("new_token"));
        assert_eq!(read, unknown(409, Some("new_token")));
        assert_eq!(read.status(), 409);
        assert!(!read.is_known());
        assert_eq!(E2eRefusal::from_response(500, None), unknown(500, None));
    }

    #[test]
    fn a_known_token_with_another_status_is_unknown() {
        let read = E2eRefusal::from_response(409, Some("inbox_full"));
        assert_eq!(read, unknown(409, Some("inbox_full")));
    }

    #[test]
    fn a_rejected_client_error_becomes_a_refusal() {
        let rejected = GrappaClientError::Rejected {
            status: reqwest::StatusCode::CONFLICT,
            code: Some("key_taken".to_string()),
            retry_after: None,
        };
        assert!(matches!(
            E2eRouteError::from(rejected),
            E2eRouteError::Refused {
                refusal: E2eRefusal::KeyTaken,
                retry_after: None
            }
        ));
        let other = GrappaClientError::InvalidUrl("x".to_string());
        assert!(matches!(
            E2eRouteError::from(other),
            E2eRouteError::Client(_)
        ));
    }

    #[test]
    fn a_refusal_keeps_the_wait_the_server_asked_for() {
        let rejected = GrappaClientError::Rejected {
            status: reqwest::StatusCode::TOO_MANY_REQUESTS,
            code: Some("rate_limited".to_string()),
            retry_after: Some(Duration::from_millis(1500)),
        };
        let err = E2eRouteError::from(rejected);
        assert_eq!(err.retry_after(), Some(Duration::from_millis(1500)));
        assert!(matches!(
            err,
            E2eRouteError::Refused {
                refusal: E2eRefusal::RateLimited,
                ..
            }
        ));
    }
}
