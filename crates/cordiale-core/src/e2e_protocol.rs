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

//! Map of the E2E operations to the protocol version that has them.
//!
//! The routes are the ones of section 4f of the client protocol document.
//! The claim and copy routes are below `/networks/:id` like the others.
//! Cordiale speaks the per-device shape of protocol 49. A server between 42
//! and 48 speaks the single-bundle shape, which no release ever carried, so
//! every operation here needs 49 at least, and the claim and copy doors need
//! 50. A server with an unknown version never allows an operation.
//!
//! The pairing relay of protocol 48 (`/e2e/pairings`) is not below
//! `/networks/:id`. [`PairingOperation`] holds its routes and its version
//! check.

use std::time::Duration;

use crate::e2e_pacing::KEYS_ANSWER_INTERVAL;
use crate::e2e_pairing::is_rendezvous_id;
use crate::e2e_wire::{is_did_shape, WireError};

/// One E2E operation of the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2eOperation {
    /// `POST /networks/:id/e2e/messages`.
    SendMessage,
    /// A KEYS frame that answers a KEYREQ. It is sent with `SendMessage`.
    KeysAnswer,
    /// `POST /networks/:id/e2e/devices`: register an id block.
    DeviceRegister,
    /// `GET /networks/:id/e2e/devices`.
    DeviceList,
    /// `DELETE /networks/:id/e2e/devices/:did`: drop an unlisted device.
    DeviceDrop,
    /// `PUT /networks/:id/e2e/list`: put the signed list.
    ListPut,
    /// `GET /networks/:id/e2e/list`.
    ListFetch,
    /// `DELETE /networks/:id/e2e/keys`: drop the whole identity.
    IdentityDelete,
    /// `GET /networks/:id/e2e/devices/:did/inbox`.
    InboxFetch,
    /// `POST /networks/:id/e2e/devices/:did/inbox/ack`.
    InboxAck,
    /// `POST /networks/:id/e2e/devices/:did/keys`.
    KeysPublish,
    /// `GET /networks/:id/e2e/devices/:did/keys`.
    KeysFetch,
    /// `POST /networks/:id/e2e/devices/:did/claim`.
    Claim,
    /// `POST /networks/:id/e2e/devices/:did/copies`.
    Copy,
}

/// HTTP method of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2eMethod {
    Get,
    Post,
    Put,
    Delete,
}

/// First protocol version whose inbox rows carry the `own` flag. Source:
/// section 4f, "`own` (v50)".
pub const OWN_FLAG_MIN_PROTOCOL: u32 = 50;

/// Whether a server with this protocol version may send the `own` flag. An
/// unknown version never may.
pub fn own_flag_allowed(server_protocol: Option<u32>) -> bool {
    server_protocol.is_some_and(|version| version >= OWN_FLAG_MIN_PROTOCOL)
}

/// The place of the device id in a route.
const DID: &str = ":did";

impl E2eOperation {
    pub const ALL: [E2eOperation; 14] = [
        Self::SendMessage,
        Self::KeysAnswer,
        Self::DeviceRegister,
        Self::DeviceList,
        Self::DeviceDrop,
        Self::ListPut,
        Self::ListFetch,
        Self::IdentityDelete,
        Self::InboxFetch,
        Self::InboxAck,
        Self::KeysPublish,
        Self::KeysFetch,
        Self::Claim,
        Self::Copy,
    ];

    /// First protocol version that has the operation in the shape that
    /// Cordiale uses.
    pub fn min_protocol(self) -> u32 {
        match self {
            Self::Claim | Self::Copy => 50,
            _ => 49,
        }
    }

    /// Method and path below `/networks/:id`. A device id is the `:did`
    /// segment: use [`E2eOperation::path`] to fill it. A KEYS answer goes
    /// through the send door.
    pub fn route(self) -> (E2eMethod, &'static str) {
        match self {
            Self::SendMessage | Self::KeysAnswer => (E2eMethod::Post, "/e2e/messages"),
            Self::DeviceRegister => (E2eMethod::Post, "/e2e/devices"),
            Self::DeviceList => (E2eMethod::Get, "/e2e/devices"),
            Self::DeviceDrop => (E2eMethod::Delete, "/e2e/devices/:did"),
            Self::ListPut => (E2eMethod::Put, "/e2e/list"),
            Self::ListFetch => (E2eMethod::Get, "/e2e/list"),
            Self::IdentityDelete => (E2eMethod::Delete, "/e2e/keys"),
            Self::InboxFetch => (E2eMethod::Get, "/e2e/devices/:did/inbox"),
            Self::InboxAck => (E2eMethod::Post, "/e2e/devices/:did/inbox/ack"),
            Self::KeysPublish => (E2eMethod::Post, "/e2e/devices/:did/keys"),
            Self::KeysFetch => (E2eMethod::Get, "/e2e/devices/:did/keys"),
            Self::Claim => (E2eMethod::Post, "/e2e/devices/:did/claim"),
            Self::Copy => (E2eMethod::Post, "/e2e/devices/:did/copies"),
        }
    }

    /// Whether the route names a device.
    pub fn needs_did(self) -> bool {
        self.route().1.contains(DID)
    }

    /// The path below `/networks/:id`. `did` fills the `:did` segment. A
    /// `did` that is not url-safe base64 of the right length is refused, so
    /// it can never change the shape of the path. A route without a device
    /// ignores `did`.
    pub fn path(self, did: Option<&str>) -> Result<String, WireError> {
        let template = self.route().1;
        if !self.needs_did() {
            return Ok(template.to_string());
        }
        match did {
            Some(did) if is_did_shape(did) => Ok(template.replace(DID, did)),
            _ => Err(WireError::BadDid),
        }
    }

    /// Whether a server with this protocol version has the operation. An
    /// unknown version never allows it.
    pub fn available(self, server_protocol: Option<u32>) -> bool {
        server_protocol.is_some_and(|version| version >= self.min_protocol())
    }

    /// Per-nickname interval the client keeps between two uses. Only the
    /// KEYS answer has one. The fake-lag bank of the relay is never an
    /// interval of the client.
    pub fn client_interval(self) -> Option<Duration> {
        match self {
            Self::KeysAnswer => Some(KEYS_ANSWER_INTERVAL),
            _ => None,
        }
    }
}

/// First protocol version that has the X1 pairing relay.
pub const PAIRING_MIN_PROTOCOL: u32 = 48;

/// One call of the X1 pairing relay. The routes are not below `/networks/:id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingOperation {
    /// `POST /e2e/pairings`: open a rendezvous.
    Create,
    /// `POST /e2e/pairings/:id/join`.
    Join,
    /// `POST /e2e/pairings/:id/messages`.
    Post,
    /// `GET /e2e/pairings/:id/messages?after=<seq>`.
    Fetch,
    /// `DELETE /e2e/pairings/:id`: close the rendezvous.
    Close,
}

impl PairingOperation {
    pub const ALL: [PairingOperation; 5] = [
        Self::Create,
        Self::Join,
        Self::Post,
        Self::Fetch,
        Self::Close,
    ];

    /// Method and path template. `:id` is the rendezvous id.
    pub fn route(self) -> (E2eMethod, &'static str) {
        match self {
            Self::Create => (E2eMethod::Post, "/e2e/pairings"),
            Self::Join => (E2eMethod::Post, "/e2e/pairings/:id/join"),
            Self::Post => (E2eMethod::Post, "/e2e/pairings/:id/messages"),
            Self::Fetch => (E2eMethod::Get, "/e2e/pairings/:id/messages"),
            Self::Close => (E2eMethod::Delete, "/e2e/pairings/:id"),
        }
    }

    /// The path with the rendezvous id filled in. An id that has not the
    /// shape of a rendezvous id is refused, so it never changes the path.
    pub fn path(self, rendezvous_id: Option<&str>) -> Result<String, WireError> {
        let template = self.route().1;
        if !template.contains(":id") {
            return Ok(template.to_string());
        }
        match rendezvous_id {
            Some(id) if is_rendezvous_id(id) => Ok(template.replace(":id", id)),
            _ => Err(WireError::BadId),
        }
    }

    /// Whether a server with this protocol version has the relay. An unknown
    /// version never allows it.
    pub fn available(self, server_protocol: Option<u32>) -> bool {
        server_protocol.is_some_and(|version| version >= PAIRING_MIN_PROTOCOL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_pacing::FAKE_LAG_BANK;

    const DID_TEXT: &str = "If4x36FUomE";

    #[test]
    fn every_route_matches_section_4f() {
        let cases = [
            (
                E2eOperation::SendMessage,
                E2eMethod::Post,
                "/e2e/messages",
                49,
            ),
            (
                E2eOperation::DeviceRegister,
                E2eMethod::Post,
                "/e2e/devices",
                49,
            ),
            (E2eOperation::DeviceList, E2eMethod::Get, "/e2e/devices", 49),
            (
                E2eOperation::DeviceDrop,
                E2eMethod::Delete,
                "/e2e/devices/If4x36FUomE",
                49,
            ),
            (E2eOperation::ListPut, E2eMethod::Put, "/e2e/list", 49),
            (E2eOperation::ListFetch, E2eMethod::Get, "/e2e/list", 49),
            (
                E2eOperation::IdentityDelete,
                E2eMethod::Delete,
                "/e2e/keys",
                49,
            ),
            (
                E2eOperation::InboxFetch,
                E2eMethod::Get,
                "/e2e/devices/If4x36FUomE/inbox",
                49,
            ),
            (
                E2eOperation::InboxAck,
                E2eMethod::Post,
                "/e2e/devices/If4x36FUomE/inbox/ack",
                49,
            ),
            (
                E2eOperation::KeysPublish,
                E2eMethod::Post,
                "/e2e/devices/If4x36FUomE/keys",
                49,
            ),
            (
                E2eOperation::KeysFetch,
                E2eMethod::Get,
                "/e2e/devices/If4x36FUomE/keys",
                49,
            ),
            (
                E2eOperation::Claim,
                E2eMethod::Post,
                "/e2e/devices/If4x36FUomE/claim",
                50,
            ),
            (
                E2eOperation::Copy,
                E2eMethod::Post,
                "/e2e/devices/If4x36FUomE/copies",
                50,
            ),
        ];
        for (operation, method, path, version) in cases {
            assert_eq!(operation.route().0, method, "{operation:?}");
            assert_eq!(
                operation.path(Some(DID_TEXT)).unwrap(),
                path,
                "{operation:?}"
            );
            assert_eq!(operation.min_protocol(), version, "{operation:?}");
        }
        assert_eq!(
            E2eOperation::KeysAnswer.route(),
            E2eOperation::SendMessage.route()
        );
    }

    #[test]
    fn a_route_with_a_device_needs_a_valid_did() {
        for operation in E2eOperation::ALL {
            assert!(operation.route().1.starts_with("/e2e/"), "{operation:?}");
            if operation.needs_did() {
                for did in [None, Some(""), Some("../etc/passwd"), Some("AAAAAAAAAAAA")] {
                    assert_eq!(operation.path(did), Err(WireError::BadDid), "{operation:?}");
                }
            } else {
                assert!(operation.path(None).is_ok(), "{operation:?}");
            }
        }
    }

    #[test]
    fn availability_follows_the_protocol_version() {
        for operation in E2eOperation::ALL {
            let min = operation.min_protocol();
            assert!(!operation.available(None), "{operation:?}");
            assert!(!operation.available(Some(0)), "{operation:?}");
            assert!(!operation.available(Some(min - 1)), "{operation:?}");
            assert!(operation.available(Some(min)), "{operation:?}");
            assert!(operation.available(Some(min + 1)), "{operation:?}");
        }
        assert!(!E2eOperation::Claim.available(Some(49)));
        assert!(E2eOperation::Claim.available(Some(50)));
        assert!(!E2eOperation::SendMessage.available(Some(47)));
    }

    #[test]
    fn pairing_routes_need_protocol_48_and_a_valid_id() {
        let id = "AbCdEfGhIjKlMnOpQrStUv";
        let paths = [
            "/e2e/pairings",
            "/e2e/pairings/AbCdEfGhIjKlMnOpQrStUv/join",
            "/e2e/pairings/AbCdEfGhIjKlMnOpQrStUv/messages",
            "/e2e/pairings/AbCdEfGhIjKlMnOpQrStUv/messages",
            "/e2e/pairings/AbCdEfGhIjKlMnOpQrStUv",
        ];
        for (operation, path) in PairingOperation::ALL.into_iter().zip(paths) {
            assert_eq!(operation.path(Some(id)).unwrap(), path, "{operation:?}");
            assert!(!operation.available(None));
            assert!(!operation.available(Some(47)));
            assert!(operation.available(Some(48)));
            if operation != PairingOperation::Create {
                for bad in [None, Some("../x"), Some("short")] {
                    assert_eq!(operation.path(bad), Err(WireError::BadId), "{operation:?}");
                }
            }
        }
        assert_eq!(PairingOperation::Fetch.route().0, E2eMethod::Get);
        assert_eq!(PairingOperation::Close.route().0, E2eMethod::Delete);
    }

    #[test]
    fn the_own_flag_needs_protocol_50() {
        assert!(!own_flag_allowed(None));
        assert!(!own_flag_allowed(Some(49)));
        assert!(own_flag_allowed(Some(50)));
        assert!(own_flag_allowed(Some(51)));
        assert_eq!(OWN_FLAG_MIN_PROTOCOL, E2eOperation::Claim.min_protocol());
    }

    #[test]
    fn keys_interval_is_separate_from_the_fake_lag_bank() {
        let interval = E2eOperation::KeysAnswer
            .client_interval()
            .expect("keys answer interval");
        assert_eq!(interval, Duration::from_secs(15));
        assert_eq!(FAKE_LAG_BANK, Duration::from_secs(22));
        assert_ne!(interval, FAKE_LAG_BANK);
        for operation in E2eOperation::ALL {
            assert_ne!(operation.client_interval(), Some(FAKE_LAG_BANK));
        }
        assert_eq!(E2eOperation::SendMessage.client_interval(), None);
    }
}
