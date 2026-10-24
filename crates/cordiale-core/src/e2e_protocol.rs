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

//! Map of the E2E operations to the protocol version that introduced them.
//!
//! The routes are the single-bundle routes of protocols 42 to 44. The
//! per-device routes of protocol 49 are not in this map: the upstream change
//! is still a candidate and Cordiale does not claim a final protocol 49
//! contract.

use std::time::Duration;

use crate::e2e_pacing::KEYS_ANSWER_INTERVAL;

/// One E2E operation of the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2eOperation {
    /// `POST /networks/:id/e2e/messages`.
    SendMessage,
    /// `GET /networks/:id/e2e/inbox`.
    InboxFetch,
    /// `POST /networks/:id/e2e/inbox/ack`.
    InboxAck,
    /// `POST /networks/:id/e2e/keys`.
    KeysPublish,
    /// `GET /networks/:id/e2e/keys`.
    KeysFetch,
    /// `DELETE /networks/:id/e2e/keys`.
    KeysDelete,
    /// A KEYS frame that answers a KEYREQ. It is sent with `SendMessage`.
    KeysAnswer,
}

/// HTTP method of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2eMethod {
    Get,
    Post,
    Delete,
}

impl E2eOperation {
    pub const ALL: [E2eOperation; 7] = [
        Self::SendMessage,
        Self::InboxFetch,
        Self::InboxAck,
        Self::KeysPublish,
        Self::KeysFetch,
        Self::KeysDelete,
        Self::KeysAnswer,
    ];

    /// First protocol version that has the operation.
    pub fn min_protocol(self) -> u32 {
        match self {
            Self::SendMessage | Self::KeysAnswer => 42,
            Self::InboxFetch | Self::InboxAck => 43,
            Self::KeysPublish | Self::KeysFetch | Self::KeysDelete => 44,
        }
    }

    /// Method and path below `/networks/:id`. A KEYS answer goes through the
    /// send door.
    pub fn route(self) -> (E2eMethod, &'static str) {
        match self {
            Self::SendMessage | Self::KeysAnswer => (E2eMethod::Post, "/e2e/messages"),
            Self::InboxFetch => (E2eMethod::Get, "/e2e/inbox"),
            Self::InboxAck => (E2eMethod::Post, "/e2e/inbox/ack"),
            Self::KeysPublish => (E2eMethod::Post, "/e2e/keys"),
            Self::KeysFetch => (E2eMethod::Get, "/e2e/keys"),
            Self::KeysDelete => (E2eMethod::Delete, "/e2e/keys"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_pacing::FAKE_LAG_BANK;

    #[test]
    fn every_operation_has_a_version_and_a_route() {
        for operation in E2eOperation::ALL {
            let (_, path) = operation.route();
            assert!(path.starts_with("/e2e/"), "{operation:?}");
            assert!(
                (42..=44).contains(&operation.min_protocol()),
                "{operation:?}"
            );
        }
        assert_eq!(
            E2eOperation::KeysDelete.route(),
            (E2eMethod::Delete, "/e2e/keys")
        );
    }

    #[test]
    fn availability_follows_the_protocol_version() {
        assert!(!E2eOperation::InboxFetch.available(None));
        assert!(!E2eOperation::InboxFetch.available(Some(42)));
        assert!(E2eOperation::InboxFetch.available(Some(43)));
        assert!(E2eOperation::SendMessage.available(Some(46)));
        assert!(!E2eOperation::KeysPublish.available(Some(43)));
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
