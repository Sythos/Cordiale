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

//! Grappa wire protocol compatibility contract.
//!
//! See `docs/protocol-notes.md` §3 for the full rationale. Two rules drive
//! everything here: compare `protocol_version` with `>=`, never `==`; and
//! never fail to parse a message just because it carries a field or event
//! kind we don't recognize yet.

use serde::{Deserialize, Serialize};

/// The lowest Grappa `protocol_version` this build of Cordiale can talk to.
///
/// Cordiale doesn't rely on any field the server only started sending at a
/// later version, so this starts at the protocol's own floor. Raise it only
/// when Cordiale starts requiring a field a server below some version might
/// not send — and record the `protocol_version` that introduced it (see
/// `docs/protocol-notes.md` §7).
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 1;

/// The bootstrap compatibility fields from `GET /api/config`, and echoed
/// again in the WebSocket user-topic join response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCompatibility {
    /// What the server speaks right now.
    pub protocol_version: u32,
    /// The floor the server enforces on `client_proto` during the WS
    /// handshake; unrelated to what Cordiale itself requires.
    pub min_protocol_version: u32,
}

impl ServerCompatibility {
    /// Whether this build of Cordiale can understand what the server emits.
    ///
    /// Deliberately ignores `min_protocol_version`: that field constrains
    /// what a *client* must declare over the wire, not whether Cordiale can
    /// parse the server's current shape.
    pub fn supported_by_cordiale(&self) -> bool {
        self.protocol_version >= MIN_SUPPORTED_PROTOCOL_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_protocol_version_is_supported() {
        let compat = ServerCompatibility {
            protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION,
            min_protocol_version: 1,
        };
        assert!(compat.supported_by_cordiale());
    }

    #[test]
    fn newer_protocol_version_is_still_supported() {
        let compat = ServerCompatibility {
            protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION + 25,
            min_protocol_version: 1,
        };
        assert!(compat.supported_by_cordiale());
    }

    #[test]
    fn older_protocol_version_is_not_supported() {
        let compat = ServerCompatibility {
            protocol_version: 0,
            min_protocol_version: 0,
        };
        assert!(!compat.supported_by_cordiale());
    }
}
