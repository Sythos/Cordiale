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

//! Domain model: servers, profiles and authentication method.
//!
//! A server is identified by its `base_url`; a profile belongs to a server
//! and is identified by `(server_base_url, identifier)`. Actual credentials
//! don't live here: that's the `CredentialStore`'s job (Phase 1, item 3),
//! queried with the same key.

use serde::{Deserialize, Serialize};

/// A Grappa server the user can connect to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    /// Base URL of the server, also used as its identifying key.
    pub base_url: String,
    /// Label shown to the user when selecting a server.
    pub label: String,
}

/// How a profile authenticates against `POST /auth/login`.
///
/// Both variants travel on the wire `password` field, but are kept distinct
/// locally: a per-client token is scoped, and a `403 client_token_scope`
/// must never be treated as a wrong password to retry (see
/// `docs/protocol-notes.md`, §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Password,
    ClientToken,
}

/// A profile that can authenticate on a given server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// `base_url` of the `Server` this profile belongs to.
    pub server_base_url: String,
    /// Identifier sent as `identifier` in `POST /auth/login`.
    pub identifier: String,
    pub auth_method: AuthMethod,
    /// If `true`, the profile is offered again as selectable on later
    /// launches; the credential itself still lives only in the
    /// `CredentialStore`, never here.
    pub remembered: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_round_trips_through_json() {
        let server = Server {
            base_url: "https://irc.sindro.me".to_string(),
            label: "Sindro".to_string(),
        };

        let json = serde_json::to_string(&server).expect("serialize");
        let decoded: Server = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(server, decoded);
    }

    #[test]
    fn profile_round_trips_through_json() {
        let profile = Profile {
            server_base_url: "https://irc.sindro.me".to_string(),
            identifier: "vjt".to_string(),
            auth_method: AuthMethod::ClientToken,
            remembered: true,
        };

        let json = serde_json::to_string(&profile).expect("serialize");
        let decoded: Profile = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(profile, decoded);
    }
}
