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

//! Opt-in checks against a real Grappa server of protocol 50.
//!
//! These tests need a server that Cordiale cannot start by itself. They are
//! `#[ignore]` and do not run in the normal test run. Run them with
//! `cargo test -p cordiale-core --test e2e_live_server -- --ignored`
//! after you set these variables:
//!
//! - `CORDIALE_LIVE_SERVER`: the base URL of the server.
//! - `CORDIALE_LIVE_TOKEN`: a bearer token of a test account.
//! - `CORDIALE_LIVE_NETWORK`: the network id of that account.
//!
//! The checks only read. They do not send a message and they do not change a
//! list or a device. A mock server is not a substitute: do not point these
//! tests at one and call the result interoperation.

use cordiale_core::client::GrappaClient;
use cordiale_core::e2e_refusal::{E2eRefusal, E2eRouteError};
use cordiale_core::protocol::CLIENT_PROTOCOL_VERSION;

fn variable(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("set {name} to run the live checks (see the module comment)"))
}

#[tokio::test]
#[ignore = "needs a protocol 50 server: see the module comment"]
async fn the_live_server_speaks_the_protocol_of_the_client() {
    let client = GrappaClient::new(variable("CORDIALE_LIVE_SERVER"));
    let config = client.fetch_config().await.expect("GET /api/config");
    assert!(
        config.protocol_version >= CLIENT_PROTOCOL_VERSION,
        "the server protocol {} is older than the client protocol {}",
        config.protocol_version,
        CLIENT_PROTOCOL_VERSION
    );
    assert!(config.min_protocol_version <= CLIENT_PROTOCOL_VERSION);
}

#[tokio::test]
#[ignore = "needs a protocol 50 server: see the module comment"]
async fn the_live_server_answers_the_device_and_list_routes_in_the_known_shapes() {
    let client = GrappaClient::new(variable("CORDIALE_LIVE_SERVER"));
    let token = variable("CORDIALE_LIVE_TOKEN");
    let network = variable("CORDIALE_LIVE_NETWORK");
    let config = client.fetch_config().await.expect("GET /api/config");
    let protocol = Some(config.protocol_version);

    client
        .list_e2e_devices(&token, &network, protocol)
        .await
        .expect("GET /networks/:id/e2e/devices");

    // Before a list is put, the server answers 404 not_found.
    match client.fetch_e2e_list(&token, &network, protocol).await {
        Ok(_)
        | Err(E2eRouteError::Refused {
            refusal: E2eRefusal::NotFound,
            ..
        }) => {}
        Err(error) => panic!("GET /networks/:id/e2e/list gave {error:?}"),
    }
}
