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

//! Phoenix Channels transport, built by hand over `tokio-tungstenite`.
//!
//! No mature Rust client for Phoenix Channels exists (checked before
//! writing this), so this wraps a plain WebSocket connection and speaks
//! the wire format from `crate::phoenix` over it. Plain `async fn`s only:
//! no runtime is started here, `cordiale-ui` owns that.
//!
//! Exercised against a real Grappa server as of 2026-09-20 (the bearer
//! subprotocol needed base64-encoding the token, not sending it raw —
//! see `bearer_subprotocol`'s own doc comment); still no mocked-server
//! test harness, so the unit tests here only cover what doesn't need an
//! actual socket (the handshake header).

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::USER_AGENT;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::phoenix::PhoenixMessage;
use crate::GRAPPA_USER_AGENT;

#[derive(Debug)]
pub enum PhoenixSocketError {
    InvalidRequest(String),
    Connect(tokio_tungstenite::tungstenite::Error),
    Codec(serde_json::Error),
}

// `session.rs` puts this in a `SessionEvent::Reconnecting`/`Disconnected`
// reason the UI shows directly — needs a short, human message, not the
// `{:?}` dump `PhoenixSocketError` doesn't derive. `tungstenite::Error`
// already has a clean one (e.g. its `Http` variant is just `"HTTP error:
// 500 Internal Server Error"`, confirmed against its real source), so this
// just delegates to it.
impl std::fmt::Display for PhoenixSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PhoenixSocketError::InvalidRequest(message) => write!(f, "invalid request: {message}"),
            PhoenixSocketError::Connect(err) => write!(f, "{err}"),
            PhoenixSocketError::Codec(err) => write!(f, "malformed message: {err}"),
        }
    }
}

/// What a `426 upgrade_required` answer to the WebSocket upgrade says:
/// Grappa's floor for `client_proto` moved above what this build declares.
/// Fields the body doesn't carry (or carries in an unexpected shape) stay
/// `None`: the status alone is enough to know the client is too old.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeRequired {
    pub protocol_version: Option<u32>,
    pub min_protocol_version: Option<u32>,
}

impl PhoenixSocketError {
    /// Whether the upgrade was refused because the bearer is missing, invalid
    /// or revoked. Grappa answers a bad bearer with 403 (`CLIENT_PROTOCOL.md`
    /// §3a); retrying the same bearer can never succeed, unlike a network
    /// error or a 5xx.
    pub fn is_auth_rejection(&self) -> bool {
        match self {
            PhoenixSocketError::Connect(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                is_auth_rejection_status(response.status().as_u16())
            }
            _ => false,
        }
    }

    /// The refusal details when Grappa answered the upgrade with `426`
    /// (this build declares a `client_proto` below the server's floor).
    /// Retrying can't succeed until Cordiale itself is updated.
    pub fn upgrade_required(&self) -> Option<UpgradeRequired> {
        match self {
            PhoenixSocketError::Connect(tokio_tungstenite::tungstenite::Error::Http(response))
                if response.status().as_u16() == 426 =>
            {
                Some(parse_upgrade_required(
                    response.body().as_deref().unwrap_or_default(),
                ))
            }
            _ => None,
        }
    }
}

fn is_auth_rejection_status(status: u16) -> bool {
    matches!(status, 401 | 403)
}

/// Reads the `426` body, `{"error": "upgrade_required", "protocol_version":
/// N, "min_protocol_version": M}` (`CLIENT_PROTOCOL.md` §3b).
fn parse_upgrade_required(body: &[u8]) -> UpgradeRequired {
    let json: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let number = |key: &str| {
        json.get(key)
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
    };
    UpgradeRequired {
        protocol_version: number("protocol_version"),
        min_protocol_version: number("min_protocol_version"),
    }
}

/// Builds the `Sec-WebSocket-Protocol` value Grappa expects for
/// authentication, per `docs/protocol-notes.md` §2: the bearer travels in
/// this header, never in the URL, so it stays out of access logs.
///
/// Despite the `base64url.bearer.phx.` name, the payload after the prefix
/// is plain standard-alphabet base64 with padding stripped (`btoa(token)`
/// then `.replace(/=/g, "")`, per phoenix.js's own `transportConnect()` —
/// confirmed by reading it directly, since this project has no mature
/// Phoenix client to crib from). The server decodes it back to the raw
/// token server-side. Sending the raw, unencoded token after the prefix
/// (the previous version of this function) made the server's decode fail
/// on every real token — every single WebSocket connect attempt got a 500
/// during the handshake itself, confirmed against a real user's
/// `cordiale.log` covering dozens of attempts across many hours.
fn bearer_subprotocol(token: &str) -> String {
    format!("base64url.bearer.phx.{}", STANDARD_NO_PAD.encode(token))
}

pub struct PhoenixSocket {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl PhoenixSocket {
    /// Connects to `ws_url`, which carries `?client_proto=...` when the
    /// caller declares a protocol version (see `CLIENT_PROTOCOL_VERSION`;
    /// omitted means "current" to the server).
    pub async fn connect(ws_url: &str, bearer_token: &str) -> Result<Self, PhoenixSocketError> {
        let mut request = ws_url
            .into_client_request()
            .map_err(|err| PhoenixSocketError::InvalidRequest(err.to_string()))?;

        // phoenix.js always offers `"phoenix"` alongside the bearer value
        // (`protocols = ["phoenix", "base64url.bearer.phx.<token>"]`,
        // joined by the WebSocket handshake into one comma-separated
        // header) — matched here even though the missing bearer encoding
        // above was the actual cause of the 500s; unclear whether Grappa's
        // server also expects `"phoenix"` to be present, so this doesn't
        // drop it without evidence either way.
        let subprotocols = format!("phoenix, {}", bearer_subprotocol(bearer_token));
        request.headers_mut().insert(
            HeaderName::from_static("sec-websocket-protocol"),
            HeaderValue::from_str(&subprotocols)
                .map_err(|err| PhoenixSocketError::InvalidRequest(err.to_string()))?,
        );

        // Same identification as the REST client (issue #102): tungstenite
        // sends no User-Agent of its own.
        request
            .headers_mut()
            .insert(USER_AGENT, HeaderValue::from_static(GRAPPA_USER_AGENT));

        let (stream, _response) = connect_async(request)
            .await
            .map_err(PhoenixSocketError::Connect)?;

        Ok(PhoenixSocket { stream })
    }

    pub async fn send(&mut self, message: &PhoenixMessage) -> Result<(), PhoenixSocketError> {
        let json = message.to_json().map_err(PhoenixSocketError::Codec)?;
        self.stream
            .send(Message::from(json))
            .await
            .map_err(PhoenixSocketError::Connect)
    }

    /// Waits for the next Phoenix frame. `Ok(None)` means the connection
    /// closed. Non-text frames (ping/pong/binary) are consumed and skipped:
    /// Phoenix only speaks JSON text frames, `tokio-tungstenite` answers
    /// pings automatically.
    pub async fn next_message(&mut self) -> Result<Option<PhoenixMessage>, PhoenixSocketError> {
        loop {
            match self.stream.next().await {
                None => return Ok(None),
                Some(Err(err)) => return Err(PhoenixSocketError::Connect(err)),
                Some(Ok(Message::Text(text))) => {
                    let message = PhoenixMessage::from_json(text.as_str())
                        .map_err(PhoenixSocketError::Codec)?;
                    return Ok(Some(message));
                }
                Some(Ok(Message::Close(_))) => return Ok(None),
                Some(Ok(_)) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handshake_identifies_the_client_build_to_grappa() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("ws://{}/socket/websocket", listener.local_addr().unwrap());
        // Reads only the handshake request, then drops the socket: the
        // client's connect fails, which is fine since only what it sent
        // matters here.
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                socket.readable().await.expect("readable");
                match socket.try_read(&mut buf) {
                    Ok(0) => panic!("connection closed before the headers ended"),
                    Ok(read) => request.extend_from_slice(&buf[..read]),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(err) => panic!("read: {err}"),
                }
            }
            String::from_utf8(request).expect("utf-8 request")
        });

        let _ = PhoenixSocket::connect(&url, "token").await;
        let request = server.await.expect("server task").to_ascii_lowercase();
        let expected = format!("user-agent: {GRAPPA_USER_AGENT}\r\n").to_ascii_lowercase();
        assert!(request.contains(&expected), "{request}");
    }

    #[test]
    fn only_401_and_403_are_terminal_auth_rejections() {
        assert!(is_auth_rejection_status(401));
        assert!(is_auth_rejection_status(403));
        // 426 is a protocol-version refusal and 5xx is transient: neither
        // means the bearer itself is dead.
        for status in [400, 404, 426, 429, 500, 502, 503] {
            assert!(!is_auth_rejection_status(status), "{status}");
        }
    }

    fn refused_upgrade(status: u16, body: Option<&[u8]>) -> PhoenixSocketError {
        let response = tokio_tungstenite::tungstenite::http::Response::builder()
            .status(status)
            .body(body.map(<[u8]>::to_vec))
            .expect("response");
        PhoenixSocketError::Connect(tokio_tungstenite::tungstenite::Error::Http(Box::new(
            response,
        )))
    }

    #[test]
    fn a_426_upgrade_refusal_carries_the_servers_versions() {
        let err = refused_upgrade(
            426,
            Some(
                br#"{"error":"upgrade_required","protocol_version":40,"min_protocol_version":36}"#,
            ),
        );
        assert_eq!(
            err.upgrade_required(),
            Some(UpgradeRequired {
                protocol_version: Some(40),
                min_protocol_version: Some(36),
            })
        );
        assert!(!err.is_auth_rejection());
    }

    #[test]
    fn a_426_without_a_readable_body_is_still_an_upgrade_refusal() {
        for body in [
            None,
            Some(&b"not json"[..]),
            Some(&br#"{"min_protocol_version":"x"}"#[..]),
        ] {
            assert_eq!(
                refused_upgrade(426, body).upgrade_required(),
                Some(UpgradeRequired {
                    protocol_version: None,
                    min_protocol_version: None,
                })
            );
        }
    }

    #[test]
    fn other_refusals_are_not_upgrade_refusals() {
        assert_eq!(refused_upgrade(403, None).upgrade_required(), None);
        assert_eq!(refused_upgrade(500, None).upgrade_required(), None);
    }

    #[test]
    fn bearer_subprotocol_base64_encodes_the_token_without_padding() {
        // Matches phoenix.js's own `btoa(token).replace(/=/g, "")` exactly
        // (confirmed by reading `transportConnect()` in the real `phoenix`
        // npm package) — the prefix alone, without this encoding step, is
        // what made every real WebSocket connect attempt get a 500 back.
        assert_eq!(
            bearer_subprotocol("abc123"),
            format!("base64url.bearer.phx.{}", STANDARD_NO_PAD.encode("abc123"))
        );
    }

    #[test]
    fn bearer_subprotocol_round_trips_back_to_the_original_token() {
        let subprotocol = bearer_subprotocol("s3cr3t-t0ken/with+special=chars");
        let encoded = subprotocol
            .strip_prefix("base64url.bearer.phx.")
            .expect("prefix");
        let decoded = STANDARD_NO_PAD.decode(encoded).expect("valid base64");
        assert_eq!(decoded, b"s3cr3t-t0ken/with+special=chars");
    }
}
