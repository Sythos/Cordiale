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
//! writing this — see the networking architecture note in `MEMORY.md`), so
//! this wraps a plain WebSocket connection and speaks the wire format from
//! `crate::phoenix` over it. Plain `async fn`s only: no runtime is started
//! here, `cordiale-ui` owns that (see `MEMORY.md`).
//!
//! Not yet exercised against a real or mocked Phoenix server — only the
//! parts that don't need an actual socket (the handshake header) are unit
//! tested here.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::phoenix::PhoenixMessage;

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
    /// Connects to `ws_url` (include `?client_proto=...` in it if Cordiale
    /// wants to declare a version — omitted means "current", the
    /// zero-friction path per the protocol notes).
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
