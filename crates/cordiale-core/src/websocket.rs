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

/// Builds the `Sec-WebSocket-Protocol` value Grappa expects for
/// authentication, per `docs/protocol-notes.md` §2: the bearer travels in
/// this header, never in the URL, so it stays out of access logs.
fn bearer_subprotocol(token: &str) -> String {
    format!("base64url.bearer.phx.{token}")
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

        let subprotocol = bearer_subprotocol(bearer_token);
        request.headers_mut().insert(
            HeaderName::from_static("sec-websocket-protocol"),
            HeaderValue::from_str(&subprotocol)
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
    fn bearer_subprotocol_has_the_documented_shape() {
        assert_eq!(bearer_subprotocol("abc123"), "base64url.bearer.phx.abc123");
    }
}
