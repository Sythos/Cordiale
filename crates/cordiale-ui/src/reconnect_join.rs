// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)
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

//! A `JOIN` on a network that is not connected: invite links, `/join` and
//! the featured channels of the home page ask one question, and only a yes
//! reconnects and joins. This module holds the pure parts; `main.rs` owns
//! the question and the task that sends the requests.

use std::time::Duration;

use cordiale_core::client::{JoinRetry, ReconnectJoinError};

/// How long a `JOIN` waits for the network to register: about 30 seconds.
pub(crate) const JOIN_RETRY: JoinRetry = JoinRetry {
    attempts: 16,
    delay: Duration::from_secs(2),
};

/// Whether a network in `connection_state` must reconnect before a `JOIN`.
pub(crate) fn needs_reconnect(connection_state: &str) -> bool {
    matches!(connection_state, "parked" | "failed" | "failing")
}

/// Where the `JOIN` was asked, which decides where its result shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JoinOrigin {
    Invite,
    /// `/join`: the server events open the window, as without a reconnect.
    Command,
    Featured,
}

/// A `JOIN` that waits for the user to accept the reconnect. It remembers
/// the session it was made for, so an account or server change drops it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PendingReconnectJoin {
    pub(crate) network: String,
    /// One channel, or the comma-separated list of `/join`.
    pub(crate) channels: String,
    pub(crate) key: Option<String>,
    pub(crate) origin: JoinOrigin,
    pub(crate) token: String,
    pub(crate) base_url: String,
}

/// The token and the channel key never reach a log.
impl std::fmt::Debug for PendingReconnectJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingReconnectJoin")
            .field("network", &self.network)
            .field("channels", &self.channels)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// How an accepted reconnect and `JOIN` ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconnectJoinOutcome {
    Joined,
    /// No `JOIN` went out.
    ReconnectFailed,
    /// The network did not register in time. The user can try again.
    StillConnecting,
    InvalidChannel,
    JoinFailed,
}

pub(crate) fn outcome(result: &Result<(), ReconnectJoinError>) -> ReconnectJoinOutcome {
    match result {
        Ok(()) => ReconnectJoinOutcome::Joined,
        Err(ReconnectJoinError::Reconnect(_)) => ReconnectJoinOutcome::ReconnectFailed,
        Err(ReconnectJoinError::Join(err)) if err.is_not_registered() => {
            ReconnectJoinOutcome::StillConnecting
        }
        Err(ReconnectJoinError::Join(err)) if err.code() == Some("invalid_channel") => {
            ReconnectJoinOutcome::InvalidChannel
        }
        Err(ReconnectJoinError::Join(_)) => ReconnectJoinOutcome::JoinFailed,
    }
}

/// Stops its task when dropped, so a logout or a new sign-in ends the
/// retries of the old session.
#[derive(Debug)]
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordiale_core::client::{GrappaClientError, StatusCode};

    fn refused(status: u16, code: &str) -> GrappaClientError {
        GrappaClientError::Rejected {
            status: StatusCode::from_u16(status).expect("status"),
            code: Some(code.to_string()),
            retry_after: None,
        }
    }

    #[test]
    fn only_a_network_that_is_not_connected_needs_a_reconnect() {
        for state in ["parked", "failed", "failing"] {
            assert!(needs_reconnect(state), "{state}");
        }
        for state in ["connected", ""] {
            assert!(!needs_reconnect(state), "{state}");
        }
    }

    #[test]
    fn each_result_has_its_outcome() {
        assert_eq!(outcome(&Ok(())), ReconnectJoinOutcome::Joined);
        assert_eq!(
            outcome(&Err(ReconnectJoinError::Reconnect(refused(
                503,
                "not_registered"
            )))),
            ReconnectJoinOutcome::ReconnectFailed
        );
        for (status, code, expected) in [
            (503, "not_registered", ReconnectJoinOutcome::StillConnecting),
            (422, "invalid_channel", ReconnectJoinOutcome::InvalidChannel),
            (503, "db_unavailable", ReconnectJoinOutcome::JoinFailed),
        ] {
            let result = Err(ReconnectJoinError::Join(refused(status, code)));
            assert_eq!(outcome(&result), expected, "{code}");
        }
    }

    #[test]
    fn debug_output_hides_the_token_and_the_key() {
        let secret = format!("secret-{}", std::process::id());
        let pending = PendingReconnectJoin {
            network: "libera".to_string(),
            channels: "#grappa".to_string(),
            key: Some(secret.clone()),
            origin: JoinOrigin::Command,
            token: secret.clone(),
            base_url: "https://grappa.example".to_string(),
        };
        assert!(!format!("{pending:?}").contains(&secret));
    }
}
