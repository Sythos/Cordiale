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

//! Channel invite links, `https://<server>/?go=<network>/<channel>`, as
//! Cicchetto builds them. This module holds the pure parts: the link
//! parser, the check that the link names the server of the signed-in
//! profile, and the decisions of the flow. `main.rs` owns the REST calls.
//!
//! The link is only data. Cordiale never contacts the host of a link: every
//! request goes to the server of the profile, and a link for another server
//! is refused before any request is made.

use cordiale_core::rest::MeResponse;

use crate::reconnect_join::needs_reconnect;

/// The network and the channel a link points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InviteTarget {
    pub(crate) network: String,
    pub(crate) channel: String,
}

/// An invite that waits for the user to accept the JOIN. It remembers the
/// session it was made for, so an account or server change drops it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PendingInvite {
    pub(crate) target: InviteTarget,
    pub(crate) token: String,
    pub(crate) base_url: String,
}

/// The token never reaches a log.
impl std::fmt::Debug for PendingInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingInvite")
            .field("target", &self.target)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Why a link is refused. The key is a status key for the home page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InviteError {
    /// Not an HTTP(S) link with exactly one valid `go` value.
    Invalid,
    /// A valid link for another server than the one of the profile.
    WrongServer,
}

impl InviteError {
    pub(crate) fn key(self) -> &'static str {
        match self {
            InviteError::Invalid => "invite-invalid",
            InviteError::WrongServer => "invite-wrong-server",
        }
    }
}

const MAX_NETWORK_LEN: usize = 64;
const MAX_CHANNEL_LEN: usize = 200;

/// Scheme, lower-case host and port of an HTTP(S) URL. A user-info part,
/// a backslash or a control character makes the URL invalid.
fn origin(url: &str) -> Option<(String, String, u16)> {
    if url.chars().any(|c| c.is_control() || c == '\\') {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port_text) = if let Some(inner) = authority.strip_prefix('[') {
        let close = inner.find(']')?;
        let after = &inner[close + 1..];
        let port_text = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        (format!("[{}]", &inner[..close]), port_text)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':'))
    {
        return None;
    }
    let port = match port_text {
        None => default_port,
        Some(text) => text.parse::<u16>().ok().filter(|port| *port != 0)?,
    };
    Some((scheme, host.to_ascii_lowercase(), port))
}

/// Decodes `%XX` once. A bad escape or bytes that are not UTF-8 fail.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = text.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(pair, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn valid_network(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= MAX_NETWORK_LEN
        && slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn valid_channel(name: &str) -> bool {
    cordiale_core::slash::is_channel(name)
        && !cordiale_core::slash::is_prefix_only_channel(name)
        && name.len() <= MAX_CHANNEL_LEN
        && !name
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ',')
}

/// Reads one invite link. `server_base_url` is the server of the signed-in
/// profile: the link must name the same scheme, host and port.
pub(crate) fn parse_invite(link: &str, server_base_url: &str) -> Result<InviteTarget, InviteError> {
    let link = link.trim();
    let link_origin = origin(link).ok_or(InviteError::Invalid)?;
    let query_start = link.find('?').ok_or(InviteError::Invalid)?;
    if link.find('#').is_some_and(|hash| hash < query_start) {
        return Err(InviteError::Invalid);
    }
    let after = &link[query_start + 1..];
    let query = after.split('#').next().unwrap_or("");
    // One part only: extra parameters make the link ambiguous.
    if query.contains('&') {
        return Err(InviteError::Invalid);
    }
    let raw = query.strip_prefix("go=").ok_or(InviteError::Invalid)?;
    let value = percent_decode(raw).ok_or(InviteError::Invalid)?;
    if value.chars().any(char::is_control) {
        return Err(InviteError::Invalid);
    }
    let (network, channel) = value.split_once('/').ok_or(InviteError::Invalid)?;
    if !valid_network(network) || !valid_channel(channel) || channel.contains('/') {
        return Err(InviteError::Invalid);
    }
    if origin(server_base_url).as_ref() != Some(&link_origin) {
        return Err(InviteError::WrongServer);
    }
    Ok(InviteTarget {
        network: network.to_string(),
        channel: channel.to_string(),
    })
}

/// What the trusted `GET /me` says about the network of an invite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkAccess {
    /// Attached to the session. `parked` is true when it is parked or
    /// failed.
    Attached { parked: bool },
    /// The user can attach it with one request.
    Available,
    /// Not in either list: unknown, or not allowed for this user.
    Unknown,
}

pub(crate) fn network_access(me: &MeResponse, network: &str) -> NetworkAccess {
    let Some(home) = &me.home_data else {
        return NetworkAccess::Unknown;
    };
    if let Some(row) = home.networks.iter().find(|row| row.slug == network) {
        let parked = needs_reconnect(&row.connection_state);
        return NetworkAccess::Attached { parked };
    }
    if home
        .available_networks
        .iter()
        .any(|row| row.slug == network)
    {
        return NetworkAccess::Available;
    }
    NetworkAccess::Unknown
}

/// The next step of the flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InviteStep {
    /// Open the channel. No question, no JOIN.
    Select,
    /// Ask the user to join. No JOIN before the answer.
    AskJoin,
    /// Send one attach request.
    Attach,
    /// The network is parked or failed: ask once, then reconnect and join.
    AskReconnect,
    /// Same error for an unknown network and one the user cannot attach.
    Unavailable,
}

/// Decides from a fresh read of `/me`.
pub(crate) fn plan(access: NetworkAccess, joined: bool) -> InviteStep {
    match access {
        NetworkAccess::Attached { parked: true } => InviteStep::AskReconnect,
        NetworkAccess::Attached { parked: false } if joined => InviteStep::Select,
        NetworkAccess::Attached { parked: false } => InviteStep::AskJoin,
        NetworkAccess::Available => InviteStep::Attach,
        NetworkAccess::Unknown => InviteStep::Unavailable,
    }
}

/// What to do with the answer of the attach request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttachNext {
    /// Read `/me` again: attached now, or already attached (a race).
    Reread,
    /// Show this status key.
    Refused(&'static str),
}

/// A refusal is its HTTP status (`None` for a failure without one) and the
/// `error` code of its body. `409 already_attached` is a race, not an
/// error. A code that Grappa sends for an attach shows its reason. The code
/// itself is never shown: any other one gets the message of its status.
/// `network_not_visitor_enabled` and `not_found` mean "not available".
pub(crate) fn attach_next(result: Result<(), (Option<u16>, Option<&str>)>) -> AttachNext {
    let Err((status, code)) = result else {
        return AttachNext::Reread;
    };
    if status == Some(409) {
        return AttachNext::Reread;
    }
    AttachNext::Refused(match (code, status) {
        // The limit of this source address.
        (Some("too_many_sessions"), _) => "invite-attach-sessions",
        // The limit of the network, for all accounts.
        (Some("network_busy"), _) => "invite-attach-full",
        (Some("network_unreachable" | "upstream_unreachable"), _) => "invite-attach-unreachable",
        (Some("network_unconfigured" | "session_plan_resolve_failed"), _) => {
            "invite-attach-unconfigured"
        }
        (Some("validation_failed"), _) => "invite-attach-settings",
        (Some("db_unavailable"), _) => "invite-attach-server-busy",
        (Some("rate_limited"), _) => "invite-attach-rate-limited",
        (_, Some(400..=499)) => "invite-unavailable",
        _ => "invite-attach-failed",
    })
}

/// The step after the second read of `/me`. The network must be present;
/// otherwise the user can try again, which starts with a new read.
pub(crate) fn after_attach_read(
    access: NetworkAccess,
    joined: bool,
) -> Result<InviteStep, &'static str> {
    match access {
        NetworkAccess::Attached { .. } => Ok(plan(access, joined)),
        _ => Err("invite-not-ready"),
    }
}

/// Whether a result for `token` on `base_url` still belongs to the session
/// that is signed in. A logout, an account change or a server change
/// makes the invite stop.
pub(crate) fn same_session(
    current_token: Option<&str>,
    current_base_url: Option<&str>,
    token: &str,
    base_url: &str,
) -> bool {
    current_token == Some(token) && current_base_url == Some(base_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordiale_core::rest::{AvailableNetworkRow, HomeData, HomeNetworkRow};

    const SERVER: &str = "https://chat.example.org";

    fn ok(link: &str) -> InviteTarget {
        parse_invite(link, SERVER).expect("valid link")
    }

    fn err(link: &str) -> InviteError {
        parse_invite(link, SERVER).expect_err("invalid link")
    }

    #[test]
    fn parses_an_encoded_channel() {
        let target = ok("https://chat.example.org/?go=libera/%23cordiale");
        assert_eq!(target.network, "libera");
        assert_eq!(target.channel, "#cordiale");
    }

    #[test]
    fn parses_with_path_port_case_and_spaces() {
        let target = ok("  HTTPS://Chat.Example.ORG:443/app/?go=oftc/%26ops#x ");
        assert_eq!(target.network, "oftc");
        assert_eq!(target.channel, "&ops");
        let local = parse_invite(
            "http://127.0.0.1:4000/?go=net/%23a",
            "http://127.0.0.1:4000/api",
        )
        .expect("local");
        assert_eq!(local.channel, "#a");
    }

    #[test]
    fn decodes_the_query_only_once() {
        let target = ok("https://chat.example.org/?go=libera/%23a%2541");
        assert_eq!(target.channel, "#a%41");
    }

    #[test]
    fn refuses_bad_links() {
        for link in [
            "",
            "libera/#a",
            "ftp://chat.example.org/?go=libera/%23a",
            "https://chat.example.org/",
            "https://chat.example.org/?go=",
            "https://chat.example.org/?go=libera",
            "https://chat.example.org/?go=libera/",
            "https://chat.example.org/?go=libera/chan",
            "https://chat.example.org/?go=libera/%23",
            "https://chat.example.org/?go=libera/#a",
            "https://chat.example.org/?go=/%23a",
            "https://chat.example.org/?go=bad%20net/%23a",
            "https://chat.example.org/?go=libera/%23a%2Cb",
            "https://chat.example.org/?go=libera/%23a%20b",
            "https://chat.example.org/?go=libera/%23a/b",
            "https://chat.example.org/?go=libera/%23a%00",
            "https://chat.example.org/?go=libera/%23a%0D%0AJOIN",
            "https://chat.example.org/?go=libera/%23a%07",
            "https://chat.example.org/?go=libera/%23a%zz",
            "https://chat.example.org/?go=libera/%23a%ff",
            "https://chat.example.org/#x?go=libera/%23a",
            "https://chat.example.org/?go=libera/%23a&go=oftc/%23b",
            "https://chat.example.org/?go=libera/%23a&x=1",
            "https://chat.example.org/?x=1&go=libera/%23a",
            "https://chat.example.org/?other=libera/%23a",
            "https://user@chat.example.org/?go=libera/%23a",
            "https://chat.example.org\\@evil.test/?go=libera/%23a",
            "https://chat.example.org:99999/?go=libera/%23a",
            "https://:443/?go=libera/%23a",
        ] {
            assert_eq!(err(link), InviteError::Invalid, "{link}");
        }
    }

    #[test]
    fn refuses_a_link_with_a_control_character() {
        assert_eq!(
            err("https://chat.example.org/?go=libera/%23a\u{7}"),
            InviteError::Invalid
        );
        assert_eq!(
            err("https://chat.exa\tmple.org/?go=libera/%23a"),
            InviteError::Invalid
        );
    }

    #[test]
    fn refuses_another_server() {
        for link in [
            "https://evil.test/?go=libera/%23a",
            "http://chat.example.org/?go=libera/%23a",
            "https://chat.example.org:8443/?go=libera/%23a",
            "https://chat.example.org.evil.test/?go=libera/%23a",
        ] {
            assert_eq!(err(link), InviteError::WrongServer, "{link}");
        }
        assert_eq!(
            parse_invite("https://chat.example.org/?go=libera/%23a", "not a url"),
            Err(InviteError::WrongServer)
        );
    }

    #[test]
    fn error_keys_differ() {
        assert_eq!(InviteError::Invalid.key(), "invite-invalid");
        assert_eq!(InviteError::WrongServer.key(), "invite-wrong-server");
    }

    fn me_with(networks: &[(&str, &str)], available: &[&str]) -> MeResponse {
        MeResponse {
            read_cursors: serde_json::json!({}),
            unread_counts: serde_json::json!({}),
            badge_count: serde_json::json!(0),
            is_admin: false,
            kind: None,
            id: None,
            name: None,
            registered: None,
            home_data: Some(HomeData {
                networks: networks
                    .iter()
                    .map(|(slug, state)| HomeNetworkRow {
                        slug: (*slug).to_string(),
                        connection_state: (*state).to_string(),
                        ..HomeNetworkRow::default()
                    })
                    .collect(),
                available_networks: available
                    .iter()
                    .map(|slug| AvailableNetworkRow {
                        slug: (*slug).to_string(),
                    })
                    .collect(),
            }),
        }
    }

    #[test]
    fn reads_the_access_from_me() {
        let me = me_with(
            &[
                ("libera", "connected"),
                ("oftc", "parked"),
                ("efnet", "failed"),
                ("ircnet", "failing"),
                ("old", ""),
            ],
            &["rizon"],
        );
        assert_eq!(
            network_access(&me, "libera"),
            NetworkAccess::Attached { parked: false }
        );
        assert_eq!(
            network_access(&me, "oftc"),
            NetworkAccess::Attached { parked: true }
        );
        assert_eq!(
            network_access(&me, "efnet"),
            NetworkAccess::Attached { parked: true }
        );
        // A failing network keeps its session.
        for live in ["ircnet", "old"] {
            assert_eq!(
                network_access(&me, live),
                NetworkAccess::Attached { parked: false },
                "{live}"
            );
        }
        assert_eq!(network_access(&me, "rizon"), NetworkAccess::Available);
        assert_eq!(network_access(&me, "nope"), NetworkAccess::Unknown);
        let mut empty = me_with(&[], &[]);
        empty.home_data = None;
        assert_eq!(network_access(&empty, "libera"), NetworkAccess::Unknown);
    }

    #[test]
    fn plans_every_branch() {
        let live = NetworkAccess::Attached { parked: false };
        let parked = NetworkAccess::Attached { parked: true };
        // Connected and joined: select, no dialog, no JOIN.
        assert_eq!(plan(live, true), InviteStep::Select);
        // Connected, not joined: ask first.
        assert_eq!(plan(live, false), InviteStep::AskJoin);
        // Parked: ask to reconnect and join, even when joined.
        assert_eq!(plan(parked, true), InviteStep::AskReconnect);
        assert_eq!(plan(parked, false), InviteStep::AskReconnect);
        // Available: one attach request, no dialog.
        assert_eq!(plan(NetworkAccess::Available, false), InviteStep::Attach);
        // Unknown or not allowed: one error.
        assert_eq!(plan(NetworkAccess::Unknown, false), InviteStep::Unavailable);
    }

    #[test]
    fn attach_answers() {
        assert_eq!(attach_next(Ok(())), AttachNext::Reread);
        // The race: another client attached first.
        assert_eq!(
            attach_next(Err((Some(409), Some("already_attached")))),
            AttachNext::Reread
        );
        // Denied, unknown or invalid, with no known reason: one message.
        for status in [400, 401, 403, 404, 422] {
            for code in [None, Some("new_reason"), Some("not_found")] {
                assert_eq!(
                    attach_next(Err((Some(status), code))),
                    AttachNext::Refused("invite-unavailable")
                );
            }
        }
        for failure in [
            (Some(500), None),
            (Some(503), Some("new_reason")),
            (None, None),
        ] {
            assert_eq!(
                attach_next(Err(failure)),
                AttachNext::Refused("invite-attach-failed")
            );
        }
    }

    #[test]
    fn a_known_attach_reason_has_its_own_message() {
        for (status, code, key) in [
            (503, "too_many_sessions", "invite-attach-sessions"),
            (503, "network_busy", "invite-attach-full"),
            (503, "network_unreachable", "invite-attach-unreachable"),
            (502, "upstream_unreachable", "invite-attach-unreachable"),
            (503, "network_unconfigured", "invite-attach-unconfigured"),
            (
                500,
                "session_plan_resolve_failed",
                "invite-attach-unconfigured",
            ),
            (422, "validation_failed", "invite-attach-settings"),
            (503, "db_unavailable", "invite-attach-server-busy"),
            (429, "rate_limited", "invite-attach-rate-limited"),
            (403, "network_not_visitor_enabled", "invite-unavailable"),
        ] {
            assert_eq!(
                attach_next(Err((Some(status), Some(code)))),
                AttachNext::Refused(key),
                "{code}"
            );
        }
    }

    #[test]
    fn the_second_read_must_show_the_network() {
        let live = NetworkAccess::Attached { parked: false };
        assert_eq!(after_attach_read(live, false), Ok(InviteStep::AskJoin));
        assert_eq!(after_attach_read(live, true), Ok(InviteStep::Select));
        assert_eq!(
            after_attach_read(NetworkAccess::Attached { parked: true }, false),
            Ok(InviteStep::AskReconnect)
        );
        assert_eq!(
            after_attach_read(NetworkAccess::Available, false),
            Err("invite-not-ready")
        );
        assert_eq!(
            after_attach_read(NetworkAccess::Unknown, false),
            Err("invite-not-ready")
        );
    }

    #[test]
    fn an_account_or_server_change_stops_the_invite() {
        let same = same_session(Some("tok"), Some(SERVER), "tok", SERVER);
        assert!(same);
        // Logout.
        assert!(!same_session(None, None, "tok", SERVER));
        // Another account.
        assert!(!same_session(Some("other"), Some(SERVER), "tok", SERVER));
        // Another server.
        assert!(!same_session(
            Some("tok"),
            Some("https://other.test"),
            "tok",
            SERVER
        ));
    }
}
