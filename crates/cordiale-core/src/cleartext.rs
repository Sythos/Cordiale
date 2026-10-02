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

//! Plain `http://` to a server that isn't this device (issue #201).
//!
//! Over `http://` the password crosses the network in the clear on sign-in,
//! and the bearer token then rides every request and the WebSocket
//! handshake. A loopback server (`localhost`, `127.0.0.0/8`, `::1`) never
//! leaves the machine, so it is fine, and a LAN or development instance is
//! legitimate too: the connect screen warns about cleartext to anything else
//! and asks for an explicit confirmation, it never blocks. The check is
//! purely textual: nothing resolves a name, so a host that merely points at
//! the loopback address still counts as remote.

use reqwest::Url;
use std::net::IpAddr;

/// The `http://host[:port]` origin of `url` when it is plain `http://` to a
/// host that isn't loopback, otherwise `None`. A URL that can't be read, has
/// another scheme or has no scheme at all (the connect screen takes it as
/// `https://`) is not cleartext.
fn cleartext_origin(url: &str) -> Option<String> {
    let url = Url::parse(url.trim()).ok()?;
    if url.scheme() != "http" || is_loopback_host(url.host_str()?) {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

/// Whether a host, as `Url::host_str` writes it (lowercase, an IPv6 address
/// in brackets, an IPv4 address in dotted-quad form), is the loopback
/// interface: `localhost` and any name under it (RFC 6761), `127.0.0.0/8`,
/// `::1`, and the IPv4-mapped `::ffff:127.0.0.0/104`.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
        Err(_) => false,
    }
}

/// Whether `url` is plain `http://` to a host that isn't loopback.
pub fn is_cleartext_remote(url: &str) -> bool {
    cleartext_origin(url).is_some()
}

/// What a sign-in confirmation covers: the cleartext origins of the server
/// URL and of the passkey origin override. Empty when neither is cleartext
/// to a remote host (nothing to confirm); otherwise it changes whenever
/// either of them moves to another scheme, host or port, so a confirmation
/// kept for one key never covers a different server.
pub fn confirmation_key(server_url: &str, passkey_origin: &str) -> String {
    let server = cleartext_origin(server_url);
    let origin = cleartext_origin(passkey_origin);
    if server.is_none() && origin.is_none() {
        return String::new();
    }
    format!(
        "{}|{}",
        server.unwrap_or_default(),
        origin.unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_to_a_remote_host_is_cleartext() {
        for url in [
            "http://irc.example.com",
            "http://irc.example.com/",
            "http://irc.example.com:4000",
            "http://irc.example.com:4000/some/path?x=1",
            "http://192.168.1.20:4000",
            "http://10.0.0.5",
            "http://[2001:db8::1]:4000",
            "http://localhost.example.com",
            "http://notlocalhost",
            "http://128.0.0.1",
        ] {
            assert!(is_cleartext_remote(url), "{url}");
        }
    }

    #[test]
    fn loopback_hosts_are_not_flagged() {
        for url in [
            "http://localhost",
            "http://localhost:4000",
            "http://localhost./",
            "http://LOCALHOST:4000",
            "http://127.0.0.1",
            "http://127.0.0.1:4000/x",
            "http://127.1.2.3",
            "http://127.255.255.255:80",
            "http://[::1]",
            "http://[::1]:4000",
            "http://[::ffff:127.0.0.1]:4000",
            "http://grappa.localhost",
            "http://a.b.localhost:4000",
        ] {
            assert!(!is_cleartext_remote(url), "{url}");
        }
    }

    #[test]
    fn https_and_other_schemes_are_not_flagged() {
        for url in [
            "https://irc.example.com",
            "https://192.168.1.20:4000",
            "https://localhost:4000",
            "ws://irc.example.com",
            "wss://irc.example.com",
            "ftp://irc.example.com",
        ] {
            assert!(!is_cleartext_remote(url), "{url}");
        }
    }

    #[test]
    fn scheme_and_host_case_do_not_matter() {
        assert!(is_cleartext_remote("HTTP://Irc.Example.COM"));
        assert!(is_cleartext_remote("Http://irc.example.com:4000"));
        assert!(!is_cleartext_remote("HTTP://LocalHost:4000"));
        assert!(!is_cleartext_remote("HTTPS://irc.example.com"));
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        assert!(is_cleartext_remote("  http://irc.example.com \n"));
        assert!(!is_cleartext_remote("  http://localhost:4000  "));
    }

    #[test]
    fn userinfo_does_not_hide_the_real_host() {
        assert!(is_cleartext_remote("http://user:pw@irc.example.com"));
        assert!(is_cleartext_remote("http://localhost@irc.example.com"));
        assert!(is_cleartext_remote("http://127.0.0.1:80@irc.example.com"));
        assert!(!is_cleartext_remote("http://user:pw@localhost:4000"));
        assert!(!is_cleartext_remote("http://irc.example.com@127.0.0.1"));
    }

    #[test]
    fn a_url_without_a_scheme_or_unreadable_is_not_flagged() {
        for url in [
            "",
            "   ",
            "irc.example.com",
            "localhost:4000",
            "//irc.example.com",
            "http://",
            "http://exa mple.com",
            "not a url",
            "http",
            "://",
        ] {
            assert!(!is_cleartext_remote(url), "{url:?}");
        }
    }

    #[test]
    fn key_is_empty_when_there_is_nothing_to_confirm() {
        assert_eq!(confirmation_key("https://irc.example.com", ""), "");
        assert_eq!(
            confirmation_key("http://localhost:4000", "http://127.0.0.1:5173"),
            ""
        );
        assert_eq!(confirmation_key("", ""), "");
    }

    #[test]
    fn key_follows_the_server_url_and_ignores_spelling() {
        let key = confirmation_key("http://irc.example.com:4000", "");
        assert!(!key.is_empty());
        for same in [
            "http://irc.example.com:4000/",
            " HTTP://IRC.example.com:4000 ",
            "http://irc.example.com:4000/path?q=1",
            "http://user@irc.example.com:4000",
        ] {
            assert_eq!(confirmation_key(same, ""), key, "{same}");
        }
        for other in [
            "http://irc.example.com",
            "http://irc.example.com:4001",
            "http://irc.example.org:4000",
        ] {
            assert_ne!(confirmation_key(other, ""), key, "{other}");
        }
        // The default port is the same origin.
        assert_eq!(
            confirmation_key("http://irc.example.com:80", ""),
            confirmation_key("http://irc.example.com", "")
        );
    }

    #[test]
    fn key_also_covers_a_cleartext_passkey_origin() {
        let server_only = confirmation_key("http://irc.example.com", "");
        let with_origin = confirmation_key("http://irc.example.com", "http://auth.example.com");
        assert_ne!(server_only, with_origin);
        // An https server with a cleartext override still needs a confirmation.
        let origin_only = confirmation_key("https://irc.example.com", "http://auth.example.com/");
        assert!(!origin_only.is_empty());
        assert_ne!(origin_only, server_only);
        // A loopback override on a cleartext server adds nothing.
        assert_eq!(
            confirmation_key("http://irc.example.com", "http://localhost:5173"),
            server_only
        );
    }
}
