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

//! The WebAuthn origin Cordiale puts in `clientDataJSON` (issue #163).
//!
//! Grappa binds every passkey ceremony to one exact origin string: the
//! operator's `GRAPPA_PASSKEY_ORIGIN` when set, otherwise the endpoint's
//! public URL. Wax compares the client data's origin to it character by
//! character and the authenticator's RP ID hash to the origin's host. The
//! options Grappa sends carry only the RP ID and `/api/config` does not
//! expose the origin, so a native client rebuilds it from the URL it
//! connected to, or from a per-server override the user types in when the
//! server sets its own. A wrong origin comes back as an opaque
//! `401 invalid_two_factor`.

use reqwest::Url;

/// What the per-server override field holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideCheck {
    /// Empty or blank: no override, the origin is rebuilt from the URL.
    Unset,
    /// A well-formed origin (`http(s)://host[:port]`, no path, query or
    /// credentials), trimmed and without a trailing slash, otherwise exactly
    /// as typed: the server compares its own string verbatim, so a literal
    /// copy of `GRAPPA_PASSKEY_ORIGIN` must survive unchanged.
    Valid(String),
    /// Something that can't be an origin.
    Invalid,
}

/// Validates the text of the override field.
pub fn check_override(input: &str) -> OverrideCheck {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return OverrideCheck::Unset;
    }
    let origin = trimmed.trim_end_matches('/');
    if origin.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return OverrideCheck::Invalid;
    }
    let Some((_, authority)) = origin.split_once("://") else {
        return OverrideCheck::Invalid;
    };
    if authority.is_empty() || authority.contains(['/', '?', '#', '@', '\\']) {
        return OverrideCheck::Invalid;
    }
    match Url::parse(origin) {
        Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => {
            OverrideCheck::Valid(origin.to_string())
        }
        _ => OverrideCheck::Invalid,
    }
}

/// The origin string to put in `clientDataJSON` for a ceremony with the
/// server at `server_url`.
///
/// A valid `override_origin` wins as typed (see `OverrideCheck::Valid`); a
/// blank or invalid one is ignored. Otherwise the origin is the server
/// URL's scheme, host and port the way a browser writes it: host in
/// lowercase, a default port (443 for https, 80 for http) dropped, any
/// other port kept, an IPv6 host in brackets, and no path, query or
/// credentials. A URL without a scheme is taken as https, like the
/// connect screen does. A URL that can't be read comes back trimmed and
/// without trailing slashes, so the server refuses it instead of this
/// function guessing.
pub fn passkey_origin(server_url: &str, override_origin: Option<&str>) -> String {
    if let Some(OverrideCheck::Valid(origin)) = override_origin.map(check_override) {
        return origin;
    }
    let trimmed = server_url.trim();
    match parse_lenient(trimmed) {
        Some(url) => {
            let scheme = url.scheme();
            let host = url.host_str().unwrap_or_default();
            match url.port() {
                Some(port) => format!("{scheme}://{host}:{port}"),
                None => format!("{scheme}://{host}"),
            }
        }
        None => trimmed.trim_end_matches('/').to_string(),
    }
}

/// The RP ID of an origin: its host in lowercase, without the brackets of
/// an IPv6 address (the way Grappa derives it from the origin). Empty when
/// `origin` has no host.
pub fn rp_id(origin: &str) -> String {
    parse_lenient(origin.trim())
        .and_then(|url| {
            url.host_str()
                .map(|host| host.trim_matches(['[', ']']).to_string())
        })
        .unwrap_or_default()
}

/// Parses a URL that may lack its scheme, requiring a host.
fn parse_lenient(input: &str) -> Option<Url> {
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("https://{input}")
    };
    Url::parse(&with_scheme)
        .ok()
        .filter(|url| url.host_str().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(server_url: &str) -> String {
        passkey_origin(server_url, None)
    }

    #[test]
    fn https_server_gives_scheme_and_host() {
        assert_eq!(origin("https://irc.sindro.me"), "https://irc.sindro.me");
    }

    #[test]
    fn http_server_keeps_its_scheme() {
        assert_eq!(origin("http://grappa.lan"), "http://grappa.lan");
    }

    #[test]
    fn default_ports_are_dropped() {
        assert_eq!(origin("https://irc.sindro.me:443"), "https://irc.sindro.me");
        assert_eq!(origin("http://grappa.lan:80"), "http://grappa.lan");
    }

    #[test]
    fn other_ports_are_kept() {
        assert_eq!(
            origin("https://irc.sindro.me:8443"),
            "https://irc.sindro.me:8443"
        );
        assert_eq!(origin("http://localhost:4000"), "http://localhost:4000");
        assert_eq!(origin("http://grappa.lan:443"), "http://grappa.lan:443");
        assert_eq!(
            origin("https://irc.sindro.me:80"),
            "https://irc.sindro.me:80"
        );
    }

    #[test]
    fn scheme_and_host_are_lowercased() {
        assert_eq!(origin("HTTPS://IRC.Sindro.ME/"), "https://irc.sindro.me");
    }

    #[test]
    fn trailing_slash_and_path_are_removed() {
        assert_eq!(origin("https://irc.sindro.me/"), "https://irc.sindro.me");
        assert_eq!(origin("https://irc.sindro.me//"), "https://irc.sindro.me");
        assert_eq!(
            origin("https://irc.sindro.me/grappa/app?x=1#top"),
            "https://irc.sindro.me"
        );
        assert_eq!(
            origin("http://localhost:4000/api/"),
            "http://localhost:4000"
        );
    }

    #[test]
    fn credentials_never_reach_the_origin() {
        assert_eq!(
            origin("https://vjt@irc.sindro.me:8443/"),
            "https://irc.sindro.me:8443"
        );
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        assert_eq!(
            origin("  https://irc.sindro.me/ \n"),
            "https://irc.sindro.me"
        );
    }

    #[test]
    fn missing_scheme_is_https() {
        assert_eq!(origin("irc.sindro.me"), "https://irc.sindro.me");
        assert_eq!(origin("localhost:5173"), "https://localhost:5173");
    }

    #[test]
    fn ipv6_hosts_keep_their_brackets() {
        assert_eq!(origin("http://[::1]:4000/"), "http://[::1]:4000");
        assert_eq!(origin("http://[::1]:80"), "http://[::1]");
        assert_eq!(
            origin("https://[2001:DB8::1]:8443"),
            "https://[2001:db8::1]:8443"
        );
    }

    #[test]
    fn ipv4_hosts_work() {
        assert_eq!(
            origin("http://192.168.1.10:4000"),
            "http://192.168.1.10:4000"
        );
    }

    #[test]
    fn unreadable_urls_come_back_trimmed_so_the_server_refuses_them() {
        assert_eq!(origin(""), "");
        assert_eq!(origin("   "), "");
        assert_eq!(origin("https://exa mple.com/"), "https://exa mple.com");
        assert_eq!(origin("https://host:99999"), "https://host:99999");
    }

    #[test]
    fn a_valid_override_wins_over_the_server_url() {
        assert_eq!(
            passkey_origin("https://irc.sindro.me", Some("http://localhost:5173")),
            "http://localhost:5173"
        );
    }

    #[test]
    fn an_override_is_trimmed_and_loses_its_trailing_slash() {
        assert_eq!(
            passkey_origin("https://a.example", Some("  https://b.example:8443/  ")),
            "https://b.example:8443"
        );
    }

    #[test]
    fn an_override_is_kept_as_typed() {
        assert_eq!(
            passkey_origin("https://a.example", Some("https://b.example:443")),
            "https://b.example:443"
        );
    }

    #[test]
    fn a_blank_or_invalid_override_is_ignored() {
        for bad in [
            "",
            "   ",
            "b.example",
            "ftp://b.example",
            "https://b.example/path",
            "https://b.example?x=1",
            "https://b.example#top",
            "https://user@b.example",
            "https://",
            "https://b .example",
            "https://b.example:99999",
            "https://b.example\nhttps://c.example",
        ] {
            assert_eq!(
                passkey_origin("https://a.example", Some(bad)),
                "https://a.example",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn override_check_tells_unset_valid_and_invalid_apart() {
        assert_eq!(check_override(""), OverrideCheck::Unset);
        assert_eq!(check_override("  \t "), OverrideCheck::Unset);
        assert_eq!(
            check_override(" https://b.example/ "),
            OverrideCheck::Valid("https://b.example".to_string())
        );
        assert_eq!(
            check_override("http://[::1]:4000"),
            OverrideCheck::Valid("http://[::1]:4000".to_string())
        );
        assert_eq!(check_override("b.example"), OverrideCheck::Invalid);
        assert_eq!(
            check_override("https://b.example/x"),
            OverrideCheck::Invalid
        );
        assert_eq!(check_override("/"), OverrideCheck::Invalid);
    }

    #[test]
    fn rp_id_is_the_host_of_the_origin() {
        assert_eq!(rp_id("https://irc.sindro.me"), "irc.sindro.me");
        assert_eq!(rp_id("https://irc.sindro.me:8443"), "irc.sindro.me");
        assert_eq!(rp_id("http://localhost:5173"), "localhost");
        assert_eq!(rp_id("HTTPS://IRC.Sindro.ME"), "irc.sindro.me");
        assert_eq!(rp_id("https://irc.sindro.me/"), "irc.sindro.me");
    }

    #[test]
    fn rp_id_of_an_ipv6_origin_has_no_brackets() {
        assert_eq!(rp_id("http://[::1]:4000"), "::1");
        assert_eq!(rp_id("https://[2001:DB8::1]"), "2001:db8::1");
    }

    #[test]
    fn rp_id_of_nothing_useful_is_empty() {
        assert_eq!(rp_id(""), "");
        assert_eq!(rp_id("https://"), "");
        assert_eq!(rp_id("https://exa mple.com"), "");
    }

    #[test]
    fn the_rp_id_follows_the_override() {
        let server = "https://irc.sindro.me";
        let used = passkey_origin(server, Some("https://auth.sindro.me"));
        assert_eq!(rp_id(&used), "auth.sindro.me");
        assert_eq!(rp_id(&passkey_origin(server, None)), "irc.sindro.me");
    }
}
