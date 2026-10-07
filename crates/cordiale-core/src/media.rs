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

//! Links in chat text and what a click on one opens, following Cicchetto:
//! scrollback stays text (no inline previews); a click on an image or text
//! upload, or on an https image elsewhere, opens the in-app viewer, and
//! anything else goes to the browser.

use std::error::Error as _;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;

/// A link found in a message: where its text is, and the URL to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub range: Range<usize>,
    pub href: String,
}

/// Links in `text`, as Cicchetto's linkify finds them: `http://`,
/// `https://` and `ftp://` URLs, `www.` hosts, and bare `host.tld/path`
/// (the slash is required, so `node.js` or a version number never
/// links). Trailing punctuation is left out, except a `)` that closes a
/// `(` inside the URL; a scheme-less match gets `https://`.
pub fn find_links(text: &str) -> Vec<Link> {
    let mut links = Vec::new();
    for (start, token) in tokens(text) {
        // Wrapping punctuation before the link, like "(see" or "<http".
        let lead = token.len()
            - token
                .trim_start_matches(['(', '[', '{', '<', '"', '\''])
                .len();
        let candidate = &token[lead..];
        // `<`, `>` and `"` never belong to a URL here.
        let candidate = candidate.split(['<', '>', '"']).next().unwrap_or_default();
        let candidate = trim_trailing(candidate);
        let lower = candidate.to_ascii_lowercase();
        let with_scheme = ["http://", "https://", "ftp://"]
            .iter()
            .any(|scheme| lower.starts_with(scheme) && lower.len() > scheme.len());
        let www_host =
            lower.starts_with("www.") && lower.len() > 4 && is_host(host_of(&lower[4..]));
        let bare_path = lower.contains('/') && is_host(host_of(&lower));
        let href = if with_scheme {
            candidate.to_string()
        } else if www_host || bare_path {
            format!("https://{candidate}")
        } else {
            continue;
        };
        let begin = start + lead;
        links.push(Link {
            range: begin..begin + candidate.len(),
            href,
        });
    }
    links
}

/// Whitespace-separated words with their byte offsets.
fn tokens(text: &str) -> Vec<(usize, &str)> {
    let mut words = Vec::new();
    let mut begin = None;
    for (index, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = begin.take() {
                words.push((start, &text[start..index]));
            }
        } else if begin.is_none() {
            begin = Some(index);
        }
    }
    if let Some(start) = begin {
        words.push((start, &text[start..]));
    }
    words
}

fn host_of(text: &str) -> &str {
    text.split(['/', '?', '#']).next().unwrap_or_default()
}

/// `label(.label)*.tld`, with an alphabetic TLD of two letters or more.
fn is_host(host: &str) -> bool {
    let host = host.split(':').next().unwrap_or_default();
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|ch| ch.is_ascii_alphabetic()))
}

fn trim_trailing(mut url: &str) -> &str {
    loop {
        let Some(last) = url.chars().last() else {
            return url;
        };
        let strip = match last {
            '.' | ',' | ';' | ':' | '!' | '?' | ']' | '}' | '\'' => true,
            ')' => url.matches('(').count() < url.matches(')').count(),
            _ => false,
        };
        if !strip {
            return url;
        }
        url = &url[..url.len() - last.len_utf8()];
    }
}

/// What a click on a link opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkTarget {
    /// The in-app image viewer.
    Image,
    /// The in-app text viewer (`.txt`/`.md` uploads on Grappa only).
    Text,
    /// The integrated player, with the decoder hint for its format.
    Audio(&'static str),
    /// The system browser.
    Browser,
}

const IMAGE_EXTENSIONS: [&str; 6] = ["png", "jpg", "jpeg", "gif", "webp", "bmp"];
const TEXT_EXTENSIONS: [&str; 2] = ["txt", "md"];

/// Audio the integrated player decodes, and the hint it is given.
fn audio_hint(extension: &str) -> Option<&'static str> {
    match extension {
        "mp3" => Some("mp3"),
        "ogg" | "oga" => Some("ogg"),
        "flac" => Some("flac"),
        _ => None,
    }
}

/// Where `href` opens, given the Grappa server's base URL: an upload on
/// Grappa (`/uploads/<slug>.<ext>`) opens images and text in the viewer,
/// an https image elsewhere opens in the viewer too, the rest in the
/// browser.
pub fn link_target(href: &str, server_base: &str) -> LinkTarget {
    let Ok(url) = reqwest::Url::parse(href) else {
        return LinkTarget::Browser;
    };
    let extension = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    let image = IMAGE_EXTENSIONS.contains(&extension.as_str());
    let same_host = reqwest::Url::parse(server_base).is_ok_and(|base| {
        base.host_str() == url.host_str()
            && base.port_or_known_default() == url.port_or_known_default()
    });
    if same_host && matches!(url.scheme(), "http" | "https") && url.path().starts_with("/uploads/")
    {
        if image {
            return LinkTarget::Image;
        }
        if TEXT_EXTENSIONS.contains(&extension.as_str()) {
            return LinkTarget::Text;
        }
        if let Some(hint) = audio_hint(&extension) {
            return LinkTarget::Audio(hint);
        }
    }
    if url.scheme() == "https" && image {
        return LinkTarget::Image;
    }
    if url.scheme() == "https" {
        if let Some(hint) = audio_hint(&extension) {
            return LinkTarget::Audio(hint);
        }
    }
    LinkTarget::Browser
}

/// Longest link the browser or the downloader is given; the Windows shell
/// stops at about this length.
const MAX_LINK_LEN: usize = 2048;

/// Why a link isn't opened or downloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRefusal {
    TooLong,
    /// Whitespace or a control character anywhere in the text.
    UnsafeCharacters,
    Invalid,
    /// Anything but `http`, `https` and `ftp`.
    Scheme,
    /// A user name or password in front of the host.
    Credentials,
}

impl std::fmt::Display for LinkRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "link too long",
            Self::UnsafeCharacters => "link has spaces or control characters",
            Self::Invalid => "not a valid link",
            Self::Scheme => "only http, https and ftp links are opened",
            Self::Credentials => "link carries a user name or password",
        })
    }
}

/// The URL `href` stands for, when it is fit to hand to the system browser
/// or to download: `http`, `https` or `ftp` only, no whitespace or control
/// characters, no user name or password, at most 2048 bytes.
/// What gets opened or fetched is the returned (normalised) URL, never the
/// original text, so the string that was checked is the string that is used.
pub fn validated_url(href: &str) -> Result<reqwest::Url, LinkRefusal> {
    if href.len() > MAX_LINK_LEN {
        return Err(LinkRefusal::TooLong);
    }
    if href.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(LinkRefusal::UnsafeCharacters);
    }
    let url = reqwest::Url::parse(href).map_err(|_| LinkRefusal::Invalid)?;
    if !matches!(url.scheme(), "http" | "https" | "ftp") {
        return Err(LinkRefusal::Scheme);
    }
    if has_userinfo(&url) {
        return Err(LinkRefusal::Credentials);
    }
    Ok(url)
}

fn has_userinfo(url: &reqwest::Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

/// Most redirects a download follows.
const MAX_REDIRECTS: usize = 5;

/// Why a redirect isn't followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectRefusal {
    TooMany,
    /// From `https` to `http`.
    Downgrade,
    Scheme,
    Credentials,
    /// From a public host to a loopback, private or link-local address.
    LocalHost,
}

impl std::fmt::Display for RedirectRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooMany => "too many redirects",
            Self::Downgrade => "redirect from https to http refused",
            Self::Scheme => "redirect to a scheme other than http or https refused",
            Self::Credentials => "redirect to an address with a user name or password refused",
            Self::LocalHost => "redirect to a local address refused",
        })
    }
}

impl std::error::Error for RedirectRefusal {}

/// Whether a download may follow a redirect to `next`, given the URLs
/// already requested (the first one included, as reqwest reports them).
/// A relative `Location` has already been resolved against the last URL.
pub fn redirect_decision(
    previous: &[reqwest::Url],
    next: &reqwest::Url,
) -> Result<(), RedirectRefusal> {
    let last_is_local = previous.last().is_some_and(is_local_host);
    redirect_decision_from(previous, next, last_is_local)
}

/// [`redirect_decision`] when the caller already knows whether the last URL
/// is in the local network (a name can be, once resolved).
fn redirect_decision_from(
    previous: &[reqwest::Url],
    next: &reqwest::Url,
    last_is_local: bool,
) -> Result<(), RedirectRefusal> {
    if previous.len() > MAX_REDIRECTS {
        return Err(RedirectRefusal::TooMany);
    }
    if !matches!(next.scheme(), "http" | "https") {
        return Err(RedirectRefusal::Scheme);
    }
    if has_userinfo(next) {
        return Err(RedirectRefusal::Credentials);
    }
    if let Some(last) = previous.last() {
        if last.scheme() == "https" && next.scheme() == "http" {
            return Err(RedirectRefusal::Downgrade);
        }
        // A link the user clicked may point at a LAN host on purpose, but a
        // public host must not bounce the request into the local network.
        if is_local_host(next) && !last_is_local {
            return Err(RedirectRefusal::LocalHost);
        }
    }
    Ok(())
}

/// Whether the host of `url`, as `Url::host_str` writes it, is `localhost`
/// (or a name under it) or an IP literal that is loopback, private,
/// link-local, shared (CGNAT) or unspecified. Nothing is resolved here: a
/// name that merely points at such an address is caught by [`vet_addrs`].
fn is_local_host(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return true;
    };
    let host = host.trim_end_matches('.');
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    host.trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok_and(is_local_ip)
}

fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_local_v4(ip),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| is_local_v6(ip), is_local_v4),
    }
}

/// Whether `url` has a name to resolve: not an IP literal, not `localhost`
/// or a name under it.
fn has_resolvable_host(url: &reqwest::Url) -> bool {
    if is_local_host(url) {
        return false;
    }
    url.host_str()
        .is_some_and(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().is_err())
}

/// What a name resolved to: whether every address is local, and the
/// addresses a connection may use (the public ones; all of them when
/// `allow_local`).
fn vet_addrs(addrs: Vec<SocketAddr>, allow_local: bool) -> (bool, Vec<SocketAddr>) {
    let all_local = !addrs.is_empty() && addrs.iter().all(|addr| is_local_ip(addr.ip()));
    let usable = addrs
        .into_iter()
        .filter(|addr| allow_local || !is_local_ip(addr.ip()))
        .collect();
    (all_local, usable)
}

fn is_local_v4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || first == 0
        || (first == 100 && second & 0xc0 == 64)
}

fn is_local_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback() || ip.is_unspecified() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
}

/// Largest image and text the viewer downloads.
pub const MAX_IMAGE_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;

/// Why a file couldn't be shown.
#[derive(Debug)]
pub enum FetchError {
    /// The server says it's gone (404 or 410).
    Gone,
    TooLarge,
    Failed(String),
}

/// The reason a request failed, without the URL reqwest would add (a
/// redirect target can carry credentials) and with the refused redirect's own
/// reason when that is what stopped it.
fn fetch_error(err: reqwest::Error) -> FetchError {
    let err = err.without_url();
    let mut source = err.source();
    while let Some(inner) = source {
        if let Some(refusal) = inner.downcast_ref::<RedirectRefusal>() {
            return FetchError::Failed(refusal.to_string());
        }
        source = inner.source();
    }
    FetchError::Failed(err.to_string())
}

/// Downloads a file from a host other than Grappa, without credentials,
/// up to `max_bytes`; a text file over the limit is cut there (`true`).
/// `href` must pass [`validated_url`] (and be http or https). Redirects are
/// followed here, one request at a time, so each passes [`redirect_decision`]
/// and the name it points at is resolved first: the download can't be led to
/// another scheme, down from https to http, or from a public host into the
/// local network, by address or by name. Each connection only uses the
/// addresses that were checked.
pub async fn fetch_public(
    href: &str,
    max_bytes: usize,
    cut_when_larger: bool,
) -> Result<(Vec<u8>, Option<String>, bool), FetchError> {
    fetch_public_with(href, max_bytes, cut_when_larger, lookup).await
}

async fn lookup(host: String, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok(tokio::net::lookup_host((host, port)).await?.collect())
}

async fn fetch_public_with<R, F>(
    href: &str,
    max_bytes: usize,
    cut_when_larger: bool,
    resolve: R,
) -> Result<(Vec<u8>, Option<String>, bool), FetchError>
where
    R: Fn(String, u16) -> F,
    F: Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    let mut url = validated_url(href).map_err(|refusal| FetchError::Failed(refusal.to_string()))?;
    if url.scheme() == "ftp" {
        return Err(FetchError::Failed(
            "only http and https can be downloaded".to_string(),
        ));
    }
    let refused = |refusal: RedirectRefusal| FetchError::Failed(refusal.to_string());
    let mut chain: Vec<reqwest::Url> = Vec::new();
    // The link the user clicked may be local; a redirect only if the last
    // request was too.
    let mut last_is_local = true;
    let mut response = loop {
        let mut builder = reqwest::Client::builder()
            .user_agent(crate::EXTERNAL_USER_AGENT)
            .timeout(std::time::Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none());
        let mut is_local = is_local_host(&url);
        if has_resolvable_host(&url) {
            let host = url.host_str().unwrap_or_default().to_string();
            let port = url.port_or_known_default().unwrap_or(80);
            let addrs = resolve(host.clone(), port)
                .await
                .map_err(|err| FetchError::Failed(format!("could not resolve {host}: {err}")))?;
            let (all_local, usable) = vet_addrs(addrs, last_is_local);
            if usable.is_empty() {
                return Err(if all_local {
                    refused(RedirectRefusal::LocalHost)
                } else {
                    FetchError::Failed(format!("could not resolve {host}"))
                });
            }
            is_local = all_local;
            builder = builder.resolve_to_addrs(&host, &usable);
        }
        let http = builder
            .build()
            .map_err(|err| FetchError::Failed(err.without_url().to_string()))?;
        let response = http.get(url.clone()).send().await.map_err(fetch_error)?;
        let location = match response.status().as_u16() {
            301 | 302 | 303 | 307 | 308 => response.headers().get(reqwest::header::LOCATION),
            _ => None,
        };
        let Some(location) = location.and_then(|value| value.to_str().ok()) else {
            break response;
        };
        let next = url
            .join(location)
            .map_err(|_| FetchError::Failed("invalid redirect address".to_string()))?;
        chain.push(url);
        redirect_decision_from(&chain, &next, is_local).map_err(refused)?;
        last_is_local = is_local;
        url = next;
    };
    let status = response.status().as_u16();
    if status == 404 || status == 410 {
        return Err(FetchError::Gone);
    }
    if !response.status().is_success() {
        return Err(FetchError::Failed(format!("HTTP {status}")));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(fetch_error)? {
        bytes.extend_from_slice(&chunk);
        if bytes.len() > max_bytes {
            if cut_when_larger {
                bytes.truncate(max_bytes);
                return Ok((bytes, content_type, true));
            }
            return Err(FetchError::TooLarge);
        }
    }
    Ok((bytes, content_type, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hrefs(text: &str) -> Vec<(String, String)> {
        find_links(text)
            .into_iter()
            .map(|link| (text[link.range].to_string(), link.href))
            .collect()
    }

    #[test]
    fn finds_links_like_cicchetto() {
        assert_eq!(
            hrefs("see https://x.com/a. and (http://w.org/wiki/A_(b)) ok"),
            vec![
                ("https://x.com/a".to_string(), "https://x.com/a".to_string()),
                (
                    "http://w.org/wiki/A_(b)".to_string(),
                    "http://w.org/wiki/A_(b)".to_string()
                ),
            ]
        );
        assert_eq!(
            hrefs("www.rust-lang.org, example.com/docs! node.js 1.2.3 example.com"),
            vec![
                (
                    "www.rust-lang.org".to_string(),
                    "https://www.rust-lang.org".to_string()
                ),
                (
                    "example.com/docs".to_string(),
                    "https://example.com/docs".to_string()
                ),
            ]
        );
        assert_eq!(
            hrefs("<https://a.b/c>"),
            vec![("https://a.b/c".to_string(), "https://a.b/c".to_string())]
        );
        assert!(find_links("ftp:// and http:// alone").is_empty());
        assert!(find_links("user@host.org/x mail").is_empty());
    }

    #[test]
    fn link_targets_follow_the_upload_and_extension() {
        let base = "https://grappa.example";
        assert_eq!(
            link_target("https://grappa.example/uploads/abc.png", base),
            LinkTarget::Image
        );
        assert_eq!(
            link_target("https://grappa.example/uploads/abc.md", base),
            LinkTarget::Text
        );
        assert_eq!(
            link_target("https://grappa.example/uploads/abc.mp4", base),
            LinkTarget::Browser
        );
        assert_eq!(
            link_target("https://grappa.example/uploads/song.OGA", base),
            LinkTarget::Audio("ogg")
        );
        assert_eq!(
            link_target("https://elsewhere.org/live.flac", base),
            LinkTarget::Audio("flac")
        );
        assert_eq!(
            link_target("http://elsewhere.org/a.mp3", base),
            LinkTarget::Browser
        );
        assert_eq!(
            link_target("https://elsewhere.org/cat.JPG", base),
            LinkTarget::Image
        );
        assert_eq!(
            link_target("http://elsewhere.org/cat.jpg", base),
            LinkTarget::Browser
        );
        assert_eq!(
            link_target("https://elsewhere.org/notes.txt", base),
            LinkTarget::Browser
        );
        assert_eq!(
            link_target("http://grappa.example:8443/uploads/a.png", base),
            LinkTarget::Browser
        );
        let spaced = "a\u{3000}https://x.io/p";
        assert_eq!(find_links(spaced)[0].range, 4..spaced.len());
    }

    fn url(text: &str) -> reqwest::Url {
        reqwest::Url::parse(text).expect("test URL")
    }

    fn checked(href: &str) -> Result<String, LinkRefusal> {
        validated_url(href).map(String::from)
    }

    #[test]
    fn valid_links_come_back_normalised() {
        assert_eq!(
            checked("https://example.org/a%20b"),
            Ok("https://example.org/a%20b".to_string())
        );
        assert_eq!(
            checked("https://example.org"),
            Ok("https://example.org/".to_string())
        );
        assert_eq!(
            checked("HTTPS://Example.ORG:443/Path?q=1#frag"),
            Ok("https://example.org/Path?q=1#frag".to_string())
        );
        assert_eq!(
            checked("http://example.org:8080/x"),
            Ok("http://example.org:8080/x".to_string())
        );
        assert_eq!(
            checked("https://example.org\\@evil.test/x"),
            Ok("https://example.org/@evil.test/x".to_string())
        );
    }

    #[test]
    fn ftp_links_are_accepted_and_normalised() {
        assert_eq!(
            checked("FTP://Files.Example.org:21/pub/a.txt"),
            Ok("ftp://files.example.org/pub/a.txt".to_string())
        );
        assert_eq!(
            checked("ftp://user:pw@files.example.org/a"),
            Err(LinkRefusal::Credentials)
        );
    }

    #[test]
    fn internationalised_hosts_become_punycode() {
        assert_eq!(
            checked("https://bücher.example/ä"),
            Ok("https://xn--bcher-kva.example/%C3%A4".to_string())
        );
    }

    #[test]
    fn links_with_whitespace_or_control_characters_are_refused() {
        for href in [
            " https://example.org/",
            "https://example.org/ ",
            "https://exa mple.org/",
            "https://example.org/\tx",
            "https://example.org/\nx",
            "https://example.org/\rx",
            "https://example.org/\u{0}x",
            "https://example.org/\u{7f}x",
            "https://example.org/\u{3000}x",
            "java\nscript:alert(1)",
        ] {
            assert_eq!(
                checked(href),
                Err(LinkRefusal::UnsafeCharacters),
                "{href:?}"
            );
        }
    }

    #[test]
    fn links_with_credentials_are_refused() {
        for href in [
            "https://user@example.org/",
            "https://user:secret@example.org/",
            "https://:secret@example.org/",
            "http://user:@example.org/",
        ] {
            assert_eq!(checked(href), Err(LinkRefusal::Credentials), "{href}");
        }
    }

    #[test]
    fn only_http_https_and_ftp_links_are_accepted() {
        for href in [
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<b>x</b>",
            "mailto:someone@example.org",
            "vscode://open",
            "about:blank",
        ] {
            assert_eq!(checked(href), Err(LinkRefusal::Scheme), "{href}");
        }
    }

    #[test]
    fn garbage_and_oversized_links_are_refused() {
        for href in [
            "",
            "not a url",
            "example.org/path",
            "https://",
            "http://[::1",
        ] {
            assert!(checked(href).is_err(), "{href}");
        }
        let long_path = "a".repeat(MAX_LINK_LEN);
        assert_eq!(
            checked(&format!("https://example.org/{long_path}")),
            Err(LinkRefusal::TooLong)
        );
        let fits = "a".repeat(MAX_LINK_LEN - "https://example.org/".len());
        assert!(checked(&format!("https://example.org/{fits}")).is_ok());
    }

    #[test]
    fn redirects_keep_https_and_never_downgrade() {
        let from_https = [url("https://a.example/x.png")];
        let from_http = [url("http://a.example/x.png")];
        assert_eq!(
            redirect_decision(&from_https, &url("https://b.example/y.png")),
            Ok(())
        );
        assert_eq!(
            redirect_decision(&from_http, &url("https://b.example/y.png")),
            Ok(())
        );
        assert_eq!(
            redirect_decision(&from_http, &url("http://b.example/y.png")),
            Ok(())
        );
        assert_eq!(
            redirect_decision(&from_https, &url("http://b.example/y.png")),
            Err(RedirectRefusal::Downgrade)
        );
        // Same host, other scheme: still a downgrade.
        assert_eq!(
            redirect_decision(&from_https, &url("http://a.example/x.png")),
            Err(RedirectRefusal::Downgrade)
        );
    }

    #[test]
    fn redirects_stop_after_five_hops() {
        let chain = |count: usize| -> Vec<reqwest::Url> {
            (0..count)
                .map(|n| url(&format!("https://a.example/{n}")))
                .collect()
        };
        let next = url("https://a.example/next");
        // `previous` holds the first request plus every redirect followed.
        assert_eq!(redirect_decision(&chain(1), &next), Ok(()));
        assert_eq!(redirect_decision(&chain(5), &next), Ok(()));
        assert_eq!(
            redirect_decision(&chain(6), &next),
            Err(RedirectRefusal::TooMany)
        );
    }

    #[test]
    fn relative_redirects_resolve_against_the_last_url() {
        let first = url("https://a.example/dir/x.png");
        let previous = [first.clone()];
        for location in ["y.png", "/y.png", "../y.png", "//b.example/y.png", "?v=2"] {
            let next = first.join(location).expect("relative location");
            assert_eq!(next.scheme(), "https", "{location}");
            assert_eq!(redirect_decision(&previous, &next), Ok(()), "{location}");
        }
        let downgraded = first.join("http://a.example/y.png").expect("absolute");
        assert_eq!(
            redirect_decision(&previous, &downgraded),
            Err(RedirectRefusal::Downgrade)
        );
    }

    #[test]
    fn redirects_to_other_schemes_or_with_credentials_are_refused() {
        let previous = [url("https://a.example/x.png")];
        for next in [
            "ftp://b.example/y.png",
            "file:///etc/passwd",
            "data:text/plain,x",
        ] {
            assert_eq!(
                redirect_decision(&previous, &url(next)),
                Err(RedirectRefusal::Scheme),
                "{next}"
            );
        }
        for next in [
            "https://user@b.example/y.png",
            "https://user:secret@b.example/y.png",
        ] {
            assert_eq!(
                redirect_decision(&previous, &url(next)),
                Err(RedirectRefusal::Credentials),
                "{next}"
            );
        }
    }

    #[test]
    fn a_public_host_cannot_redirect_into_the_local_network() {
        let public = [url("https://a.example/x.png")];
        for next in [
            "https://localhost/y.png",
            "https://cam.localhost/y.png",
            "https://127.0.0.1/y.png",
            "https://127.1/y.png",
            "https://2130706433/y.png",
            "https://10.0.0.5/y.png",
            "https://172.16.3.4/y.png",
            "https://192.168.1.1/y.png",
            "https://169.254.169.254/latest",
            "https://100.64.0.1/y.png",
            "https://0.0.0.0/y.png",
            "https://[::1]/y.png",
            "https://[fe80::1]/y.png",
            "https://[fd00::1]/y.png",
            "https://[::ffff:127.0.0.1]/y.png",
            "https://[::ffff:10.1.2.3]/y.png",
        ] {
            assert_eq!(
                redirect_decision(&public, &url(next)),
                Err(RedirectRefusal::LocalHost),
                "{next}"
            );
        }
        for next in [
            "https://8.8.8.8/y.png",
            "https://172.32.0.1/y.png",
            "https://100.128.0.1/y.png",
            "https://[2001:4860:4860::8888]/y.png",
            "https://b.example/y.png",
        ] {
            assert_eq!(redirect_decision(&public, &url(next)), Ok(()), "{next}");
        }
    }

    #[test]
    fn a_link_to_the_local_network_may_stay_there() {
        let lan = [url("https://192.168.1.10/x.png")];
        assert_eq!(
            redirect_decision(&lan, &url("https://192.168.1.11/y.png")),
            Ok(())
        );
        assert_eq!(
            redirect_decision(&lan, &url("https://localhost/y.png")),
            Ok(())
        );
    }

    #[tokio::test]
    async fn fetch_follows_a_relative_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/old.png"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/new.png"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/new.png"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "image/png")
                    .set_body_bytes(vec![1u8, 2, 3]),
            )
            .mount(&server)
            .await;

        let (bytes, content_type, cut) =
            fetch_public(&format!("{}/old.png", server.uri()), 1024, false)
                .await
                .expect("fetch");
        assert_eq!(bytes, [1u8, 2, 3]);
        assert_eq!(content_type.as_deref(), Some("image/png"));
        assert!(!cut);
    }

    #[tokio::test]
    async fn fetch_gives_up_on_a_redirect_loop() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/loop.png"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/loop.png"))
            .mount(&server)
            .await;

        let result = fetch_public(&format!("{}/loop.png", server.uri()), 1024, false).await;
        assert!(
            matches!(&result, Err(FetchError::Failed(reason)) if reason == "too many redirects"),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn fetch_refuses_a_redirect_to_another_scheme() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/a.png"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "ftp://files.example/a.png"),
            )
            .mount(&server)
            .await;

        let result = fetch_public(&format!("{}/a.png", server.uri()), 1024, false).await;
        assert!(
            matches!(&result, Err(FetchError::Failed(reason)) if reason.contains("scheme")),
            "{result:?}"
        );
    }

    fn addr(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().expect("ip"), 443)
    }

    fn resolved_to(ips: &[&str]) -> std::io::Result<Vec<SocketAddr>> {
        Ok(ips.iter().copied().map(addr).collect())
    }

    #[test]
    fn resolved_addresses_are_vetted() {
        let local = addr("127.0.0.1");
        let private = addr("10.0.0.5");
        let public = addr("93.184.216.34");
        assert_eq!(vet_addrs(vec![local, private], false), (true, vec![]));
        assert_eq!(vet_addrs(vec![public], false), (false, vec![public]));
        // A mixed answer keeps only the public addresses.
        assert_eq!(
            vet_addrs(vec![local, public, private], false),
            (false, vec![public])
        );
        assert_eq!(
            vet_addrs(vec![local, private], true),
            (true, vec![local, private])
        );
        assert_eq!(vet_addrs(vec![], false), (false, vec![]));
    }

    /// Fetches a link whose server redirects to `target`, a name that
    /// resolves to `resolved`. The first name has a public address next to
    /// the loopback one, so the first request counts as public yet still
    /// reaches the test server. Gives the refusal, if any.
    async fn redirect_to_name(
        target: &str,
        resolved: &'static [&'static str],
    ) -> Result<(), String> {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let port = server.address().port();
        let location = format!("http://{target}:{port}/b.png");
        Mock::given(method("GET"))
            .and(path("/a.png"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", location))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/b.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7u8]))
            .mount(&server)
            .await;
        let result = fetch_public_with(
            &format!("http://start.example:{port}/a.png"),
            1024,
            false,
            |host, _| async move {
                if host == "start.example" {
                    resolved_to(&["127.0.0.1", "93.184.216.34"])
                } else {
                    resolved_to(resolved)
                }
            },
        )
        .await;
        let requests = server.received_requests().await.expect("requests");
        let reached_target = requests.iter().any(|request| request.url.path() == "/b.png");
        match result {
            Ok(_) => {
                assert!(reached_target);
                Ok(())
            }
            Err(FetchError::Failed(reason)) => {
                assert!(!reached_target, "the target was contacted");
                Err(reason)
            }
            Err(other) => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_refuses_a_redirect_to_a_name_that_resolves_locally() {
        for resolved in [
            &["127.0.0.1"][..],
            &["10.0.0.5", "192.168.1.9"],
            &["169.254.169.254"],
            &["::1"],
        ] {
            let result = redirect_to_name("inner.example", resolved).await;
            assert_eq!(
                result,
                Err("redirect to a local address refused".to_string()),
                "{resolved:?}"
            );
        }
    }

    #[tokio::test]
    async fn fetch_lets_a_local_name_redirect_within_the_local_network() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let port = server.address().port();
        let location = format!("http://nas2.lan:{port}/b.png");
        Mock::given(method("GET"))
            .and(path("/a.png"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", location))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/b.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![9u8]))
            .mount(&server)
            .await;
        let (bytes, _, _) = fetch_public_with(
            &format!("http://nas.lan:{port}/a.png"),
            1024,
            false,
            |_, _| async { resolved_to(&["127.0.0.1"]) },
        )
        .await
        .expect("fetch");
        assert_eq!(bytes, [9u8]);
    }

    #[tokio::test]
    async fn fetch_resolves_again_for_every_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let port = server.address().port();
        let location = format!("http://same.example:{port}/b.png");
        Mock::given(method("GET"))
            .and(path("/a.png"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", location))
            .mount(&server)
            .await;
        let calls = AtomicUsize::new(0);
        // First answer is mixed (public as far as the guard goes), the second
        // is local only: the redirect to the same name must be refused.
        let result = fetch_public_with(
            &format!("http://same.example:{port}/a.png"),
            1024,
            false,
            |_, _| {
                let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    if first {
                        resolved_to(&["127.0.0.1", "93.184.216.34"])
                    } else {
                        resolved_to(&["127.0.0.1"])
                    }
                }
            },
        )
        .await;
        assert!(
            matches!(&result, Err(FetchError::Failed(reason)) if reason == "redirect to a local address refused"),
            "{result:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fetch_refuses_a_link_with_credentials_before_connecting() {
        let result = fetch_public("https://user:secret@example.org/a.png", 1024, false).await;
        assert!(
            matches!(&result, Err(FetchError::Failed(reason)) if !reason.contains("secret")),
            "{result:?}"
        );
        let result = fetch_public("ftp://example.org/a.png", 1024, false).await;
        assert!(matches!(result, Err(FetchError::Failed(_))));
    }
}
