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
    /// The system browser.
    Browser,
}

const IMAGE_EXTENSIONS: [&str; 6] = ["png", "jpg", "jpeg", "gif", "webp", "bmp"];
const TEXT_EXTENSIONS: [&str; 2] = ["txt", "md"];

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
    }
    if url.scheme() == "https" && image {
        return LinkTarget::Image;
    }
    LinkTarget::Browser
}

/// Whether the system browser may be asked to open `href`.
pub fn is_openable(href: &str) -> bool {
    reqwest::Url::parse(href).is_ok_and(|url| matches!(url.scheme(), "http" | "https" | "ftp"))
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

/// Downloads a file from a host other than Grappa, without credentials,
/// up to `max_bytes`; a text file over the limit is cut there (`true`).
pub async fn fetch_public(
    href: &str,
    max_bytes: usize,
    cut_when_larger: bool,
) -> Result<(Vec<u8>, Option<String>, bool), FetchError> {
    let http = reqwest::Client::builder()
        .user_agent(concat!("Cordiale/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|err| FetchError::Failed(err.to_string()))?;
    let mut response = http
        .get(href)
        .send()
        .await
        .map_err(|err| FetchError::Failed(err.to_string()))?;
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
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| FetchError::Failed(err.to_string()))?
    {
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
        assert!(is_openable("ftp://a.b/c"));
        assert!(!is_openable("javascript:alert(1)"));
        assert!(!is_openable("file:///etc/passwd"));
    }
}
