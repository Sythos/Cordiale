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

//! Session sharing: the link Grappa's web client wraps a share token in,
//! and the reverse, reading a token out of what a user pasted.
//!
//! The link is `<server>/share#<token>`. The token rides the fragment so it
//! never travels in a request or a `Referer`; Cordiale builds and reads the
//! same shape, so a link from either client works in the other.

/// The link that opens a shared session in a browser.
///
/// Grappa tokens are URL-safe already (base64url and dots), which is why
/// the same text Cicchetto percent-encodes is used as it is.
pub fn share_link(base_url: &str, token: &str) -> String {
    format!("{}/share#{token}", base_url.trim_end_matches('/'))
}

/// Reads a share token from what the user pasted: the bare token, or a
/// share link whose fragment holds it. `None` when there is nothing to
/// send (empty input, or a link that carries no fragment).
pub fn token_from_input(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let candidate = match trimmed.rsplit_once('#') {
        Some((_, fragment)) => fragment,
        None if trimmed.contains("://") => return None,
        None => trimmed,
    };
    let decoded = percent_decode(candidate);
    let token: String = decoded.chars().filter(|c| !c.is_whitespace()).collect();
    (!token.is_empty()).then_some(token)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if let Some(byte) = bytes.get(index + 1..index + 3).and_then(hex_byte) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_byte(pair: &[u8]) -> Option<u8> {
    let high = char::from(*pair.first()?).to_digit(16)?;
    let low = char::from(*pair.get(1)?).to_digit(16)?;
    u8::try_from(high * 16 + low).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_carries_the_token_in_the_fragment() {
        assert_eq!(
            share_link("https://irc.example/", "SFMyNTY.a.b"),
            "https://irc.example/share#SFMyNTY.a.b"
        );
    }

    #[test]
    fn a_bare_token_or_a_link_yields_the_same_token() {
        assert_eq!(
            token_from_input("  SFMyNTY.a-b_c.d  \n").as_deref(),
            Some("SFMyNTY.a-b_c.d")
        );
        assert_eq!(
            token_from_input("https://irc.example/share#SFMyNTY.a-b_c.d").as_deref(),
            Some("SFMyNTY.a-b_c.d")
        );
        let link = share_link("https://irc.example", "SFMyNTY.a.b");
        assert_eq!(token_from_input(&link).as_deref(), Some("SFMyNTY.a.b"));
    }

    #[test]
    fn a_percent_encoded_fragment_is_decoded() {
        assert_eq!(
            token_from_input("https://irc.example/share#ab%2Bcd%3D").as_deref(),
            Some("ab+cd=")
        );
        // A stray or truncated escape is left as typed.
        assert_eq!(token_from_input("ab%zz%4").as_deref(), Some("ab%zz%4"));
    }

    #[test]
    fn input_with_nothing_to_send_is_refused() {
        assert_eq!(token_from_input(""), None);
        assert_eq!(token_from_input("   "), None);
        assert_eq!(token_from_input("https://irc.example/share#"), None);
        assert_eq!(token_from_input("https://irc.example/share"), None);
    }
}
