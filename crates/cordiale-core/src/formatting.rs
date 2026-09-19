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

//! mIRC control-code parsing for chat message rendering.
//!
//! IRC clients have rendered these control bytes the mIRC way since the
//! 90s (Cicchetto, the reference web client, does the same) — this parses
//! them into plain color/weight runs so `cordiale-ui` can render each run
//! as its own styled Slint `Text`, without pulling any rendering concern
//! into this crate.

/// One run of text sharing the same color/weight, as split out of a raw
/// message by `parse_mirc_text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorSegment {
    pub text: String,
    /// `None` means "no color code active" — the caller should use its own
    /// default text color, not a literal black/white guess.
    pub color: Option<(u8, u8, u8)>,
    pub bold: bool,
}

const BOLD: char = '\u{02}';
const COLOR: char = '\u{03}';
const RESET: char = '\u{0F}';
const REVERSE: char = '\u{16}';
const ITALIC: char = '\u{1D}';
const UNDERLINE: char = '\u{1F}';

/// The 16 standard mIRC colors (index 0-15), as RGB triples — the palette
/// mIRC shipped and every client since (Cicchetto included) has kept
/// stable, since scripts/logs elsewhere hardcode these indexes.
const MIRC_PALETTE: [(u8, u8, u8); 16] = [
    (255, 255, 255), // 0 white
    (0, 0, 0),       // 1 black
    (0, 0, 127),     // 2 blue
    (0, 147, 0),     // 3 green
    (255, 0, 0),     // 4 red
    (127, 0, 0),     // 5 brown
    (156, 0, 156),   // 6 purple
    (252, 127, 0),   // 7 orange
    (255, 255, 0),   // 8 yellow
    (0, 252, 0),     // 9 light green
    (0, 147, 147),   // 10 cyan
    (0, 255, 255),   // 11 light cyan
    (0, 0, 252),     // 12 light blue
    (255, 0, 255),   // 13 pink
    (127, 127, 127), // 14 grey
    (210, 210, 210), // 15 light grey
];

/// Splits `raw` (a message body possibly containing mIRC control codes)
/// into color/weight runs, stripping the control bytes themselves.
/// `\x16`/`\x1D`/`\x1F` (reverse/italic/underline) have no Slint-side
/// rendering yet, so they're dropped silently rather than left in the
/// visible text — leaving the raw control byte would show as garbage,
/// which is worse than losing the styling.
pub fn parse_mirc_text(raw: &str) -> Vec<ColorSegment> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut color: Option<(u8, u8, u8)> = None;
    let mut bold = false;

    let mut chars = raw.chars().peekable();
    // Not a `for ch in chars` loop on purpose: the `COLOR` arm hands
    // `chars` to `parse_color_code`, which consumes further chars off the
    // same iterator (the color code's digits) before this loop continues —
    // a `for` loop would take ownership and make that impossible.
    #[allow(clippy::while_let_on_iterator)]
    while let Some(ch) = chars.next() {
        match ch {
            BOLD => {
                flush(&mut segments, &mut current, color, bold);
                bold = !bold;
            }
            RESET => {
                flush(&mut segments, &mut current, color, bold);
                color = None;
                bold = false;
            }
            REVERSE | ITALIC | UNDERLINE => {}
            COLOR => {
                flush(&mut segments, &mut current, color, bold);
                color = parse_color_code(&mut chars);
            }
            other => current.push(other),
        }
    }
    flush(&mut segments, &mut current, color, bold);
    segments
}

/// Consumes the 1-2 digit foreground (and optional `,` + 1-2 digit
/// background, which Cordiale ignores — no background-color rendering
/// surface in the chat list yet) that can follow a `\x03` control byte. A
/// bare `\x03` with no following digits resets to no color, matching mIRC.
fn parse_color_code(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<(u8, u8, u8)> {
    let mut digits = String::new();
    while digits.len() < 2 && chars.peek().is_some_and(|c| c.is_ascii_digit()) {
        digits.push(chars.next().expect("just peeked"));
    }
    if chars.peek() == Some(&',') {
        chars.next();
        while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
            chars.next();
        }
    }
    digits
        .parse::<usize>()
        .ok()
        .and_then(|index| MIRC_PALETTE.get(index).copied())
}

fn flush(
    segments: &mut Vec<ColorSegment>,
    current: &mut String,
    color: Option<(u8, u8, u8)>,
    bold: bool,
) {
    if !current.is_empty() {
        segments.push(ColorSegment {
            text: std::mem::take(current),
            color,
            bold,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mirc_text_returns_a_single_plain_segment_for_uncoded_text() {
        let segments = parse_mirc_text("hello there");
        assert_eq!(
            segments,
            vec![ColorSegment {
                text: "hello there".to_string(),
                color: None,
                bold: false,
            }]
        );
    }

    #[test]
    fn parse_mirc_text_splits_on_a_color_code() {
        let segments = parse_mirc_text("plain \u{03}4red\u{03}plain again");
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].text, "plain ");
        assert_eq!(segments[0].color, None);
        assert_eq!(segments[1].text, "red");
        assert_eq!(segments[1].color, Some((255, 0, 0)));
        assert_eq!(segments[2].text, "plain again");
        assert_eq!(segments[2].color, None);
    }

    #[test]
    fn parse_mirc_text_ignores_a_background_color() {
        let segments = parse_mirc_text("\u{03}4,8red on yellow");
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].text, "red on yellow");
        assert_eq!(segments[0].color, Some((255, 0, 0)));
    }

    #[test]
    fn parse_mirc_text_toggles_bold() {
        let segments = parse_mirc_text("normal \u{02}bold\u{02} normal");
        assert_eq!(segments.len(), 3);
        assert!(!segments[0].bold);
        assert!(segments[1].bold);
        assert!(!segments[2].bold);
    }

    #[test]
    fn parse_mirc_text_reset_clears_color_and_bold() {
        let segments = parse_mirc_text("\u{03}4\u{02}bold red\u{0F}plain");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].color, Some((255, 0, 0)));
        assert!(segments[0].bold);
        assert_eq!(segments[1].text, "plain");
        assert_eq!(segments[1].color, None);
        assert!(!segments[1].bold);
    }

    #[test]
    fn parse_mirc_text_strips_unsupported_control_codes() {
        let segments = parse_mirc_text("under\u{1F}line\u{1F} done");
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].text, "underline done");
    }

    #[test]
    fn parse_mirc_text_ignores_an_out_of_range_color_index() {
        let segments = parse_mirc_text("\u{03}99oops");
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].color, None);
        assert_eq!(segments[0].text, "oops");
    }
}
