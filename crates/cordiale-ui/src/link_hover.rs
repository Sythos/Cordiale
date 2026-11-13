// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)

//! Which link of a chat row lies under the pointer. The chat text sits under
//! a transparent text input that owns the mouse, and Slint gives no hover
//! hit-test for it. The window measures the whole row once (the width of its
//! longest line); this module spreads that width over the characters by
//! their relative widths, wraps the words like the row does, and finds the
//! character under the pointer. The result is an estimate, so the row uses
//! it to show the link cursor and to give the text input the press that the
//! link area took. A link opens only from the cursor offset of the text
//! input, never from the estimated link itself.

use super::*;

/// The relative width of a character. Only the ratios matter: the caller
/// scales them to the measured width of the row.
pub(crate) fn glyph_weight(c: char) -> f32 {
    use unicode_width::UnicodeWidthChar as _;
    match c.width() {
        None | Some(0) => 0.0,
        Some(width) if width >= 2 => 2.0,
        Some(_) => match c {
            'i' | 'j' | 'l' | 'I' | '.' | ',' | ':' | ';' | '\'' | '!' | '|' | '`' => 0.45,
            ' ' | 't' | 'f' | 'r' | '(' | ')' | '[' | ']' | '-' | '/' | '\\' => 0.6,
            'm' | 'w' => 1.4,
            'M' | 'W' => 1.6,
            c if c.is_uppercase() => 1.15,
            _ => 1.0,
        },
    }
}

/// The weight of a run of text.
fn text_weight(text: &str) -> f32 {
    text.chars().map(glyph_weight).sum()
}

/// The place of one character: its line and its horizontal span, in the
/// relative units of `glyph_weight`.
struct Placed {
    byte: usize,
    line: usize,
    start: f32,
    end: f32,
}

/// Places every character of `text` on the lines of a row of `width` units.
/// A line ends at a line feed, or before the word that does not fit. A word
/// longer than a line breaks at the character. Spaces never wrap: they hang
/// at the end of the line.
fn place_chars(text: &str, width: f32) -> Vec<Placed> {
    let mut placed = Vec::with_capacity(text.len());
    let mut line = 0usize;
    let mut x = 0.0f32;
    let mut chars = text.char_indices().peekable();
    while let Some(&(byte, c)) = chars.peek() {
        if c == '\n' {
            chars.next();
            line += 1;
            x = 0.0;
            continue;
        }
        if c.is_whitespace() {
            chars.next();
            let w = glyph_weight(c);
            placed.push(Placed {
                byte,
                line,
                start: x,
                end: x + w,
            });
            x += w;
            continue;
        }
        // One word: the characters up to the next white space.
        let word_end = text[byte..]
            .find(char::is_whitespace)
            .map_or(text.len(), |offset| byte + offset);
        let word_weight = text_weight(&text[byte..word_end]);
        if x > 0.0 && x + word_weight > width {
            line += 1;
            x = 0.0;
        }
        while let Some(&(byte, c)) = chars.peek() {
            if byte >= word_end {
                break;
            }
            chars.next();
            let w = glyph_weight(c);
            if x > 0.0 && x + w > width {
                line += 1;
                x = 0.0;
            }
            placed.push(Placed {
                byte,
                line,
                start: x,
                end: x + w,
            });
            x += w;
        }
    }
    placed
}

/// The link under a pointer in a row text, or an empty string. `x` and `y`
/// are the pointer in the text area; `width` is the width the text wraps
/// at; `line_height` is the height of one line; `text_width` is the measured
/// width of the longest line when nothing wraps. With `channels` a channel
/// name is a link too. Empty space, plain text and invalid sizes give "".
pub(crate) fn link_at_point(
    text: &str,
    x: f32,
    y: f32,
    width: f32,
    line_height: f32,
    text_width: f32,
    channels: Option<&ChannelLinkContext>,
) -> String {
    if x < 0.0 || y < 0.0 {
        return String::new();
    }
    let links = row_links(text, channels);
    if links.is_empty() {
        return String::new();
    }
    let Some(spot) = Spot::new(text, x, y, width, line_height, text_width) else {
        return String::new();
    };
    spot.placed
        .into_iter()
        .find(|c| c.line == spot.line && c.start <= spot.at && spot.at < c.end)
        .and_then(|c| {
            links
                .into_iter()
                .find(|link| link.range.start <= c.byte && c.byte < link.range.end)
        })
        .map(|link| link.href)
        .unwrap_or_default()
}

/// The pointer on the placed characters of a row: the characters, the line
/// under the pointer and the horizontal place on it, in the units of
/// `glyph_weight`.
struct Spot {
    placed: Vec<Placed>,
    line: usize,
    at: f32,
}

impl Spot {
    /// `None` for a size that is not usable. A pointer left of or above the
    /// text counts as its start.
    fn new(
        text: &str,
        x: f32,
        y: f32,
        width: f32,
        line_height: f32,
        text_width: f32,
    ) -> Option<Self> {
        let sizes = [x, y, width, line_height, text_width];
        if sizes.iter().any(|value| !value.is_finite()) {
            return None;
        }
        if width <= 0.0 || line_height <= 0.0 || text_width <= 0.0 {
            return None;
        }
        let longest = text.split('\n').map(text_weight).fold(0.0f32, f32::max);
        if longest <= 0.0 {
            return None;
        }
        let scale = text_width / longest;
        let line = (y.max(0.0) / line_height).floor();
        if line >= usize::MAX as f32 {
            return None;
        }
        Some(Self {
            placed: place_chars(text, width / scale),
            line: line as usize,
            at: x.max(0.0) / scale,
        })
    }
}

/// The byte offset of the text cursor for a press at a point of a row text:
/// the nearest character edge, as the text input would put it. On a link the
/// offset stays inside the link, so a click on any character of it reads the
/// link, like a click that the text input handles itself. Past the end of a
/// line it is the end of the line, below the text the end of the text. A size
/// that is not usable gives 0.
pub(crate) fn offset_at_point(
    text: &str,
    x: f32,
    y: f32,
    width: f32,
    line_height: f32,
    text_width: f32,
    channels: Option<&ChannelLinkContext>,
) -> usize {
    let Some(spot) = Spot::new(text, x, y, width, line_height, text_width) else {
        return 0;
    };
    let char_len = |byte: usize| text[byte..].chars().next().map_or(0, char::len_utf8);
    let on_line: Vec<&Placed> = spot.placed.iter().filter(|c| c.line == spot.line).collect();
    let (Some(first), Some(last)) = (on_line.first(), on_line.last()) else {
        // A line with no character: the start of the next line with one.
        return spot
            .placed
            .iter()
            .find(|c| c.line > spot.line)
            .map_or(text.len(), |c| c.byte);
    };
    let nearest = if spot.at < first.start {
        first.byte
    } else if spot.at >= last.end {
        last.byte + char_len(last.byte)
    } else {
        let under = on_line
            .iter()
            .find(|c| c.start <= spot.at && spot.at < c.end)
            .unwrap_or(last);
        if spot.at < (under.start + under.end) / 2.0 {
            under.byte
        } else {
            under.byte + char_len(under.byte)
        }
    };
    // Keep the offset strictly inside the link under the point, if any.
    let under_byte = on_line
        .iter()
        .find(|c| c.start <= spot.at && spot.at < c.end)
        .map(|c| c.byte);
    let link = under_byte.and_then(|byte| {
        row_links(text, channels)
            .into_iter()
            .find(|link| link.range.start <= byte && byte < link.range.end)
    });
    match link {
        Some(link) => {
            let low = link.range.start + char_len(link.range.start);
            let last_start = text[..link.range.end]
                .char_indices()
                .next_back()
                .map_or(link.range.end, |(byte, _)| byte);
            if low <= last_start {
                nearest.clamp(low, last_start)
            } else {
                nearest
            }
        }
        None => nearest,
    }
}
