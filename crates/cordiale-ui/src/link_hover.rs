// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)

//! Which link of a chat row lies under the pointer. The chat text sits under
//! a transparent text input that owns the mouse, and Slint gives no hover
//! hit-test for it. The window measures the whole row once (the width of its
//! longest line); this module spreads that width over the characters by
//! their relative widths, wraps the words like the row does, and finds the
//! character under the pointer. The result is an estimate, so the row only
//! uses it to show the link cursor; the click itself still uses the cursor
//! offset of the text input.

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
    let sizes = [x, y, width, line_height, text_width];
    if sizes.iter().any(|value| !value.is_finite()) || x < 0.0 || y < 0.0 {
        return String::new();
    }
    if width <= 0.0 || line_height <= 0.0 || text_width <= 0.0 {
        return String::new();
    }
    let links = row_links(text, channels);
    if links.is_empty() {
        return String::new();
    }
    let longest = text.split('\n').map(text_weight).fold(0.0f32, f32::max);
    if longest <= 0.0 {
        return String::new();
    }
    let scale = text_width / longest;
    let line = (y / line_height).floor();
    if line >= usize::MAX as f32 {
        return String::new();
    }
    let line = line as usize;
    let at = x / scale;
    let layout_width = width / scale;
    place_chars(text, layout_width)
        .into_iter()
        .find(|c| c.line == line && c.start <= at && at < c.end)
        .and_then(|c| {
            links
                .into_iter()
                .find(|link| link.range.start <= c.byte && c.byte < link.range.end)
        })
        .map(|link| link.href)
        .unwrap_or_default()
}
