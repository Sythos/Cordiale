//! Emoji search and text edits for the compose box: the `:shortcode`
//! suggestions and the emoji picker.
//!
//! The data comes from the `emojis` crate, so the set, the names and the
//! shortcodes are the same on every platform. The crate version in
//! `Cargo.lock` pins the Unicode and shortcode data; a reviewed dependency
//! update is the only way to change it. Nothing here touches the GUI.

use emojis::{Emoji, Group};

/// Number of categories in the picker (faces and people share one).
pub(crate) const CATEGORY_COUNT: usize = 8;

/// Most results the `:shortcode` list shows.
pub(crate) const SUGGESTION_LIMIT: usize = 8;

/// Most results the picker search shows.
pub(crate) const SEARCH_LIMIT: usize = 120;

/// Shortest search term that opens the `:shortcode` list. It keeps `:D`
/// and similar short text from opening it.
const MIN_QUERY_CHARS: usize = 2;

/// The Unicode groups shown in a picker category, in order: faces and
/// people, animals and nature, food, travel, activities, objects, symbols,
/// flags.
fn category_groups(category: usize) -> &'static [Group] {
    match category {
        0 => &[Group::SmileysAndEmotion, Group::PeopleAndBody],
        1 => &[Group::AnimalsAndNature],
        2 => &[Group::FoodAndDrink],
        3 => &[Group::TravelAndPlaces],
        4 => &[Group::Activities],
        5 => &[Group::Objects],
        6 => &[Group::Symbols],
        7 => &[Group::Flags],
        _ => &[],
    }
}

/// The emoji of a picker category in Unicode order. A category that does
/// not exist is empty.
pub(crate) fn category_emojis(category: usize) -> Vec<&'static Emoji> {
    category_groups(category)
        .iter()
        .flat_map(|group| group.emojis())
        .collect()
}

/// The text shown next to an emoji: the first shortcode, or the Unicode
/// name when the emoji has none.
pub(crate) fn label(emoji: &Emoji) -> String {
    match emoji.shortcode() {
        Some(code) => format!(":{code}:"),
        None => emoji.name().to_string(),
    }
}

/// Words of a search term: lower case, split on spaces, colons and
/// underscores.
fn query_words(query: &str) -> Vec<String> {
    query
        .split(|c: char| c.is_whitespace() || c == '_' || c == ':')
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// How well an emoji matches the words: `None` for no match, a lower number
/// for a better match. A shortcode that equals the term ranks first, then a
/// shortcode that starts with it, then a name that starts with it, then any
/// match of all the words in a name or shortcode.
fn match_rank(emoji: &Emoji, words: &[String]) -> Option<u8> {
    let name = emoji.name().to_lowercase();
    let codes: Vec<&str> = emoji.shortcodes().collect();
    let joined = words.join("_");
    if codes.iter().any(|code| *code == joined) {
        return Some(0);
    }
    if codes.iter().any(|code| code.starts_with(&joined)) {
        return Some(1);
    }
    if name.starts_with(&words.join(" ")) {
        return Some(2);
    }
    let all_found = words
        .iter()
        .all(|word| name.contains(word.as_str()) || codes.iter().any(|code| code.contains(word)));
    all_found.then_some(3)
}

/// Searches shortcodes, aliases and names. `with_tones` adds the skin tone
/// variants, which have a name but no shortcode of their own. The best
/// matches come first; equal matches keep the Unicode order.
pub(crate) fn search(query: &str, limit: usize, with_tones: bool) -> Vec<&'static Emoji> {
    let words = query_words(query);
    if words.is_empty() || limit == 0 {
        return Vec::new();
    }
    let mut hits: Vec<(u8, usize, &'static Emoji)> = Vec::new();
    let mut order = 0usize;
    for base in emojis::iter() {
        let variants: Vec<&'static Emoji> = match base.skin_tones() {
            Some(tones) if with_tones => tones.collect(),
            _ => vec![base],
        };
        for emoji in variants {
            if let Some(rank) = match_rank(emoji, &words) {
                hits.push((rank, order, emoji));
            }
            order += 1;
        }
    }
    hits.sort_by_key(|(rank, order, _)| (*rank, *order));
    hits.into_iter()
        .take(limit)
        .map(|(_, _, emoji)| emoji)
        .collect()
}

/// A character that can be part of a shortcode search term.
fn is_term_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '+' || c == '-'
}

/// The largest char boundary of `text` that is not after `caret`.
fn clamp_to_boundary(text: &str, caret: usize) -> usize {
    let mut caret = caret.min(text.len());
    while !text.is_char_boundary(caret) {
        caret -= 1;
    }
    caret
}

/// The `:term` that ends at the caret, as the byte offset of its colon and
/// the term without the colon. It is `None` when the text before the caret
/// is not a shortcode being typed:
/// - a slash command (the draft starts with a slash);
/// - a colon that follows a word character, as in `12:30` or `http://`;
/// - a term shorter than two characters or without a letter, as in `:)`
///   or `:3`.
pub(crate) fn active_shortcode(text: &str, caret: usize) -> Option<(usize, &str)> {
    let caret = clamp_to_boundary(text, caret);
    let head = &text[..caret];
    if head.starts_with('/') {
        return None;
    }
    let term_start = head
        .char_indices()
        .rev()
        .take_while(|(_, c)| is_term_char(*c))
        .last()
        .map_or(caret, |(index, _)| index);
    let term = &head[term_start..];
    let before = &head[..term_start];
    let colon = before.len().checked_sub(1)?;
    if !before.ends_with(':') {
        return None;
    }
    if let Some(previous) = before[..colon].chars().next_back() {
        if !previous.is_whitespace() {
            return None;
        }
    }
    if term.chars().count() < MIN_QUERY_CHARS || !term.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some((colon, term))
}

/// The suggestions for the text before the caret: empty when there is no
/// active shortcode.
pub(crate) fn suggestions(text: &str, caret: usize) -> Vec<&'static Emoji> {
    match active_shortcode(text, caret) {
        Some((_, term)) => search(term, SUGGESTION_LIMIT, false),
        None => Vec::new(),
    }
}

/// Replaces the active shortcode at the caret with the emoji. The text
/// before and after it stays. Returns the new text and the new caret, which
/// is right after the emoji. `None` when there is no active shortcode.
pub(crate) fn replace_active_shortcode(
    text: &str,
    caret: usize,
    emoji: &str,
) -> Option<(String, usize)> {
    let caret = clamp_to_boundary(text, caret);
    let (colon, _) = active_shortcode(text, caret)?;
    let mut new_text = String::with_capacity(text.len() + emoji.len());
    new_text.push_str(&text[..colon]);
    new_text.push_str(emoji);
    let new_caret = new_text.len();
    new_text.push_str(&text[caret..]);
    Some((new_text, new_caret))
}

/// Inserts the emoji at the caret. The text before and after it stays.
/// Returns the new text and the new caret, which is right after the emoji.
/// The emoji goes in as one string, so a sequence (a skin tone or a joined
/// emoji) is never split.
pub(crate) fn insert_at(text: &str, caret: usize, emoji: &str) -> (String, usize) {
    let caret = clamp_to_boundary(text, caret);
    let mut new_text = String::with_capacity(text.len() + emoji.len());
    new_text.push_str(&text[..caret]);
    new_text.push_str(emoji);
    let new_caret = new_text.len();
    new_text.push_str(&text[caret..]);
    (new_text, new_caret)
}
