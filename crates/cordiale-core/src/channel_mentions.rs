//! Channel names in message text. A name is a word that starts with a
//! channel prefix of the network (`CHANTYPES`, `#` when unknown). It is
//! found only for display and for a click: finding a name never joins it.

use std::ops::Range;

/// A channel name found in a message: where its text is, and the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMention {
    pub range: Range<usize>,
    pub name: String,
}

/// The prefix characters of `chantypes`, or `#` when the network gave none.
fn prefix_chars(chantypes: &[String]) -> Vec<char> {
    let mut prefixes: Vec<char> = chantypes
        .iter()
        .flat_map(|entry| entry.chars())
        .filter(|ch| !ch.is_whitespace() && !ch.is_control() && *ch != ',')
        .collect();
    if prefixes.is_empty() {
        prefixes.push('#');
    }
    prefixes
}

/// Whether a channel name can start after `previous`: at the start of the
/// text, after a space or after an opening mark.
fn boundary_before(previous: Option<char>) -> bool {
    previous.is_none_or(|ch| ch.is_whitespace() || matches!(ch, '(' | '[' | '{' | '<' | '"' | '\''))
}

/// Punctuation that ends a sentence or closes a mark after a name.
fn is_trailing_mark(ch: char) -> bool {
    matches!(
        ch,
        '.' | ';' | ':' | '!' | '?' | ')' | ']' | '}' | '>' | '"' | '\'' | '”' | '’' | '»' | '›'
    )
}

/// The channel names in `text`, in order, with their byte ranges. A name
/// needs a boundary before it, ends at a space, a comma or a control
/// character, and loses the sentence punctuation at its end. A word inside
/// a link is no name. A name longer than `channellen` (when known) is no name.
pub fn find_channels(
    text: &str,
    chantypes: &[String],
    channellen: Option<u64>,
) -> Vec<ChannelMention> {
    let prefixes = prefix_chars(chantypes);
    let links: Vec<Range<usize>> = crate::media::find_links(text)
        .into_iter()
        .map(|link| link.range)
        .collect();
    let mut found = Vec::new();
    let mut skip_until = 0;
    let mut previous: Option<char> = None;
    for (start, ch) in text.char_indices() {
        let before = previous.replace(ch);
        if start < skip_until || !prefixes.contains(&ch) || !boundary_before(before) {
            continue;
        }
        if links
            .iter()
            .any(|range| range.start <= start && start < range.end)
        {
            continue;
        }
        let rest = &text[start..];
        let end = rest
            .char_indices()
            .find(|(_, next)| next.is_whitespace() || next.is_control() || *next == ',')
            .map_or(rest.len(), |(index, _)| index);
        let name = rest[..end].trim_end_matches(is_trailing_mark);
        skip_until = start + end;
        let body_length = name.chars().filter(|next| !prefixes.contains(next)).count();
        if body_length == 0 {
            continue;
        }
        if channellen.is_some_and(|limit| name.chars().count() as u64 > limit) {
            continue;
        }
        found.push(ChannelMention {
            range: start..start + name.len(),
            name: name.to_string(),
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash() -> Vec<String> {
        vec!["#".to_string()]
    }

    fn names(text: &str) -> Vec<String> {
        find_channels(text, &hash(), None)
            .into_iter()
            .map(|mention| mention.name)
            .collect()
    }

    #[test]
    fn finds_only_the_channel_in_a_sentence() {
        let text = "This is a chat line about #cordiale on IRC.";
        let found = find_channels(text, &hash(), None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "#cordiale");
        assert_eq!(&text[found[0].range.clone()], "#cordiale");
    }

    #[test]
    fn needs_a_boundary_before_the_name() {
        assert!(names("word#cordiale").is_empty());
        assert_eq!(names("#cordiale"), ["#cordiale"]);
        assert_eq!(names("(#cordiale)"), ["#cordiale"]);
        assert_eq!(names("\"#cordiale\""), ["#cordiale"]);
    }

    #[test]
    fn leaves_sentence_punctuation_out() {
        assert_eq!(names("Join #cordiale, now"), ["#cordiale"]);
        assert_eq!(names("Join #cordiale."), ["#cordiale"]);
        assert_eq!(names("Is it #cordiale?"), ["#cordiale"]);
        assert_eq!(names("Try #a.b."), ["#a.b"]);
        let text = "Join #cordiale,";
        let found = find_channels(text, &hash(), None);
        assert_eq!(&text[found[0].range.clone()], "#cordiale");
    }

    #[test]
    fn a_link_fragment_is_no_channel() {
        assert!(names("see https://host.example/page#section now").is_empty());
        assert!(names("https://host.example/#section").is_empty());
        assert!(names("www.host.example/a #b").len() == 1);
        assert_eq!(
            names("https://host.example/page#section and #real"),
            ["#real"]
        );
    }

    #[test]
    fn finds_several_names_in_order() {
        let text = "#one, #two and (#three).";
        let found = find_channels(text, &hash(), None);
        let found: Vec<&str> = found.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(found, ["#one", "#two", "#three"]);
    }

    #[test]
    fn a_bare_prefix_is_no_channel() {
        assert!(names("# ").is_empty());
        assert!(names("##").is_empty());
        assert!(names("a # b").is_empty());
    }

    #[test]
    fn follows_the_chantypes_of_the_network() {
        let types = vec!["#".to_string(), "&".to_string()];
        let found = find_channels("go &local or #global", &types, None);
        assert_eq!(found.len(), 2);
        let only_amp = vec!["&".to_string()];
        let found = find_channels("go &local or #global", &only_amp, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "&local");
        assert_eq!(find_channels("##double", &[], None)[0].name, "##double");
    }

    #[test]
    fn respects_the_channel_length_limit() {
        assert!(find_channels("#abcdef", &hash(), Some(5)).is_empty());
        assert_eq!(find_channels("#abcd", &hash(), Some(5)).len(), 1);
    }

    #[test]
    fn keeps_non_ascii_ranges_exact() {
        let text = "è #città, ok";
        let found = find_channels(text, &hash(), None);
        assert_eq!(&text[found[0].range.clone()], "#città");
    }
}
