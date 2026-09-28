// Copyright (c) 2026 Sythos. MIT License.

//! A chat-row Reply inserts a Cicchetto-shaped quote into the draft.
//! The source is the message body, never the rendered timestamp or role glyph.

use cordiale_core::formatting::parse_mirc_text;

const BODY_LIMIT: usize = 100;
const TAIL: &str = " << ";

fn valid_nick(nick: &str) -> bool {
    let mut chars = nick.chars();
    let first = chars.next();
    let special = |ch: char| "[]\\`_^{|}".contains(ch);
    matches!(first, Some(ch) if ch.is_ascii_alphabetic() || special(ch))
        && nick.chars().count() <= 30
        && chars.all(|ch| ch.is_ascii_alphanumeric() || special(ch) || ch == '-')
}

// Cicchetto accepts a narrow pasted timestamp and a real IRC nick wrapper,
// then peels through the last `<< ` marker. A bare shift operator is not one.
fn previous_quote_head_len(text: &str) -> usize {
    let mut start = 0;
    if let Some((clock, rest)) = text.split_once(' ') {
        let parts: Vec<_> = clock.split(':').collect();
        if (parts.len() == 2 || parts.len() == 3)
            && parts[0].len() <= 2
            && !parts[0].is_empty()
            && parts[0].bytes().all(|ch| ch.is_ascii_digit())
            && parts[1].len() == 2
            && parts[1].bytes().all(|ch| ch.is_ascii_digit())
            && (parts.len() == 2
                || (parts[2].len() == 2 && parts[2].bytes().all(|ch| ch.is_ascii_digit())))
        {
            start = text.len() - rest.len();
        }
    }
    let rest = &text[start..];
    let after_head = if let Some(without_bracket) = rest.strip_prefix('<') {
        let Some((nick, after)) = without_bracket.split_once("> ") else {
            return 0;
        };
        let nick = nick.trim_start_matches(['@', '%', '+', '~', '&']);
        if !valid_nick(nick) {
            return 0;
        }
        after
    } else if let Some(without_action) = rest.strip_prefix("* ") {
        let Some((nick, after)) = without_action.split_once(' ') else {
            return 0;
        };
        if !valid_nick(nick) {
            return 0;
        }
        after
    } else {
        return 0;
    };
    let body_start = text.len() - after_head.len();
    let Some(marker) = after_head.rmatch_indices("<<").find_map(|(at, _)| {
        let after = &after_head[at + 2..];
        (after.is_empty() || after.starts_with(' ')).then_some(at)
    }) else {
        return 0;
    };
    body_start + marker + 2 + usize::from(after_head[marker + 2..].starts_with(' '))
}

fn plain_body(raw: &str) -> String {
    parse_mirc_text(raw)
        .into_iter()
        .map(|segment| segment.text)
        .collect::<String>()
}

/// The visible message content with any earlier reply quote stripped.
fn attributed_body(raw: &str) -> Option<(Option<String>, String)> {
    let plain = plain_body(raw);
    let plain = plain.trim();
    let head_len = previous_quote_head_len(plain);
    let body = plain[head_len..].trim();
    if body.is_empty() {
        return None;
    }
    if let Some(rest) = body.strip_prefix('<') {
        if let Some((author, content)) = rest.split_once("> ") {
            if valid_nick(author) {
                return (!content.trim().is_empty())
                    .then(|| (Some(author.to_string()), content.trim().to_string()));
            }
        }
        if let Some(author) = rest.strip_suffix('>') {
            if valid_nick(author) {
                return None;
            }
        }
    }
    Some((None, body.to_string()))
}

/// A nonempty message gets its source author (or relay author) and at most
/// 100 Unicode code points of body, followed by Cicchetto's ` << ` marker.
pub(super) fn reply_quote(nick: &str, raw_body: &str) -> Option<String> {
    if nick.is_empty() {
        return None;
    }
    let (relayed_author, body) = attributed_body(raw_body)?;
    let mut capped: String = body.chars().take(BODY_LIMIT).collect();
    if body.chars().count() > BODY_LIMIT {
        capped.push_str("...");
    }
    let head = relayed_author.map_or_else(|| format!("<{nick}>"), |author| format!("@{author}"));
    Some(format!("{head} {capped}{TAIL}"))
}

/// Repeat Reply without duplicating a trailing marker. Otherwise prepend the
/// quote before existing operator text, leaving the caret after that text.
pub(super) fn draft_with_reply_quote(draft: &str, quote: &str) -> String {
    if draft.ends_with(TAIL) {
        return format!("{}{quote}", &draft[..draft.len() - "<< ".len()]);
    }
    if previous_quote_head_len(draft) > 0 {
        return format!("{draft}{quote}");
    }
    format!("{quote}{draft}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_quotes_plain_message_and_caps_unicode_body() {
        assert_eq!(
            reply_quote("alice", "hello"),
            Some("<alice> hello << ".into())
        );
        assert_eq!(
            reply_quote("alice", "\u{02}hi\u{0f}"),
            Some("<alice> hi << ".into())
        );
        let long = "🙂".repeat(101);
        assert_eq!(
            reply_quote("alice", &long),
            Some(format!("<alice> {}... << ", "🙂".repeat(100)))
        );
    }

    #[test]
    fn reply_ignores_presence_and_old_quote_content() {
        assert_eq!(reply_quote("alice", "   "), None);
        assert_eq!(reply_quote("alice", "<bob> old << "), None);
        assert_eq!(
            reply_quote("alice", "<bob> old << new"),
            Some("<alice> new << ".into())
        );
        assert_eq!(
            reply_quote("alice", "shift << 2"),
            Some("<alice> shift << 2 << ".into())
        );
    }

    #[test]
    fn reply_recovers_bridge_author() {
        assert_eq!(
            reply_quote("relay", "<bob> hello"),
            Some("@bob hello << ".into())
        );
    }

    #[test]
    fn replies_preserve_draft_order_and_one_trailing_marker() {
        assert_eq!(
            draft_with_reply_quote("my answer", "<a> hi << "),
            "<a> hi << my answer"
        );
        assert_eq!(
            draft_with_reply_quote("<a> hi << ", "<b> hey << "),
            "<a> hi <b> hey << "
        );
        assert_eq!(
            draft_with_reply_quote("<a> hi << answer", "<b> hey << "),
            "<a> hi << answer<b> hey << "
        );
    }
}
