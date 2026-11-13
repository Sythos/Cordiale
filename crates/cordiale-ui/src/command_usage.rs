// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)

//! How often each slash command ran, to order the command picker. It keeps
//! only the command name, a count and the order of the last use: never the
//! text the user typed after the name. It is separate from the compose
//! history, lives in client memory only and is cleared on sign-out.

use std::collections::HashMap;

use cordiale_core::slash::{matching_commands, CommandInfo};

#[derive(Default)]
struct Usage {
    count: u32,
    /// Position of the last use in the whole session.
    last: u64,
}

#[derive(Default)]
pub(crate) struct CommandUsage {
    by_name: HashMap<&'static str, Usage>,
    clock: u64,
}

impl CommandUsage {
    /// Drops every count (used on sign-out).
    pub(crate) fn clear(&mut self) {
        self.by_name.clear();
        self.clock = 0;
    }

    /// Counts one accepted run of the command `name`.
    pub(crate) fn record(&mut self, name: &'static str) {
        self.clock += 1;
        let usage = self.by_name.entry(name).or_default();
        usage.count = usage.count.saturating_add(1);
        usage.last = self.clock;
    }

    /// The commands that match `prefix`: most used first, the most recently
    /// used first among equal counts, then the table order.
    pub(crate) fn suggestions(&self, prefix: &str) -> Vec<&'static CommandInfo> {
        let mut found = matching_commands(prefix);
        // A stable sort keeps the table order for commands never used.
        found.sort_by_key(|info| {
            let usage = self.by_name.get(info.name);
            std::cmp::Reverse((
                usage.map_or(0, |usage| usage.count),
                usage.map_or(0, |usage| usage.last),
            ))
        });
        found
    }
}

/// The prefix to filter the picker with, when `text` is a command name still
/// being typed: a slash, then letters, with no space and no second slash.
pub(crate) fn picker_prefix(text: &str) -> Option<&str> {
    let prefix = text.strip_prefix('/')?;
    prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric())
        .then_some(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(usage: &CommandUsage, prefix: &str) -> Vec<&'static str> {
        usage
            .suggestions(prefix)
            .iter()
            .map(|info| info.name)
            .collect()
    }

    #[test]
    fn unused_commands_keep_the_table_order() {
        let usage = CommandUsage::default();
        assert_eq!(names(&usage, "ki"), vec!["kick", "kb", "kill"]);
    }

    #[test]
    fn most_used_command_comes_first() {
        let mut usage = CommandUsage::default();
        usage.record("kb");
        assert_eq!(names(&usage, "ki"), vec!["kb", "kick", "kill"]);
        usage.record("kick");
        usage.record("kick");
        assert_eq!(names(&usage, "ki"), vec!["kick", "kb", "kill"]);
    }

    #[test]
    fn equal_counts_put_the_latest_use_first() {
        let mut usage = CommandUsage::default();
        usage.record("kick");
        usage.record("kb");
        assert_eq!(names(&usage, "k"), vec!["kb", "kick", "kill"]);
    }

    #[test]
    fn usage_holds_names_and_counts_only() {
        let mut usage = CommandUsage::default();
        usage.record("join");
        assert_eq!(usage.by_name.len(), 1);
        assert_eq!(usage.by_name["join"].count, 1);
    }

    #[test]
    fn reply_commands_are_in_the_table() {
        for verb in [
            "who", "info", "version", "whois", "whowas", "banlist", "motd", "admin", "invite",
            "lusers",
        ] {
            assert!(
                crate::parse_reply_command(&format!("/{verb} x"), "#c").is_some(),
                "{verb}"
            );
            assert_eq!(
                cordiale_core::slash::accepted_command_name(&format!("/{verb} x")),
                Some(verb)
            );
        }
    }

    #[test]
    fn clear_forgets_the_counts() {
        let mut usage = CommandUsage::default();
        usage.record("kb");
        usage.clear();
        assert_eq!(names(&usage, "ki"), vec!["kick", "kb", "kill"]);
    }

    #[test]
    fn picker_prefix_needs_a_bare_command_word() {
        assert_eq!(picker_prefix("/"), Some(""));
        assert_eq!(picker_prefix("/jo"), Some("jo"));
        assert_eq!(picker_prefix("/join "), None);
        assert_eq!(picker_prefix("//jo"), None);
        assert_eq!(picker_prefix("hello"), None);
        assert_eq!(picker_prefix(""), None);
    }
}
