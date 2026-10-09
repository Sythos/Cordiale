// Copyright (c) 2026 Sythos. MIT License.

//! Reply keeps the quoted author's channel presence next to the draft, never
//! inside it. The log below only knows what this client observed since it
//! started; whenever identity can't be linked reliably the answer is
//! `Unknown`, never a guess.

use cordiale_core::isupport::CaseMapping;

use super::*;

/// Oldest entries are dropped past this, per channel.
const LOG_CAP: usize = 256;
/// Message positions are kept as long as the transcript keeps the rows.
const MESSAGE_CAP: usize = CHAT_HISTORY_CAP + CHAT_HISTORY_TRIM_SLACK;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Membership {
    Present,
    Left,
    Unknown,
}

/// What this client saw happen to nicks in one channel. `seq` orders the
/// events, so a departure recorded before a rename isn't charged to it.
#[derive(Default)]
pub(crate) struct PresenceLog {
    seq: u64,
    /// Nicks whose occupant went away (part, quit, kick, nick change away).
    vacated: Vec<(String, u64)>,
    /// `(old, new, seq)` observed nick changes.
    renames: Vec<(String, String, u64)>,
    /// Vacated nicks that someone took again: a message by one of these
    /// can't be tied to a single occupant.
    reoccupied: Vec<(String, u64)>,
    /// `(message id, seq)` of the rows seen live: where each one falls among
    /// the events above.
    messages: Vec<(i64, u64)>,
    /// Events up to this seq were dropped to stay in bounds: what happened
    /// before it can't be told any more.
    floor: u64,
}

/// Adds `item`, and gives back the oldest one when the list overflows.
fn push_capped<T>(list: &mut Vec<T>, item: T) -> Option<T> {
    list.push(item);
    (list.len() > LOG_CAP).then(|| list.remove(0))
}

impl PresenceLog {
    fn tick(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn was_vacated(&self, nick: &str, casemapping: CaseMapping) -> bool {
        self.vacated
            .iter()
            .any(|(name, _)| casemapping.nick_eq(name, nick))
    }

    fn vacated_after(&self, nick: &str, seq: u64, casemapping: CaseMapping) -> bool {
        self.vacated
            .iter()
            .any(|(name, at)| *at > seq && casemapping.nick_eq(name, nick))
    }

    fn reoccupied_after(&self, nick: &str, seq: u64, casemapping: CaseMapping) -> bool {
        self.reoccupied
            .iter()
            .any(|(name, at)| *at > seq && casemapping.nick_eq(name, nick))
    }

    fn arrive(&mut self, nick: &str, seq: u64, casemapping: CaseMapping) {
        if self.was_vacated(nick, casemapping) {
            if let Some((_, dropped)) = push_capped(&mut self.reoccupied, (nick.to_string(), seq)) {
                self.floor = self.floor.max(dropped);
            }
        }
    }

    pub(crate) fn note_message(&mut self, id: i64) {
        if self.messages.iter().all(|(known, _)| *known != id) {
            let seq = self.seq;
            self.messages.push((id, seq));
            if self.messages.len() > MESSAGE_CAP {
                self.messages.remove(0);
            }
        }
    }

    /// Where a message falls among the events; 0 (before everything seen)
    /// for one this client didn't see arrive.
    fn seq_of(&self, id: i64) -> u64 {
        self.messages
            .iter()
            .find(|(known, _)| *known == id)
            .map_or(0, |(_, seq)| *seq)
    }

    pub(crate) fn note_join(&mut self, nick: &str, casemapping: CaseMapping) {
        let seq = self.tick();
        self.arrive(nick, seq, casemapping);
    }

    pub(crate) fn note_departure(&mut self, nick: &str) {
        let seq = self.tick();
        if let Some((_, dropped)) = push_capped(&mut self.vacated, (nick.to_string(), seq)) {
            self.floor = self.floor.max(dropped);
        }
    }

    /// Whether observed renames lead from `from` to `to`.
    fn renames_reach(&self, from: &str, to: &str, casemapping: CaseMapping) -> bool {
        let mut current = from;
        let mut after = 0;
        for _ in 0..=LOG_CAP {
            if casemapping.nick_eq(current, to) {
                return true;
            }
            let Some((next, at)) = self.rename_of(current, after, casemapping) else {
                return false;
            };
            current = next;
            after = at;
        }
        false
    }

    pub(crate) fn note_rename(&mut self, old: &str, new: &str, casemapping: CaseMapping) {
        let seq = self.tick();
        // Going back to an earlier nick of the same person isn't a reuse.
        if !self.renames_reach(new, old, casemapping) {
            self.arrive(new, seq, casemapping);
        }
        if let Some((_, dropped)) = push_capped(&mut self.vacated, (old.to_string(), seq)) {
            self.floor = self.floor.max(dropped);
        }
        if let Some((_, _, dropped)) =
            push_capped(&mut self.renames, (old.to_string(), new.to_string(), seq))
        {
            self.floor = self.floor.max(dropped);
        }
    }

    fn rename_of(&self, nick: &str, after: u64, casemapping: CaseMapping) -> Option<(&str, u64)> {
        self.renames
            .iter()
            .rev()
            .find(|(old, _, at)| *at > after && casemapping.nick_eq(old, nick))
            .map(|(_, new, at)| (new.as_str(), *at))
    }

    /// The author's current nick and whether they are in the channel.
    /// `frozen` means the nick was reused, so the historical nick stays and
    /// no later event is attributed to the same person.
    pub(crate) fn resolve(
        &self,
        author: &str,
        roster: &[MemberEntry],
        casemapping: CaseMapping,
        since: u64,
    ) -> (String, Membership, bool) {
        // The roster's own spelling, which is the nick to quote.
        let in_roster = |nick: &str| {
            roster
                .iter()
                .find(|(name, _)| casemapping.nick_eq(name, nick))
                .map(|(name, _)| name.clone())
        };
        let mut current = author.to_string();
        // Dropped evidence can't be read either way: keep the historical nick.
        if since < self.floor {
            return (author.to_string(), Membership::Unknown, true);
        }
        // Only what happened after the replied-to message counts.
        let mut linked_at = since;
        for _ in 0..=LOG_CAP {
            // A nick taken by someone else after the link names another person.
            if self.reoccupied_after(&current, linked_at, casemapping) {
                break;
            }
            if let Some(name) = in_roster(&current) {
                return (name, Membership::Present, false);
            }
            if let Some((next, at)) = self.rename_of(&current, linked_at, casemapping) {
                current = next.to_string();
                linked_at = at;
                continue;
            }
            let left = self.vacated_after(&current, linked_at, casemapping);
            let presence = if left {
                Membership::Left
            } else {
                Membership::Unknown
            };
            return (current, presence, false);
        }
        (author.to_string(), Membership::Unknown, true)
    }
}

/// The pending reply of one channel draft.
pub(crate) struct ReplyContext {
    /// The nick the quote currently names.
    nick: String,
    /// The exact quote text inserted into the draft.
    quote: String,
    presence: Membership,
    /// Presence was confirmed at some point, so a refreshed roster without
    /// the nick means they left.
    seen_present: bool,
    /// The quote has been seen in the stored draft; until then a draft
    /// without it is an edit made before the quote arrived.
    confirmed: bool,
    /// The nick was reused: don't follow it.
    frozen: bool,
}

impl ReplyContext {
    pub(crate) fn left(&self) -> bool {
        self.presence == Membership::Left
    }

    pub(crate) fn quote(&self) -> &str {
        &self.quote
    }
}

fn quote_head(nick: &str) -> String {
    format!("<{nick}> ")
}

/// Builds the context for a quote just inserted for `author`'s message, and
/// the quote naming their current nick. A relayed (`@author`) quote has no
/// context: its author is not a channel member.
pub(crate) fn new_reply(
    log: &PresenceLog,
    roster: &[MemberEntry],
    casemapping: CaseMapping,
    author: &str,
    body: &str,
    message_id: Option<i64>,
) -> Option<(String, Option<ReplyContext>)> {
    let since = message_id.map_or(0, |id| log.seq_of(id));
    let (nick, presence, frozen) = log.resolve(author, roster, casemapping, since);
    let quote = reply::reply_quote(&nick, body)?;
    let context = quote.starts_with(&quote_head(&nick)).then(|| ReplyContext {
        nick,
        quote: quote.clone(),
        presence,
        seen_present: presence == Membership::Present,
        confirmed: false,
        frozen,
    });
    Some((quote, context))
}

/// Swaps the nick in the quote head, leaving everything else of the draft
/// alone. `None` when the quote is not in the draft any more.
pub(crate) fn rename_in_draft(draft: &str, quote: &str, old: &str, new: &str) -> Option<String> {
    let at = draft.rfind(quote)?;
    let head = quote_head(old);
    let renamed = format!("{}{}", quote_head(new), quote.strip_prefix(&head)?);
    Some(format!(
        "{}{renamed}{}",
        &draft[..at],
        &draft[at + quote.len()..]
    ))
}

impl ReplyContext {
    pub(crate) fn on_departure(&mut self, nick: &str, casemapping: CaseMapping) {
        if !self.frozen && casemapping.nick_eq(&self.nick, nick) {
            self.presence = Membership::Left;
        }
    }

    /// Follows a nick change of the quoted member and returns the nick it
    /// had, when the quote has to be rewritten.
    pub(crate) fn on_rename(
        &mut self,
        old: &str,
        new: &str,
        casemapping: CaseMapping,
    ) -> Option<String> {
        if self.frozen || self.presence == Membership::Left || !casemapping.nick_eq(&self.nick, old)
        {
            return None;
        }
        let previous = std::mem::replace(&mut self.nick, new.to_string());
        self.presence = Membership::Present;
        self.seen_present = true;
        Some(previous)
    }

    pub(crate) fn on_roster(&mut self, roster: &[MemberEntry], casemapping: CaseMapping) {
        if self.frozen || self.presence == Membership::Left {
            return;
        }
        if roster
            .iter()
            .any(|(name, _)| casemapping.nick_eq(name, &self.nick))
        {
            self.presence = Membership::Present;
            self.seen_present = true;
        } else if self.seen_present {
            self.presence = Membership::Left;
        }
    }

    /// Checks the stored draft against the quote; false once a quote that
    /// was there is gone.
    pub(crate) fn in_draft(&mut self, draft: &str) -> bool {
        if draft.contains(&self.quote) {
            self.confirmed = true;
            return true;
        }
        !self.confirmed
    }

    /// Records the quote after a head rewrite.
    pub(crate) fn set_quote(&mut self, quote: String) {
        self.quote = quote;
    }
}

/// Whether the current channel's pending reply targets someone who left.
pub(crate) fn target_left(state: &WorkerState) -> bool {
    if state.windows.current_query {
        return false;
    }
    state
        .windows
        .current_channel
        .as_ref()
        .and_then(|key| state.transcript.reply_contexts.get(key))
        .is_some_and(ReplyContext::left)
}

pub(crate) fn push_reply_presence(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let left = target_left(state);
    let _ = ui.upgrade_in_event_loop(move |ui| ui.set_reply_target_left(left));
}

/// Keeps `text` as the draft of `key`; a reply whose quote has left the draft
/// is over.
pub(crate) fn store_draft(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    key: (String, String),
    text: String,
) {
    let reply_over = state
        .transcript
        .reply_contexts
        .get_mut(&key)
        .is_some_and(|context| !context.in_draft(&text));
    if reply_over {
        state.transcript.reply_contexts.remove(&key);
        push_reply_presence(state, ui);
    }
    if text.is_empty() {
        state.transcript.drafts.remove(&key);
    } else {
        state.transcript.drafts.insert(key, text);
    }
}

/// Reply on a chat row: quotes the author by the nick they have now (when an
/// observed nick change says so), puts the quote into the draft and starts
/// watching the author's presence in the channel. A private window keeps the
/// plain quote and no watch.
pub(crate) fn start_reply(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    nick: &str,
    body: &str,
    message_id: Option<i64>,
) {
    let draft_key = state.windows.current_channel.clone();
    let channel_key = draft_key.clone().filter(|_| !state.windows.current_query);
    let (quote, context) = match &channel_key {
        Some(key) => {
            let casemapping = network_casemapping(state, &key.0);
            let empty_log = PresenceLog::default();
            let log = state.transcript.presence_log.get(key).unwrap_or(&empty_log);
            let roster = state
                .transcript
                .members
                .get(key)
                .map(Vec::as_slice)
                .unwrap_or_default();
            match new_reply(log, roster, casemapping, nick, body, message_id) {
                Some(built) => built,
                None => return,
            }
        }
        None => match reply::reply_quote(nick, body) {
            Some(quote) => (quote, None),
            None => return,
        },
    };
    let current = draft_key
        .as_ref()
        .and_then(|key| state.transcript.drafts.get(key))
        .map(String::as_str)
        .unwrap_or_default();
    // What the stored draft looks like for now; the open field is merged below.
    let stored = reply::draft_with_reply_quote(current, &quote);
    if let Some(key) = &draft_key {
        state.transcript.drafts.insert(key.clone(), stored.clone());
    }
    if let Some(key) = channel_key {
        match context {
            Some(context) => state.transcript.reply_contexts.insert(key, context),
            None => state.transcript.reply_contexts.remove(&key),
        };
    }
    let left = target_left(state);
    let worker = state.conn.chat_rebuild_tx.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        // Edits typed after the click are already in the field: put the quote
        // into what is there now, and only into the window it was asked for.
        let label = draft_key
            .as_ref()
            .map(|(network, window)| format!("{network} — {window}"));
        if label.is_none_or(|label| ui.get_current_channel_label() == label.as_str()) {
            let draft = reply::draft_with_reply_quote(ui.get_compose_text().as_str(), &quote);
            ui.set_compose_text(draft.clone().into());
            // A programmatic write doesn't emit `edited`; tell the worker, keyed.
            if let (Some(worker), Some(key)) = (worker, draft_key) {
                let _ = worker.send(WorkerCommand::DraftSynced { key, text: draft });
            }
            // Focus the field and put the caret after the quote, now that it's there.
            ui.set_compose_focus_request(ui.get_compose_focus_request() + 1);
        }
        ui.set_reply_target_left(left);
    });
}

/// Feeds one join/part/quit/kick/nick_change frame to the presence log and
/// to the pending reply of `key`. Returns the rewrite (old quote, new quote)
/// to apply to the draft when the quoted member changed nick.
pub(crate) fn track_frame(
    state: &mut WorkerState,
    key: &(String, String),
    payload: &Value,
) -> Option<(String, String)> {
    let kind = payload.get("kind").and_then(Value::as_str)?;
    let casemapping = network_casemapping(state, &key.0);
    let actor = payload
        .get("from")
        .or_else(|| payload.get("nick"))
        .or_else(|| payload.get("sender"))
        .and_then(Value::as_str);
    let log = state
        .transcript
        .presence_log
        .entry(key.clone())
        .or_default();
    if let Some(id) = message_id(payload) {
        log.note_message(id);
    }
    let context = state.transcript.reply_contexts.get_mut(key);
    match kind {
        "join" => {
            log.note_join(actor?, casemapping);
            None
        }
        "part" | "quit" => {
            let nick = actor?;
            log.note_departure(nick);
            context?.on_departure(nick, casemapping);
            None
        }
        "kick" => {
            let nick = payload
                .get("meta")
                .and_then(|meta| meta.get("target"))
                .and_then(Value::as_str)?;
            log.note_departure(nick);
            context?.on_departure(nick, casemapping);
            None
        }
        "nick_change" => {
            let old = actor?;
            let new = payload
                .get("meta")
                .and_then(|meta| meta.get("new_nick"))
                .and_then(Value::as_str)?;
            log.note_rename(old, new, casemapping);
            let context = context?;
            let previous = context.on_rename(old, new, casemapping)?;
            let before = context.quote().to_string();
            let after = quote_head(new) + before.strip_prefix(&quote_head(&previous))?;
            context.set_quote(after.clone());
            Some((before, after))
        }
        _ => None,
    }
}

/// Re-checks the pending reply of `key` against a refreshed roster.
pub(crate) fn refresh_roster(state: &mut WorkerState, key: &(String, String)) {
    let casemapping = network_casemapping(state, &key.0);
    let roster = state
        .transcript
        .members
        .get(key)
        .cloned()
        .unwrap_or_default();
    if let Some(context) = state.transcript.reply_contexts.get_mut(key) {
        context.on_roster(&roster, casemapping);
    }
}

/// Puts a quote rewrite into the draft of `key`: the stored draft, and the
/// compose field when that channel is open.
pub(crate) fn apply_draft_rewrite(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    key: &(String, String),
    rewrite: (String, String),
) {
    let (before, after) = rewrite;
    let rename = move |draft: &str| -> Option<String> {
        let old = before.strip_prefix('<')?.split_once("> ")?.0;
        let new = after.strip_prefix('<')?.split_once("> ")?.0;
        rename_in_draft(draft, &before, old, new)
    };
    // The stored draft changes at once, under its own key, so a channel switch
    // already queued can't file the rewrite under another channel.
    if let Some(draft) = state
        .transcript
        .drafts
        .get(key)
        .and_then(|draft| rename(draft))
    {
        state.transcript.drafts.insert(key.clone(), draft);
    }
    if state.windows.current_channel.as_ref() == Some(key) && !state.windows.current_query {
        let _ = ui.upgrade_in_event_loop(move |ui| {
            if let Some(draft) = rename(ui.get_compose_text().as_str()) {
                ui.set_compose_text(draft.into());
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CM: CaseMapping = CaseMapping::Rfc1459;

    fn roster(nicks: &[&str]) -> Vec<MemberEntry> {
        nicks
            .iter()
            .map(|nick| (nick.to_string(), String::new()))
            .collect()
    }

    #[test]
    fn present_author_keeps_their_nick() {
        let log = PresenceLog::default();
        let (nick, presence, frozen) = log.resolve("Alice", &roster(&["alice"]), CM, 0);
        assert_eq!(
            (nick.as_str(), presence, frozen),
            ("alice", Membership::Present, false)
        );
    }

    #[test]
    fn departure_is_only_claimed_when_observed() {
        let mut log = PresenceLog::default();
        let (_, presence, _) = log.resolve("alice", &roster(&["bob"]), CM, 0);
        assert_eq!(presence, Membership::Unknown);
        log.note_departure("alice");
        let (_, presence, _) = log.resolve("alice", &roster(&["bob"]), CM, 0);
        assert_eq!(presence, Membership::Left);
    }

    #[test]
    fn chained_renames_resolve_to_the_current_nick() {
        let mut log = PresenceLog::default();
        log.note_rename("alice", "alice2", CM);
        log.note_rename("alice2", "alice3", CM);
        let (nick, presence, _) = log.resolve("alice", &roster(&["alice3"]), CM, 0);
        assert_eq!((nick.as_str(), presence), ("alice3", Membership::Present));
        log.note_departure("alice3");
        let (nick, presence, _) = log.resolve("alice", &roster(&[]), CM, 0);
        assert_eq!((nick.as_str(), presence), ("alice3", Membership::Left));
    }

    #[test]
    fn a_nick_taken_over_after_a_rename_is_not_the_renamed_person() {
        let mut log = PresenceLog::default();
        log.note_rename("alice", "bob", CM);
        log.note_departure("bob");
        log.note_join("bob", CM);
        let (nick, presence, frozen) = log.resolve("alice", &roster(&["bob"]), CM, 0);
        assert_eq!(
            (nick.as_str(), presence, frozen),
            ("alice", Membership::Unknown, true)
        );

        // A nick that was taken before the rename doesn't spoil the link.
        let mut log = PresenceLog::default();
        log.note_departure("bob");
        log.note_rename("alice", "bob", CM);
        let (nick, presence, frozen) = log.resolve("alice", &roster(&["bob"]), CM, 0);
        assert_eq!(
            (nick.as_str(), presence, frozen),
            ("bob", Membership::Present, false)
        );
    }

    #[test]
    fn a_message_sent_after_the_nick_was_reused_belongs_to_the_new_occupant() {
        let mut log = PresenceLog::default();
        log.note_message(1);
        log.note_departure("alice");
        log.note_join("alice", CM);
        log.note_message(2);
        let roster = roster(&["alice"]);
        let old = new_reply(&log, &roster, CM, "alice", "hi", Some(1)).expect("quote");
        assert!(old.1.is_some_and(|context| !context.left()));
        let (_, presence, frozen) = log.resolve("alice", &roster, CM, log.seq_of(1));
        assert_eq!((presence, frozen), (Membership::Unknown, true));
        let (_, presence, frozen) = log.resolve("alice", &roster, CM, log.seq_of(2));
        assert_eq!((presence, frozen), (Membership::Present, false));
    }

    #[test]
    fn dropped_evidence_freezes_older_messages_only() {
        let mut log = PresenceLog::default();
        log.note_message(1);
        for index in 0..=LOG_CAP {
            log.note_departure(&format!("user{index}"));
        }
        log.note_message(2);
        let roster = roster(&["alice"]);
        let (_, presence, frozen) = log.resolve("alice", &roster, CM, log.seq_of(1));
        assert_eq!((presence, frozen), (Membership::Unknown, true));
        let (_, presence, frozen) = log.resolve("alice", &roster, CM, log.seq_of(2));
        assert_eq!((presence, frozen), (Membership::Present, false));
    }

    #[test]
    fn returning_to_an_earlier_nick_keeps_the_identity() {
        let mut log = PresenceLog::default();
        log.note_rename("alice", "bob", CM);
        log.note_rename("bob", "alice", CM);
        let (nick, presence, frozen) = log.resolve("alice", &roster(&["alice"]), CM, 0);
        assert_eq!(
            (nick.as_str(), presence, frozen),
            ("alice", Membership::Present, false)
        );
        log.note_departure("alice");
        let (_, presence, frozen) = log.resolve("alice", &roster(&[]), CM, 0);
        assert_eq!((presence, frozen), (Membership::Left, false));
    }

    #[test]
    fn an_earlier_departure_is_not_charged_to_a_later_rename() {
        let mut log = PresenceLog::default();
        log.note_departure("alice2");
        log.note_rename("alice", "alice2", CM);
        let (nick, presence, _) = log.resolve("alice", &roster(&[]), CM, 0);
        assert_eq!((nick.as_str(), presence), ("alice2", Membership::Unknown));
    }

    #[test]
    fn a_reused_nick_is_never_linked() {
        let mut log = PresenceLog::default();
        log.note_departure("alice");
        log.note_join("alice", CM);
        let (nick, presence, frozen) = log.resolve("alice", &roster(&["alice"]), CM, 0);
        assert_eq!(
            (nick.as_str(), presence, frozen),
            ("alice", Membership::Unknown, true)
        );

        let mut log = PresenceLog::default();
        log.note_rename("alice", "bob", CM);
        log.note_join("alice", CM);
        let (nick, presence, frozen) = log.resolve("alice", &roster(&["alice", "bob"]), CM, 0);
        assert_eq!(
            (nick.as_str(), presence, frozen),
            ("alice", Membership::Unknown, true)
        );
    }

    #[test]
    fn reply_follows_rename_and_leave_without_touching_the_answer() {
        let log = PresenceLog::default();
        let (quote, context) =
            new_reply(&log, &roster(&["alice"]), CM, "alice", "hello", None).expect("quote");
        let mut context = context.expect("context");
        assert_eq!(quote, "<alice> hello << ");
        assert!(!context.left());

        let previous = context.on_rename("alice", "alice_", CM).expect("followed");
        assert_eq!(previous, "alice");
        let rewritten = rename_in_draft(
            "<alice> hello << my <alice> answer",
            "<alice> hello << ",
            "alice",
            "alice_",
        );
        assert_eq!(
            rewritten.as_deref(),
            Some("<alice_> hello << my <alice> answer")
        );
        assert_eq!(
            rename_in_draft("edited", "<alice> hello << ", "alice", "alice_"),
            None
        );

        context.on_departure("ALICE_", CM);
        assert!(context.left());
        // Coming back doesn't clear a departure that was seen.
        context.on_roster(&roster(&["alice_"]), CM);
        assert!(context.left());
    }

    #[test]
    fn relayed_quotes_have_no_context() {
        let log = PresenceLog::default();
        let (quote, context) =
            new_reply(&log, &roster(&["relay"]), CM, "relay", "<bob> hi", None).expect("quote");
        assert_eq!(quote, "@bob hi << ");
        assert!(context.is_none());
    }

    #[test]
    fn refreshed_roster_only_flags_a_member_seen_present() {
        let log = PresenceLog::default();
        let (_, unseen) = new_reply(&log, &roster(&[]), CM, "alice", "hi", None).expect("quote");
        let mut unseen = unseen.expect("context");
        unseen.on_roster(&roster(&["bob"]), CM);
        assert!(!unseen.left());

        let (_, seen) =
            new_reply(&log, &roster(&["alice"]), CM, "alice", "hi", None).expect("quote");
        let mut seen = seen.expect("context");
        seen.on_roster(&roster(&["bob"]), CM);
        assert!(seen.left());
    }
}
