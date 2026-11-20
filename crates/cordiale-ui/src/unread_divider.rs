//! The temporary "N unread messages" divider of a channel pane.
//!
//! The divider is visual only. Rust finds the first unread message from the
//! read cursor the channel had when it opened and sends its id and the
//! count to the window. The row with that id draws the line. Nothing here
//! changes a row model, a read cursor, a count or a server event.

use super::*;

/// The first unread message and the number of unread messages in `messages`,
/// given the read cursor the channel had when it opened. A message is unread
/// when its id is higher than the cursor. Rows that Denoise hides are not
/// shown, so they never hold the divider and are not counted. The result is
/// `None` when no shown message is unread.
pub(crate) fn first_unread(
    messages: &[RenderedMessage],
    cursor: i64,
    hide_presence: bool,
) -> Option<(i64, usize)> {
    let mut unread = messages
        .iter()
        .filter(|message| !(hide_presence && message.presence_noise))
        .filter_map(|message| message.message_id)
        .filter(|id| *id > cursor);
    let first = unread.next()?;
    Some((first, unread.count() + 1))
}

/// Remembers the read cursor of a window that opens, before the window reads
/// it. Opening the window that is already open keeps what is stored. Returns
/// true when another window opened, so the divider starts again.
pub(crate) fn remember_baseline(
    state: &mut WorkerState,
    key: &(String, String),
    is_open: bool,
) -> bool {
    let cursor_key = window_state_key(&key.0, &key.1);
    if is_open
        && state
            .windows
            .unread_baseline
            .as_ref()
            .is_some_and(|(stored, _)| *stored == cursor_key)
    {
        return false;
    }
    state.windows.unread_baseline = state
        .windows
        .read_cursors
        .get(&cursor_key)
        .map(|cursor| (cursor_key, *cursor));
    true
}

/// Sets the divider of the open channel from the messages known now. The
/// window ignores it when another window is open or when the user already
/// scrolled. Without a known first unread message the divider is cleared.
pub(crate) fn refresh(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let Some(key) = state.windows.current_channel.clone() else {
        return;
    };
    if state.windows.current_query {
        return;
    }
    let cursor_key = window_state_key(&key.0, &key.1);
    let found = state
        .windows
        .unread_baseline
        .as_ref()
        .filter(|(stored, _)| *stored == cursor_key)
        .and_then(|(_, cursor)| {
            first_unread(
                state.transcript.messages.get(&key)?,
                *cursor,
                state.denoise_active(&key),
            )
        });
    let start = current_placement(state).map(|placement| placement.start_id);
    if start.is_none() {
        state.windows.unread_hold.set(false);
    }
    let label = format!("{} — {}", key.0, key.1);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        if ui.get_current_channel_label() != label.as_str() || ui.get_unread_divider_dismissed() {
            return;
        }
        match found {
            Some((id, count)) => {
                ui.set_unread_divider_label(label.clone().into());
                ui.set_unread_divider_count(i32::try_from(count).unwrap_or(i32::MAX));
                ui.set_unread_divider_id(id.to_string().into());
            }
            None => {
                ui.set_unread_divider_id("".into());
                ui.set_unread_divider_count(0);
            }
        }
        // The pane starts at the first unread message. The pane places
        // itself when the start row or the hold changes.
        let row = start.map_or(-1, |id| row_of(&ui, &id.to_string()));
        ui.set_unread_start_label(label.into());
        ui.set_unread_start_row(row);
        ui.set_unread_start_hold(false);
    });
}

/// How many read chat messages the pane shows above the first unread one.
pub(crate) const CONTEXT_MESSAGES: usize = 3;

/// Where the pane starts when a channel opens with unread messages.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Placement {
    /// The message at the top of the pane.
    pub(crate) start_id: i64,
    /// How many read chat messages sit above the first unread message, up to
    /// `CONTEXT_MESSAGES`. Fewer means older rows may be missing.
    pub(crate) context: usize,
}

/// A chat message has a stable id and is not a join, part, quit, nick or mode
/// line. Date separators are not messages, so they never count.
fn is_chat_message(message: &RenderedMessage) -> bool {
    message.message_id.is_some() && !message.presence_noise
}

/// The message at the top of a pane that starts at the first unread message,
/// given the read cursor the channel had when it opened. The pane shows up to
/// `CONTEXT_MESSAGES` chat messages above the first unread message, and all
/// rows between them. The result is `None` when no shown message is unread.
pub(crate) fn placement(
    messages: &[RenderedMessage],
    cursor: i64,
    hide_presence: bool,
) -> Option<Placement> {
    let shown: Vec<&RenderedMessage> = messages
        .iter()
        .filter(|message| !(hide_presence && message.presence_noise))
        .collect();
    let first = shown
        .iter()
        .position(|message| message.message_id.is_some_and(|id| id > cursor))?;
    let mut start = first;
    let mut context = 0;
    for index in (0..first).rev() {
        if context == CONTEXT_MESSAGES {
            break;
        }
        if is_chat_message(shown[index]) {
            context += 1;
            start = index;
        }
    }
    Some(Placement {
        start_id: shown[start].message_id?,
        context,
    })
}

/// The placement of the open channel from the messages known now, or `None`
/// when no baseline is known or nothing is unread.
pub(crate) fn current_placement(state: &WorkerState) -> Option<Placement> {
    let key = state.windows.current_channel.as_ref()?;
    if state.windows.current_query {
        return None;
    }
    let cursor_key = window_state_key(&key.0, &key.1);
    let (stored, cursor) = state.windows.unread_baseline.as_ref()?;
    if *stored != cursor_key {
        return None;
    }
    placement(
        state.transcript.messages.get(key)?,
        *cursor,
        state.denoise_active(key),
    )
}

/// Whether the open channel starts at an unread message but still lacks read
/// messages above it that the server may hold.
pub(crate) fn needs_older_context(state: &WorkerState) -> bool {
    let Some(key) = state.windows.current_channel.as_ref() else {
        return false;
    };
    current_placement(state).is_some_and(|placement| {
        placement.context < CONTEXT_MESSAGES
            && !state.transcript.history_start_reached.contains(key)
    })
}

/// The read cursor and the unread count after the reader sees the message
/// `visible_id`. The cursor goes through that message and no further, so a
/// later message stays unread. The result is `None` when the message is
/// unknown or already read. The count is the number of known messages after
/// the cursor, and it never grows above `count`.
pub(crate) fn read_through(
    messages: &[RenderedMessage],
    cursor: i64,
    visible_id: i64,
    count: u64,
) -> Option<(i64, u64)> {
    if visible_id <= cursor
        || !messages
            .iter()
            .any(|message| message.message_id == Some(visible_id))
    {
        return None;
    }
    let after = messages
        .iter()
        .filter_map(|message| message.message_id)
        .filter(|id| *id > visible_id)
        .count();
    Some((visible_id, count.min(after as u64)))
}

/// Marks the open channel read through the message with `id`, which the
/// pane shows. Nothing changes while the window is hidden or for a query.
/// The pane sends no row while it waits for its first unread message. Other
/// channels keep their cursor and count.
pub(crate) fn mark_row_visible(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, id: &str) {
    if !state.windows.chat_visible
        || state.windows.current_query
        || open_locked_window(state).is_some()
    {
        return;
    }
    let Ok(id) = id.parse::<i64>() else {
        return;
    };
    let Some((network, channel)) = state.windows.current_channel.clone() else {
        return;
    };
    let cursor = state
        .windows
        .read_cursors
        .get(&window_state_key(&network, &channel))
        .copied()
        .unwrap_or(i64::MIN);
    let counts_key = window_counts_key(&network, &channel);
    let count = state
        .windows
        .window_messages
        .get(&counts_key)
        .copied()
        .unwrap_or(0);
    let Some(messages) = state
        .transcript
        .messages
        .get(&(network.clone(), channel.clone()))
    else {
        return;
    };
    let Some((through, remaining)) = read_through(messages, cursor, id, count) else {
        return;
    };
    if !write_back_read_cursor_through(state, &network, &channel, through) {
        return;
    }
    if count > 0 {
        state.windows.window_messages.insert(counts_key, remaining);
        refresh_network_groups(state, ui);
    }
}

/// The row of the message with `id` in the pane, or -1 when it is not shown.
pub(crate) fn row_of(ui: &AppWindow, id: &str) -> i32 {
    use slint::Model as _;
    ui.get_chat_lines()
        .iter()
        .position(|line| line.reply_id.as_str() == id)
        .and_then(|row| i32::try_from(row).ok())
        .unwrap_or(-1)
}
