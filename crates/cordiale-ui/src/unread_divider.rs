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
    let (first, rest) = unread.fold((first, 0), |(first, rest), id| (first.min(id), rest + 1));
    Some((first, rest + 1))
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
    let label = format!("{} — {}", key.0, key.1);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        if ui.get_current_channel_label() != label.as_str() || ui.get_unread_divider_dismissed() {
            return;
        }
        match found {
            Some((id, count)) => {
                ui.set_unread_divider_label(label.into());
                ui.set_unread_divider_count(i32::try_from(count).unwrap_or(i32::MAX));
                ui.set_unread_divider_id(id.to_string().into());
            }
            None => {
                ui.set_unread_divider_id("".into());
                ui.set_unread_divider_count(0);
            }
        }
    });
}
