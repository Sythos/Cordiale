use super::*;

/// Rows asked for around a mention: enough context either side of it.
const AROUND_PAGE: usize = 50;
/// How long the landed message keeps its highlight.
const MENTION_HIGHLIGHT: std::time::Duration = std::time::Duration::from_millis(3000);

fn mention_status(ui: &slint::Weak<AppWindow>, kind: &'static str) {
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_kind(kind.into());
    });
}

/// Opens the window a row of the mentions summary lives in and, when the
/// server gave the row an id (protocol v35), loads the page around it,
/// scrolls to the message and highlights it for a moment. Without an id
/// it stops at the window.
pub(crate) async fn handle_open_mention(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    index: usize,
) {
    let Some(network) = state
        .panels
        .reply_view
        .as_ref()
        .filter(|view| view.kind == "mentions_bundle")
        .map(|view| view.network.clone())
    else {
        return;
    };
    let Some(jump) = state
        .panels
        .mention_jumps
        .get(&network)
        .and_then(|jumps| jumps.get(index))
        .cloned()
        .flatten()
    else {
        return;
    };
    write_back_read_cursor(state);
    let key = match &jump.window {
        MentionWindow::Query(peer) => {
            let Some(query) =
                find_query_window(&state.transcript.query_windows, &network, peer).cloned()
            else {
                mention_status(ui, "mention-window-gone");
                return;
            };
            handle_select_query(state, ui, network.clone(), query.target_nick.clone()).await;
            (query.network, query.target_nick)
        }
        MentionWindow::Channel(name) => {
            let wanted = window_state_key(&network, name);
            let Some(channel) = state
                .windows
                .channel_entries
                .iter()
                .find(|(entry_network, entry_channel, _)| {
                    window_state_key(entry_network, entry_channel) == wanted
                })
                .map(|(_, entry_channel, _)| entry_channel.clone())
            else {
                mention_status(ui, "mention-window-gone");
                return;
            };
            handle_select_channel(state, ui, network.clone(), channel.clone()).await;
            (network.clone(), channel)
        }
    };
    let _ = ui.upgrade_in_event_loop(|ui| ui.set_screen("connected".into()));
    let Some(id) = jump.id else {
        return;
    };
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let rows = match client
        .fetch_messages_around(&token, &key.0, &key.1, id, AROUND_PAGE)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            persistence::log_line(&format!(
                "mention page fetch failed for {}/{}: {error:?}",
                key.0, key.1
            ));
            let gone = error.status().map(|status| status.as_u16()) == Some(404);
            mention_status(
                ui,
                if gone {
                    "mention-not-found"
                } else {
                    "mention-load-failed"
                },
            );
            return;
        }
    };
    // A page entirely older than what the window holds would sit next to
    // the loaded tail with a hole between them that paging back can't fill
    // (it only asks for rows before the oldest id). The window is then
    // rebuilt from the page, and paging back starts again from its oldest row.
    let page_newest = rows
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_i64))
        .max();
    let messages = state.transcript.messages.entry(key.clone()).or_default();
    let loaded_oldest = messages.iter().filter_map(|line| line.message_id).min();
    if matches!((page_newest, loaded_oldest), (Some(page), Some(loaded)) if page < loaded) {
        messages.clear();
        state.transcript.history_start_reached.remove(&key);
        state
            .transcript
            .history_cursors_fetched
            .retain(|(cursor_key, _)| cursor_key != &key);
        let _ = ui.upgrade_in_event_loop(|ui| ui.set_history_start_reached(false));
    }
    let messages = state.transcript.messages.entry(key.clone()).or_default();
    merge_rendered_messages(messages, rows.iter().map(render_history_entry));
    // The reader may have switched window while the page was loading.
    if state.windows.current_channel.as_ref() != Some(&key) {
        return;
    }
    let denoise = state.denoise_active(&key);
    let row = state
        .transcript
        .messages
        .get(&key)
        .and_then(|lines| mention_row(lines, id, denoise));
    let Some(row) = row else {
        mention_status(ui, "mention-not-found");
        return;
    };
    push_chat_lines_update(state, ui, &key);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        // The pane stops following the newest line and goes to the row the
        // way a restored reader position does: by the average row height
        // of what it measured last.
        let rows = ui.get_chat_content_rows();
        let height = ui.get_chat_content_height();
        ui.set_chat_follow_bottom(false);
        if rows > 0 && height > 0.0 {
            restore_chat_anchor(
                &ui,
                ChatAnchor {
                    row,
                    offset: 0.0,
                    row_height: height / rows as f32,
                },
            );
        }
        ui.set_chat_highlight_row(row as i32);
        let weak = ui.as_weak();
        slint::Timer::single_shot(MENTION_HIGHLIGHT, move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_chat_highlight_row(-1);
            }
        });
    });
}

/// The pane row of message `id`: its place among the rows the pane shows
/// (presence noise is left out while Denoise hides it). `None` when the
/// message isn't in the window's rows.
pub(crate) fn mention_row(
    messages: &[RenderedMessage],
    id: i64,
    hide_presence: bool,
) -> Option<usize> {
    messages
        .iter()
        .filter(|message| !(hide_presence && message.presence_noise))
        .position(|message| message.message_id == Some(id))
}
