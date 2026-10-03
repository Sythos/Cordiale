use super::*;

/// The synthetic server window is absent from `boot.channels`; like Cicchetto,
/// load its scrollback explicitly and merge it with any already received push.
pub(crate) async fn fetch_server_window_history(state: &mut WorkerState, network: &str) -> bool {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return false;
    };
    let key = (network.to_string(), SERVER_WINDOW_NAME.to_string());
    let after_id = query_high_water_id(state, &key);
    let rows = client
        .fetch_messages(
            &token,
            network,
            SERVER_WINDOW_NAME,
            after_id,
            after_id.map(|_| 200),
        )
        .await;
    match rows {
        Ok(rows) => {
            merge_query_history(state, &key, &rows);
            true
        }
        Err(error) => {
            persistence::log_line(&format!(
                "server window history fetch failed for {network}: {error:?}"
            ));
            false
        }
    }
}

/// Grappa leaves presence rows out of the history pages it serves while a
/// channel hides them, so a window loaded in that state has none to show
/// when Denoise goes off. Reads the newest page again and merges it in.
pub(crate) async fn reload_history_tail(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    key: &(String, String),
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let rows = match client
        .fetch_messages(&token, &key.0, &key.1, None, Some(CATCH_UP_PAGE))
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            persistence::log_line(&format!(
                "history reload failed for {}/{}: {error:?}",
                key.0, key.1
            ));
            return;
        }
    };
    let messages = state.transcript.messages.entry(key.clone()).or_default();
    merge_rendered_messages(messages, rows.iter().map(render_history_entry));
    if !state.current_query && state.current_channel.as_ref() == Some(key) {
        push_chat_lines_update(state, ui, key);
    }
}

/// Pages the open window's history back from its oldest known message
/// (`?before=`), like Cicchetto's scroll-to-top: the chat pane asks for it
/// when the reader reaches the oldest loaded line. A short page, or one
/// that brings nothing older, means the first message was reached; a
/// cursor already fetched is never asked for again.
pub(crate) async fn handle_load_older_history(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
) {
    // Every way out clears `history-loading`, and none of them lets the
    // pane ask again straight away: a failure waits for the reader, and a
    // window with nothing older to fetch is marked as fully loaded.
    let finish = |failed: bool, start_reached: bool| {
        let _ = ui.upgrade_in_event_loop(move |ui| {
            if start_reached {
                ui.set_history_start_reached(true);
            }
            ui.set_history_failed(failed);
            ui.set_history_loading(false);
        });
    };
    let (Some(client), Some(token), Some(key)) = (
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.current_channel.clone(),
    ) else {
        finish(true, false);
        return;
    };
    let oldest = state
        .transcript
        .messages
        .get(&key)
        .and_then(|lines| lines.iter().filter_map(|line| line.message_id).min());
    // No line with a Grappa id (a server window), or a cursor already
    // fetched: there is no page left to ask for.
    let Some(oldest) = oldest.filter(|oldest| {
        !state
            .transcript
            .history_cursors_fetched
            .contains(&(key.clone(), *oldest))
    }) else {
        state.transcript.history_start_reached.insert(key);
        finish(false, true);
        return;
    };
    let rows = client
        .fetch_messages_before(&token, &key.0, &key.1, oldest, OLDER_HISTORY_PAGE)
        .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(err) => {
            persistence::log_line(&format!("older history fetch failed: {err:?}"));
            if state.current_channel.as_ref() == Some(&key) {
                finish(true, false);
            }
            return;
        }
    };
    state
        .transcript
        .history_cursors_fetched
        .insert((key.clone(), oldest));
    let messages = state.transcript.messages.entry(key.clone()).or_default();
    let position_of_oldest = |lines: &[RenderedMessage]| {
        lines
            .iter()
            .position(|line| line.message_id == Some(oldest))
    };
    let old_rows = messages.len();
    let before = position_of_oldest(messages);
    merge_rendered_messages(messages, rows.iter().map(render_history_entry));
    let prepended = match (before, position_of_oldest(messages)) {
        (Some(before), Some(after)) => after.saturating_sub(before),
        _ => 0,
    };
    let start_reached = rows.len() < OLDER_HISTORY_PAGE || prepended == 0;
    if start_reached {
        state.transcript.history_start_reached.insert(key.clone());
    }
    publish_held_rows(state);
    // The user may have switched window while the page was loading.
    if state.current_channel.as_ref() != Some(&key) {
        return;
    }
    let lines = state
        .transcript
        .messages
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let roster = (!state.current_query).then(|| {
        (
            state
                .transcript
                .members
                .get(&key)
                .cloned()
                .unwrap_or_default(),
            network_casemapping(state, &key.0),
            state.denoise_active(&key),
        )
    });
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let model = match roster {
            Some((members, casemapping, denoise)) => {
                chat_lines_model_with_roster(&lines, dark_theme, &members, casemapping, denoise)
            }
            None => chat_lines_model(&lines, dark_theme),
        };
        // The page goes in above what's on screen, and
        // `current-channel-label` (appwindow.slint's cue for a real window
        // switch) isn't touched, so the pane doesn't jump to the newest
        // line. A pane following the newest line stays on it; otherwise
        // the line the reader had at the top is put back there.
        let anchor = (!ui.get_chat_follow_bottom())
            .then(|| {
                prepend_scroll_anchor(
                    ui.get_chat_scroll_y(),
                    ui.get_chat_content_height(),
                    old_rows,
                    prepended,
                )
            })
            .flatten();
        show_chat_lines(&ui, model);
        ui.set_history_start_reached(start_reached);
        if let Some(anchor) = anchor {
            restore_chat_anchor(&ui, anchor);
        }
        ui.set_history_failed(false);
        ui.set_history_loading(false);
    });
}

/// The top line moves down by `prepended` rows when that many older lines
/// go in above the `old_rows` the pane had.
pub(crate) fn prepend_scroll_anchor(
    scroll_y: f32,
    content_height: f32,
    old_rows: usize,
    prepended: usize,
) -> Option<ChatAnchor> {
    if prepended == 0 {
        return None;
    }
    let anchor = top_line_anchor(scroll_y, content_height, old_rows, old_rows)?;
    Some(ChatAnchor {
        row: anchor.row + prepended,
        ..anchor
    })
}

/// Renders one `boot.heads` scrollback row the same way a live frame would
/// be, minus the `event`/`topic` envelope a bootstrap history row doesn't
/// have.
pub(crate) fn render_history_entry(value: &Value) -> RenderedMessage {
    render_message(value, None)
}

pub(crate) fn query_high_water_id(state: &WorkerState, key: &(String, String)) -> Option<i64> {
    state
        .transcript
        .messages
        .get(key)?
        .iter()
        .filter_map(|message| message.message_id)
        .max()
}

pub(crate) fn catch_up_plan(gap: u64) -> CatchUpPlan {
    if gap == 0 {
        CatchUpPlan::Nothing
    } else if gap > CATCH_UP_PAGE as u64 {
        CatchUpPlan::ReloadTail
    } else {
        CatchUpPlan::PageForward
    }
}

/// Notes, when the socket drops, the newest message id of every joined
/// channel: the point its catch-up resumes from. An anchor already noted
/// stays (a second drop before the catch-up ran must not skip rows).
pub(crate) fn note_catch_up_anchors(state: &mut WorkerState) {
    let anchors: Vec<((String, String), i64)> = state
        .channel_entries
        .iter()
        .filter(|(network, channel, _)| {
            state.window_states.get(&window_state_key(network, channel))
                == Some(&ChannelWindowState::Joined)
        })
        .filter_map(|(network, channel, _)| {
            let key = (network.clone(), channel.clone());
            let id = query_high_water_id(state, &key)?;
            Some((key, id))
        })
        .collect();
    for (key, id) in anchors {
        state.transcript.catch_up_anchors.entry(key).or_insert(id);
    }
}

/// Backfills the next queued channel, then schedules the one after it: the
/// requests go out one at a time and spaced out, never as a burst.
pub(crate) async fn handle_catch_up_next(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    worker_self: &mpsc::UnboundedSender<WorkerCommand>,
) {
    if state.conn.session.is_none() {
        state.transcript.catch_up_anchors.clear();
        return;
    }
    let Some((key, anchor)) = state.transcript.catch_up_anchors.pop_first() else {
        return;
    };
    catch_up_channel(state, ui, &key, anchor).await;
    if !state.transcript.catch_up_anchors.is_empty() {
        let next = worker_self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(CATCH_UP_PACING).await;
            let _ = next.send(WorkerCommand::CatchUpNext);
        });
    }
}

/// Fetches what `key` missed after message `anchor` while the socket was
/// down. A gap of up to one page is read with `?after=`; a bigger one
/// replaces the window with the newest page and leaves a note where the
/// hole is, which scrolling up fills, like Cicchetto's far-behind reload.
async fn catch_up_channel(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    key: &(String, String),
    anchor: i64,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let plan = match client
        .fetch_messages_count(&token, &key.0, &key.1, anchor, Some(CATCH_UP_PROBE_CAP))
        .await
    {
        Ok(gap) => catch_up_plan(gap),
        // A server without the probe still answers `?after=`.
        Err(error) if error.status() == Some(cordiale_core::client::StatusCode::NOT_FOUND) => {
            CatchUpPlan::PageForward
        }
        Err(error) => {
            persistence::log_line(&format!(
                "catch-up probe failed for {}/{}: {error:?}",
                key.0, key.1
            ));
            return;
        }
    };
    let rows = match plan {
        CatchUpPlan::Nothing => return,
        CatchUpPlan::PageForward => {
            client
                .fetch_messages(&token, &key.0, &key.1, Some(anchor), Some(CATCH_UP_PAGE))
                .await
        }
        CatchUpPlan::ReloadTail => {
            client
                .fetch_messages(&token, &key.0, &key.1, None, Some(CATCH_UP_PAGE))
                .await
        }
    };
    let rows = match rows {
        Ok(rows) => rows,
        Err(error) => {
            persistence::log_line(&format!(
                "catch-up fetch failed for {}/{}: {error:?}",
                key.0, key.1
            ));
            return;
        }
    };
    // The awaits above can outlast the session or the channel membership.
    if state.conn.session.is_none()
        || state.window_states.get(&window_state_key(&key.0, &key.1))
            != Some(&ChannelWindowState::Joined)
    {
        return;
    }
    let incoming: Vec<RenderedMessage> = rows.iter().map(render_history_entry).collect();
    if incoming.is_empty() {
        return;
    }
    let messages = state.transcript.messages.entry(key.clone()).or_default();
    if plan == CatchUpPlan::ReloadTail {
        replace_with_history_tail(messages, incoming);
        state.transcript.history_start_reached.remove(key);
        state
            .transcript
            .history_cursors_fetched
            .retain(|(window, _)| window != key);
    } else {
        merge_rendered_messages(messages, incoming);
    }
    if !state.current_query && state.current_channel.as_ref() == Some(key) {
        push_members_update(state, ui, key);
        if plan == CatchUpPlan::ReloadTail {
            let _ = ui.upgrade_in_event_loop(|ui| ui.set_history_start_reached(false));
        }
    }
}

/// Swaps a window's rows for the newest page, keeping the rows that came
/// in live after it, and puts a note above the page where the skipped
/// stretch is. The skipped rows are below what `?before=` pages from, so
/// scrolling up fills them in.
pub(crate) fn replace_with_history_tail(
    messages: &mut Vec<RenderedMessage>,
    tail: Vec<RenderedMessage>,
) {
    let newest = tail.iter().filter_map(|message| message.message_id).max();
    let first = tail
        .iter()
        .min_by(|a, b| compare_rendered_message_order(a, b));
    let (Some(newest), Some(first)) = (newest, first) else {
        return;
    };
    let note = RenderedMessage {
        timestamp: first.timestamp.clone(),
        nick: None,
        text: format!(
            "… more than {CATCH_UP_PAGE} messages were missed while disconnected; scroll up to load them"
        ),
        italic: true,
        message_id: None,
        server_time: first.server_time,
        presence_noise: false,
    };
    messages.retain(|message| message.message_id.is_some_and(|id| id > newest));
    merge_rendered_messages(messages, tail.into_iter().chain(std::iter::once(note)));
}

/// How many rows to drop from the old end of a window holding `len` rows:
/// none until it is more than `slack` past `cap`, then back down to `cap`.
pub(crate) fn history_excess(len: usize, cap: usize, slack: usize) -> usize {
    if len > cap.saturating_add(slack) {
        len - cap
    } else {
        0
    }
}

/// Drops a window's oldest rows (see `history_excess`) and returns how many
/// went. Nothing is dropped unless a row with a Grappa id is left: that id
/// is the `?before=` cursor the dropped rows are paged back in from.
pub(crate) fn trim_oldest_rows(
    messages: &mut Vec<RenderedMessage>,
    cap: usize,
    slack: usize,
) -> usize {
    let excess = history_excess(messages.len(), cap, slack);
    if excess == 0
        || !messages[excess..]
            .iter()
            .any(|message| message.message_id.is_some())
    {
        return 0;
    }
    messages.drain(..excess);
    excess
}

/// Trims one window's stored rows to `CHAT_HISTORY_CAP` when it is well past
/// it. The rows dropped are older than any left, so the window's history
/// paging state is reset: its start has not been reached any more, and a
/// cursor already fetched may now be the oldest row still held. Returns
/// whether anything was dropped.
pub(crate) fn trim_window_history(state: &mut WorkerState, key: &(String, String)) -> bool {
    let Some(messages) = state.transcript.messages.get_mut(key) else {
        return false;
    };
    if trim_oldest_rows(messages, CHAT_HISTORY_CAP, CHAT_HISTORY_TRIM_SLACK) == 0 {
        return false;
    }
    state.transcript.history_start_reached.remove(key);
    state
        .transcript
        .history_cursors_fetched
        .retain(|(window, _)| window != key);
    true
}

/// Rows held across all windows, and in the largest one.
pub(crate) fn held_rows(messages: &MessagesByChannel) -> (usize, usize) {
    let total: usize = messages.values().map(Vec::len).sum();
    let largest = messages.values().map(Vec::len).max().unwrap_or(0);
    (total, largest)
}

/// Hands the Debug page the current row counts.
pub(crate) fn publish_held_rows(state: &WorkerState) {
    let (total, largest) = held_rows(&state.transcript.messages);
    debug_info::note_chat_rows(total, largest);
}
