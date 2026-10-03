use super::*;

/// Selects a query row already present in the server-owned snapshot. Joining
/// the query topic only subscribes to its realtime stream; it never sends an
/// IRC JOIN. The server's snapshot is the authority for whether the window is
/// currently open.
pub(crate) async fn handle_select_query(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    nick: String,
) {
    let Some(query) = find_query_window(&state.transcript.query_windows, &network, &nick).cloned()
    else {
        return;
    };
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    close_directory(state, ui);

    let topic = query_topic(&identifier, &query.network, &query.target_nick);
    if let Some(handle) = &state.conn.session {
        if state.conn.joined_topics.insert(topic.clone()) {
            handle.join_topic(topic, false);
        }
    }

    let key = (query.network.clone(), query.target_nick.clone());
    let identity = query_window_key(&query.network, &query.target_nick);
    state.current_query = true;
    state.current_query_ready = state.transcript.query_ready.contains(&identity);
    open_window(state, &key);
    push_mute_bar(state, ui);
    show_query_window(state, ui, &query, &key);

    // Cicchetto loads the latest page when a query is selected, independently
    // of the history refresh that follows the Phoenix join ACK. The endpoint's
    // default page is newest-first, so merge_query_history restores chronological
    // display order and deduplicates any messages received live in the meantime.
    if fetch_query_history(state, &query, None, None).await {
        state
            .transcript
            .query_full_history_required
            .remove(&identity);
        mark_query_ready_after_history(state, &identity);
        show_query_window(state, ui, &query, &key);
    }
}

pub(crate) fn show_query_window(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    query: &QueryWindow,
    key: &(String, String),
) {
    let lines = state
        .transcript
        .messages
        .get(key)
        .cloned()
        .unwrap_or_default();
    let draft = state
        .transcript
        .drafts
        .get(key)
        .cloned()
        .unwrap_or_default();
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let query_ready = state.current_query_ready;
    let history_start = state.transcript.history_start_reached.contains(key);
    let label = format!("{} — {}", query.network, query.target_nick);
    let window_status = window_status_for(state);
    let peer_nick = query.target_nick.clone();
    push_peer_away_banner(state, ui);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_channel_label(label.into());
        ui.set_current_topic("".into());
        ui.set_window_status(window_status.into());
        ui.set_current_window_is_joined(false);
        ui.set_current_server_window(false);
        ui.set_has_selected_channel(true);
        ui.set_current_query(true);
        ui.set_current_query_ready(query_ready);
        ui.set_current_query_peer_nick(peer_nick.into());
        ui.set_compose_text(draft.into());
        ui.set_can_moderate_members(false);
        ui.set_history_start_reached(history_start);
        ui.set_history_loading(false);
        ui.set_history_failed(false);
        let model = chat_lines_model(&lines, dark_theme);
        show_chat_lines(&ui, model);
        let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
        ui.set_channel_members(empty_members.into());
    });
}

pub(crate) async fn fetch_query_history(
    state: &mut WorkerState,
    query: &QueryWindow,
    after_id: Option<i64>,
    limit: Option<usize>,
) -> bool {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return false;
    };
    let rows = match client
        .fetch_messages(&token, &query.network, &query.target_nick, after_id, limit)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            persistence::log_line(&format!(
                "query history fetch failed for {}/{}: {error:?}",
                query.network, query.target_nick
            ));
            return false;
        }
    };

    // A newer full snapshot can close/rename this query while the request is
    // in flight. The worker serializes awaits today, but retain the guard so a
    // later async refactor cannot resurrect a stale conversation.
    if find_query_window(
        &state.transcript.query_windows,
        &query.network,
        &query.target_nick,
    )
    .is_none()
    {
        return false;
    }
    let key = (query.network.clone(), query.target_nick.clone());
    merge_query_history(state, &key, &rows);
    true
}

pub(crate) fn mark_query_ready_after_history(state: &mut WorkerState, identity: &(String, String)) {
    if !state.transcript.query_joined.contains(identity) {
        return;
    }
    state.transcript.query_ready.insert(identity.clone());
    if state.current_query
        && state
            .current_channel
            .as_ref()
            .is_some_and(|(network, nick)| &query_window_key(network, nick) == identity)
    {
        state.current_query_ready = true;
    }
}

pub(crate) fn reset_query_session_readiness(state: &mut WorkerState) {
    state.transcript.query_joined.clear();
    state.transcript.query_ready.clear();
    state.current_query_ready = false;
}

/// Merges a query history page into the local conversation by the server's
/// stable message ID, then restores Cicchetto's chronological
/// `(server_time, id)` ordering. This makes the default newest-first tail and
/// the post-join `after` page converge without duplicate echoes.
pub(crate) fn merge_query_history(state: &mut WorkerState, key: &(String, String), rows: &[Value]) {
    let messages = state.transcript.messages.entry(key.clone()).or_default();
    merge_rendered_messages(messages, rows.iter().map(render_history_entry));
}

pub(crate) fn query_window_key(network: &str, nick: &str) -> (String, String) {
    (network.to_string(), ascii_fold_channel(nick))
}

pub(crate) fn find_query_window<'a>(
    windows: &'a [QueryWindow],
    network: &str,
    nick: &str,
) -> Option<&'a QueryWindow> {
    let key = query_window_key(network, nick);
    windows
        .iter()
        .find(|window| query_window_key(&window.network, &window.target_nick) == key)
}
