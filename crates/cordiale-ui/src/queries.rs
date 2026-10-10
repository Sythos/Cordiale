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
    // A window folded into a followed peer's DM opens that DM.
    let query = query_anchor_window(state, &query);
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
    state.windows.current_query = true;
    state.windows.current_query_ready = state.transcript.query_ready.contains(&identity);
    open_window(state, &key);
    refresh_network_groups(state, ui);
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
        // The peer's newer-nick windows hold the rest of the conversation;
        // their rows merge into this view by message ID.
        for followed in followed_query_windows(state, &query) {
            fetch_query_history(state, &followed, None, None).await;
        }
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
    let query_ready = state.windows.current_query_ready;
    let history_start = state.transcript.history_start_reached.contains(key);
    let (label, peer_nick) = query_label(state, query);
    let window_status = window_status_for(state);
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
        ui.set_reply_target_left(false);
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
    // Rows of a window folded into a followed peer's DM go to that DM.
    let key = query_view_key(state, query);
    merge_query_history(state, &key, &rows);
    note_history_source(state, query, &rows);
    true
}

/// How far back one query window was loaded. A DM view that folds in the
/// windows of the peer's older nicks pages each of them from its own oldest
/// row, because the merged rows do not tell which window a row came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HistorySource {
    pub(crate) oldest: Option<i64>,
    pub(crate) start_reached: bool,
}

pub(crate) fn history_source_key(query: &QueryWindow) -> (String, String) {
    query_window_key(&query.network, &query.target_nick)
}

pub(crate) fn note_history_source(state: &mut WorkerState, query: &QueryWindow, rows: &[Value]) {
    let Some(oldest) = rows.iter().filter_map(message_id).min() else {
        return;
    };
    let source = state
        .transcript
        .query_history_sources
        .entry(history_source_key(query))
        .or_default();
    source.oldest = Some(source.oldest.map_or(oldest, |known| known.min(oldest)));
}

/// The windows whose older history the open DM pages: its own and the ones
/// folded into it. Empty when the open window is not a followed DM.
pub(crate) fn older_history_sources(
    state: &WorkerState,
    key: &(String, String),
) -> Vec<QueryWindow> {
    if !state.windows.current_query {
        return Vec::new();
    }
    let Some(anchor) = find_query_window(&state.transcript.query_windows, &key.0, &key.1) else {
        return Vec::new();
    };
    let followed = followed_query_windows(state, anchor);
    if followed.is_empty() {
        return Vec::new();
    }
    std::iter::once(anchor.clone()).chain(followed).collect()
}

/// Pages `sources` back by one page each, merging the rows into `key`.
/// Returns whether every window reached its first message, or `None` when a
/// request failed.
pub(crate) async fn load_older_query_sources(
    state: &mut WorkerState,
    key: &(String, String),
    sources: &[QueryWindow],
    merged_oldest: Option<i64>,
) -> Option<bool> {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return None;
    };
    let mut all_reached = true;
    for source in sources {
        let source_key = history_source_key(source);
        let known = state
            .transcript
            .query_history_sources
            .get(&source_key)
            .copied()
            .unwrap_or_default();
        if known.start_reached {
            continue;
        }
        let oldest = known.oldest.or(merged_oldest);
        let Some(oldest) = oldest.filter(|oldest| {
            !state
                .transcript
                .history_cursors_fetched
                .contains(&(source_key.clone(), *oldest))
        }) else {
            state
                .transcript
                .query_history_sources
                .entry(source_key)
                .or_default()
                .start_reached = true;
            continue;
        };
        let rows = match client
            .fetch_messages_before(
                &token,
                &source.network,
                &source.target_nick,
                oldest,
                OLDER_HISTORY_PAGE,
            )
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                persistence::log_line(&format!("older history fetch failed: {err:?}"));
                return None;
            }
        };
        state
            .transcript
            .history_cursors_fetched
            .insert((source_key.clone(), oldest));
        merge_query_history(state, key, &rows);
        note_history_source(state, source, &rows);
        let reached = rows.len() < OLDER_HISTORY_PAGE;
        if reached {
            state
                .transcript
                .query_history_sources
                .entry(source_key)
                .or_default()
                .start_reached = true;
        }
        all_reached &= reached;
    }
    Some(all_reached)
}

pub(crate) fn mark_query_ready_after_history(state: &mut WorkerState, identity: &(String, String)) {
    if !state.transcript.query_joined.contains(identity) {
        return;
    }
    state.transcript.query_ready.insert(identity.clone());
    if state.windows.current_query
        && state
            .windows
            .current_channel
            .as_ref()
            .is_some_and(|(network, nick)| &query_window_key(network, nick) == identity)
    {
        state.windows.current_query_ready = true;
    }
}

pub(crate) fn reset_query_session_readiness(state: &mut WorkerState) {
    state.transcript.query_joined.clear();
    state.transcript.query_ready.clear();
    state.windows.current_query_ready = false;
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

/// A DM window whose peer was seen changing nick. The window (and so its
/// rows, draft, selection and read state) stays under `anchor`, the nick it
/// was opened with; `peers` are the nicks the peer took since, oldest first.
/// The server keeps one query window per nick (protocol 37), so the newer
/// windows are only folded into this view, never merged on the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueryPeerLink {
    pub(crate) network: String,
    pub(crate) anchor: String,
    pub(crate) peers: Vec<String>,
}

impl QueryPeerLink {
    /// The nick the peer has now: where outgoing messages go.
    fn current_peer(&self) -> &str {
        self.peers
            .last()
            .map_or(self.anchor.as_str(), String::as_str)
    }
}

fn link_for_anchor<'a>(
    state: &'a WorkerState,
    network: &str,
    anchor: &str,
) -> Option<&'a QueryPeerLink> {
    let casemapping = network_casemapping(state, network);
    state
        .transcript
        .query_peer_links
        .iter()
        .find(|link| link.network == network && casemapping.nick_eq(&link.anchor, anchor))
}

fn link_for_peer<'a>(
    state: &'a WorkerState,
    network: &str,
    nick: &str,
) -> Option<&'a QueryPeerLink> {
    let casemapping = network_casemapping(state, network);
    state.transcript.query_peer_links.iter().find(|link| {
        link.network == network
            && link
                .peers
                .iter()
                .any(|peer| casemapping.nick_eq(peer, nick))
    })
}

/// The nick an outgoing message of the DM window `window_nick` is addressed
/// to: the peer's latest nick when a nick change was seen, else the window's.
pub(crate) fn query_send_target(state: &WorkerState, network: &str, window_nick: &str) -> String {
    link_for_anchor(state, network, window_nick).map_or_else(
        || window_nick.to_string(),
        |link| link.current_peer().to_string(),
    )
}

/// The key under which the rows and the draft of `query` are shown: the
/// anchor window's when `query` is a window of the same peer under a newer
/// nick, its own otherwise.
pub(crate) fn query_view_key(state: &WorkerState, query: &QueryWindow) -> (String, String) {
    let own = (query.network.clone(), query.target_nick.clone());
    let Some(link) = link_for_peer(state, &query.network, &query.target_nick) else {
        return own;
    };
    find_query_window(
        &state.transcript.query_windows,
        &query.network,
        &link.anchor,
    )
    .map_or(own, |anchor| {
        (anchor.network.clone(), anchor.target_nick.clone())
    })
}

/// `query` itself, or the anchor window when `query` is one of the folded
/// windows of a followed peer.
pub(crate) fn query_anchor_window(state: &WorkerState, query: &QueryWindow) -> QueryWindow {
    let (network, nick) = query_view_key(state, query);
    find_query_window(&state.transcript.query_windows, &network, &nick)
        .cloned()
        .unwrap_or_else(|| query.clone())
}

/// The windows folded into `anchor`'s view, for history loading.
pub(crate) fn followed_query_windows(
    state: &WorkerState,
    anchor: &QueryWindow,
) -> Vec<QueryWindow> {
    let Some(link) = link_for_anchor(state, &anchor.network, &anchor.target_nick) else {
        return Vec::new();
    };
    link.peers
        .iter()
        .filter_map(|peer| {
            find_query_window(&state.transcript.query_windows, &anchor.network, peer)
        })
        .cloned()
        .collect()
}

/// Query rows for the sidebar: a window folded into another one is not
/// listed, its unread counts are added to the anchor's row instead.
pub(crate) fn sidebar_query_windows(state: &WorkerState) -> Vec<QueryWindow> {
    state
        .transcript
        .query_windows
        .iter()
        .filter(|query| {
            query_view_key(state, query) == (query.network.clone(), query.target_nick.clone())
        })
        .cloned()
        .collect()
}

pub(crate) fn merge_followed_query_counts(
    state: &WorkerState,
    counts: &HashMap<WindowCountsKey, u64>,
) -> HashMap<WindowCountsKey, u64> {
    let mut merged = counts.clone();
    for query in &state.transcript.query_windows {
        let (network, nick) = query_view_key(state, query);
        if network == query.network && nick == query.target_nick {
            continue;
        }
        if let Some(count) = merged.remove(&window_counts_key(&query.network, &query.target_nick)) {
            *merged
                .entry(window_counts_key(&network, &nick))
                .or_default() += count;
        }
    }
    merged
}

/// The header label of a DM and the peer's current nick: the label names
/// the nick the window was opened with too when the peer has moved on.
pub(crate) fn query_label(state: &WorkerState, query: &QueryWindow) -> (String, String) {
    let peer = query_send_target(state, &query.network, &query.target_nick);
    let label = if peer == query.target_nick {
        format!("{} — {}", query.network, peer)
    } else {
        format!("{} — {} (← {})", query.network, peer, query.target_nick)
    };
    (label, peer)
}

/// Records a peer's nick change seen on `network` and returns whether a DM
/// view changed. Only an observed `old` → `new` event links windows, and
/// only when it cannot join two conversations: our own nick is skipped, and
/// so is a new nick that already has a window of its own (a pre-existing DM
/// or a reused nick) or belongs to another followed peer.
pub(crate) fn note_peer_nick_change(
    state: &mut WorkerState,
    network: &str,
    old: &str,
    new: &str,
) -> bool {
    let casemapping = network_casemapping(state, network);
    if state
        .networks
        .own_nicks
        .get(network)
        .is_some_and(|own| casemapping.nick_eq(own, old) || casemapping.nick_eq(own, new))
    {
        return false;
    }
    let existing =
        state.transcript.query_peer_links.iter().position(|link| {
            link.network == network && casemapping.nick_eq(link.current_peer(), old)
        });
    if casemapping.nick_eq(old, new) {
        // Case-only change: the peer stays the same, only the spelling moves.
        let Some(index) = existing else { return false };
        let link = &mut state.transcript.query_peer_links[index];
        match link.peers.last_mut() {
            Some(last) => *last = new.to_string(),
            None => link.anchor = new.to_string(),
        }
        return true;
    }
    let owner = |nick: &str| {
        state.transcript.query_peer_links.iter().position(|link| {
            link.network == network
                && (casemapping.nick_eq(&link.anchor, nick)
                    || link
                        .peers
                        .iter()
                        .any(|peer| casemapping.nick_eq(peer, nick)))
        })
    };
    let has_window =
        |nick: &str| {
            state.transcript.query_windows.iter().any(|query| {
                query.network == network && casemapping.nick_eq(&query.target_nick, nick)
            })
        };
    match existing {
        Some(index) => {
            // Back to a nick of the same conversation is fine; any other
            // known window or link under `new` is somebody else's.
            let same_conversation = owner(new) == Some(index);
            if !same_conversation && (has_window(new) || owner(new).is_some()) {
                return false;
            }
            let link = &mut state.transcript.query_peer_links[index];
            // Coming back to the first nick keeps the link: the windows of
            // the nicks in between stay folded into this DM.
            link.peers.retain(|peer| !casemapping.nick_eq(peer, new));
            link.peers.push(new.to_string());
            true
        }
        None => {
            if has_window(new) || owner(new).is_some() || owner(old).is_some() {
                return false;
            }
            let Some(anchor) = state
                .transcript
                .query_windows
                .iter()
                .find(|query| {
                    query.network == network && casemapping.nick_eq(&query.target_nick, old)
                })
                .map(|query| query.target_nick.clone())
            else {
                return false;
            };
            state.transcript.query_peer_links.push(QueryPeerLink {
                network: network.to_string(),
                anchor,
                peers: vec![new.to_string()],
            });
            true
        }
    }
}

/// Picks where a live frame of the query window `query` is stored. A frame
/// sent by a nick the peer has left means that nick is somebody else now:
/// the link ends, the windows are separate again and the frame stays in its
/// own window. The windows of the ended link are returned too: their cached
/// rows were merged under one key, so they are dropped here and the caller
/// reloads each window.
pub(crate) fn live_query_key(
    state: &mut WorkerState,
    query: &QueryWindow,
    payload: &Value,
) -> ((String, String), Vec<QueryWindow>) {
    let own = (query.network.clone(), query.target_nick.clone());
    let casemapping = network_casemapping(state, &query.network);
    let sender = payload
        .get("sender")
        .or_else(|| payload.get("from"))
        .and_then(Value::as_str);
    let link_index = state.transcript.query_peer_links.iter().position(|link| {
        link.network == query.network
            && (casemapping.nick_eq(&link.anchor, &query.target_nick)
                || link
                    .peers
                    .iter()
                    .any(|peer| casemapping.nick_eq(peer, &query.target_nick)))
    });
    let Some(index) = link_index else {
        return (own, Vec::new());
    };
    let link = &state.transcript.query_peer_links[index];
    let left = sender.is_some_and(|sender| {
        !casemapping.nick_eq(link.current_peer(), sender)
            && (casemapping.nick_eq(&link.anchor, sender)
                || link
                    .peers
                    .iter()
                    .any(|peer| casemapping.nick_eq(peer, sender)))
    });
    if left {
        persistence::log_line(&format!(
            "dm peer link ended on {}: a former nick wrote again",
            query.network
        ));
        let link = state.transcript.query_peer_links.remove(index);
        let affected = split_link_caches(state, &link);
        return (own, affected);
    }
    (query_view_key(state, query), Vec::new())
}

/// Forgets the rows, the paging marks and the read state of the windows of
/// an ended link, so that each window can be loaded again on its own.
fn split_link_caches(state: &mut WorkerState, link: &QueryPeerLink) -> Vec<QueryWindow> {
    let windows = &state.transcript.query_windows;
    let mut seen = std::collections::HashSet::new();
    let affected: Vec<QueryWindow> = find_query_window(windows, &link.network, &link.anchor)
        .into_iter()
        .chain(
            link.peers
                .iter()
                .filter_map(|peer| find_query_window(windows, &link.network, peer)),
        )
        .filter(|query| seen.insert(history_source_key(query)))
        .cloned()
        .collect();
    for query in &affected {
        let key = (query.network.clone(), query.target_nick.clone());
        let identity = history_source_key(query);
        state.transcript.messages.remove(&key);
        state.transcript.history_start_reached.remove(&key);
        state
            .transcript
            .history_cursors_fetched
            .retain(|(fetched, _)| fetched != &key && fetched != &identity);
        state.transcript.query_history_sources.remove(&identity);
        state
            .transcript
            .query_full_history_required
            .insert(identity);
    }
    affected
}

/// Reloads the latest page of each window after a link ended and shows the
/// open one again, with the label and the sidebar the new state calls for.
pub(crate) async fn reload_split_query_windows(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    affected: &[QueryWindow],
) {
    for query in affected {
        if fetch_query_history(state, query, None, None).await {
            state
                .transcript
                .query_full_history_required
                .remove(&history_source_key(query));
        }
    }
    refresh_network_groups(state, ui);
    if !state.windows.current_query {
        return;
    }
    let Some((network, nick)) = state.windows.current_channel.clone() else {
        return;
    };
    if let Some(open) = find_query_window(&state.transcript.query_windows, &network, &nick).cloned()
    {
        show_query_window(state, ui, &open, &(network, nick));
    }
}

/// Drops the links whose anchor window is gone from the snapshot.
pub(crate) fn prune_query_peer_links(state: &mut WorkerState) {
    let windows = &state.transcript.query_windows;
    state
        .transcript
        .query_peer_links
        .retain(|link| find_query_window(windows, &link.network, &link.anchor).is_some());
}

/// Pushes the open DM's label and peer nick after a link changed, leaving
/// the compose box, the rows and the scroll position alone.
pub(crate) fn push_query_peer_label(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    if !state.windows.current_query {
        return;
    }
    let Some((network, nick)) = state.windows.current_channel.as_ref() else {
        return;
    };
    let Some(query) = find_query_window(&state.transcript.query_windows, network, nick) else {
        return;
    };
    let (label, peer) = query_label(state, query);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_channel_label(label.into());
        ui.set_current_query_peer_nick(peer.into());
    });
}
