use super::*;

pub(crate) async fn handle_select_channel(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    channel: String,
) {
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    close_directory(state, ui);
    let server_window = channel == SERVER_WINDOW_NAME;
    if server_window && !state.networks.network_ids.contains_key(&network) {
        return;
    }
    let topic = channel_topic(&identifier, &network, &channel);
    if let Some(handle) = &state.conn.session {
        if state.conn.joined_topics.insert(topic.clone()) {
            handle.join_topic(topic, !server_window);
        }
    }

    if server_window && !fetch_server_window_history(state, &network).await {
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_status_kind("server-history-failed".into());
        });
    }

    let key = (network.clone(), channel.clone());
    state
        .windows
        .recent_channels
        .retain(|(known_network, known_channel)| {
            window_state_key(known_network, known_channel) != window_state_key(&network, &channel)
        });
    state.windows.recent_channels.insert(0, key.clone());
    state.windows.current_query = false;
    state.windows.current_query_ready = false;
    open_window(state, &key);
    state
        .windows
        .window_messages
        .insert(window_counts_key(&network, &channel), 0);
    refresh_network_groups(state, ui);
    push_mute_bar(state, ui);

    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.last_channel = Some(key.clone());
    let _ = persistence::save_settings(&settings);

    let lines = state
        .transcript
        .messages
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let draft = state
        .transcript
        .drafts
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let irc_topic = state
        .transcript
        .topics
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let window_status = window_status_for(state);
    let members = state
        .transcript
        .members
        .get(&key)
        .cloned()
        .unwrap_or_default();
    let window_is_joined = !server_window
        && state
            .windows
            .window_states
            .get(&window_state_key(&network, &channel))
            == Some(&ChannelWindowState::Joined);
    let ranking = MemberRanking::new(state.networks.isupport_by_network.get(&network));
    let can_moderate = is_own_nick_an_op(&members, &identifier, &ranking);
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let casemapping = network_casemapping(state, &network);
    let history_start = state.transcript.history_start_reached.contains(&key);
    let denoise = state.denoise_active(&key);
    let reply_left = reply_presence::target_left(state);

    push_window_note(state, ui);
    let label = format!("{network} — {channel}");
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_current_channel_label(label.into());
        ui.set_current_topic(irc_topic.into());
        ui.set_window_status(window_status.into());
        ui.set_current_window_is_joined(window_is_joined);
        ui.set_current_server_window(server_window);
        ui.set_has_selected_channel(true);
        ui.set_current_query(false);
        ui.set_current_query_ready(false);
        ui.set_compose_text(draft.into());
        ui.set_reply_target_left(reply_left);
        ui.set_can_moderate_members(can_moderate);
        ui.set_history_start_reached(history_start);
        ui.set_history_loading(false);
        ui.set_history_failed(false);
        ui.set_current_denoise(denoise);
        let model =
            chat_lines_model_with_roster(&lines, dark_theme, &members, casemapping, denoise);
        show_chat_lines(&ui, model);
        let member_rows = members_model(&members, dark_theme, &ranking);
        ui.set_members_average_nick(members_average_probe(&member_rows).into());
        ui.set_channel_members(Rc::new(slint::VecModel::from(member_rows)).into());
    });
}

/// A successful REST response is the server's acknowledgement of PART. Keep
/// the sidebar and current view intact on failure, then reconcile local topic
/// ownership only after that acknowledgement.
pub(crate) async fn handle_part_channel(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    channel: String,
    reason: Option<String>,
) {
    let key = window_state_key(&network, &channel);
    if state.windows.window_states.get(&key) != Some(&ChannelWindowState::Joined)
        || !state
            .windows
            .channel_entries
            .iter()
            .any(|(entry_network, entry_channel, _)| {
                window_state_key(entry_network, entry_channel) == key
            })
    {
        return;
    }
    let (Some(client), Some(token), Some(identifier)) = (
        state.conn.client.clone(),
        state.conn.token.clone(),
        state.conn.identifier.clone(),
    ) else {
        return;
    };

    if let Err(error) = client
        .part_channel(&token, &network, &channel, reason.as_deref())
        .await
    {
        persistence::log_line(&format!("channel part failed: {error:?}"));
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(|ui| ui.set_status_kind("part-failed".into()));
        return;
    }

    let selected =
        state
            .windows
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_channel)| {
                !state.windows.current_query
                    && window_state_key(current_network, current_channel) == key
            });
    let mut remaining_entries = state.windows.channel_entries.clone();
    remove_sidebar_channel_entry(&mut remaining_entries, &network, &channel);
    let actions = reconcile_channel_entries(state, &identifier, remaining_entries);
    if let Some(session) = state.conn.session.as_ref() {
        for action in actions {
            if let ChannelTopicAction::Leave(topic) = action {
                session.leave_topic(topic);
            }
        }
    }
    state.windows.window_states.remove(&key);
    state.windows.window_failures.remove(&key);
    state.windows.window_kicks.remove(&key);
    state.windows.invited_by.remove(&key);
    state.transcript.channel_modes.remove(&key);
    state
        .transcript
        .topics
        .remove(&(network.clone(), channel.clone()));
    state
        .transcript
        .members
        .remove(&(network.clone(), channel.clone()));
    state
        .transcript
        .messages
        .remove(&(network.clone(), channel.clone()));
    state
        .transcript
        .drafts
        .remove(&(network.clone(), channel.clone()));
    state
        .transcript
        .reply_contexts
        .remove(&(network.clone(), channel.clone()));
    state
        .transcript
        .presence_log
        .remove(&(network.clone(), channel.clone()));
    state
        .windows
        .recent_channels
        .retain(|(recent_network, recent_channel)| {
            window_state_key(recent_network, recent_channel) != key
        });
    refresh_network_groups(state, ui);

    if selected {
        handle_select_channel(state, ui, network, SERVER_WINDOW_NAME.to_string()).await;
    }
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(|ui| {
        if ui.get_status_kind().as_str() == "part-failed" {
            ui.set_status_kind("signed-in".into());
        }
    });
}

/// Dismisses a kicked pseudo-window with the same optimistic semantics as
/// Cicchetto: authenticated REST PART in the background, then local window
/// removal immediately. If the dismissed window was selected, return to the
/// most-recent remaining channel or the server/home view.
pub(crate) async fn handle_dismiss_kicked_channel(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    channel: String,
) {
    if !window_is_kicked(&state.windows.window_states, &network, &channel) {
        return;
    }
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };

    let part_network = network.clone();
    let part_channel = channel.clone();
    tokio::spawn(async move {
        if let Err(err) = client
            .part_channel(&token, &part_network, &part_channel, None)
            .await
        {
            persistence::log_line(&format!("kicked channel part failed: {err:?}"));
        }
    });

    let Some(selected) = dismiss_kicked_window_locally(state, &network, &channel) else {
        return;
    };
    refresh_network_groups(state, ui);

    if !selected {
        return;
    }

    let next_channel = state
        .windows
        .recent_channels
        .iter()
        .find(|(recent_network, recent_channel)| {
            state
                .windows
                .channel_entries
                .iter()
                .any(|(entry_network, entry_channel, _)| {
                    window_state_key(recent_network, recent_channel)
                        == window_state_key(entry_network, entry_channel)
                })
        })
        .cloned();
    if let Some((next_network, next_channel)) = next_channel {
        handle_select_channel(state, ui, next_network, next_channel).await;
        return;
    }

    if state.networks.network_ids.contains_key(&network) {
        handle_select_channel(state, ui, network, SERVER_WINDOW_NAME.to_string()).await;
        return;
    }

    state.windows.current_channel = None;
    let mut settings = persistence::load_settings().unwrap_or_default();
    settings.last_channel = None;
    let _ = persistence::save_settings(&settings);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
        ui.set_has_selected_channel(false);
        ui.set_current_channel_label("".into());
        ui.set_current_topic("".into());
        ui.set_window_status("".into());
        ui.set_current_window_is_joined(false);
        ui.set_current_server_window(false);
        ui.set_can_moderate_members(false);
        ui.set_compose_text("".into());
        ui.set_reply_target_left(false);
        show_chat_lines(&ui, Vec::new());
        ui.set_channel_members(empty_members.into());
    });
}

/// Cicchetto's `forceParted` projection for a kicked channel: remove its
/// lifecycle metadata and cached modes immediately after REST PART. The
/// sidebar channel list is maintained separately by Cordiale.
pub(crate) fn force_parted_kicked_window(
    state: &mut WorkerState,
    network: &str,
    channel: &str,
) -> bool {
    if !window_is_kicked(&state.windows.window_states, network, channel) {
        return false;
    }

    let key = window_state_key(network, channel);
    state.windows.window_states.remove(&key);
    state.windows.window_failures.remove(&key);
    state.windows.window_kicks.remove(&key);
    state.windows.invited_by.remove(&key);
    state
        .transcript
        .channel_modes
        .retain(|(known_network, known_channel), _| {
            window_state_key(known_network, known_channel) != key
        });
    true
}

/// Applies the kicked-row portion of Cicchetto's close action locally and
/// reports whether that pseudo-window was selected, without changing the
/// current selection or its MRU ordering.
pub(crate) fn dismiss_kicked_window_locally(
    state: &mut WorkerState,
    network: &str,
    channel: &str,
) -> Option<bool> {
    let key = window_state_key(network, channel);
    let selected =
        state
            .windows
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_channel)| {
                window_state_key(current_network, current_channel) == key
            });
    if !force_parted_kicked_window(state, network, channel) {
        return None;
    }
    remove_sidebar_channel_entry(&mut state.windows.channel_entries, network, channel);
    // A later join of this channel starts without this session's reply state.
    state
        .transcript
        .reply_contexts
        .retain(|(known_network, known_channel), _| {
            window_state_key(known_network, known_channel) != key
        });
    state
        .transcript
        .presence_log
        .retain(|(known_network, known_channel), _| {
            window_state_key(known_network, known_channel) != key
        });
    Some(selected)
}

/// Removes a dismissed channel from Cordiale's current sidebar projection.
pub(crate) fn remove_sidebar_channel_entry(
    entries: &mut Vec<(String, String, String)>,
    network: &str,
    channel: &str,
) -> bool {
    let key = window_state_key(network, channel);
    let previous_len = entries.len();
    entries.retain(|(entry_network, entry_channel, _)| {
        window_state_key(entry_network, entry_channel) != key
    });
    entries.len() != previous_len
}

/// Reads `(network, channel, label)` triples out of `boot.channels`. Field
/// names aren't fully confirmed (see `docs/protocol-notes.md` §4), so this
/// tries the plausible candidates and falls back to a positional
/// placeholder rather than guessing further. `label` is just the channel
/// name — the sidebar groups by network already, so repeating it per row
/// would be redundant (that's what the old flat "network — channel" list
/// did).
pub(crate) fn channel_entries_from_boot(
    outcome: &BootstrapOutcome,
) -> Vec<(String, String, String)> {
    channel_entries_from_channels(&outcome.boot.channels)
}

pub(crate) fn channel_entries_from_channels(
    channels_by_network: &HashMap<String, Vec<Value>>,
) -> Vec<(String, String, String)> {
    let mut entries = Vec::new();
    for (network, channels) in channels_by_network {
        for (index, value) in channels.iter().enumerate() {
            let channel = value
                .get("name")
                .or_else(|| value.get("channel"))
                .and_then(|field| field.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("channel #{}", index + 1));
            let label = channel.clone();
            entries.push((network.clone(), channel, label));
        }
    }
    entries
}

pub(crate) fn channel_topics_for_entries(
    user: &str,
    entries: &[(String, String, String)],
) -> std::collections::HashSet<String> {
    entries
        .iter()
        .map(|(network, channel, _)| channel_topic(user, network, channel))
        .collect()
}

pub(crate) fn channel_topic_is_owned_elsewhere(
    state: &WorkerState,
    user: &str,
    topic: &str,
) -> bool {
    state
        .transcript
        .query_windows
        .iter()
        .any(|query| query_topic(user, &query.network, &query.target_nick) == topic)
        || state
            .transcript
            .stale_query_topics
            .iter()
            .any(|(network, nick)| query_topic(user, network, nick) == topic)
        || state
            .networks
            .own_nicks
            .iter()
            .any(|(network, nick)| own_nick_listener_topic(user, network, nick) == topic)
}

/// Window states Grappa's channel list never reports: a window waiting for
/// its join, an invitation, a rejected join and a kick all describe a
/// channel the account is not in (and that may not be an autojoin channel
/// either), so it is missing from `GET /networks/:slug/channels` until the
/// user rejoins or dismisses it.
pub(crate) fn is_unlisted_window_state(window_state: &ChannelWindowState) -> bool {
    matches!(
        window_state,
        ChannelWindowState::Pending
            | ChannelWindowState::Invited
            | ChannelWindowState::Failed
            | ChannelWindowState::Kicked
    )
}

/// Replaces only the server-owned channel projection. Message history,
/// cursors, query windows, and listener ownership remain untouched. A row
/// whose window is pending, invited, failed or kicked outlives the
/// replacement, together with its topic subscription: the server list can't
/// show it, and only rejoining or dismissing it removes the row.
pub(crate) fn reconcile_channel_entries(
    state: &mut WorkerState,
    user: &str,
    entries: Vec<(String, String, String)>,
) -> Vec<ChannelTopicAction> {
    let known_networks: std::collections::HashSet<String> =
        state.networks.network_ids.keys().cloned().collect();
    reconcile_channel_entries_in(state, user, entries, &known_networks)
}

/// `reconcile_channel_entries` for the networks in `known_networks`, which a
/// refresh that is about to replace `state.network_ids` passes explicitly.
pub(crate) fn reconcile_channel_entries_in(
    state: &mut WorkerState,
    user: &str,
    mut entries: Vec<(String, String, String)>,
    known_networks: &std::collections::HashSet<String>,
) -> Vec<ChannelTopicAction> {
    for (network, channel, label) in &state.windows.channel_entries {
        let key = window_state_key(network, channel);
        let unlisted = state
            .windows
            .window_states
            .get(&key)
            .is_some_and(is_unlisted_window_state);
        if !unlisted
            || !known_networks.contains(network)
            || entries.iter().any(|(entry_network, entry_channel, _)| {
                window_state_key(entry_network, entry_channel) == key
            })
        {
            continue;
        }
        entries.push((network.clone(), channel.clone(), label.clone()));
    }

    let next_topics = channel_topics_for_entries(user, &entries);
    let previous_topics = std::mem::replace(&mut state.windows.channel_topics, next_topics.clone());
    let mut actions = Vec::new();

    let mut removed_topics: Vec<String> =
        previous_topics.difference(&next_topics).cloned().collect();
    removed_topics.sort();
    for topic in removed_topics {
        if channel_topic_is_owned_elsewhere(state, user, &topic) {
            continue;
        }
        if state.conn.joined_topics.remove(&topic) {
            actions.push(ChannelTopicAction::Leave(topic));
        }
    }

    let mut desired_topics: Vec<String> = next_topics.into_iter().collect();
    desired_topics.sort();
    for topic in desired_topics {
        if state.conn.joined_topics.insert(topic.clone()) {
            actions.push(ChannelTopicAction::Join(topic));
        }
    }

    state.windows.channel_entries = entries;
    actions
}

/// Seeds the runtime joined map only from Grappa's explicit `/boot` flag.
/// The channel tree also contains persisted autojoin intentions that can be
/// disconnected, so mere presence in `boot.channels` is not enough.
pub(crate) fn joined_window_states_from_boot_channels(
    channels: &HashMap<String, Vec<Value>>,
) -> HashMap<(String, String), ChannelWindowState> {
    let mut window_states = HashMap::new();
    for (network, entries) in channels {
        for entry in entries {
            if entry.get("joined").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let Some(channel) = entry
                .get("name")
                .or_else(|| entry.get("channel"))
                .and_then(Value::as_str)
                .filter(|channel| !channel.is_empty())
            else {
                continue;
            };
            window_states.insert(
                window_state_key(network, channel),
                ChannelWindowState::Joined,
            );
        }
    }
    window_states
}
