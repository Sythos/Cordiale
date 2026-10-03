use super::*;

/// The `*!*@host` ban mask from a `resolve_userhost` reply, if it has one.
pub(crate) fn kickban_mask(reply: &Value) -> Option<String> {
    if reply.get("status").and_then(Value::as_str) != Some("ok") {
        return None;
    }
    let host = reply.get("response")?.get("host")?.as_str()?;
    (!host.is_empty()).then(|| format!("*!*@{host}"))
}

/// Bans by host when it was known, then kicks regardless, as Cicchetto
/// does; an unknown host (`not_cached`) is reported, not fatal.
fn finish_kickban(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    pending: PendingKickBan,
    reply: &Value,
) {
    match kickban_mask(reply) {
        Some(mask) => send_user_verb(
            state,
            &pending.network,
            "ban",
            serde_json::json!({ "channel": pending.channel, "mask": mask }),
        ),
        None => {
            let nick = pending.nick.clone();
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_status_command_hint(nick.into());
                ui.set_status_kind("kickban-host-unknown".into());
            });
        }
    }
    send_user_verb(
        state,
        &pending.network,
        "kick",
        serde_json::json!({
            "channel": pending.channel,
            "nick": pending.nick,
            "reason": pending.reason,
        }),
    );
}

/// Handles a push on the live admin topic: the join `snapshot` (newest
/// first), a single audit event, a session-log event, or the periodic
/// `overview` that keeps the panel's summary line current.
fn handle_admin_feed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    frame: &cordiale_core::phoenix::PhoenixMessage,
) {
    match frame.event.as_str() {
        "overview" => {
            if let Ok(overview) =
                serde_json::from_value::<cordiale_core::admin::AdminOverview>(frame.payload.clone())
            {
                let text = admin_overview_text(&overview);
                let _ = ui.upgrade_in_event_loop(move |ui| {
                    ui.set_admin_overview_text(text.into());
                });
            }
            return;
        }
        "snapshot" => {
            state.panels.admin_events = frame
                .payload
                .get("events")
                .and_then(Value::as_array)
                .map(|events| {
                    events
                        .iter()
                        .map(cordiale_core::admin::admin_event_line)
                        .collect()
                })
                .unwrap_or_default();
        }
        "session_log_event" => {
            let line = format!(
                "session · {}",
                cordiale_core::admin::admin_session_log_line(&frame.payload)
            );
            state.panels.admin_events.insert(0, line);
        }
        _ if frame.payload.get("kind").is_some() => {
            let line = cordiale_core::admin::admin_event_line(&frame.payload);
            state.panels.admin_events.insert(0, line);
        }
        _ => return,
    }
    state.panels.admin_events.truncate(ADMIN_EVENTS_CAP);
    let lines: Vec<slint::SharedString> = state
        .panels
        .admin_events
        .iter()
        .map(|line| line.into())
        .collect();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_admin_events(Rc::new(slint::VecModel::from(lines)).into());
    });
}

/// The `patterns` of an `ok` reply to the watchlist list request.
pub(crate) fn watch_patterns_from_reply(reply: &Value) -> Option<Vec<String>> {
    if reply.get("status").and_then(Value::as_str) != Some("ok") {
        return None;
    }
    let patterns = reply.get("response")?.get("patterns")?.as_array()?;
    Some(
        patterns
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
    )
}

/// Center of the square `/links` canvas: large enough for the outermost
/// ring plus room for its labels, and never smaller than the default view.
fn links_canvas_center(nodes: &[cordiale_core::links::LinksGraphNode]) -> f64 {
    const MIN_CENTER: f64 = 380.0;
    const LABEL_ROOM: f64 = 160.0;
    let reach = nodes
        .iter()
        .map(|node| node.x.abs().max(node.y.abs()))
        .fold(0.0, f64::max);
    (reach + LABEL_ROOM).max(MIN_CENTER)
}

/// Whether a known event kind is rendered as a chat line. Only `message`
/// envelopes are: every other kind of the protocol's closed set has its own
/// handler (or explicit no-op) in `handle_frame`, and any kind that reaches
/// the rendering path without one is dropped instead of becoming a raw
/// chat line. `"parted"` is not a kind at all — a self-part shows up as the
/// window leaving window-state, never as a push.
pub(crate) fn renders_as_chat_line(kind: &str) -> bool {
    kind == "message"
}

pub(crate) fn record_query_join_success(state: &mut WorkerState, identity: &(String, String)) {
    state.transcript.query_joined.insert(identity.clone());
}

pub(crate) fn reset_query_join_failure(
    state: &mut WorkerState,
    identity: &(String, String),
    topic: &str,
) -> bool {
    state.transcript.query_joined.remove(identity);
    state.transcript.query_ready.remove(identity);
    state.conn.joined_topics.remove(topic);
    let selected = state.windows.current_query
        && state
            .windows
            .current_channel
            .as_ref()
            .is_some_and(|(network, nick)| &query_window_key(network, nick) == identity);
    if selected {
        state.windows.current_query_ready = false;
    }
    selected
}

async fn handle_query_join_reply(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    topic: &str,
    status: Option<&str>,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network, nick)) = query_from_topic(identifier, topic) else {
        return;
    };
    let (identity, query) = match resolve_query_topic(
        &state.transcript.query_windows,
        &state.transcript.stale_query_topics,
        &network,
        &nick,
    ) {
        QueryTopicResolution::Active(query) => (
            query_window_key(&query.network, &query.target_nick),
            Some(query.clone()),
        ),
        QueryTopicResolution::Stale => (query_window_key(&network, &nick), None),
        QueryTopicResolution::Untracked => return,
    };

    if status != Some("ok") {
        let selected = reset_query_join_failure(state, &identity, topic);
        if selected {
            let ui = ui.clone();
            let _ = ui.upgrade_in_event_loop(|ui| ui.set_current_query_ready(false));
        }
        persistence::log_line(&format!(
            "query topic join was not acknowledged: {network}/{nick}"
        ));
        return;
    }

    record_query_join_success(state, &identity);
    let Some(query) = query else {
        // Cicchetto leaves old query topics joined for the session lifetime.
        // Remember the ACK so a later close→reopen can reuse that topic; the
        // selected query will load its latest tail before becoming ready.
        return;
    };
    let key = (query.network.clone(), query.target_nick.clone());
    let (high_water, limit) = query_history_fetch_window(state, &identity, &key);

    // Phoenix's join reply is only the window/cursor seed; it carries no
    // message rows. Fetch the after-page from Grappa, using a known local
    // message ID as a high-water mark when available, and fall back to the
    // normal tail page rather than treating read_cursor as a message ID.
    if !fetch_query_history(state, &query, high_water, limit).await {
        return;
    }
    state
        .transcript
        .query_full_history_required
        .remove(&identity);
    mark_query_ready_after_history(state, &identity);

    let selected =
        state.windows.current_query
            && state.windows.current_channel.as_ref().is_some_and(
                |(current_network, current_nick)| {
                    query_window_key(current_network, current_nick) == identity
                },
            );
    if selected {
        show_query_window(state, ui, &query, &key);
    }
}

/// Appends an incoming realtime frame to the channel it belongs to (if any)
/// and, if that channel is currently open, pushes the update to the UI.
///
/// Every kind of the protocol's closed set has its own handler (or an
/// explicit no-op) below; only `message` envelopes reach chat rendering
/// (`renders_as_chat_line`). A kind unknown to `ClientEventKind` is dropped
/// silently, per `docs/CLIENT_PROTOCOL.md`'s policy on unrecognized kinds
/// (§4).
/// The error token of a refused command: a `phx_reply` with status
/// `error` on the user topic that isn't the reply to its join. Commands are
/// fire-and-forget pushes, so this is how a rejected `/recover`, `/kick`,
/// `/mode` and the like gets noticed at all.
pub(crate) fn command_error_reason(
    frame: &cordiale_core::phoenix::PhoenixMessage,
    identifier: &str,
) -> Option<String> {
    if frame.topic != format!("grappa:user:{identifier}")
        || frame.payload.get("status").and_then(Value::as_str) != Some("error")
        || frame.message_ref.is_none()
        || frame.message_ref == frame.join_ref
    {
        return None;
    }
    let response = frame.payload.get("response");
    let reason = ["error", "reason"]
        .iter()
        .find_map(|key| response?.get(*key)?.as_str())
        .unwrap_or("error");
    Some(reason.to_string())
}

pub(crate) async fn handle_frame(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    frame: cordiale_core::phoenix::PhoenixMessage,
) {
    if frame.topic == cordiale_core::admin::ADMIN_EVENTS_TOPIC {
        if frame.event != "phx_reply" {
            handle_admin_feed(state, ui, &frame);
        }
        return;
    }
    if frame.event == "phx_reply" {
        let status = frame.payload.get("status").and_then(Value::as_str);
        if apply_window_counts_join_reply(state, &frame.topic, &frame.payload, status) {
            refresh_network_groups(state, ui);
        }
        if handle_own_nick_listener_join_reply(state, &frame.topic, status)
            == OwnNickListenerJoinReply::Rejected
        {
            persistence::log_line(&format!(
                "own-nick listener join was not acknowledged: {}",
                frame.topic
            ));
        }
        handle_query_join_reply(state, ui, &frame.topic, status).await;
        if frame.message_ref.is_some() && frame.message_ref == state.prefs.pending_watchlist_ref {
            state.prefs.pending_watchlist_ref = None;
            if let Some(patterns) = watch_patterns_from_reply(&frame.payload) {
                state.prefs.watch_patterns = patterns;
                push_watch_patterns(state, ui);
            }
            return;
        }
        if let Some(pending) = frame
            .message_ref
            .as_ref()
            .and_then(|message_ref| state.panels.pending_kickbans.remove(message_ref))
        {
            finish_kickban(state, ui, pending, &frame.payload);
            return;
        }
        if let Some(reason) = state
            .conn
            .identifier
            .as_deref()
            .and_then(|identifier| command_error_reason(&frame, identifier))
        {
            persistence::log_line(&format!("command refused: {reason}"));
            let wait = (reason == "rate_limited")
                .then(|| {
                    cordiale_core::backoff::rate_limit_wait(
                        None,
                        frame.payload.get("response"),
                        SystemTime::now(),
                    )
                })
                .flatten();
            if let Some(wait) = wait {
                set_rate_limited_status(ui, wait);
            } else {
                let _ = ui.upgrade_in_event_loop(move |ui| {
                    ui.set_status_command_hint(reason.into());
                    ui.set_status_kind("command-refused".into());
                });
            }
        }
        return;
    }

    // The `kind:` field is the real discriminator for these server-push
    // "bundle" replies per `docs/protocol-notes.md` §4ter — the Phoenix
    // `event` name itself isn't confirmed to equal the bundle name, so
    // this checks both rather than betting on one interpretation.
    let Some(event_kind) = ClientEventKind::from_payload(&frame.payload) else {
        // Grappa explicitly requires unknown event kinds to be ignored for
        // forward compatibility. Never turn an unrecognized event payload
        // into a raw JSON chat line.
        return;
    };
    let payload_kind = event_kind.as_wire_name();
    if payload_kind == "channels_changed" {
        handle_channels_changed(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "network_detached" {
        handle_network_detached(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "network_attached" {
        handle_network_attached(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "connection_state_changed" {
        handle_connection_state_changed(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "connection_progress" {
        handle_connection_progress(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "recover_progress" {
        handle_recover_progress(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "recover_result" {
        handle_recover_result(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "web_session_severed" {
        handle_web_session_severed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "auto_away_debounce_changed" {
        handle_auto_away_debounce_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "quit_part_reason_changed" {
        handle_quit_part_reason_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "auto_away_reason_changed" {
        handle_auto_away_reason_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "away_nick_suffix_changed" {
        handle_away_nick_suffix_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "who_reply" {
        handle_who_reply(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "server_reply" {
        handle_server_reply(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "whois_bundle" {
        handle_whois_bundle(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "whois_avatar_ready" {
        handle_whois_avatar_ready(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "whowas_bundle" {
        handle_whowas_bundle(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "directory_progress" {
        handle_directory_progress(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "directory_complete" {
        handle_directory_complete(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "directory_failed" {
        handle_directory_failed(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "dcc_offer" {
        handle_dcc_offer(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "dcc_offer_resolved" {
        handle_dcc_offer_resolved(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "archive_changed" {
        handle_archive_changed(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "archive_purged" {
        handle_archive_purged(state, ui, &frame.topic, &frame.payload).await;
        return;
    }
    if payload_kind == "notify_list" {
        handle_notify_list(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "presence_snapshot" {
        handle_presence_snapshot(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "presence_changed" {
        handle_presence_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "presence_error" {
        handle_presence_error(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "peer_away" {
        handle_peer_away(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "mentions_bundle" {
        handle_mentions_bundle(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "server_settings_changed" {
        handle_server_settings_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "bundle_hash" {
        handle_bundle_hash(state, &frame.topic, &frame.payload);
        return;
    }
    // 329 RPL_CREATIONTIME changes no state: Cicchetto keeps the kind but
    // dropped its join banner, so it is consumed without any UI.
    if payload_kind == "channel_created" {
        return;
    }
    if payload_kind == "invite_ack" {
        handle_invite_ack(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "lusers_bundle" {
        handle_lusers_bundle(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "banlist_bundle" {
        handle_banlist_bundle(state, ui, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "own_nick_changed" {
        handle_own_nick_changed(state, &frame.topic, &frame.payload);
        return;
    }
    // `read_cursor_set` omits both network and target from its payload; the
    // Phoenix channel topic is its window identity. Cicchetto applies these
    // authoritative pushes last-write-wins, including a lower cursor from a
    // later-arriving frame, and treats the account-wide badge separately.
    if payload_kind == "read_cursor_set" {
        if let Some(identifier) = state.conn.identifier.clone() {
            apply_read_cursor_set(state, &identifier, &frame.topic, &frame.payload);
        }
        return;
    }
    if payload_kind == "away_confirmed" {
        handle_away_confirmed(state, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "session_identity_changed" {
        handle_session_identity_changed(state, &frame.topic, &frame.payload);
        return;
    }
    if payload_kind == "isupport_changed" {
        handle_isupport_changed(state, &frame.topic, &frame.payload);
        if let Some(key) = state
            .windows
            .current_channel
            .as_ref()
            .filter(|_| !state.windows.current_query)
        {
            push_members_update(state, ui, key);
        }
        return;
    }
    if payload_kind == "umode_changed" {
        handle_umode_changed(state, &frame.topic, &frame.payload);
        push_umode_view(state, ui, false);
        push_window_status(state, ui);
        return;
    }
    if payload_kind == "supported_umodes_changed" {
        handle_supported_umodes_changed(state, &frame.topic, &frame.payload);
        push_umode_view(state, ui, false);
        return;
    }
    if frame.event == "links_bundle" || payload_kind == "links_bundle" {
        handle_links_bundle(ui, &frame.payload);
        return;
    }

    if payload_kind == "query_windows_list" {
        handle_query_windows_list(state, ui, &frame.topic, &frame.payload);
        return;
    }

    // A JOIN accepted by Grappa first creates a transient window on the user
    // topic. Subscribe immediately to the channel-shaped topic so the
    // subsequent `joined` or `join_failed` transition cannot race past this
    // client. Unlike those terminal states, `window_pending` is live-only and
    // must never be accepted from a channel reconnect snapshot.
    if payload_kind == "window_pending" {
        handle_window_pending(state, ui, &frame.topic, &frame.payload);
        return;
    }

    // An invitation is replayable on the user topic, unlike the live-only
    // pending transition. Store it immediately and join the matching channel
    // topic so the eventual `joined`/`join_failed` event cannot race us.
    if payload_kind == "window_invited" {
        handle_window_invited(state, ui, &frame.topic, &frame.payload);
        return;
    }

    // A declined invitation is a terminal removal broadcast on the user
    // topic. The server has already removed the invited window, so there is
    // no client-side IRC DECLINE command and no replacement `declined` state.
    if payload_kind == "window_invite_declined" {
        handle_window_invite_declined(state, ui, &frame.topic, &frame.payload);
        return;
    }

    // Grappa doesn't use Phoenix Presence (`presence_state`/`presence_diff`)
    // — confirmed by reading Cicchetto's actual source
    // (`cicchetto/src/lib/subscribe.ts`). The full initial roster instead
    // arrives as this one-shot event, fired after a channel join and on
    // every real `366 RPL_ENDOFNAMES`; carries its own `network`/`channel`
    // fields so it's handled here rather than through `channel_from_topic`,
    // matching `links_bundle` above (may not even arrive on a channel
    // topic). Without this, the member list only ever grows through
    // incremental join/part/nick_change frames and starts empty for every
    // channel that already had people in it before Cordiale connected.
    if payload_kind == "members_seeded" {
        match apply_members_seeded(state, &frame.payload) {
            Some(key) => {
                let count = state
                    .transcript
                    .members
                    .get(&key)
                    .map(Vec::len)
                    .unwrap_or(0);
                persistence::log_line(&format!(
                    "members_seeded applied: {}/{} -> {count} member(s)",
                    key.0, key.1
                ));
                if state.windows.current_channel.as_ref() == Some(&key) {
                    push_members_update(state, ui, &key);
                }
            }
            // Confirms the event arrives but this server's actual field
            // names differ from Cicchetto's (`network`/`channel`/`members`
            // with each member `{nick, modes}`) — logged instead of
            // guessed again; the payload is safe to log verbatim, it never
            // carries credentials.
            None => {
                persistence::log_line(&format!(
                    "members_seeded frame didn't match the expected shape: {}",
                    frame.payload
                ));
            }
        }
        return;
    }

    // Confirmed real (not a guess): a chat row doesn't arrive as a flat
    // `kind: "privmsg"`/`"notice"` object the way a `boot.heads` history
    // row does — it's nested one level deeper, under a `kind: "message"`
    // envelope (`{"kind": "message", "message": {"kind": "privmsg", ...}}`).
    // Every frame this session before now was read straight off
    // `frame.payload`, so every live chat message fell through to the raw
    // dump fallback (`sender`/`body` both absent at the top level) — the
    // WebSocket connection itself never even succeeding until now meant
    // this had no chance to be noticed until a real user screenshot
    // showed the literal envelope shape.
    let effective_payload: &Value = if payload_kind == "message" {
        match frame.payload.get("message") {
            Some(inner) => inner,
            None => return,
        }
    } else {
        &frame.payload
    };

    if let Some(network) = own_nick_listener_network_for_topic(state, &frame.topic) {
        if payload_kind == "window_counts" {
            handle_window_counts(state, ui, &frame.topic, &frame.payload);
            return;
        }
        if payload_kind == "message"
            && state.conn.own_listener_ready.contains(&frame.topic)
            && own_nick_listener_accepts_inbound_dm(effective_payload)
        {
            if let Some(key) = own_nick_dm_query_key(state, &network, effective_payload) {
                require_query_full_history_if_unready(state, &key);
                if let Some(insert) =
                    append_query_live_message(state, &key, effective_payload, Some(&frame.event))
                {
                    show_live_query_message(state, ui, &key, insert);
                }
            } else {
                buffer_pending_own_nick_dm(state, &network, effective_payload, &frame.event);
            }
        }
        return;
    }

    if payload_kind == "topic_changed" {
        handle_topic_changed(state, ui, &frame.payload);
        return;
    }

    if payload_kind == "channel_modes_changed" {
        handle_channel_modes_changed(state, ui, &frame.topic, &frame.payload);
        return;
    }

    // `names_reply` carries the exact same shape as `members_seeded`
    // (`{network, channel, members: [{nick, modes}]}`) — another real
    // source for the initial roster, confirmed by reading
    // `session/wire.ex` directly (not the same code path as
    // `members_seeded`, but the payload contract matches byte for byte).
    if payload_kind == "names_reply" {
        if let Some(key) = apply_members_seeded(state, &frame.payload) {
            if state.windows.current_channel.as_ref() == Some(&key) {
                push_members_update(state, ui, &key);
            }
        }
        return;
    }

    // A successful join is broadcast on the user topic and replayed as a
    // cold snapshot on a subscribed channel topic. Both paths carry the
    // same typed payload; accepting only the matching topic keeps a stale or
    // unrelated frame from adding another channel, while the upsert below
    // makes dual delivery idempotent (Cicchetto's setJoined semantics).
    if payload_kind == "joined" {
        let Some(identifier) = state.conn.identifier.as_deref() else {
            return;
        };
        let Some((network, channel)) = parse_joined_event(&frame.payload, &frame.topic, identifier)
        else {
            return;
        };
        let state_changed = set_joined_window_state(
            &mut state.windows.window_states,
            &mut state.windows.window_failures,
            &mut state.windows.window_kicks,
            &mut state.windows.invited_by,
            &network,
            &channel,
        );
        let selected_window_joined = state.windows.current_channel.as_ref().is_some_and(
            |(current_network, current_channel)| {
                window_state_key(current_network, current_channel)
                    == window_state_key(&network, &channel)
            },
        );
        let sidebar_changed = upsert_channel_entry(
            &mut state.windows.channel_entries,
            network.clone(),
            channel.clone(),
        );
        if selected_window_joined {
            let ui = ui.clone();
            let _ = ui.upgrade_in_event_loop(|ui| ui.set_current_window_is_joined(true));
        }
        refresh_invite_banner(state, ui);
        if state_changed || sidebar_changed {
            refresh_network_groups(state, ui);
        }
        return;
    }

    // A rejected join is also a window-state transition: Cicchetto applies
    // it on the user topic and as a channel-topic reconnect snapshot. Keep a
    // faded pseudo-row, but never show a roster for a failed window. The
    // nullable reason/numeric stay in the session store only.
    if payload_kind == "join_failed" {
        let Some(identifier) = state.conn.identifier.as_deref() else {
            return;
        };
        let Some((network, channel, failure)) =
            parse_join_failed_event(&frame.payload, &frame.topic, identifier)
        else {
            return;
        };

        let state_changed = set_failed_window_state(
            &mut state.windows.window_states,
            &mut state.windows.window_failures,
            &mut state.windows.window_kicks,
            &mut state.windows.invited_by,
            &network,
            &channel,
            failure,
        );
        let sidebar_changed = upsert_channel_entry(
            &mut state.windows.channel_entries,
            network.clone(),
            channel.clone(),
        );
        let selected_window_failed = state.windows.current_channel.as_ref().is_some_and(
            |(current_network, current_channel)| {
                window_state_key(current_network, current_channel)
                    == window_state_key(&network, &channel)
            },
        );

        if selected_window_failed {
            let ui = ui.clone();
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_current_window_is_joined(false);
                ui.set_can_moderate_members(false);
            });
        }
        refresh_invite_banner(state, ui);
        if state_changed || sidebar_changed {
            refresh_network_groups(state, ui);
        }
        return;
    }

    // A kick becomes a retained, muted pseudo-window just like Cicchetto's
    // UI state. The server sends it live on the user topic and as a cold
    // snapshot on the matching channel topic; query/DM topics are rejected
    // by the parser. Keep the by/reason metadata in session state only.
    if payload_kind == "kicked" {
        let Some(identifier) = state.conn.identifier.as_deref() else {
            return;
        };
        let Some((network, channel, kick)) =
            parse_kicked_event(&frame.payload, &frame.topic, identifier)
        else {
            return;
        };

        let state_changed = set_kicked_window_state(
            &mut state.windows.window_states,
            &mut state.windows.window_failures,
            &mut state.windows.window_kicks,
            &mut state.windows.invited_by,
            &network,
            &channel,
            kick,
        );
        let sidebar_changed = upsert_channel_entry(
            &mut state.windows.channel_entries,
            network.clone(),
            channel.clone(),
        );
        let key = window_state_key(&network, &channel);
        state
            .transcript
            .members
            .retain(|(known_network, known_channel), _| {
                window_state_key(known_network, known_channel) != key
            });
        let selected_window_kicked = state.windows.current_channel.as_ref().is_some_and(
            |(current_network, current_channel)| {
                window_state_key(current_network, current_channel) == key
            },
        );

        if selected_window_kicked {
            let ui = ui.clone();
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_current_window_is_joined(false);
                ui.set_can_moderate_members(false);
                let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
                ui.set_channel_members(empty_members.into());
            });
        }
        refresh_invite_banner(state, ui);
        if state_changed || sidebar_changed {
            refresh_network_groups(state, ui);
        }
        return;
    }

    if payload_kind == "window_counts" {
        handle_window_counts(state, ui, &frame.topic, &frame.payload);
        return;
    }

    if !renders_as_chat_line(payload_kind) {
        return;
    }

    if let Some((network, topic_nick)) = state
        .conn
        .identifier
        .as_deref()
        .and_then(|identifier| query_from_topic(identifier, &frame.topic))
    {
        match resolve_query_topic(
            &state.transcript.query_windows,
            &state.transcript.stale_query_topics,
            &network,
            &topic_nick,
        ) {
            QueryTopicResolution::Active(query) => {
                let key = (query.network.clone(), query.target_nick.clone());
                if let Some(insert) =
                    append_query_live_message(state, &key, effective_payload, Some(&frame.event))
                {
                    show_live_query_message(state, ui, &key, insert);
                }
                return;
            }
            QueryTopicResolution::Stale => {
                // The topic can remain joined after its query row disappears;
                // the full snapshot is authoritative, so don't render late
                // data from the obsolete conversation.
                return;
            }
            QueryTopicResolution::Untracked => {
                // The query parser starts from the common `/channel:` form.
                // A channel that isn't in the query snapshot must continue
                // into the normal channel message path below.
            }
        }
    }

    let Some((network, channel)) = channel_from_topic(&frame.topic) else {
        return;
    };

    let key = (network.clone(), channel.clone());

    let line = render_message(effective_payload, Some(&frame.event));
    let messages = state.transcript.messages.entry(key.clone()).or_default();
    // A reconnect catch-up can already hold a row this push announces.
    let already_shown = line
        .message_id
        .is_some_and(|id| messages.iter().any(|known| known.message_id == Some(id)));
    if !already_shown {
        messages.push(line.clone());
    }
    let rows = messages.len();
    let open = state.windows.current_channel.as_ref() == Some(&key);
    // A window nobody has open is trimmed at once; the open one only when
    // its pane asks for it (below), as only the pane knows whether the
    // reader is following the newest line.
    if !already_shown && !open {
        trim_window_history(state, &key);
    }
    publish_held_rows(state);
    let rebuild_worker =
        if open && history_excess(rows, CHAT_HISTORY_CAP, CHAT_HISTORY_TRIM_SLACK) > 0 {
            state.conn.chat_rebuild_tx.clone()
        } else {
            None
        };

    // A Denoise line is kept above but never reaches the transcript.
    if !already_shown && open && state.transcript_shows(&key, &line) {
        let rebuild_key = key.clone();
        let dark_theme = state.prefs.theme == Theme::Dark;
        refresh_mention_context(state);
        let members = state
            .transcript
            .members
            .get(&key)
            .cloned()
            .unwrap_or_default();
        let casemapping = network_casemapping(state, &network);
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            // A plain append (not `show_chat_lines`): channel history is
            // only ever pushed to, never reordered, so the new row is
            // guaranteed to belong at the end — see `append_chat_line`.
            let prefix = line
                .nick
                .as_deref()
                .map(|nick| member_prefix_for_nick(&members, nick, casemapping))
                .unwrap_or("");
            append_chat_line(&ui, chat_line_from_message(&line, dark_theme, prefix));
            if let Some(worker) = rebuild_worker.filter(|_| ui.get_chat_follow_bottom()) {
                request_chat_rebuild(&worker, &rebuild_key, true);
            }
        });
    }

    let members_changed = update_members_from_frame(state, &key, effective_payload);
    if members_changed && state.windows.current_channel.as_ref() == Some(&key) {
        push_members_update(state, ui, &key);
    }
}

/// Applies a `topic_changed` push — real shape confirmed via a live user
/// frame and `github.com/vjt/grappa-irc/issues/2260`:
/// `{"channel", "kind": "topic_changed", "network", "topic": {"set_at",
/// "set_by", "text"}}`. `topic` is an object here, not the plain string
/// the old ad-hoc extraction assumed (dead code against real traffic —
/// removed, this replaces it), so only `.topic.text` is used; `set_by`/
/// `set_at` aren't surfaced yet.
fn handle_topic_changed(state: &mut WorkerState, ui: &slint::Weak<AppWindow>, payload: &Value) {
    let Some((key, text)) = parse_topic_changed(payload) else {
        return;
    };

    state.transcript.topics.insert(key.clone(), text.clone());
    if state.windows.current_channel.as_ref() == Some(&key) {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            ui.set_current_topic(text.into());
        });
    }
}

/// Pulls `(network, channel)` and the new topic text out of a
/// `topic_changed` payload — `{"channel", "network", "topic": {"text", ...}}`.
pub(crate) fn parse_topic_changed(payload: &Value) -> Option<((String, String), String)> {
    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    let text = payload
        .get("topic")
        .and_then(|topic| topic.get("text"))
        .and_then(Value::as_str)?;
    Some(((network.to_string(), channel.to_string()), text.to_string()))
}

/// Applies a complete `channel_modes_changed` snapshot. This event replaces,
/// rather than incrementally mutates, the cached modes for its channel.
fn handle_channel_modes_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    topic: &str,
    payload: &Value,
) {
    let Some((key, _label)) = apply_channel_modes_changed(state, topic, payload) else {
        return;
    };
    if state.windows.current_channel.as_ref() == Some(&key) && !state.windows.current_query {
        push_window_status(state, ui);
    }
}

/// Stores one full mode snapshot and returns its `(network, channel)` key and
/// compact display label when the payload satisfies the wire contract.
pub(crate) fn apply_channel_modes_changed(
    state: &mut WorkerState,
    topic: &str,
    payload: &Value,
) -> Option<((String, String), String)> {
    let (key, snapshot) = parse_channel_modes_changed(payload)?;
    // Cicchetto consumes this kind only on its per-channel Phoenix topic;
    // require the payload identity to agree with that topic as well.
    if channel_from_topic(topic).as_ref() != Some(&key) {
        return None;
    }
    let label = format_channel_modes(&snapshot.modes);
    state.transcript.channel_modes.insert(key.clone(), snapshot);
    Some((key, label))
}

/// Parses `{ network, channel, modes: { modes: string[], params:
/// Record<string, string | null> } }`. Unknown fields are ignored, while
/// malformed values are rejected instead of corrupting the cached snapshot.
fn parse_channel_modes_changed(payload: &Value) -> Option<((String, String), ChannelModes)> {
    let network = payload.get("network")?.as_str()?.to_owned();
    let channel = payload.get("channel")?.as_str()?.to_owned();
    let mode_state = payload.get("modes")?.as_object()?;
    let modes = mode_state
        .get("modes")?
        .as_array()?
        .iter()
        .map(|mode| mode.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let params = mode_state
        .get("params")?
        .as_object()?
        .iter()
        .map(|(name, value)| {
            let value = if value.is_null() {
                None
            } else {
                Some(value.as_str()?.to_owned())
            };
            Some((name.clone(), value))
        })
        .collect::<Option<HashMap<_, _>>>()?;

    Some(((network, channel), ChannelModes { modes, params }))
}

/// Validates a live snapshot against the channel-shaped topic that carried
/// it. The server-owned `channel` must agree with the topic under Cicchetto's
/// ASCII-folded channel equivalence.
fn parse_window_counts(
    payload: &Value,
    topic: &str,
    identifier: &str,
) -> Option<(WindowCountsKey, WindowCountSnapshot)> {
    if payload.get("kind")?.as_str()? != "window_counts" {
        return None;
    }
    let channel = payload.get("channel")?.as_str()?;
    if channel.trim().is_empty() {
        return None;
    }
    let counts = parse_window_count_snapshot(payload)?;

    let (network, _) = channel_from_topic(topic)?;
    if !channel_topic_matches(identifier, topic, &network, channel) {
        return None;
    }
    Some((window_counts_key(&network, channel), counts))
}

/// Cicchetto routes the own-nick listener's count to the self-message window,
/// keyed by the current own nick. Peer-DM counts arrive on each peer query's
/// own channel topic, not on this listener.
fn parse_own_nick_window_counts(
    state: &WorkerState,
    topic: &str,
    payload: &Value,
) -> Option<(WindowCountsKey, WindowCountSnapshot)> {
    if payload.get("kind")?.as_str()? != "window_counts" {
        return None;
    }
    let channel = payload.get("channel")?.as_str()?;
    if channel.trim().is_empty() {
        return None;
    }
    let counts = parse_window_count_snapshot(payload)?;
    let network = own_nick_listener_network_for_topic(state, topic)?;
    let own_nick = state.networks.own_nicks.get(&network)?;
    if ascii_fold_channel(channel) != ascii_fold_channel(own_nick) {
        return None;
    }
    Some((window_counts_key(&network, own_nick), counts))
}

/// Applies one authoritative unread snapshot only to an existing channel or
/// query row. The own-nick listener is an exception: Cicchetto tracks its
/// self-message window even though it is not a peer query row.
pub(crate) fn apply_window_counts(state: &mut WorkerState, topic: &str, payload: &Value) -> bool {
    let own_nick_listener = own_nick_listener_network_for_topic(state, topic).is_some();
    let parsed = if own_nick_listener {
        parse_own_nick_window_counts(state, topic, payload)
    } else {
        state
            .conn
            .identifier
            .as_deref()
            .and_then(|identifier| parse_window_counts(payload, topic, identifier))
    };
    let Some((key, counts)) = parsed else {
        return false;
    };
    let known_window = state
        .windows
        .channel_entries
        .iter()
        .any(|(network, channel, _)| window_counts_key(network, channel) == key)
        || state
            .transcript
            .query_windows
            .iter()
            .any(|query| window_counts_key(&query.network, &query.target_nick) == key);
    if !known_window && !own_nick_listener {
        return false;
    }
    apply_window_count_snapshot(state, key, counts)
}

/// Reads the server-authoritative unread seed from a successful Phoenix join
/// reply. Missing or malformed counts default to zero, matching the join-reply
/// narrowing used by Cicchetto.
fn parse_window_counts_join_reply(
    identifier: &str,
    topic: &str,
    payload: &Value,
    status: Option<&str>,
) -> Option<(WindowCountsKey, WindowCountSnapshot)> {
    if status != Some("ok") {
        return None;
    }
    let (network, channel) = channel_from_topic(topic)?;
    if network.is_empty()
        || channel.is_empty()
        || !channel_topic_matches(identifier, topic, &network, &channel)
    {
        return None;
    }

    let counts = payload
        .get("response")
        .and_then(|response| response.get("window_counts"))
        .and_then(Value::as_object);
    let messages = counts
        .and_then(|counts| counts.get("messages"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let mentions = counts
        .and_then(|counts| counts.get("mentions"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    Some((
        window_counts_key(&network, &channel),
        WindowCountSnapshot { messages, mentions },
    ))
}

pub(crate) fn apply_window_counts_join_reply(
    state: &mut WorkerState,
    topic: &str,
    payload: &Value,
    status: Option<&str>,
) -> bool {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return false;
    };
    let Some((key, counts)) = parse_window_counts_join_reply(identifier, topic, payload, status)
    else {
        return false;
    };
    apply_window_count_snapshot(state, key, counts)
}

fn apply_window_count_snapshot(
    state: &mut WorkerState,
    key: WindowCountsKey,
    counts: WindowCountSnapshot,
) -> bool {
    let mentions_changed = apply_window_mention_count(state, key.clone(), counts.mentions);
    let messages_changed = state.windows.window_messages.get(&key) != Some(&counts.messages);
    if messages_changed {
        state.windows.window_messages.insert(key, counts.messages);
    }
    mentions_changed || messages_changed
}

fn apply_window_mention_count(
    state: &mut WorkerState,
    key: WindowCountsKey,
    mentions: u64,
) -> bool {
    if mentions == 0 {
        return state.windows.window_mentions.remove(&key).is_some();
    }
    if state.windows.window_mentions.get(&key) == Some(&mentions) {
        return false;
    }
    state.windows.window_mentions.insert(key, mentions);
    true
}

fn handle_window_counts(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    topic: &str,
    payload: &Value,
) {
    if apply_window_counts(state, topic, payload) {
        refresh_network_groups(state, ui);
    }
}

/// Drops counts for query rows that the latest full snapshot closed. Channel
/// counts and the own-nick self-message window remain until connection reset.
pub(crate) fn retain_window_counts_for_open_windows(state: &mut WorkerState) {
    let mut retained = std::collections::HashSet::new();
    retained.extend(
        state
            .windows
            .channel_entries
            .iter()
            .map(|(network, channel, _)| window_counts_key(network, channel)),
    );
    retained.extend(
        state
            .transcript
            .query_windows
            .iter()
            .map(|query| window_counts_key(&query.network, &query.target_nick)),
    );
    retained.extend(
        state
            .networks
            .own_nicks
            .iter()
            .map(|(network, nick)| window_counts_key(network, nick)),
    );
    state
        .windows
        .window_mentions
        .retain(|key, _| retained.contains(key));
    state
        .windows
        .window_messages
        .retain(|key, _| retained.contains(key));
}

/// Re-renders the status line after a live mode change.
fn push_window_status(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let status = window_status_for(state);
    let _ = ui.upgrade_in_event_loop(move |ui| ui.set_window_status(status.into()));
}

/// Parses Cicchetto's typed `joined` payload from either supported delivery
/// path: the current user's live topic or the matching channel's reconnect
/// snapshot. Cicchetto's shared wire narrower requires `network`, `channel`,
/// and the exact `state: "joined"` discriminant.
pub(crate) fn parse_joined_event(
    payload: &Value,
    topic: &str,
    identifier: &str,
) -> Option<(String, String)> {
    if payload.get("kind").and_then(Value::as_str) != Some("joined")
        || payload.get("state").and_then(Value::as_str) != Some("joined")
    {
        return None;
    }

    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    let user_topic = format!("grappa:user:{identifier}");
    if topic != user_topic && !channel_topic_matches(identifier, topic, network, channel) {
        return None;
    }

    Some((network.to_string(), channel.to_string()))
}

/// Parses Cicchetto's required `join_failed` payload from either the live
/// user topic or the matching per-channel reconnect snapshot. Nullable fields
/// must be present, but unknown additive fields are deliberately ignored.
pub(crate) fn parse_join_failed_event(
    payload: &Value,
    topic: &str,
    identifier: &str,
) -> Option<(String, String, WindowFailure)> {
    let object = payload.as_object()?;
    if object.get("kind").and_then(Value::as_str) != Some("join_failed")
        || object.get("state").and_then(Value::as_str) != Some("failed")
    {
        return None;
    }

    let network = object.get("network")?.as_str()?;
    let channel = object.get("channel")?.as_str()?;
    let reason = match object.get("reason")? {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        _ => return None,
    };
    let numeric = match object.get("numeric")? {
        Value::Null => None,
        Value::Number(value) => Some(value.clone()),
        _ => return None,
    };

    let user_topic = format!("grappa:user:{identifier}");
    if topic != user_topic && !channel_topic_matches(identifier, topic, network, channel) {
        return None;
    }

    Some((
        network.to_string(),
        channel.to_string(),
        WindowFailure { reason, numeric },
    ))
}

/// Parses Cicchetto's required `kicked` payload from either the live user
/// topic or the matching per-channel cold snapshot. Nullable fields must be
/// present, but unknown additive fields are deliberately ignored.
pub(crate) fn parse_kicked_event(
    payload: &Value,
    topic: &str,
    identifier: &str,
) -> Option<(String, String, WindowKick)> {
    let object = payload.as_object()?;
    if object.get("kind").and_then(Value::as_str) != Some("kicked")
        || object.get("state").and_then(Value::as_str) != Some("kicked")
    {
        return None;
    }

    let network = object.get("network")?.as_str()?;
    let channel = object.get("channel")?.as_str()?;
    let by = match object.get("by")? {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        _ => return None,
    };
    let reason = match object.get("reason")? {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        _ => return None,
    };

    let user_topic = format!("grappa:user:{identifier}");
    if topic != user_topic && !channel_topic_matches(identifier, topic, network, channel) {
        return None;
    }

    Some((
        network.to_string(),
        channel.to_string(),
        WindowKick { by, reason },
    ))
}

/// Matches the server's channel topic with the same identifier key used by
/// Cicchetto: exact user and network, ASCII-folded channel only.
fn channel_topic_matches(identifier: &str, topic: &str, network: &str, channel: &str) -> bool {
    let prefix = channel_topic(identifier, network, "");
    topic.strip_prefix(&prefix).is_some_and(|topic_channel| {
        ascii_fold_channel(topic_channel) == ascii_fold_channel(channel)
    })
}

/// Parses one channel-topic cursor push. The kind is checked again here so
/// the helper is safe to exercise independently in tests; an unrelated user
/// topic, foreign identity, empty window, or malformed cursor is rejected.
pub(crate) fn parse_read_cursor_set_event(
    identifier: &str,
    topic: &str,
    payload: &Value,
) -> Option<((String, String), i64, u64)> {
    if payload.get("kind").and_then(Value::as_str) != Some("read_cursor_set") {
        return None;
    }
    let (network, channel) = channel_from_topic(topic)?;
    if network.is_empty()
        || channel.is_empty()
        || !channel_topic_matches(identifier, topic, &network, &channel)
    {
        return None;
    }
    let last_read_message_id = payload.get("last_read_message_id")?.as_i64()?;
    let badge_count = normalize_badge_count(payload.get("badge_count"));
    Some((
        window_state_key(&network, &channel),
        last_read_message_id,
        badge_count,
    ))
}

/// Applies a server-authoritative cursor/badge update. A malformed required
/// cursor leaves both values unchanged; an omitted or malformed badge is
/// normalized to zero, as Cicchetto's badge setter does.
pub(crate) fn apply_read_cursor_set(
    state: &mut WorkerState,
    identifier: &str,
    topic: &str,
    payload: &Value,
) -> bool {
    let Some((key, last_read_message_id, badge_count)) =
        parse_read_cursor_set_event(identifier, topic, payload)
    else {
        return false;
    };

    let cursor_changed =
        state.windows.read_cursors.get(&key).copied() != Some(last_read_message_id);
    let badge_changed = state.windows.badge_count != badge_count;
    state.windows.read_cursors.insert(key, last_read_message_id);
    state.windows.badge_count = badge_count;
    cursor_changed || badge_changed
}

/// Parses the live-only `window_pending` transition. Grappa emits this on the
/// authenticated user topic before the channel subscription exists; accepting
/// it anywhere else would accidentally turn a channel snapshot into a seed.
/// Unknown additive fields are deliberately ignored for forward compatibility.
pub(crate) fn parse_window_pending_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String)> {
    if carrier_topic != format!("grappa:user:{identifier}")
        || payload.get("kind").and_then(Value::as_str) != Some("window_pending")
        || payload.get("state").and_then(Value::as_str) != Some("pending")
    {
        return None;
    }

    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    if network.is_empty() || channel.is_empty() {
        return None;
    }

    Some((network.to_string(), channel.to_string()))
}

/// Mirrors Cicchetto's pending-window reducer: replace any stale terminal
/// state and metadata without manufacturing history or a channel snapshot.
pub(crate) fn set_pending_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Pending)
        != Some(ChannelWindowState::Pending);
    let failure_cleared = window_failures.remove(&key).is_some();
    let kick_cleared = window_kicks.remove(&key).is_some();
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_cleared || kick_cleared || invite_cleared
}

pub(crate) fn register_pending_channel_topic(
    joined_topics: &mut std::collections::HashSet<String>,
    channel_topics: &mut std::collections::HashSet<String>,
    topic: String,
) -> bool {
    channel_topics.insert(topic.clone());
    joined_topics.insert(topic)
}

fn handle_window_pending(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    let Some((network, channel)) = parse_window_pending_event(payload, carrier_topic, &identifier)
    else {
        return;
    };
    // The event identifies a window on an already bootstrapped network. Do
    // not invent a new network from an unsolicited or stale payload.
    if !state.networks.network_ids.contains_key(&network) {
        return;
    }

    let state_changed = set_pending_window_state(
        &mut state.windows.window_states,
        &mut state.windows.window_failures,
        &mut state.windows.window_kicks,
        &mut state.windows.invited_by,
        &network,
        &channel,
    );
    let sidebar_changed = upsert_channel_entry(
        &mut state.windows.channel_entries,
        network.clone(),
        channel.clone(),
    );

    let topic = channel_topic(&identifier, &network, &channel);
    let subscription_added = register_pending_channel_topic(
        &mut state.conn.joined_topics,
        &mut state.windows.channel_topics,
        topic.clone(),
    );
    if let (true, Some(handle)) = (subscription_added, state.conn.session.as_ref()) {
        handle.join_topic(topic, true);
    }

    let selected_window_pending =
        state
            .windows
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_channel)| {
                window_state_key(current_network, current_channel)
                    == window_state_key(&network, &channel)
            });
    if selected_window_pending {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_current_window_is_joined(false);
            ui.set_can_moderate_members(false);
        });
    }
    refresh_invite_banner(state, ui);
    if state_changed || sidebar_changed {
        refresh_network_groups(state, ui);
    }
}

/// Parses the replayable `window_invited` transition. Grappa sends this only
/// on the authenticated user topic; accepting a matching channel-topic frame
/// would incorrectly seed invitation state from a channel snapshot.
/// Unknown additive fields remain tolerated, while the required `inviter`
/// field must be a JSON string (the server uses `"*"` when no prefix exists).
pub(crate) fn parse_window_invited_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String, String)> {
    if identifier.is_empty()
        || carrier_topic != format!("grappa:user:{identifier}")
        || payload.get("kind").and_then(Value::as_str) != Some("window_invited")
        || payload.get("state").and_then(Value::as_str) != Some("invited")
    {
        return None;
    }

    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    let inviter = payload.get("inviter").and_then(Value::as_str)?;
    if network.is_empty() || channel.is_empty() || inviter.is_empty() {
        return None;
    }

    Some((
        network.to_string(),
        channel.to_string(),
        inviter.to_string(),
    ))
}

/// Mirrors Cicchetto's invited-window reducer: replace any stale terminal
/// state, retain the required inviter for the Join banner, and make repeated
/// live/replay delivery idempotent.
pub(crate) fn set_invited_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
    inviter: String,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Invited)
        != Some(ChannelWindowState::Invited);
    let failure_cleared = window_failures.remove(&key).is_some();
    let kick_cleared = window_kicks.remove(&key).is_some();
    let inviter_changed = invited_by.get(&key) != Some(&inviter);
    invited_by.insert(key, inviter);
    state_changed || failure_cleared || kick_cleared || inviter_changed
}

/// Projects the most stable invited entry into the native banner. The
/// invitation itself must not change `current_channel`, so receiving a live
/// event never steals focus from the user's current window.
fn refresh_invite_banner(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let banner = state
        .windows
        .invited_by
        .iter()
        .min_by(|(left, _), (right, _)| left.cmp(right))
        .map(|((network, channel), inviter)| {
            (
                format!("{network} {channel}"),
                network.clone(),
                channel.clone(),
                inviter.clone(),
            )
        });
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        if let Some((label, network, channel, inviter)) = banner {
            ui.set_window_invite_banner(
                format!("Invited to {label} by {inviter}. Select Join to open it.").into(),
            );
            ui.set_window_invite_network(network.into());
            ui.set_window_invite_channel(channel.into());
            ui.set_window_invite_inviter(inviter.into());
        } else {
            ui.set_window_invite_banner("".into());
            ui.set_window_invite_network("".into());
            ui.set_window_invite_channel("".into());
            ui.set_window_invite_inviter("".into());
        }
    });
}

fn handle_window_invited(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    let Some((network, channel, inviter)) =
        parse_window_invited_event(payload, carrier_topic, &identifier)
    else {
        return;
    };
    // Do not manufacture a sidebar/network entry from an invite for a stale
    // or unknown network; the bootstrap snapshot remains authoritative.
    if !state.networks.network_ids.contains_key(&network) {
        return;
    }

    let state_changed = set_invited_window_state(
        &mut state.windows.window_states,
        &mut state.windows.window_failures,
        &mut state.windows.window_kicks,
        &mut state.windows.invited_by,
        &network,
        &channel,
        inviter,
    );
    let sidebar_changed = upsert_channel_entry(
        &mut state.windows.channel_entries,
        network.clone(),
        channel.clone(),
    );

    let topic = channel_topic(&identifier, &network, &channel);
    let subscription_added = register_pending_channel_topic(
        &mut state.conn.joined_topics,
        &mut state.windows.channel_topics,
        topic.clone(),
    );
    if let (true, Some(handle)) = (subscription_added, state.conn.session.as_ref()) {
        handle.join_topic(topic, true);
    }

    // The event is deliberately not an auto-focus request. If the invited
    // window is already selected, keep the roster hidden until `joined`.
    let selected_window_invited =
        state
            .windows
            .current_channel
            .as_ref()
            .is_some_and(|(current_network, current_channel)| {
                window_state_key(current_network, current_channel)
                    == window_state_key(&network, &channel)
            });
    if selected_window_invited {
        let ui = ui.clone();
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_current_window_is_joined(false);
            ui.set_can_moderate_members(false);
        });
    }
    refresh_invite_banner(state, ui);
    if state_changed || sidebar_changed {
        refresh_network_groups(state, ui);
    }
}

/// Parses the terminal `window_invite_declined` transition. Grappa sends it
/// only on the authenticated user topic and intentionally omits `state`: the
/// server has already removed the invited window. Unknown additive fields are
/// tolerated for forward compatibility.
pub(crate) fn parse_window_invite_declined_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String)> {
    if identifier.is_empty()
        || carrier_topic != format!("grappa:user:{identifier}")
        || payload.get("kind").and_then(Value::as_str) != Some("window_invite_declined")
    {
        return None;
    }

    let network = payload.get("network").and_then(Value::as_str)?;
    let channel = payload.get("channel").and_then(Value::as_str)?;
    if network.trim().is_empty() || channel.trim().is_empty() {
        return None;
    }

    Some((network.to_string(), channel.to_string()))
}

/// Removes all lifecycle metadata for a declined invitation. In particular,
/// this also clears `Pending`, so a decline racing with the transient JOIN
/// state cannot leave a stale pseudo-row behind. No `declined` state is
/// created, and cached messages/drafts/topics remain untouched like
/// Cicchetto's `forceParted` projection.
fn clear_declined_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
) -> bool {
    let key = window_state_key(network, channel);
    let state_removed = window_states.remove(&key).is_some();
    let failure_removed = window_failures.remove(&key).is_some();
    let kick_removed = window_kicks.remove(&key).is_some();
    let invite_removed = invited_by.remove(&key).is_some();
    state_removed || failure_removed || kick_removed || invite_removed
}

/// Applies the server-authoritative removal to both lifecycle state and the
/// native sidebar projection. Repeated delivery is therefore a no-op.
pub(crate) fn remove_declined_window(
    state: &mut WorkerState,
    network: &str,
    channel: &str,
) -> bool {
    let lifecycle_changed = clear_declined_window_state(
        &mut state.windows.window_states,
        &mut state.windows.window_failures,
        &mut state.windows.window_kicks,
        &mut state.windows.invited_by,
        network,
        channel,
    );
    let sidebar_changed =
        remove_sidebar_channel_entry(&mut state.windows.channel_entries, network, channel);
    lifecycle_changed || sidebar_changed
}

/// Removes the channel-topic subscription that was created for the invited
/// window, while preserving a topic still owned by an open query or the
/// own-nick listener (all three use the same Phoenix topic shape).
pub(crate) fn remove_declined_channel_subscription(
    state: &mut WorkerState,
    identifier: &str,
    network: &str,
    channel: &str,
) -> bool {
    let canonical_topic = channel_topic(identifier, network, &ascii_fold_channel(channel));
    let topic_is_owned_elsewhere =
        channel_topic_is_owned_elsewhere(state, identifier, &canonical_topic);
    let matching_channel_topics: Vec<String> = state
        .windows
        .channel_topics
        .iter()
        .filter(|topic| channel_topic_matches(identifier, topic, network, channel))
        .cloned()
        .collect();
    let channel_topic_removed = !matching_channel_topics.is_empty();
    for topic in matching_channel_topics {
        state.windows.channel_topics.remove(&topic);
    }

    let matching_joined_topics: Vec<String> = if topic_is_owned_elsewhere {
        Vec::new()
    } else {
        state
            .conn
            .joined_topics
            .iter()
            .filter(|topic| channel_topic_matches(identifier, topic, network, channel))
            .cloned()
            .collect()
    };
    let joined_topic_removed = !matching_joined_topics.is_empty();
    for topic in matching_joined_topics {
        state.conn.joined_topics.remove(&topic);
        if let Some(handle) = state.conn.session.as_ref() {
            handle.leave_topic(topic);
        }
    }
    channel_topic_removed || joined_topic_removed
}

fn handle_window_invite_declined(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    let Some((network, channel)) =
        parse_window_invite_declined_event(payload, carrier_topic, &identifier)
    else {
        return;
    };
    // Bootstrap remains authoritative for known networks; malformed or stale
    // network names must not remove an unrelated row or lifecycle entry.
    if !state.networks.network_ids.contains_key(&network) {
        return;
    }

    let window_changed = remove_declined_window(state, &network, &channel);
    let subscription_changed =
        remove_declined_channel_subscription(state, &identifier, &network, &channel);
    if window_changed || subscription_changed {
        refresh_invite_banner(state, ui);
        refresh_network_groups(state, ui);
    }
}

/// Adds a channel window to the session's sidebar source of truth after a
/// server-reported join, invitation, join failure, or kick. The return value
/// lets callers avoid rebuilding Slint models for duplicate delivery.
pub(crate) fn upsert_channel_entry(
    entries: &mut Vec<(String, String, String)>,
    network: String,
    channel: String,
) -> bool {
    if entries.iter().any(|(known_network, known_channel, _)| {
        window_state_key(known_network, known_channel) == window_state_key(&network, &channel)
    }) {
        return false;
    }

    entries.push((network, channel.clone(), channel));
    true
}

/// Mirrors Cicchetto's `setJoined`: assignment overwrites the prior
/// window-state value and clears stale invite/failure/kick metadata. Repeated
/// delivery on the live user topic and channel reconnect snapshot is
/// idempotent.
pub(crate) fn set_joined_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Joined)
        != Some(ChannelWindowState::Joined);
    let failure_cleared = window_failures.remove(&key).is_some();
    let kick_cleared = window_kicks.remove(&key).is_some();
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_cleared || kick_cleared || invite_cleared
}

/// Mirrors Cicchetto's `setFailed`: failure replaces the current window
/// status, retains its nullable wire metadata, and clears any invite marker.
/// Replayed snapshots are idempotent.
pub(crate) fn set_failed_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
    failure: WindowFailure,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Failed)
        != Some(ChannelWindowState::Failed);
    let failure_changed = window_failures.insert(key.clone(), failure.clone()) != Some(failure);
    let kick_cleared = window_kicks.remove(&key).is_some();
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_changed || kick_cleared || invite_cleared
}

/// Mirrors Cicchetto's `setKicked`: replaces the current window status,
/// retains nullable actor/reason metadata, and clears stale failure/invite
/// data. Replayed user-topic and channel-topic deliveries are idempotent.
pub(crate) fn set_kicked_window_state(
    window_states: &mut HashMap<(String, String), ChannelWindowState>,
    window_failures: &mut HashMap<(String, String), WindowFailure>,
    window_kicks: &mut HashMap<(String, String), WindowKick>,
    invited_by: &mut HashMap<(String, String), String>,
    network: &str,
    channel: &str,
    kick: WindowKick,
) -> bool {
    let key = window_state_key(network, channel);
    let state_changed = window_states.insert(key.clone(), ChannelWindowState::Kicked)
        != Some(ChannelWindowState::Kicked);
    let failure_cleared = window_failures.remove(&key).is_some();
    let kick_changed = window_kicks.insert(key.clone(), kick.clone()) != Some(kick);
    let invite_cleared = invited_by.remove(&key).is_some();
    state_changed || failure_cleared || kick_changed || invite_cleared
}

/// Parses a `members_seeded` payload (`{kind, network, channel, members}`,
/// each member `{nick, modes: [...]}`) and replaces the stored roster for
/// that channel outright — it's a full snapshot, not a delta.
pub(crate) fn apply_members_seeded(
    state: &mut WorkerState,
    payload: &Value,
) -> Option<(String, String)> {
    let network = payload.get("network").and_then(Value::as_str)?.to_string();
    let channel = payload.get("channel").and_then(Value::as_str)?.to_string();
    let list = payload.get("members").and_then(Value::as_array)?;
    let isupport = state.networks.isupport_by_network.get(&network);
    let order = cordiale_core::isupport::prefix_symbol_order(isupport);
    let mut members: Vec<MemberEntry> = list
        .iter()
        .filter_map(|entry| member_from_entry(entry, &order, isupport))
        .collect();
    sort_members_by_rank(&mut members, &order);
    let key = (network, channel);
    state.transcript.members.insert(key.clone(), members);
    Some(key)
}

/// Maintains `state.members` from live join/part/quit/nick_change frames,
/// on top of the `members_seeded` snapshot. Returns whether the
/// member list for `key` actually changed (callers use this to decide
/// whether to push an update to the UI).
pub(crate) fn update_members_from_frame(
    state: &mut WorkerState,
    key: &(String, String),
    payload: &Value,
) -> bool {
    let kind = payload.get("kind").and_then(Value::as_str);
    let nick = payload
        .get("from")
        .or_else(|| payload.get("nick"))
        .or_else(|| payload.get("sender"))
        .and_then(Value::as_str);

    match kind {
        Some("join") => {
            let Some(nick) = nick else { return false };
            let order = cordiale_core::isupport::prefix_symbol_order(
                state.networks.isupport_by_network.get(&key.0),
            );
            let members = state.transcript.members.entry(key.clone()).or_default();
            if members.iter().any(|(name, _)| name == nick) {
                return false;
            }
            members.push((nick.to_string(), String::new()));
            sort_members_by_rank(members, &order);
            true
        }
        Some("part") | Some("quit") => {
            let Some(nick) = nick else { return false };
            let Some(members) = state.transcript.members.get_mut(key) else {
                return false;
            };
            let before = members.len();
            members.retain(|(name, _)| name != nick);
            before != members.len()
        }
        Some("nick_change") => {
            let (Some(old_nick), Some(new_nick)) = (
                nick,
                payload
                    .get("meta")
                    .and_then(|meta| meta.get("new_nick"))
                    .and_then(Value::as_str),
            ) else {
                return false;
            };
            let order = cordiale_core::isupport::prefix_symbol_order(
                state.networks.isupport_by_network.get(&key.0),
            );
            let Some(members) = state.transcript.members.get_mut(key) else {
                return false;
            };
            let Some(entry) = members.iter_mut().find(|(name, _)| name == old_nick) else {
                return false;
            };
            entry.0 = new_nick.to_string();
            sort_members_by_rank(members, &order);
            true
        }
        // Real, observed shape (a screenshot caught this leaking as raw
        // JSON before this was handled): `meta.modes` like `"+o"`/`"-o"`,
        // `meta.args` the parameters in order. Which letters take one comes
        // from the network's ISUPPORT PREFIX and CHANMODES, so a mixed
        // string like `"+bo mask nick"` lines up.
        Some("mode") => {
            let modes = payload
                .get("meta")
                .and_then(|meta| meta.get("modes"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let isupport = state.networks.isupport_by_network.get(&key.0);
            let prefix_changes =
                cordiale_core::isupport::prefix_mode_changes(modes, &mode_args(payload), isupport);
            let order = cordiale_core::isupport::prefix_symbol_order(isupport);
            let casemapping = network_casemapping(state, &key.0);
            let Some(members) = state.transcript.members.get_mut(key) else {
                return false;
            };
            let mut changed = false;
            for (adding, symbol, target) in prefix_changes {
                let Some(entry) = members
                    .iter_mut()
                    .find(|(name, _)| casemapping.nick_eq(name, &target))
                else {
                    continue;
                };
                entry.1 = update_member_prefix(&entry.1, &symbol, adding, &order);
                changed = true;
            }
            if changed {
                sort_members_by_rank(members, &order);
            }
            changed
        }
        _ => false,
    }
}

/// Parses a `links_bundle` payload, reconstructs the tree (see
/// `cordiale_core::links`), and pushes an indented rendering to the
/// `"links"` screen. Never crashes on an unexpected shape: an
/// unparseable `entries` array just shows nothing rather than erroring.
fn handle_links_bundle(ui: &slint::Weak<AppWindow>, payload: &Value) {
    let entries: Vec<cordiale_core::links::LinksEntry> = payload
        .get("entries")
        .and_then(|entries| serde_json::from_value(entries.clone()).ok())
        .unwrap_or_default();
    let network_label = payload
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let tree = cordiale_core::links::build_links_tree(&entries);

    let mut children_of: HashMap<Option<String>, Vec<&cordiale_core::links::LinksNode>> =
        HashMap::new();
    let mut by_server: HashMap<&str, &cordiale_core::links::LinksNode> = HashMap::new();
    for node in &tree {
        children_of
            .entry(node.parent.clone())
            .or_default()
            .push(node);
        by_server.insert(node.server.as_str(), node);
    }
    for children in children_of.values_mut() {
        children.sort_by(|a, b| a.server.cmp(&b.server));
    }

    let mut ordered: Vec<&cordiale_core::links::LinksNode> = Vec::with_capacity(tree.len());
    let mut stack: Vec<&str> = tree
        .iter()
        .filter(|node| node.is_root)
        .map(|node| node.server.as_str())
        .collect();
    while let Some(server) = stack.pop() {
        let Some(node) = by_server.get(server) else {
            continue;
        };
        ordered.push(node);
        if let Some(children) = children_of.get(&Some(server.to_string())) {
            for child in children.iter().rev() {
                stack.push(child.server.as_str());
            }
        }
    }

    let rows: Vec<LinksRow> = ordered
        .into_iter()
        .map(|node| {
            let indent = "  ".repeat(node.depth as usize);
            let hops = node
                .hopcount
                .map(|hops| format!(" (hops: {hops})"))
                .unwrap_or_default();
            let description = node
                .description
                .as_deref()
                .map(|description| format!(" — {description}"))
                .unwrap_or_default();
            LinksRow {
                display: format!("{indent}{}{hops}{description}", node.server).into(),
            }
        })
        .collect();

    // Radial layout for the optional graph window ("Show graph" on the
    // list screen) — computed here too so it's ready the moment the user
    // asks for it, rather than recomputed on click.
    const RING_GAP: f64 = 64.0;
    let layout = cordiale_core::links::radial_layout(&tree, RING_GAP);
    let canvas_center = links_canvas_center(&layout.nodes);
    let edges_commands = cordiale_core::links::links_graph_edges_svg_path(
        &layout.edges,
        canvas_center,
        canvas_center,
    );
    let graph_nodes: Vec<LinksGraphNode> = layout
        .nodes
        .into_iter()
        .map(|node| LinksGraphNode {
            server: node.server.into(),
            x: (node.x + canvas_center).round() as i32,
            y: (node.y + canvas_center).round() as i32,
        })
        .collect();
    let canvas_size = (canvas_center * 2.0).round() as i32;

    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_links_network_label(network_label.into());
        ui.set_links_rows(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_links_graph_edges_commands(edges_commands.into());
        ui.set_links_graph_canvas_size(canvas_size);
        ui.set_links_graph_nodes(Rc::new(slint::VecModel::from(graph_nodes)).into());
        ui.set_screen("links".into());
    });
}

pub(crate) fn query_history_fetch_window(
    state: &WorkerState,
    identity: &(String, String),
    key: &(String, String),
) -> (Option<i64>, Option<usize>) {
    if state
        .transcript
        .query_full_history_required
        .contains(identity)
    {
        // The highest local ID may be the just-buffered inbound DM, not a
        // history checkpoint. Fetch the default tail and merge it by ID.
        return (None, None);
    }
    let high_water = query_high_water_id(state, key);
    (high_water, high_water.map(|_| 200))
}

pub(crate) fn require_query_full_history_if_unready(
    state: &mut WorkerState,
    key: &(String, String),
) {
    let identity = query_window_key(&key.0, &key.1);
    if !state.transcript.query_ready.contains(&identity) {
        state
            .transcript
            .query_full_history_required
            .insert(identity);
    }
}

/// Adds a live message to a window's rows in `(server_time, id)` order. It
/// only counts as appended when the rows were already in order and the new
/// one sorts last (equal keys stay behind what was there, like the stable
/// sort does); otherwise the rows are sorted again, as before.
pub(crate) fn insert_live_message(
    messages: &mut Vec<RenderedMessage>,
    message: RenderedMessage,
) -> LiveInsert {
    let in_order = |left: &RenderedMessage, right: &RenderedMessage| {
        compare_rendered_message_order(left, right) != std::cmp::Ordering::Greater
    };
    let appended = messages.is_sorted_by(in_order)
        && messages.last().is_none_or(|last| in_order(last, &message));
    messages.push(message);
    if appended {
        LiveInsert::Appended
    } else {
        messages.sort_by(compare_rendered_message_order);
        LiveInsert::Reordered
    }
}

/// Stores a live DM line; `None` when the window already has it.
pub(crate) fn append_query_live_message(
    state: &mut WorkerState,
    key: &(String, String),
    payload: &Value,
    event_fallback: Option<&str>,
) -> Option<LiveInsert> {
    let message = render_message(payload, event_fallback);
    let messages = state.transcript.messages.entry(key.clone()).or_default();
    if message.message_id.is_some_and(|id| {
        messages
            .iter()
            .any(|existing| existing.message_id == Some(id))
    }) {
        return None;
    }
    Some(insert_live_message(messages, message))
}

/// Asks the worker (from the UI thread, where the pane's follow state can
/// be read) for a `WorkerCommand::RebuildChat`.
fn request_chat_rebuild(
    worker: &mpsc::UnboundedSender<WorkerCommand>,
    key: &(String, String),
    trim: bool,
) {
    let _ = worker.send(WorkerCommand::RebuildChat {
        key: key.clone(),
        trim,
    });
}

/// Shows a stored live DM line in the open query window, or just keeps the
/// stored rows in bounds when another window is open. A line that sorts
/// last is added to the pane as one row; anything else (or a pane whose
/// rows don't match the stored ones) rebuilds it, as every line used to.
fn show_live_query_message(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    key: &(String, String),
    insert: LiveInsert,
) {
    let open = state.windows.current_query && state.windows.current_channel.as_ref() == Some(key);
    if !open {
        trim_window_history(state, key);
    }
    publish_held_rows(state);
    if !open {
        return;
    }
    let dark_theme = state.prefs.theme == Theme::Dark;
    refresh_mention_context(state);
    let ui = ui.clone();
    if insert == LiveInsert::Reordered {
        let lines = state
            .transcript
            .messages
            .get(key)
            .cloned()
            .unwrap_or_default();
        let _ = ui.upgrade_in_event_loop(move |ui| {
            show_chat_lines(&ui, chat_lines_model(&lines, dark_theme));
        });
        return;
    }
    let rows = state.transcript.messages.get(key).map_or(0, Vec::len);
    let Some(line) = state
        .transcript
        .messages
        .get(key)
        .and_then(|rows| rows.last())
        .cloned()
    else {
        return;
    };
    let over_cap = history_excess(rows, CHAT_HISTORY_CAP, CHAT_HISTORY_TRIM_SLACK) > 0;
    let worker = state.conn.chat_rebuild_tx.clone();
    let key = key.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        use slint::Model as _;
        // The pane holds every stored row but this one; if it doesn't, it
        // has drifted from the stored rows and the worker rebuilds it.
        if ui.get_chat_lines().row_count() + 1 != rows {
            if let Some(worker) = &worker {
                request_chat_rebuild(worker, &key, false);
            }
            return;
        }
        append_chat_line(&ui, chat_line_from_message(&line, dark_theme, ""));
        if let Some(worker) = worker.filter(|_| over_cap && ui.get_chat_follow_bottom()) {
            request_chat_rebuild(&worker, &key, true);
        }
    });
}

/// Parses a channel-shaped query topic only when it belongs to the active
/// user. It intentionally accepts the same `channel:` topic contract as
/// Grappa; callers must additionally confirm the target is in the current
/// `query_windows_list` snapshot before treating it as a DM.
pub(crate) fn query_from_topic(user: &str, topic: &str) -> Option<(String, String)> {
    let prefix = format!("grappa:user:{user}/network:");
    let rest = topic.strip_prefix(&prefix)?;
    let (network, nick) = rest.split_once("/channel:")?;
    if network.is_empty() || nick.is_empty() || network.contains('/') || nick.contains('/') {
        return None;
    }
    Some((network.to_string(), nick.to_string()))
}

pub(crate) fn own_nick_listener_network_for_topic(
    state: &WorkerState,
    topic: &str,
) -> Option<String> {
    let user = state.conn.identifier.as_deref()?;
    state.networks.own_nicks.iter().find_map(|(network, nick)| {
        (own_nick_listener_topic(user, network, nick) == topic).then(|| network.clone())
    })
}

pub(crate) fn own_nick_listener_accepts_inbound_dm(payload: &Value) -> bool {
    matches!(
        payload.get("kind").and_then(Value::as_str),
        Some("privmsg" | "action")
    )
}

pub(crate) fn own_nick_dm_query_key(
    state: &WorkerState,
    network: &str,
    payload: &Value,
) -> Option<(String, String)> {
    let sender = own_nick_dm_sender(payload)?;
    let query = find_query_window(&state.transcript.query_windows, network, sender)?;
    Some((query.network.clone(), query.target_nick.clone()))
}

fn own_nick_dm_sender(payload: &Value) -> Option<&str> {
    let sender = ["from", "nick", "sender"]
        .iter()
        .find_map(|field| payload.get(*field).and_then(Value::as_str))?;
    if sender.trim().is_empty()
        || payload
            .get("body")
            .or_else(|| payload.get("message"))
            .and_then(Value::as_str)
            .is_none()
    {
        return None;
    }
    Some(sender)
}

pub(crate) fn buffer_pending_own_nick_dm(
    state: &mut WorkerState,
    network: &str,
    payload: &Value,
    event_fallback: &str,
) {
    let Some(sender) = own_nick_dm_sender(payload) else {
        return;
    };
    if find_query_window(&state.transcript.query_windows, network, sender).is_some() {
        return;
    }
    if state.transcript.pending_own_nick_dms.len() >= MAX_PENDING_OWN_NICK_DMS {
        // The dropped DM is in Grappa's scrollback: if its query opens, the
        // first history load fetches the full tail instead of only what
        // follows the buffered messages, so nothing goes missing.
        if let Some(dropped) = state.transcript.pending_own_nick_dms.pop_front() {
            state
                .transcript
                .query_full_history_required
                .insert(query_window_key(&dropped.network, &dropped.sender));
        }
    }
    state
        .transcript
        .pending_own_nick_dms
        .push_back(PendingOwnNickDm {
            network: network.to_string(),
            sender: sender.to_string(),
            payload: payload.clone(),
            event_fallback: event_fallback.to_string(),
        });
}

pub(crate) fn drain_pending_own_nick_dms(state: &mut WorkerState) {
    let pending = std::mem::take(&mut state.transcript.pending_own_nick_dms);
    for dm in pending {
        let Some(query) =
            find_query_window(&state.transcript.query_windows, &dm.network, &dm.sender).cloned()
        else {
            // A valid full snapshot is authoritative: if it didn't open the
            // sender's query, don't invent a client-side window or retain the
            // message until some unrelated later snapshot.
            state
                .transcript
                .query_full_history_required
                .remove(&query_window_key(&dm.network, &dm.sender));
            continue;
        };
        let key = (query.network.clone(), query.target_nick.clone());
        require_query_full_history_if_unready(state, &key);
        append_query_live_message(state, &key, &dm.payload, Some(&dm.event_fallback));
    }
}

/// Parses `(network, channel)` back out of a channel-level topic string;
/// `None` for the user topic, a network-level topic, or the heartbeat
/// topic.
pub(crate) fn channel_from_topic(topic: &str) -> Option<(String, String)> {
    let after_network = topic.split_once("/network:")?.1;
    let (network, after_channel) = after_network.split_once("/channel:")?;
    Some((network.to_string(), after_channel.to_string()))
}

/// Adds or drops one role symbol, keeping the member's symbols in `order`
/// (highest first).
pub(crate) fn update_member_prefix(
    prefix: &str,
    symbol: &str,
    adding: bool,
    order: &[String],
) -> String {
    let mut symbols: Vec<String> = prefix
        .chars()
        .map(String::from)
        .filter(|held| held != symbol)
        .collect();
    if adding {
        symbols.push(symbol.to_string());
    }
    let rank = |held: &String| {
        order
            .iter()
            .position(|symbol| symbol == held)
            .unwrap_or(order.len())
    };
    symbols.sort_by_key(rank);
    symbols.concat()
}

/// Parses one member list entry: either a plain string with an optional
/// leading role-prefix character (`"@nick"`, `"+nick"`, `"nick"`), or an
/// object carrying a `nick`/`name` field plus either an explicit `prefix`
/// string or a `modes` array. Grappa's real wire shape (`members_seeded`,
/// `names_reply`) puts role sigils, taken from the network's ISUPPORT
/// PREFIX, directly in `modes`, not mode letters — letters are still
/// accepted for backwards compatibility and mapped through that same
/// PREFIX (`isupport`; the usual `qaohv` ladder before its snapshot).
/// `order` holds the network's symbols highest first (see
/// `prefix_symbol_order`): it decides which symbols count as roles, and a
/// member holding several ends up stored with its highest one leading.
pub(crate) fn member_from_entry(
    entry: &Value,
    order: &[String],
    isupport: Option<&IsupportState>,
) -> Option<MemberEntry> {
    if let Some(raw) = entry.as_str() {
        let name = raw.trim_start_matches(|c: char| {
            order
                .iter()
                .any(|symbol| symbol.chars().eq(std::iter::once(c)))
        });
        let prefix = raw[..raw.len() - name.len()].to_string();
        return Some((name.to_string(), prefix));
    }

    let obj = entry.as_object()?;
    let name = obj
        .get("nick")
        .or_else(|| obj.get("name"))
        .and_then(Value::as_str)?
        .to_string();
    let prefix = obj
        .get("prefix")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            obj.get("modes").and_then(Value::as_array).map(|modes| {
                let mut symbols: Vec<String> = modes
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(|held| {
                        if order.iter().any(|symbol| symbol.as_str() == held) {
                            Some(held.to_string())
                        } else {
                            cordiale_core::isupport::prefix_symbol_for_mode(isupport, held)
                        }
                    })
                    .collect();
                symbols.sort_by_key(|symbol| prefix_rank(symbol, order));
                symbols.concat()
            })
        })
        .unwrap_or_default();
    Some((name, prefix))
}

/// Highest role first as the network's PREFIX ranks them (`order`, see
/// `prefix_symbol_order`), then everyone else — each group alphabetical
/// (case-insensitive) within itself.
pub(crate) fn sort_members_by_rank(members: &mut [MemberEntry], order: &[String]) {
    members.sort_by(|(name_a, prefix_a), (name_b, prefix_b)| {
        prefix_rank(prefix_a, order)
            .cmp(&prefix_rank(prefix_b, order))
            .then_with(|| name_a.to_lowercase().cmp(&name_b.to_lowercase()))
    });
}

fn return_home_if_network_selected(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
) {
    let selected_network_matches = state
        .windows
        .current_channel
        .as_ref()
        .is_some_and(|(selected_network, _)| selected_network == network);
    if !selected_network_matches {
        return;
    }

    state.windows.current_channel = None;
    state.windows.current_query = false;
    state.windows.current_query_ready = false;
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_screen("connected".into());
        ui.set_has_selected_channel(false);
        ui.set_current_channel_label("".into());
        ui.set_current_topic("".into());
        ui.set_window_status("".into());
        ui.set_current_window_is_joined(false);
        ui.set_current_server_window(false);
        ui.set_current_query(false);
        ui.set_current_query_ready(false);
        ui.set_can_moderate_members(false);
        ui.set_compose_text("".into());
        show_chat_lines(&ui, Vec::new());
        ui.set_channel_members(Rc::new(slint::VecModel::from(Vec::<MemberRow>::new())).into());
    });
}

fn collapse_if_parked(state: &mut WorkerState, network: &str) -> bool {
    if state
        .networks
        .network_connection_states
        .get(network)
        .is_some_and(|snapshot| matches!(snapshot.status, NetworkConnectionStatus::Parked))
    {
        return state
            .windows
            .expanded_networks
            .insert(network.to_string(), false)
            != Some(false);
    }
    false
}

/// Appends one already-rendered line without rebuilding the rest of the
/// model — a plain `row_added` notification, gentler still than the
/// `set_vec` reset `show_chat_lines` triggers. Only correct when the
/// caller knows the new row truly belongs at the very end, e.g. a live
/// channel message, or a DM line that sorts last (`insert_live_message`);
/// a DM line that has to be put back in order goes through
/// `show_chat_lines` instead.
fn append_chat_line(ui: &AppWindow, line: ChatLine) {
    with_chat_lines_model(ui, |model| model.push(line));
}

pub(crate) fn record_network_connection_state(
    states: &mut HashMap<String, NetworkConnectionSnapshot>,
    slug: &str,
    snapshot: NetworkConnectionSnapshot,
) -> (bool, bool) {
    let previous = states.insert(slug.to_string(), snapshot.clone());
    let changed = previous
        .as_ref()
        .is_none_or(|previous| previous.status != snapshot.status);
    let return_home = previous.is_some_and(|previous| {
        previous.status != snapshot.status
            && matches!(
                snapshot.status,
                NetworkConnectionStatus::Parked | NetworkConnectionStatus::Failed
            )
    });
    (changed, return_home)
}

fn parse_nullable_wire_string(value: &Value) -> Option<Option<String>> {
    match value {
        Value::Null => Some(None),
        Value::String(value) => Some(Some(value.clone())),
        _ => None,
    }
}

/// Reverses `/boot`'s slug-to-id map. Duplicate IDs are rejected rather than
/// allowing an event row to be attached to an arbitrary network.
fn network_slugs_by_id(network_ids: &HashMap<String, i64>) -> Option<HashMap<i64, String>> {
    let mut slugs = HashMap::new();
    for (slug, id) in network_ids {
        if *id <= 0 {
            return None;
        }
        if let Some(previous) = slugs.insert(*id, slug.clone()) {
            if previous != *slug {
                return None;
            }
        }
    }
    Some(slugs)
}

pub(crate) fn parse_own_nick_changed(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<(String, String)> {
    if payload.get("kind")?.as_str()? != "own_nick_changed" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    if network_id <= 0 {
        return None;
    }
    let network = network_slugs.get(&network_id)?;
    let nick = payload.get("nick")?.as_str()?;
    if nick.trim().is_empty() {
        return None;
    }
    Some((network.clone(), nick.to_string()))
}

pub(crate) fn parse_away_confirmed(
    payload: &Value,
    known_networks: &HashMap<String, i64>,
) -> Option<(String, AwayStatus)> {
    if payload.get("kind")?.as_str()? != "away_confirmed" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() || !known_networks.contains_key(network) {
        return None;
    }
    let status = match payload.get("state")?.as_str()? {
        "present" => AwayStatus::Present,
        "away" => AwayStatus::Away,
        _ => return None,
    };
    Some((network.to_string(), status))
}

pub(crate) fn apply_away_confirmed(
    away_states: &mut HashMap<String, AwayStatus>,
    network: &str,
    status: AwayStatus,
) -> bool {
    if away_states.get(network) == Some(&status) {
        return false;
    }
    away_states.insert(network.to_string(), status);
    true
}

pub(crate) fn handle_away_confirmed(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(user) = state.conn.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some((network, status)) = parse_away_confirmed(payload, &state.networks.network_ids) else {
        persistence::log_line("away_confirmed rejected: invalid state or unknown network");
        return;
    };
    if apply_away_confirmed(&mut state.networks.away_states, &network, status) {
        persistence::log_line(&format!("away_confirmed applied: {network}={status:?}"));
    }
}

pub(crate) fn parse_session_identity_changed(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<(String, SessionIdentity)> {
    if payload.get("kind")?.as_str()? != "session_identity_changed" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    let network = network_slugs.get(&network_id)?;
    let identified = payload.get("identified")?.as_bool()?;
    let account = match payload.get("account")? {
        Value::Null => None,
        Value::String(account) => Some(account.clone()),
        _ => return None,
    };
    Some((
        network.clone(),
        SessionIdentity {
            identified,
            account,
        },
    ))
}

pub(crate) fn handle_session_identity_changed(
    state: &mut WorkerState,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(user) = state.conn.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.networks.network_ids) else {
        persistence::log_line("session_identity_changed rejected: invalid network map");
        return;
    };
    let Some((network, identity)) = parse_session_identity_changed(payload, &network_slugs) else {
        persistence::log_line(
            "session_identity_changed rejected: invalid payload or unknown network",
        );
        return;
    };
    state.networks.session_identities.insert(network, identity);
}

pub(crate) fn handle_isupport_changed(
    state: &mut WorkerState,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(user) = state.conn.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(event) = parse_isupport_changed(payload) else {
        persistence::log_line("isupport_changed rejected: invalid payload");
        return;
    };
    let Some(network_slugs) = network_slugs_by_id(&state.networks.network_ids) else {
        persistence::log_line("isupport_changed rejected: invalid network map");
        return;
    };
    let Some(network) = network_slugs.get(&event.network_id) else {
        persistence::log_line("isupport_changed rejected: unknown network");
        return;
    };
    state
        .networks
        .isupport_by_network
        .insert(network.clone(), event.state);
}

fn parse_umode_changed(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<(String, Vec<String>)> {
    if payload.get("kind")?.as_str()? != "umode_changed" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    if network_id <= 0 {
        return None;
    }
    let network = network_slugs.get(&network_id)?;
    let raw_modes = payload.get("modes")?.as_array()?;
    let mut seen = std::collections::HashSet::with_capacity(raw_modes.len());
    let mut modes = Vec::with_capacity(raw_modes.len());
    for value in raw_modes {
        let mode = value.as_str()?;
        if mode.is_empty() || mode.starts_with('+') || mode.starts_with('-') || !seen.insert(mode) {
            return None;
        }
        modes.push(mode.to_string());
    }
    Some((network.clone(), modes))
}

pub(crate) fn handle_umode_changed(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(user) = state.conn.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.networks.network_ids) else {
        persistence::log_line("umode_changed rejected: invalid network map");
        return;
    };
    let Some((network, modes)) = parse_umode_changed(payload, &network_slugs) else {
        persistence::log_line("umode_changed rejected: invalid payload or unknown network");
        return;
    };
    state.networks.user_modes_by_network.insert(network, modes);
}

fn parse_supported_umodes_changed(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<(String, Vec<String>)> {
    if payload.get("kind")?.as_str()? != "supported_umodes_changed" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    if network_id <= 0 {
        return None;
    }
    let network = network_slugs.get(&network_id)?;
    let raw_modes = payload.get("modes")?.as_array()?;
    let mut seen = std::collections::HashSet::with_capacity(raw_modes.len());
    let mut modes = Vec::with_capacity(raw_modes.len());
    for value in raw_modes {
        let mode = value.as_str()?;
        if mode.is_empty() || mode.starts_with('+') || mode.starts_with('-') || !seen.insert(mode) {
            return None;
        }
        modes.push(mode.to_string());
    }
    Some((network.clone(), modes))
}

pub(crate) fn handle_supported_umodes_changed(
    state: &mut WorkerState,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(user) = state.conn.identifier.as_deref() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.networks.network_ids) else {
        persistence::log_line("supported_umodes_changed rejected: invalid network map");
        return;
    };
    let Some((network, modes)) = parse_supported_umodes_changed(payload, &network_slugs) else {
        persistence::log_line(
            "supported_umodes_changed rejected: invalid payload or unknown network",
        );
        return;
    };
    state
        .networks
        .supported_user_modes_by_network
        .insert(network, modes);
}

pub(crate) fn apply_own_nick_change(
    state: &mut WorkerState,
    user: &str,
    network: &str,
    nick: &str,
) -> Vec<OwnNickListenerAction> {
    let previous = state
        .networks
        .own_nicks
        .insert(network.to_string(), nick.to_string());
    let new_topic = own_nick_listener_topic(user, network, nick);
    if previous
        .as_deref()
        .is_some_and(|old_nick| ascii_fold_channel(old_nick) == ascii_fold_channel(nick))
    {
        return Vec::new();
    }

    let mut actions = Vec::with_capacity(2);
    if let Some(old_nick) = previous {
        let old_topic = own_nick_listener_topic(user, network, &old_nick);
        state.conn.own_listener_ready.remove(&old_topic);
        if find_query_window(&state.transcript.query_windows, network, &old_nick).is_none() {
            state.conn.joined_topics.remove(&old_topic);
            actions.push(OwnNickListenerAction::Leave(old_topic));
        }
    }

    if state.conn.joined_topics.insert(new_topic.clone()) {
        state.conn.own_listener_ready.remove(&new_topic);
        actions.push(OwnNickListenerAction::Join(new_topic));
    } else if state
        .transcript
        .query_joined
        .contains(&query_window_key(network, nick))
    {
        // The canonical topic may already have been joined as a listed query.
        // Its successful query ACK is also sufficient for this listener.
        state.conn.own_listener_ready.insert(new_topic);
    }

    actions
}

pub(crate) fn handle_own_nick_listener_join_reply(
    state: &mut WorkerState,
    topic: &str,
    status: Option<&str>,
) -> OwnNickListenerJoinReply {
    if !state.conn.joined_topics.contains(topic)
        || own_nick_listener_network_for_topic(state, topic).is_none()
    {
        return OwnNickListenerJoinReply::Untracked;
    }
    if status == Some("ok") {
        state.conn.own_listener_ready.insert(topic.to_string());
        OwnNickListenerJoinReply::Accepted
    } else {
        state.conn.own_listener_ready.remove(topic);
        OwnNickListenerJoinReply::Rejected
    }
}

fn handle_own_nick_changed(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(user) = state.conn.identifier.clone() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{user}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.networks.network_ids) else {
        persistence::log_line("own_nick_changed rejected: ambiguous network ID map");
        return;
    };
    let Some((network, nick)) = parse_own_nick_changed(payload, &network_slugs) else {
        persistence::log_line("own_nick_changed rejected: invalid or unknown network");
        return;
    };

    let actions = apply_own_nick_change(state, &user, &network, &nick);
    if let Some(session) = state.conn.session.as_ref() {
        for action in actions {
            match action {
                OwnNickListenerAction::Leave(topic) => session.leave_topic(topic),
                OwnNickListenerAction::Join(topic) => session.join_topic(topic, false),
            }
        }
    }
}

pub(crate) fn is_channels_changed_signal(user: &str, carrier_topic: &str, payload: &Value) -> bool {
    carrier_topic == format!("grappa:user:{user}")
        && payload.get("kind").and_then(Value::as_str) == Some("channels_changed")
}

async fn handle_channels_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    if !is_channels_changed_signal(&identifier, carrier_topic, payload) {
        return;
    }
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };

    let mut networks: Vec<String> = state.networks.network_ids.keys().cloned().collect();
    networks.sort();
    let mut requests = tokio::task::JoinSet::new();
    for network in networks {
        let client = client.clone();
        let token = token.clone();
        requests.spawn(async move {
            let channels = client.fetch_channels(&token, &network).await;
            (network, channels)
        });
    }

    let mut channels_by_network = HashMap::new();
    while let Some(result) = requests.join_next().await {
        match result {
            Ok((network, Ok(channels))) => {
                channels_by_network.insert(network, channels);
            }
            Ok((_, Err(_))) | Err(_) => {
                persistence::log_line(
                    "channels_changed refresh failed; keeping existing channel state",
                );
                return;
            }
        }
    }

    if state.conn.session.is_none() {
        persistence::log_line(
            "channels_changed refresh skipped without an active realtime session",
        );
        return;
    }
    let entries = channel_entries_from_channels(&channels_by_network);
    let actions = reconcile_channel_entries(state, &identifier, entries);
    let Some(session) = state.conn.session.as_ref() else {
        // Checked immediately before reconciliation; keep this defensive in
        // case the state container changes independently in the future.
        return;
    };
    for action in actions {
        match action {
            ChannelTopicAction::Leave(topic) => session.leave_topic(topic),
            ChannelTopicAction::Join(topic) => session.join_topic(topic, true),
        }
    }
    refresh_network_groups(state, ui);
}

pub(crate) fn parse_connection_state_changed_event(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<NetworkConnectionTransition> {
    if identifier.is_empty()
        || carrier_topic != format!("grappa:user:{identifier}")
        || payload.get("kind").and_then(Value::as_str) != Some("connection_state_changed")
    {
        return None;
    }

    match payload.get("user_id")? {
        Value::Null | Value::String(_) => {}
        _ => return None,
    }

    let network_id = payload.get("network_id").and_then(Value::as_i64)?;
    if network_id <= 0 {
        return None;
    }
    let network_slug = payload.get("network_slug").and_then(Value::as_str)?;
    if network_slug.trim().is_empty() {
        return None;
    }
    let from = NetworkConnectionStatus::parse(payload.get("from").and_then(Value::as_str)?)?;
    let status = NetworkConnectionStatus::parse(payload.get("to").and_then(Value::as_str)?)?;
    let reason = parse_nullable_wire_string(payload.get("reason")?)?;
    let changed_at = parse_nullable_wire_string(payload.get("at")?)?;

    let network = payload.get("network")?.as_object()?;
    if network.get("slug").and_then(Value::as_str) != Some(network_slug)
        || network
            .get("connection_state")
            .and_then(Value::as_str)
            .and_then(NetworkConnectionStatus::parse)
            != Some(status)
    {
        return None;
    }
    if let Some(row_id) = network.get("id") {
        if row_id.as_i64()? != network_id {
            return None;
        }
    }
    if let Some(row_reason) = network.get("connection_state_reason") {
        if parse_nullable_wire_string(row_reason)? != reason {
            return None;
        }
    }
    if let Some(row_changed_at) = network.get("connection_state_changed_at") {
        if parse_nullable_wire_string(row_changed_at)? != changed_at {
            return None;
        }
    }

    Some(NetworkConnectionTransition {
        network_id,
        network_slug: network_slug.to_string(),
        from,
        snapshot: NetworkConnectionSnapshot {
            status,
            reason,
            changed_at,
        },
    })
}

/// Reconciles the self-message listener topics after an authoritative
/// `/boot` refresh.  Channel-shaped topics are shared with query windows, so
/// an old listener is left only when no open query still owns that topic.
fn reconcile_own_nick_listener_topics(
    state: &mut WorkerState,
    user: &str,
    next_own_nicks: HashMap<String, String>,
) -> Vec<OwnNickListenerAction> {
    let previous = std::mem::replace(&mut state.networks.own_nicks, next_own_nicks.clone());
    let mut actions = Vec::new();

    for (network, old_nick) in previous {
        let same_topic = next_own_nicks
            .get(&network)
            .is_some_and(|new_nick| ascii_fold_channel(new_nick) == ascii_fold_channel(&old_nick));
        if same_topic {
            continue;
        }

        let old_topic = own_nick_listener_topic(user, &network, &old_nick);
        state.conn.own_listener_ready.remove(&old_topic);
        if find_query_window(&state.transcript.query_windows, &network, &old_nick).is_none()
            && state.conn.joined_topics.remove(&old_topic)
        {
            actions.push(OwnNickListenerAction::Leave(old_topic));
        }
    }

    for (network, nick) in next_own_nicks {
        let topic = own_nick_listener_topic(user, &network, &nick);
        if state.conn.joined_topics.insert(topic.clone()) {
            state.conn.own_listener_ready.remove(&topic);
            actions.push(OwnNickListenerAction::Join(topic));
        }
    }

    actions
}

/// Applies the two REST snapshots that Cicchetto refreshes after a network
/// attach or detach. The REST responses are fetched before any mutation, so a
/// failed refresh leaves the existing projection intact. The WebSocket session
/// is preserved; only the state owned by `/boot` and `/me` is replaced and the
/// resulting topic differences are sent to the existing session.
pub(crate) fn apply_network_rest_refresh(
    state: &mut WorkerState,
    identifier: &str,
    boot: &BootResponse,
    me: &MeResponse,
) -> Vec<ChannelTopicAction> {
    let next_network_ids = network_ids_from_entries(&boot.networks);
    let mut entries = channel_entries_from_channels(&boot.channels);
    entries.retain(|(network, _, _)| next_network_ids.contains_key(network));
    let known_networks: std::collections::HashSet<String> =
        next_network_ids.keys().cloned().collect();
    let channel_actions = reconcile_channel_entries_in(state, identifier, entries, &known_networks);

    // The account's /boot network list is authoritative. A removed network
    // must not be recreated by an old query row or a late channel snapshot.
    state
        .transcript
        .query_windows
        .retain(|query| next_network_ids.contains_key(&query.network));
    state
        .windows
        .expanded_networks
        .retain(|network, _| next_network_ids.contains_key(network));
    state
        .transcript
        .query_joined
        .retain(|(network, _)| next_network_ids.contains_key(network));
    state
        .transcript
        .query_ready
        .retain(|(network, _)| next_network_ids.contains_key(network));
    state
        .transcript
        .query_full_history_required
        .retain(|(network, _)| next_network_ids.contains_key(network));
    state
        .transcript
        .stale_query_topics
        .retain(|(network, _)| next_network_ids.contains_key(network));
    state
        .windows
        .recent_channels
        .retain(|(network, _)| next_network_ids.contains_key(network));

    // `/boot` only knows the joined windows. A pending, invited, failed or
    // kicked one on a network that stays keeps its state and its metadata
    // (kick actor and reason, failure reason, inviter) unless `/boot` now
    // reports that window as joined.
    let previous_states = std::mem::take(&mut state.windows.window_states);
    let mut previous_failures = std::mem::take(&mut state.windows.window_failures);
    let mut previous_kicks = std::mem::take(&mut state.windows.window_kicks);
    let mut previous_invites = std::mem::take(&mut state.windows.invited_by);
    state.windows.window_states = joined_window_states_from_boot_channels(&boot.channels);
    for (key, window_state) in previous_states {
        if !is_unlisted_window_state(&window_state)
            || !next_network_ids.contains_key(&key.0)
            || state.windows.window_states.contains_key(&key)
        {
            continue;
        }
        if let Some(failure) = previous_failures.remove(&key) {
            state.windows.window_failures.insert(key.clone(), failure);
        }
        if let Some(kick) = previous_kicks.remove(&key) {
            state.windows.window_kicks.insert(key.clone(), kick);
        }
        if let Some(inviter) = previous_invites.remove(&key) {
            state.windows.invited_by.insert(key.clone(), inviter);
        }
        state.windows.window_states.insert(key, window_state);
    }
    state.windows.window_mentions = window_mentions_from_me(&me.unread_counts);
    state.windows.window_messages = window_messages_from_me(&me.unread_counts);
    // `/boot` carries neither topics nor rosters: both are re-seeded on
    // each channel's Phoenix topic.
    state.transcript.topics.clear();
    state.transcript.members.clear();
    let mut messages = messages_from_boot_response(boot);
    // `/boot.heads` is not guaranteed to include the synthetic window. Keep
    // its live/REST rows across unrelated network refreshes while dropping
    // rows belonging to networks no longer present in the authoritative list.
    for ((network, channel), rows) in &state.transcript.messages {
        if channel == SERVER_WINDOW_NAME && next_network_ids.contains_key(network) {
            merge_rendered_messages(
                messages
                    .entry((network.clone(), channel.clone()))
                    .or_default(),
                rows.iter().cloned(),
            );
        }
    }
    state.transcript.messages = messages;
    state.windows.read_cursors = read_cursors_from_me(&me.read_cursors);
    state.windows.badge_count = normalize_badge_count(Some(&me.badge_count));
    state.home.apply_me(me);
    state
        .home
        .retain_networks(&next_network_ids.keys().map(String::as_str).collect());
    state.networks.network_ids = next_network_ids;
    state.networks.network_connection_states =
        network_connection_states_from_entries(&boot.networks);

    let listener_actions = reconcile_own_nick_listener_topics(
        state,
        identifier,
        network_nicks_from_entries(&boot.networks),
    );

    // The refresh is authoritative for per-network transient snapshots too;
    // discard entries for networks no longer present while preserving the
    // latest values for networks that remain attached/parked.
    let known_networks: std::collections::HashSet<&str> = state
        .networks
        .network_ids
        .keys()
        .map(String::as_str)
        .collect();
    state
        .networks
        .away_states
        .retain(|network, _| known_networks.contains(network.as_str()));
    state
        .networks
        .session_identities
        .retain(|network, _| known_networks.contains(network.as_str()));
    state
        .networks
        .isupport_by_network
        .retain(|network, _| known_networks.contains(network.as_str()));
    state
        .networks
        .user_modes_by_network
        .retain(|network, _| known_networks.contains(network.as_str()));
    state
        .networks
        .supported_user_modes_by_network
        .retain(|network, _| known_networks.contains(network.as_str()));
    state
        .networks
        .connecting_networks
        .retain(|network| known_networks.contains(network.as_str()));

    let mut actions = channel_actions;
    // The server window exists per network even when no IRC channel is joined.
    // It shares the channel topic shape, but is not part of boot.channels.
    let mut server_networks: Vec<String> = state.networks.network_ids.keys().cloned().collect();
    server_networks.sort();
    for network in server_networks {
        let topic = channel_topic(identifier, &network, SERVER_WINDOW_NAME);
        if state.conn.joined_topics.insert(topic.clone()) {
            actions.push(ChannelTopicAction::Join(topic));
        }
    }
    for action in listener_actions {
        actions.push(match action {
            OwnNickListenerAction::Leave(topic) => ChannelTopicAction::Leave(topic),
            OwnNickListenerAction::Join(topic) => ChannelTopicAction::Join(topic),
        });
    }
    let mut obsolete_topics: Vec<String> = state
        .conn
        .joined_topics
        .iter()
        .filter(|topic| {
            query_from_topic(identifier, topic)
                .is_some_and(|(network, _)| !state.networks.network_ids.contains_key(&network))
        })
        .cloned()
        .collect();
    obsolete_topics.sort();
    for topic in obsolete_topics {
        state.conn.joined_topics.remove(&topic);
        if !actions.iter().any(
            |action| matches!(action, ChannelTopicAction::Leave(existing) if existing == &topic),
        ) {
            actions.push(ChannelTopicAction::Leave(topic));
        }
    }
    actions
}

async fn handle_connection_state_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    let Some(transition) =
        parse_connection_state_changed_event(payload, carrier_topic, &identifier)
    else {
        return;
    };
    if state.networks.network_ids.get(&transition.network_slug) != Some(&transition.network_id) {
        persistence::log_line("connection_state_changed rejected: unknown or stale network");
        return;
    }

    let network_slug = transition.network_slug.clone();
    let (snapshot_changed, return_home) = record_network_connection_state(
        &mut state.networks.network_connection_states,
        &network_slug,
        transition.snapshot.clone(),
    );
    let collapsed = snapshot_changed && collapse_if_parked(state, &network_slug);
    if return_home {
        return_home_if_network_selected(state, ui, &network_slug);
    }
    if snapshot_changed || collapsed {
        refresh_network_groups(state, ui);
    }
    persistence::log_line(&format!(
        "connection_state_changed: {network_slug} {} -> {}",
        transition.from.wire_name(),
        transition.snapshot.status.wire_name()
    ));

    reconcile_network_connection_states(state, ui, "connection_state_changed").await;
}

/// Refreshes `GET /networks` and applies each known network's durable
/// connection state. A failed request keeps the current state: callers have
/// already applied whatever their event carried.
async fn reconcile_network_connection_states(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    context: &str,
) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let networks = match client.fetch_networks(&token).await {
        Ok(networks) => networks,
        Err(error) => {
            persistence::log_line(&format!(
                "{context} network refresh failed; keeping current state: {error:?}"
            ));
            return;
        }
    };

    let refreshed_ids = network_ids_from_entries(&networks);
    let refreshed_states = network_connection_states_from_entries(&networks);
    let mut state_changed = false;
    for (slug, snapshot) in refreshed_states {
        let Some(expected_id) = state.networks.network_ids.get(&slug) else {
            continue;
        };
        if refreshed_ids
            .get(&slug)
            .is_some_and(|refreshed_id| refreshed_id != expected_id)
        {
            continue;
        }
        let (row_changed, return_home) = record_network_connection_state(
            &mut state.networks.network_connection_states,
            &slug,
            snapshot,
        );
        if row_changed {
            state_changed |= collapse_if_parked(state, &slug);
        }
        if return_home {
            return_home_if_network_selected(state, ui, &slug);
        }
        state_changed |= row_changed;
    }
    if state_changed {
        refresh_network_groups(state, ui);
    }
}

/// Validates `connection_progress`: `{kind, network, state}` on the exact
/// authenticated user topic, for a network already in the `/boot` map. The
/// state is a closed `connecting | connected` enum; extra fields are ignored.
pub(crate) fn parse_connection_progress(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
    known_networks: &HashMap<String, i64>,
) -> Option<(String, ConnectionProgressState)> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "connection_progress" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() || !known_networks.contains_key(network) {
        return None;
    }
    let progress = ConnectionProgressState::parse(payload.get("state")?.as_str()?)?;
    Some((network.to_string(), progress))
}

/// Applies one progress edge to the per-network connecting set, returning
/// whether the visible badge changed. Duplicates are no-ops.
pub(crate) fn apply_connection_progress(
    connecting: &mut std::collections::HashSet<String>,
    network: &str,
    progress: ConnectionProgressState,
) -> bool {
    match progress {
        ConnectionProgressState::Connecting => connecting.insert(network.to_string()),
        ConnectionProgressState::Connected => connecting.remove(network),
    }
}

/// `connecting` shows a transient per-network badge; `connected` (001
/// RPL_WELCOME) clears it and refetches `GET /networks`, since the durable
/// connection row only arrives through that endpoint, matching Cicchetto.
async fn handle_connection_progress(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    let Some((network, progress)) = parse_connection_progress(
        payload,
        carrier_topic,
        &identifier,
        &state.networks.network_ids,
    ) else {
        persistence::log_line("connection_progress rejected: invalid payload or unknown network");
        return;
    };
    // A `/lusers` only belongs to the connection it was issued on: the
    // registration burst of a new attempt is unsolicited.
    if progress == ConnectionProgressState::Connecting {
        state.panels.lusers_requested.remove(&network);
    }
    if apply_connection_progress(&mut state.networks.connecting_networks, &network, progress) {
        refresh_network_groups(state, ui);
    }
    if progress == ConnectionProgressState::Connected {
        reconcile_network_connection_states(state, ui, "connection_progress").await;
    }
}

/// Validates `recover_progress` on the exact user topic: `network` a
/// non-empty slug, `step`/`status` closed enums, and `reason` present as
/// `null` or any string (an additive server reason must not drop the step).
pub(crate) fn parse_recover_progress(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, RecoverStepEntry)> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "recover_progress" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let step = RecoverStep::parse(payload.get("step")?.as_str()?)?;
    let status = RecoverStepStatus::parse(payload.get("status")?.as_str()?)?;
    let reason = match payload.get("reason")? {
        Value::Null => None,
        Value::String(reason) => Some(reason.clone()),
        _ => return None,
    };
    Some((
        network.to_string(),
        RecoverStepEntry {
            step,
            status,
            reason,
        },
    ))
}

/// Cicchetto's `applyRecoverProgress`: the first event opens the panel for
/// its network, an event for any other network is ignored while one is
/// open, and a known step is replaced in place so the order stays stable.
pub(crate) fn apply_recover_progress(
    panel: &mut Option<RecoverPanel>,
    network: &str,
    entry: RecoverStepEntry,
) -> bool {
    if panel.is_none() {
        *panel = Some(RecoverPanel {
            network: network.to_string(),
            steps: vec![entry],
            outcome: None,
            outcome_reason: None,
        });
        return true;
    }
    let Some(open) = panel.as_mut() else {
        return false;
    };
    if open.network != network {
        return false;
    }
    match open.steps.iter().position(|row| row.step == entry.step) {
        Some(index) if open.steps[index] == entry => false,
        Some(index) => {
            open.steps[index] = entry;
            true
        }
        None => {
            open.steps.push(entry);
            true
        }
    }
}

fn handle_recover_progress(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network, entry)) = parse_recover_progress(payload, carrier_topic, identifier) else {
        persistence::log_line("recover_progress rejected: invalid carrier or payload");
        return;
    };
    if apply_recover_progress(&mut state.panels.recover_panel, &network, entry) {
        push_recover_panel(state, ui);
    }
}

/// Validates `recover_result` on the exact user topic: non-empty `network`,
/// closed `outcome`, and `reason` present as `null` or any string, so an
/// additive failure token never drops this terminal event.
pub(crate) fn parse_recover_result(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, RecoverOutcome, Option<String>)> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "recover_result" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let outcome = RecoverOutcome::parse(payload.get("outcome")?.as_str()?)?;
    let reason = match payload.get("reason")? {
        Value::Null => None,
        Value::String(reason) => Some(reason.clone()),
        _ => return None,
    };
    Some((network.to_string(), outcome, reason))
}

/// Cicchetto's `applyRecoverResult`: a no-op when no panel is open (dismissed
/// mid-flight, or the progress events were lost) or when it belongs to
/// another network; otherwise it records the conclusion.
pub(crate) fn apply_recover_result(
    panel: &mut Option<RecoverPanel>,
    network: &str,
    outcome: RecoverOutcome,
    reason: Option<String>,
) -> bool {
    let Some(open) = panel.as_mut() else {
        return false;
    };
    if open.network != network {
        return false;
    }
    if open.outcome == Some(outcome) && open.outcome_reason == reason {
        return false;
    }
    open.outcome = Some(outcome);
    open.outcome_reason = reason;
    true
}

fn handle_recover_result(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network, outcome, reason)) = parse_recover_result(payload, carrier_topic, identifier)
    else {
        persistence::log_line("recover_result rejected: invalid carrier or payload");
        return;
    };
    if apply_recover_result(&mut state.panels.recover_panel, &network, outcome, reason) {
        push_recover_panel(state, ui);
    }
}

/// Validates `web_session_severed` on the exact user topic. `code` must be a
/// string but any value is accepted: the action (sign out) does not depend on
/// it, and an unknown future code must never leave the client holding a
/// revoked bearer.
pub(crate) fn parse_web_session_severed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<String> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "web_session_severed" {
        return None;
    }
    Some(payload.get("code")?.as_str()?.to_string())
}

/// Grappa sends this best-effort, then revokes the bearer and closes the
/// socket; the IRC session stays up. Like Cicchetto, sign out for every code
/// and show the dedicated notice only for `rate_limit_flood`.
fn handle_web_session_severed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(code) = parse_web_session_severed(payload, carrier_topic, identifier) else {
        persistence::log_line("web_session_severed rejected: invalid carrier or payload");
        return;
    };
    persistence::log_line(&format!("web session severed by server: code={code}"));
    end_revoked_session(state, ui, code == "rate_limit_flood");
}

/// Validates `auto_away_debounce_changed` on the exact user topic. The key
/// is always present: `null` is meaningful (server default), not missing;
/// a negative or non-integer value is rejected.
pub(crate) fn parse_auto_away_debounce_changed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<AutoAwayDebounce> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != "auto_away_debounce_changed" {
        return None;
    }
    match payload.get("auto_away_debounce_seconds")? {
        Value::Null => Some(AutoAwayDebounce::ServerDefault),
        value => match value.as_u64()? {
            0 => Some(AutoAwayDebounce::Disabled),
            seconds => Some(AutoAwayDebounce::Seconds(seconds)),
        },
    }
}

/// Mirrors the server's stored auto-away delay into Settings. Cordiale never
/// originates this value; it only reflects what Grappa announced.
fn handle_auto_away_debounce_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(debounce) = parse_auto_away_debounce_changed(payload, carrier_topic, identifier)
    else {
        persistence::log_line("auto_away_debounce_changed rejected: invalid carrier or payload");
        return;
    };
    if state.prefs.auto_away_debounce == Some(debounce) {
        return;
    }
    state.prefs.auto_away_debounce = Some(debounce);
    let text = debounce.edit_text();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_edit_away_delay(text.into());
    });
}

/// Validates a user-settings echo whose single value is a string or `null`
/// on the exact user topic. The key is always present: `null` is meaningful
/// (the server falls back to its own text), not missing.
pub(crate) fn parse_nullable_setting_echo(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
    kind: &str,
    key: &str,
) -> Option<Option<String>> {
    if carrier_topic != format!("grappa:user:{identifier}") {
        return None;
    }
    if payload.get("kind")?.as_str()? != kind {
        return None;
    }
    parse_nullable_wire_string(payload.get(key)?)
}

/// Mirrors the server's remembered QUIT/PART text into its Settings
/// editor; Grappa stays the owner of the value.
fn handle_quit_part_reason_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(reason) = parse_nullable_setting_echo(
        payload,
        carrier_topic,
        identifier,
        "quit_part_reason_changed",
        "quit_part_reason",
    ) else {
        persistence::log_line("quit_part_reason_changed rejected: invalid carrier or payload");
        return;
    };
    if state.prefs.quit_part_reason.as_ref() == Some(&reason) {
        return;
    }
    state.prefs.quit_part_reason = Some(reason.clone());
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_edit_leave_message(reason.unwrap_or_default().into());
    });
}

/// Mirrors the server's auto-away text into its Settings editor; `null`
/// (Grappa keeps its own built-in text) shows as an empty field.
fn handle_auto_away_reason_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(reason) = parse_nullable_setting_echo(
        payload,
        carrier_topic,
        identifier,
        "auto_away_reason_changed",
        "auto_away_reason",
    ) else {
        persistence::log_line("auto_away_reason_changed rejected: invalid carrier or payload");
        return;
    };
    if state.prefs.auto_away_reason.as_ref() == Some(&reason) {
        return;
    }
    state.prefs.auto_away_reason = Some(reason.clone());
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_edit_away_message(reason.unwrap_or_default().into());
    });
}

/// Validates `away_nick_suffix_changed` (always-present, nullable key, on
/// the subject's own user topic) and records it; `Some(value)` when the
/// display copy changed. Only the setting moves: the nick itself stays
/// whatever the nick events say, since Grappa may skip a rename (NICKLEN)
/// or fail to restore the bare nick.
pub(crate) fn apply_away_nick_suffix_changed(
    state: &mut WorkerState,
    carrier_topic: &str,
    payload: &Value,
) -> Option<Option<String>> {
    let identifier = state.conn.identifier.as_deref()?;
    let Some(suffix) = parse_nullable_setting_echo(
        payload,
        carrier_topic,
        identifier,
        "away_nick_suffix_changed",
        "away_nick_suffix",
    ) else {
        persistence::log_line("away_nick_suffix_changed rejected: invalid carrier or payload");
        return None;
    };
    if state.prefs.away_nick_suffix.as_ref() == Some(&suffix) {
        return None;
    }
    state.prefs.away_nick_suffix = Some(suffix.clone());
    Some(suffix)
}

/// Mirrors a suffix saved on any device into the Settings field.
fn handle_away_nick_suffix_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(suffix) = apply_away_nick_suffix_changed(state, carrier_topic, payload) else {
        return;
    };
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_away_nick_suffix_supported(true);
        ui.set_edit_away_nick_suffix(suffix.unwrap_or_default().into());
    });
}

/// Requester replies all arrive on the exact authenticated user topic and
/// only on the socket that asked; anything else is rejected before parsing.
fn is_own_user_topic(carrier_topic: &str, identifier: &str) -> bool {
    carrier_topic == format!("grappa:user:{identifier}")
}

/// Validates `who_reply` as strictly as Cicchetto: every user row must carry
/// all string fields, `hops` an integer or `null` and `realname` a string or
/// `null`; one malformed row drops the whole bundle.
pub(crate) fn parse_who_reply(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<WhoReply> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "who_reply" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let target = payload.get("target")?.as_str()?.to_string();
    let mut users = Vec::new();
    for row in payload.get("users")?.as_array()? {
        let text = |key: &str| row.get(key).and_then(Value::as_str).map(str::to_string);
        let hops = match row.get("hops")? {
            Value::Null => None,
            value => Some(value.as_i64()?),
        };
        users.push(WhoUser {
            nick: text("nick")?,
            user: text("user")?,
            host: text("host")?,
            server: text("server")?,
            modes: text("modes")?,
            channel: text("channel")?,
            hops,
            realname: parse_nullable_wire_string(row.get("realname")?)?,
        });
    }
    Some(WhoReply {
        network: network.to_string(),
        target,
        users,
    })
}

/// One plain line per user, in wire order, mirroring the 352 reply layout.
pub(crate) fn who_reply_view(reply: &WhoReply) -> ReplyView {
    let rows = if reply.users.is_empty() {
        vec![("who-empty".to_string(), String::new())]
    } else {
        reply
            .users
            .iter()
            .map(|user| {
                let hops = user
                    .hops
                    .map(|hops| format!(" ({hops})"))
                    .unwrap_or_default();
                let realname = user
                    .realname
                    .as_deref()
                    .map(|realname| format!(" — {realname}"))
                    .unwrap_or_default();
                (
                    String::new(),
                    format!(
                        "{} ({}@{}) {} · {} · {}{hops}{realname}",
                        user.nick, user.user, user.host, user.modes, user.channel, user.server
                    ),
                )
            })
            .collect()
    };
    ReplyView {
        kind: "who_reply",
        subject: reply.target.clone(),
        network: reply.network.clone(),
        rows,
    }
}

/// Validates `dcc_offer` on the exact user topic: every field is required,
/// `network` and `offer_id` non-empty, `size` a non-negative integer (the
/// peer's claim). The filename was already made safe to display upstream.
pub(crate) fn parse_dcc_offer(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<DccOffer> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "dcc_offer" {
        return None;
    }
    let text = |key: &str| payload.get(key)?.as_str().map(str::to_string);
    let offer = DccOffer {
        network: text("network")?,
        channel: text("channel")?,
        offer_id: text("offer_id")?,
        from: text("from")?,
        filename: text("filename")?,
        size: payload.get("size")?.as_u64()?,
    };
    if offer.network.trim().is_empty() || offer.offer_id.is_empty() {
        return None;
    }
    Some(offer)
}

/// Holds an offer, replacing one with the same `offer_id` in place (the
/// subscribe backfill re-sends every held offer). Returns whether it changed.
pub(crate) fn apply_dcc_offer(offers: &mut Vec<DccOffer>, offer: DccOffer) -> bool {
    match offers
        .iter()
        .position(|held| held.offer_id == offer.offer_id)
    {
        Some(index) if offers[index] == offer => false,
        Some(index) => {
            offers[index] = offer;
            true
        }
        None => {
            offers.push(offer);
            true
        }
    }
}

fn handle_dcc_offer(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(offer) = parse_dcc_offer(payload, carrier_topic, identifier) else {
        persistence::log_line("dcc_offer rejected: invalid carrier or payload");
        return;
    };
    if apply_dcc_offer(&mut state.panels.dcc_offers, offer) {
        push_dcc_offers(state, ui);
    }
}

/// Validates `dcc_offer_resolved` on the exact user topic. `resolution` is
/// the closed `accepted | refused | expired` set: a value a newer server
/// invents drops the event, leaving a stale prompt rather than a wrong one.
pub(crate) fn parse_dcc_offer_resolved(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, DccResolution)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "dcc_offer_resolved" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    payload.get("channel")?.as_str()?;
    let offer_id = payload.get("offer_id")?.as_str()?;
    if network.trim().is_empty() || offer_id.is_empty() {
        return None;
    }
    let resolution = DccResolution::parse(payload.get("resolution")?.as_str()?)?;
    Some((offer_id.to_string(), resolution))
}

/// Drops a held offer by id, returning it; an unknown id (held before this
/// socket, resolved elsewhere) is a silent no-op.
pub(crate) fn apply_dcc_offer_resolved(
    offers: &mut Vec<DccOffer>,
    offer_id: &str,
) -> Option<DccOffer> {
    let index = offers.iter().position(|held| held.offer_id == offer_id)?;
    Some(offers.remove(index))
}

/// Removes the resolved offer on every device and says what happened;
/// whether this device, another one or the hold timeout resolved it, the
/// reaction is the same.
fn handle_dcc_offer_resolved(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((offer_id, resolution)) = parse_dcc_offer_resolved(payload, carrier_topic, identifier)
    else {
        persistence::log_line("dcc_offer_resolved rejected: invalid carrier or payload");
        return;
    };
    let Some(offer) = apply_dcc_offer_resolved(&mut state.panels.dcc_offers, &offer_id) else {
        return;
    };
    push_dcc_offers(state, ui);
    let status = resolution.status_kind();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_dcc_filename(offer.filename.into());
        ui.set_status_dcc_from(offer.from.into());
        ui.set_status_kind(status.into());
    });
}

/// Mirrors the held offers into the sidebar consent panel.
fn push_dcc_offers(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let offers: Vec<(String, String, String, String, String)> = state
        .panels
        .dcc_offers
        .iter()
        .map(|offer| {
            (
                offer.network.clone(),
                offer.offer_id.clone(),
                offer.from.clone(),
                offer.filename.clone(),
                format_file_size(offer.size),
            )
        })
        .collect();
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<DccOfferRow> = offers
            .into_iter()
            .map(|(network, offer_id, from, filename, size)| DccOfferRow {
                network: network.into(),
                offer_id: offer_id.into(),
                from: from.into(),
                filename: filename.into(),
                size: size.into(),
            })
            .collect();
        ui.set_dcc_offers(Rc::new(slint::VecModel::from(rows)).into());
    });
}

/// Validates `archive_changed` on the exact user topic: only a non-empty
/// `network_slug` (this kind names the network by slug, not `network`).
pub(crate) fn parse_archive_changed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<String> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "archive_changed" {
        return None;
    }
    let network = payload.get("network_slug")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    Some(network.to_string())
}

/// A window moved into the archive (for example a PART): refetch the list
/// if that network's archive is open, like Cicchetto's `loadArchive`.
async fn handle_archive_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(network) = parse_archive_changed(payload, carrier_topic, identifier) else {
        persistence::log_line("archive_changed rejected: invalid carrier or payload");
        return;
    };
    if state
        .panels
        .archive
        .as_ref()
        .is_some_and(|view| view.network == network)
    {
        load_archive(state, ui).await;
    }
}

/// Validates `archive_purged` on the exact user topic: a non-empty
/// `network_slug` and `target` (channel- or query-shaped).
pub(crate) fn parse_archive_purged(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "archive_purged" {
        return None;
    }
    let network = payload.get("network_slug")?.as_str()?;
    let target = payload.get("target")?.as_str()?;
    if network.trim().is_empty() || target.trim().is_empty() {
        return None;
    }
    Some((network.to_string(), target.to_string()))
}

/// Whether a `(network, window)` cache key names the purged target. The
/// server deletes case-insensitively, so the window is compared with the
/// network's casemapping.
pub(crate) fn is_purged_window(
    key: &(String, String),
    network: &str,
    target: &str,
    casemapping: cordiale_core::isupport::CaseMapping,
) -> bool {
    key.0 == network && casemapping.nick_eq(&key.1, target)
}

/// The bouncer deleted a target's scrollback: forget the rows and unread
/// seeds cached for it, so a later re-join can't show deleted history, then
/// refresh the archive if it is open. Read cursors stay, like Cicchetto's.
async fn handle_archive_purged(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network, target)) = parse_archive_purged(payload, carrier_topic, identifier) else {
        persistence::log_line("archive_purged rejected: invalid carrier or payload");
        return;
    };
    let casemapping = state
        .networks
        .isupport_by_network
        .get(&network)
        .map(|isupport| isupport.casemapping)
        .unwrap_or(cordiale_core::isupport::CaseMapping::Rfc1459);
    let purged = |key: &(String, String)| is_purged_window(key, &network, &target, casemapping);
    state.transcript.messages.retain(|key, _| !purged(key));
    state.windows.window_messages.retain(|key, _| !purged(key));
    state.windows.window_mentions.retain(|key, _| !purged(key));
    if state
        .panels
        .archive
        .as_ref()
        .is_some_and(|view| view.network == network)
    {
        load_archive(state, ui).await;
    }
}

/// Validates `notify_list` on the exact user topic: `networks` maps each
/// network ID (a decimal JSON key) to its entries, each needing an integer
/// `network_id` and string `nick` and `added_at`. One bad key or entry drops
/// the whole snapshot, like Cicchetto's schema. Returns nicks per network.
pub(crate) fn parse_notify_list(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<HashMap<i64, Vec<String>>> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "notify_list" {
        return None;
    }
    let mut lists = HashMap::new();
    for (key, entries) in payload.get("networks")?.as_object()? {
        let network_id: i64 = key.parse().ok()?;
        let mut nicks = Vec::new();
        for entry in entries.as_array()? {
            entry.get("network_id")?.as_i64()?;
            entry.get("added_at")?.as_str()?;
            nicks.push(entry.get("nick")?.as_str()?.to_string());
        }
        lists.insert(network_id, nicks);
    }
    Some(lists)
}

/// Replaces every network's watchlist with the snapshot (an empty map
/// clears them all) and refreshes the Settings list.
fn handle_notify_list(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(lists) = parse_notify_list(payload, carrier_topic, identifier) else {
        persistence::log_line("notify_list rejected: invalid carrier or payload");
        return;
    };
    state.networks.notify_lists = lists;
    push_notify_nicks(state, ui);
}

/// Validates `presence_snapshot` on the exact user topic: an integer
/// `network_id` and a `nicks` map of folded nick to `online | offline |
/// unknown`. One unknown value drops the whole map, like Cicchetto.
pub(crate) fn parse_presence_snapshot(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(i64, HashMap<String, Presence>)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "presence_snapshot" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    let nicks = payload
        .get("nicks")?
        .as_object()?
        .iter()
        .map(|(nick, presence)| Some((presence_key(nick), Presence::parse(presence.as_str()?)?)))
        .collect::<Option<HashMap<_, _>>>()?;
    Some((network_id, nicks))
}

/// Replaces one network's presence map (sent after join for live sessions)
/// and repaints the watchlist.
fn handle_presence_snapshot(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network_id, nicks)) = parse_presence_snapshot(payload, carrier_topic, identifier)
    else {
        persistence::log_line("presence_snapshot rejected: invalid carrier or payload");
        return;
    };
    state.networks.presence_by_network.insert(network_id, nicks);
    push_notify_nicks(state, ui);
}

/// Validates `presence_changed` on the exact user topic. `presence` is
/// `online | offline` and `source` the closed `monitor | watch | ison` set
/// (checked, not shown); `ts` must be a string.
pub(crate) fn parse_presence_changed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<PresenceChange> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "presence_changed" {
        return None;
    }
    let presence = match payload.get("presence")?.as_str()? {
        "online" => Presence::Online,
        "offline" => Presence::Offline,
        _ => return None,
    };
    if !matches!(
        payload.get("source")?.as_str()?,
        "monitor" | "watch" | "ison"
    ) {
        return None;
    }
    payload.get("ts")?.as_str()?;
    let nick = payload.get("nick")?.as_str()?;
    if nick.is_empty() {
        return None;
    }
    Some(PresenceChange {
        network_id: payload.get("network_id")?.as_i64()?,
        nick: nick.to_string(),
        presence,
        initial: payload.get("initial")?.as_bool()?,
    })
}

/// Updates one watched nick's presence and, unless it is part of the
/// initial report, says so in the status bar.
fn handle_presence_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(change) = parse_presence_changed(payload, carrier_topic, identifier) else {
        persistence::log_line("presence_changed rejected: invalid carrier or payload");
        return;
    };
    state
        .networks
        .presence_by_network
        .entry(change.network_id)
        .or_default()
        .insert(presence_key(&change.nick), change.presence);
    push_notify_nicks(state, ui);
    if change.initial {
        return;
    }
    let network = network_slugs_by_id(&state.networks.network_ids)
        .and_then(|slugs| slugs.get(&change.network_id).cloned())
        .unwrap_or_else(|| change.network_id.to_string());
    let status = if change.presence == Presence::Online {
        "presence-online"
    } else {
        "presence-offline"
    };
    let nick = change.nick;
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_presence_nick(nick.into());
        ui.set_status_presence_network(network.into());
        ui.set_status_kind(status.into());
    });
}

/// Validates `presence_error` on the exact user topic: an integer
/// `network_id`, a `reason` string (`list_full` today; kept open so a new
/// reason still reaches the user) and the rejected target(s) in `detail`.
pub(crate) fn parse_presence_error(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(i64, String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "presence_error" {
        return None;
    }
    Some((
        payload.get("network_id")?.as_i64()?,
        payload.get("reason")?.as_str()?.to_string(),
        payload.get("detail")?.as_str()?.to_string(),
    ))
}

/// The ircd refused a watch registration (MONITOR/WATCH list full). Never
/// silent: the rejected targets go to the status bar. The raw numeric also
/// lands as a server notice upstream, which this does not replace.
fn handle_presence_error(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network_id, reason, detail)) =
        parse_presence_error(payload, carrier_topic, identifier)
    else {
        persistence::log_line("presence_error rejected: invalid carrier or payload");
        return;
    };
    persistence::log_line(&format!(
        "presence error on network {network_id}: reason={reason}"
    ));
    let network = network_slugs_by_id(&state.networks.network_ids)
        .and_then(|slugs| slugs.get(&network_id).cloned())
        .unwrap_or_else(|| network_id.to_string());
    let status = if reason == "list_full" {
        "presence-list-full"
    } else {
        "presence-rejected"
    };
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_presence_nick(detail.into());
        ui.set_status_presence_network(network.into());
        ui.set_status_kind(status.into());
    });
}

/// Validates `peer_away` (a standalone 301 RPL_AWAY, not part of a WHOIS)
/// on the exact user topic: `network` and `peer` non-empty, `message` a
/// string that may be empty (no away text was given).
pub(crate) fn parse_peer_away(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "peer_away" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    let peer = payload.get("peer")?.as_str()?;
    if network.trim().is_empty() || peer.is_empty() {
        return None;
    }
    let message = payload.get("message")?.as_str()?;
    Some((network.to_string(), peer.to_string(), message.to_string()))
}

/// Remembers the peer's latest away message (replacing an older one) and
/// refreshes the banner if that peer's private window is open. Never moves
/// focus.
fn handle_peer_away(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network, peer, message)) = parse_peer_away(payload, carrier_topic, identifier) else {
        persistence::log_line("peer_away rejected: invalid carrier or payload");
        return;
    };
    let key = peer_away_key(state, &network, &peer);
    let shown = current_peer_away_key(state).as_ref() == Some(&key);
    state.networks.peer_away.insert(key, message);
    if shown {
        push_peer_away_banner(state, ui);
    }
}

/// Validates `server_settings_changed` like Cicchetto: `upload.active_host`
/// in `embedded | litterbox` and the image/video/document/audio/global caps
/// positive integers are required; the optional fields and
/// `http_host_aliases` (no native use) don't reject the snapshot.
pub(crate) fn parse_server_settings_changed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<UploadLimits> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "server_settings_changed" {
        return None;
    }
    let upload = payload.get("upload")?;
    let cap = |key: &str| upload.get(key)?.as_u64().filter(|bytes| *bytes > 0);
    let host = upload.get("active_host")?.as_str()?;
    if !matches!(host, "embedded" | "litterbox") {
        return None;
    }
    cap("global_cap_bytes")?;
    Some(UploadLimits {
        host: host.to_string(),
        image_bytes: cap("image_per_file_cap_bytes")?,
        video_bytes: cap("video_per_file_cap_bytes")?,
        video_seconds: cap("video_max_duration_seconds"),
        document_bytes: cap("document_per_file_cap_bytes")?,
        audio_bytes: cap("audio_per_file_cap_bytes")?,
    })
}

/// Mirrors the advertised upload limits into Settings > General.
fn handle_server_settings_changed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(limits) = parse_server_settings_changed(payload, carrier_topic, identifier) else {
        persistence::log_line("server_settings_changed rejected: invalid carrier or payload");
        return;
    };
    if state.prefs.upload_limits.as_ref() == Some(&limits) {
        return;
    }
    let row = UploadLimitsRow {
        host: limits.host.clone().into(),
        image: format_file_size(limits.image_bytes).into(),
        video: format_file_size(limits.video_bytes).into(),
        video_seconds: limits
            .video_seconds
            .map(|seconds| seconds.to_string())
            .unwrap_or_default()
            .into(),
        document: format_file_size(limits.document_bytes).into(),
        audio: format_file_size(limits.audio_bytes).into(),
    };
    state.prefs.upload_limits = Some(limits);
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_server_upload_limits(row);
        ui.set_server_upload_limits_known(true);
    });
}

/// Validates `bundle_hash` on the exact user topic: a non-empty `hash` and
/// an optional `version` (absent or non-string reads as none, like
/// Cicchetto).
pub(crate) fn parse_bundle_hash(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, Option<String>)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "bundle_hash" {
        return None;
    }
    let hash = payload.get("hash")?.as_str()?;
    if hash.is_empty() {
        return None;
    }
    let version = payload
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .map(str::to_string);
    Some((hash.to_string(), version))
}

/// The hash identifies the deployed Cicchetto web bundle, which has no
/// native counterpart: it is consumed and logged when it changes, and never
/// triggers a download or an update of this app.
fn handle_bundle_hash(state: &mut WorkerState, carrier_topic: &str, payload: &Value) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(bundle) = parse_bundle_hash(payload, carrier_topic, identifier) else {
        persistence::log_line("bundle_hash rejected: invalid carrier or payload");
        return;
    };
    if state.prefs.web_bundle.as_ref() == Some(&bundle) {
        return;
    }
    persistence::log_line(&format!(
        "server web bundle: hash={} version={}",
        bundle.0,
        bundle.1.as_deref().unwrap_or("-")
    ));
    state.prefs.web_bundle = Some(bundle);
}

/// Validates `mentions_bundle` on the exact user topic and renders it as a
/// reply view: the away period, the reason when set, then each message in
/// the server's order. Every message needs an integer `server_time`,
/// string `channel`/`sender`, string-or-`null` `body` and a known `kind`;
/// one bad message drops the bundle, like Cicchetto's schema.
pub(crate) fn parse_mentions_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<ReplyView> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "mentions_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let started = payload.get("away_started_at")?.as_str()?;
    let ended = payload.get("away_ended_at")?.as_str()?;
    let reason = parse_nullable_wire_string(payload.get("away_reason")?)?;
    let mut rows = vec![(
        "mentions-away-period".to_string(),
        format!(
            "{} – {}",
            format_iso_timestamp(started),
            format_iso_timestamp(ended)
        ),
    )];
    if let Some(reason) = reason {
        rows.push(("mentions-away-reason".to_string(), reason));
    }
    let messages = payload.get("messages")?.as_array()?;
    for message in messages {
        let server_time = message.get("server_time")?.as_i64()?;
        let channel = message.get("channel")?.as_str()?;
        let sender = message.get("sender")?.as_str()?;
        let body = parse_nullable_wire_string(message.get("body")?)?.unwrap_or_default();
        let kind = message.get("kind")?.as_str()?;
        if !SCROLLBACK_MESSAGE_KINDS.contains(&kind) {
            return None;
        }
        let text = if kind == "action" {
            format!("* {sender} {body}")
        } else {
            format!("<{sender}> {body}")
        };
        // An inbound DM is stored at our own nick, so `channel` alone would
        // label it with ourselves; from protocol v35 `dm_with` names the peer
        // (raw nick, null off a DM, absent on older servers).
        let window = message
            .get("dm_with")
            .and_then(Value::as_str)
            .filter(|peer| !peer.is_empty())
            .unwrap_or(channel);
        rows.push((
            String::new(),
            format!("{} {window} {text}", format_epoch_millis(server_time)),
        ));
    }
    if messages.is_empty() {
        rows.push(("mentions-empty".to_string(), String::new()));
    }
    Some(ReplyView {
        kind: "mentions_bundle",
        subject: String::new(),
        network: network.to_string(),
        rows,
    })
}

/// Back from away: keeps the summary for `/mentions` and opens it, as
/// Cicchetto focuses its mentions window (returning is the user's action).
fn handle_mentions_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(view) = parse_mentions_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("mentions_bundle rejected: invalid carrier or payload");
        return;
    };
    state
        .panels
        .mentions_bundles
        .insert(view.network.clone(), view.clone());
    show_reply_view(state, ui, view);
}

/// Validates `directory_progress` (`count`) or `directory_complete`
/// (`total`) on the exact user topic: `network` a non-empty slug and the
/// counter a non-negative integer (checked, not used — the rows always come
/// from the REST page).
pub(crate) fn parse_directory_count_signal(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
    kind: &str,
    counter: &str,
) -> Option<String> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != kind {
        return None;
    }
    payload.get(counter)?.as_u64()?;
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    Some(network.to_string())
}

/// A capture is streaming: refetch the first page if that network's
/// directory is open, like Cicchetto's `onDirectoryProgress`.
async fn handle_directory_progress(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(network) = parse_directory_count_signal(
        payload,
        carrier_topic,
        identifier,
        "directory_progress",
        "count",
    ) else {
        persistence::log_line("directory_progress rejected: invalid carrier or payload");
        return;
    };
    reload_directory_after_push(state, ui, &network, None).await;
}

/// The capture finished (323 RPL_LISTEND) and the server replaced its
/// snapshot: refetch the first page, replacing the loaded rows.
async fn handle_directory_complete(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(network) = parse_directory_count_signal(
        payload,
        carrier_topic,
        identifier,
        "directory_complete",
        "total",
    ) else {
        persistence::log_line("directory_complete rejected: invalid carrier or payload");
        return;
    };
    reload_directory_after_push(state, ui, &network, None).await;
}

/// Validates `directory_failed` on the exact user topic: `network` a
/// non-empty slug and `reason` any string (an open set; `timeout` today).
pub(crate) fn parse_directory_failed(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "directory_failed" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let reason = payload.get("reason")?.as_str()?;
    Some((network.to_string(), reason.to_string()))
}

/// The capture was abandoned; the server kept its previous snapshot. Shows
/// the reason and refetches, so the list stays the last good one.
async fn handle_directory_failed(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network, reason)) = parse_directory_failed(payload, carrier_topic, identifier) else {
        persistence::log_line("directory_failed rejected: invalid carrier or payload");
        return;
    };
    reload_directory_after_push(state, ui, &network, Some(reason)).await;
}

/// Shared tail of the `directory_*` pushes: releases the refresh latch,
/// records (or clears) the capture failure and refetches when the pushed
/// network's directory is the open one.
async fn reload_directory_after_push(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: &str,
    failed_reason: Option<String>,
) {
    let Some(view) = state.panels.directory.as_mut() else {
        return;
    };
    if view.network != network {
        return;
    }
    view.refresh_pending = false;
    view.failed_reason = failed_reason;
    push_directory(state, ui, false);
    load_directory(state, ui).await;
}

fn handle_who_reply(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(reply) = parse_who_reply(payload, carrier_topic, identifier) else {
        persistence::log_line("who_reply rejected: invalid carrier or payload");
        return;
    };
    show_reply_view(state, ui, who_reply_view(&reply));
}

/// Validates `server_reply`: `source` is the closed `info | version | motd |
/// admin` set and `lines` must hold only strings (kept in wire order, never
/// rewritten). Returns `(network, source, lines)`.
pub(crate) fn parse_server_reply(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, &'static str, Vec<String>)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "server_reply" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let source = match payload.get("source")?.as_str()? {
        "info" => "info",
        "version" => "version",
        "motd" => "motd",
        "admin" => "admin",
        _ => return None,
    };
    let lines = payload
        .get("lines")?
        .as_array()?
        .iter()
        .map(|line| line.as_str().map(str::to_string))
        .collect::<Option<Vec<_>>>()?;
    Some((network.to_string(), source, lines))
}

pub(crate) fn server_reply_view(
    network: &str,
    source: &'static str,
    lines: &[String],
) -> ReplyView {
    let rows = if lines.is_empty() {
        vec![("reply-empty".to_string(), String::new())]
    } else {
        lines
            .iter()
            .map(|line| (String::new(), line.clone()))
            .collect()
    };
    ReplyView {
        kind: "server_reply",
        subject: source.to_string(),
        network: network.to_string(),
        rows,
    }
}

fn handle_server_reply(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network, source, lines)) = parse_server_reply(payload, carrier_topic, identifier)
    else {
        persistence::log_line("server_reply rejected: invalid carrier or payload");
        return;
    };
    show_reply_view(state, ui, server_reply_view(&network, source, &lines));
}

/// Validates `whois_bundle` field by field, like Cicchetto: any malformed
/// field drops the whole bundle. `source` must be `user` or `rail` (absent
/// means `user`); `avatar_url` may be absent.
pub(crate) fn parse_whois_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<WhoisBundle> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "whois_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    match payload.get("source") {
        None => {}
        Some(source) if matches!(source.as_str(), Some("user" | "rail")) => {}
        Some(_) => return None,
    }
    let text = |key: &str| parse_nullable_wire_string(payload.get(key)?);
    let flag = |key: &str| payload.get(key)?.as_bool();
    let number = |key: &str| match payload.get(key)? {
        Value::Null => Some(None),
        value => value.as_i64().map(Some),
    };
    let channels = match payload.get("channels")? {
        Value::Null => None,
        Value::Array(items) => Some(
            items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()?,
        ),
        _ => return None,
    };
    let extra_lines = match payload.get("extra_lines")? {
        Value::Null => None,
        Value::Array(items) => Some(
            items
                .iter()
                .map(|item| {
                    Some((
                        item.get("numeric")?.as_i64()?,
                        item.get("text")?.as_str()?.to_string(),
                    ))
                })
                .collect::<Option<Vec<_>>>()?,
        ),
        _ => return None,
    };
    let avatar_url = match payload.get("avatar_url") {
        None => None,
        Some(value) => parse_nullable_wire_string(value)?,
    };
    Some(WhoisBundle {
        network: network.to_string(),
        target: payload.get("target")?.as_str()?.to_string(),
        user: text("user")?,
        host: text("host")?,
        realname: text("realname")?,
        server: text("server")?,
        server_info: text("server_info")?,
        is_operator: flag("is_operator")?,
        oper_text: text("oper_text")?,
        idle_seconds: number("idle_seconds")?,
        signon: number("signon")?,
        channels,
        using_ssl: flag("using_ssl")?,
        is_registered: flag("is_registered")?,
        is_admin: flag("is_admin")?,
        is_services_admin: flag("is_services_admin")?,
        is_helper: flag("is_helper")?,
        is_chanop: flag("is_chanop")?,
        is_agent: flag("is_agent")?,
        is_java: flag("is_java")?,
        umodes: text("umodes")?,
        away_message: text("away_message")?,
        actually_host: text("actually_host")?,
        actually_ip: text("actually_ip")?,
        account: text("account")?,
        secure: flag("secure")?,
        secure_cipher: text("secure_cipher")?,
        certfp: text("certfp")?,
        extra_lines,
        avatar_url,
    })
}

/// `h:mm:ss`, without words to translate.
pub(crate) fn format_idle(seconds: i64) -> String {
    let seconds = seconds.max(0);
    format!(
        "{}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

fn format_signon(epoch_seconds: i64) -> String {
    epoch_seconds
        .checked_mul(1000)
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|moment| dates::render_date_time(&moment.with_timezone(&chrono::Local), true))
        .unwrap_or_else(|| epoch_seconds.to_string())
}

/// Label-keyed rows for the WHOIS card; empty fields are omitted, boolean
/// flags become label-only rows, extra numerics stay in wire order.
pub(crate) fn whois_bundle_view(bundle: &WhoisBundle) -> ReplyView {
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut push = |label: &str, value: Option<String>| {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            rows.push((label.to_string(), value));
        }
    };
    let userhost = match (&bundle.user, &bundle.host) {
        (Some(user), Some(host)) => Some(format!("{user}@{host}")),
        (None, Some(host)) => Some(host.clone()),
        (Some(user), None) => Some(user.clone()),
        (None, None) => None,
    };
    push("whois-userhost", userhost);
    push("whois-realname", bundle.realname.clone());
    push("whois-account", bundle.account.clone());
    let server = match (&bundle.server, &bundle.server_info) {
        (Some(server), Some(info)) => Some(format!("{server} ({info})")),
        (server, _) => server.clone(),
    };
    push("whois-server", server);
    push(
        "whois-channels",
        bundle.channels.as_ref().map(|channels| channels.join(" ")),
    );
    push("whois-idle", bundle.idle_seconds.map(format_idle));
    push("whois-signon", bundle.signon.map(format_signon));
    push("whois-away", bundle.away_message.clone());
    push("whois-umodes", bundle.umodes.clone());
    let actually = match (&bundle.actually_host, &bundle.actually_ip) {
        (Some(host), Some(ip)) => Some(format!("{host} ({ip})")),
        (host, ip) => host.clone().or_else(|| ip.clone()),
    };
    push("whois-actually", actually);
    push("whois-certfp", bundle.certfp.clone());
    if bundle.secure || bundle.using_ssl {
        rows.push((
            "whois-secure".to_string(),
            bundle.secure_cipher.clone().unwrap_or_default(),
        ));
    }
    if bundle.is_operator {
        rows.push((
            "whois-operator".to_string(),
            bundle.oper_text.clone().unwrap_or_default(),
        ));
    }
    for (flag, label) in [
        (bundle.is_registered, "whois-registered"),
        (bundle.is_admin, "whois-admin"),
        (bundle.is_services_admin, "whois-services-admin"),
        (bundle.is_helper, "whois-helper"),
        (bundle.is_chanop, "whois-chanop"),
        (bundle.is_agent, "whois-agent"),
        (bundle.is_java, "whois-java"),
    ] {
        if flag {
            rows.push((label.to_string(), String::new()));
        }
    }
    for (numeric, text) in bundle.extra_lines.iter().flatten() {
        rows.push((String::new(), format!("{numeric:03} {text}")));
    }
    // The avatar is an authenticated server path; the image itself is not
    // rendered yet, only its availability.
    if bundle.avatar_url.is_some() {
        rows.push(("whois-avatar".to_string(), String::new()));
    }
    ReplyView {
        kind: "whois_bundle",
        subject: bundle.target.clone(),
        network: bundle.network.clone(),
        rows,
    }
}

fn handle_whois_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(bundle) = parse_whois_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("whois_bundle rejected: invalid carrier or payload");
        return;
    };
    let view = whois_bundle_view(&bundle);
    let avatar_url = bundle.avatar_url.clone();
    state.panels.whois_card = Some(bundle);
    show_reply_view(state, ui, view);
    if let Some(avatar_url) = avatar_url {
        load_whois_avatar(state, ui, avatar_url);
    }
}

/// Downloads the WHOIS avatar from Grappa and shows it on the reply
/// screen. Slint loads images from files, so it's written to the temp
/// directory first; a failure just leaves the card without a picture.
fn load_whois_avatar(state: &WorkerState, ui: &slint::Weak<AppWindow>, avatar_url: String) {
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };
    let ui = ui.clone();
    tokio::spawn(async move {
        let (bytes, content_type) = match client.fetch_server_file(&token, &avatar_url).await {
            Ok(file) => file,
            Err(err) => {
                persistence::log_line(&format!("whois avatar fetch failed: {err:?}"));
                return;
            }
        };
        let Some(extension) = avatar_extension(content_type.as_deref()) else {
            return;
        };
        // One file per avatar URL: Slint caches images by path.
        let key = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            avatar_url.hash(&mut hasher);
            hasher.finish()
        };
        let path = std::env::temp_dir().join(format!("cordiale-avatar-{key:x}.{extension}"));
        if let Err(err) = std::fs::write(&path, bytes) {
            persistence::log_line(&format!("whois avatar write failed: {err}"));
            return;
        }
        let _ = ui.upgrade_in_event_loop(move |ui| {
            if let Ok(image) = slint::Image::load_from_path(&path) {
                ui.set_reply_avatar(image);
                ui.set_reply_avatar_visible(true);
            }
        });
    });
}

/// Validates `whowas_bundle`: every key is required, the history fields are
/// strings or `null`, and `not_found` separates "no history" (406) from a
/// malformed payload, which is dropped.
pub(crate) fn parse_whowas_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<ReplyView> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "whowas_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let target = payload.get("target")?.as_str()?;
    let text = |key: &str| parse_nullable_wire_string(payload.get(key)?);
    let user = text("user")?;
    let host = text("host")?;
    let realname = text("realname")?;
    let server = text("server")?;
    let logoff_time = text("logoff_time")?;
    let not_found = payload.get("not_found")?.as_bool()?;

    let mut rows: Vec<(String, String)> = Vec::new();
    if not_found {
        rows.push(("whowas-not-found".to_string(), String::new()));
    } else {
        let userhost = match (user, host) {
            (Some(user), Some(host)) => Some(format!("{user}@{host}")),
            (user, host) => user.or(host),
        };
        for (label, value) in [
            ("whois-userhost", userhost),
            ("whois-realname", realname),
            ("whois-server", server),
            ("whowas-logoff", logoff_time),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                rows.push((label.to_string(), value));
            }
        }
    }
    Some(ReplyView {
        kind: "whowas_bundle",
        subject: target.to_string(),
        network: network.to_string(),
        rows,
    })
}

fn handle_whowas_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(view) = parse_whowas_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("whowas_bundle rejected: invalid carrier or payload");
        return;
    };
    show_reply_view(state, ui, view);
}

/// Validates `banlist_bundle`: `mode` is whichever list letter was asked for
/// (never assumed to be `b`), and each entry needs a string `mask` plus a
/// string-or-`null` `setter` and `set_ts`; one bad entry drops the bundle.
/// Entries keep the ircd's order.
pub(crate) fn parse_banlist_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<ReplyView> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "banlist_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let channel = payload.get("channel")?.as_str()?;
    let mode = payload.get("mode")?.as_str()?;
    if mode.is_empty() {
        return None;
    }
    let mut rows: Vec<(String, String)> = Vec::new();
    for entry in payload.get("entries")?.as_array()? {
        let mask = entry.get("mask")?.as_str()?;
        let setter = parse_nullable_wire_string(entry.get("setter")?)?;
        let set_ts = parse_nullable_wire_string(entry.get("set_ts")?)?;
        let details = [setter, set_ts]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        let line = if details.is_empty() {
            mask.to_string()
        } else {
            format!("{mask} — {details}")
        };
        rows.push((String::new(), line));
    }
    if rows.is_empty() {
        rows.push(("banlist-empty".to_string(), String::new()));
    }
    Some(ReplyView {
        kind: "banlist_bundle",
        subject: format!("{channel} +{mode}"),
        network: network.to_string(),
        rows,
    })
}

fn handle_banlist_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(view) = parse_banlist_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("banlist_bundle rejected: invalid carrier or payload");
        return;
    };
    show_reply_view(state, ui, view);
}

/// Validates `invite_ack` (341 RPL_INVITING) on the exact user topic:
/// `network`, `channel` and `peer` are required non-empty strings. Returns
/// them in that order.
pub(crate) fn parse_invite_ack(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "invite_ack" {
        return None;
    }
    let field = |key: &str| {
        payload
            .get(key)?
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
    };
    Some((field("network")?, field("channel")?, field("peer")?))
}

/// Confirms a sent invite in the status bar. Every acknowledgement is shown,
/// even repeats; it is transient and never stored, unlike Cicchetto's
/// synthetic server-window row.
fn handle_invite_ack(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network, channel, peer)) = parse_invite_ack(payload, carrier_topic, identifier)
    else {
        persistence::log_line("invite_ack rejected: invalid carrier or payload");
        return;
    };
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_status_invite_peer(peer.into());
        ui.set_status_invite_channel(channel.into());
        ui.set_status_invite_network(network.into());
        ui.set_status_kind("invite-sent".into());
    });
}

/// Validates `lusers_bundle`: `network` is a required non-empty slug. Like
/// Cicchetto, each counter is read on its own and a missing, `null` or
/// non-integer one shows as unknown instead of dropping the other eleven —
/// the bundle is display-only (253 RPL_LUSERUNKNOWN is optional upstream).
pub(crate) fn parse_lusers_bundle(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<ReplyView> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "lusers_bundle" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    let rows = LUSERS_COUNTERS
        .iter()
        .map(|(key, label)| {
            let value = payload
                .get(*key)
                .and_then(Value::as_i64)
                .map_or_else(|| "—".to_string(), |count| count.to_string());
            (label.to_string(), value)
        })
        .collect();
    Some(ReplyView {
        kind: "lusers_bundle",
        subject: String::new(),
        network: network.to_string(),
        rows,
    })
}

/// Shows a LUSERS bundle only when this client asked for it with `/lusers`
/// (consume-once); the unsolicited registration burst is dropped silently.
fn handle_lusers_bundle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some(view) = parse_lusers_bundle(payload, carrier_topic, identifier) else {
        persistence::log_line("lusers_bundle rejected: invalid carrier or payload");
        return;
    };
    if !state.panels.lusers_requested.remove(&view.network) {
        return;
    }
    show_reply_view(state, ui, view);
}

/// Validates `whois_avatar_ready`: `network`, `nick` and `avatar_url` are
/// all required strings. Returns them in that order.
pub(crate) fn parse_whois_avatar_ready(
    payload: &Value,
    carrier_topic: &str,
    identifier: &str,
) -> Option<(String, String, String)> {
    if !is_own_user_topic(carrier_topic, identifier) {
        return None;
    }
    if payload.get("kind")?.as_str()? != "whois_avatar_ready" {
        return None;
    }
    let network = payload.get("network")?.as_str()?;
    if network.trim().is_empty() {
        return None;
    }
    Some((
        network.to_string(),
        payload.get("nick")?.as_str()?.to_string(),
        payload.get("avatar_url")?.as_str()?.to_string(),
    ))
}

/// Cicchetto's `patchWhoisAvatarUrl`: patches only the open card for the
/// same network and nick (compared with the network's casemapping); a late
/// completion for a closed or different card is a silent no-op.
pub(crate) fn apply_whois_avatar_ready(
    card: &mut Option<WhoisBundle>,
    network: &str,
    nick: &str,
    avatar_url: String,
    casemapping: cordiale_core::isupport::CaseMapping,
) -> bool {
    let Some(card) = card.as_mut() else {
        return false;
    };
    if card.network != network || !casemapping.nick_eq(&card.target, nick) {
        return false;
    }
    if card.avatar_url.as_deref() == Some(avatar_url.as_str()) {
        return false;
    }
    card.avatar_url = Some(avatar_url);
    true
}

fn handle_whois_avatar_ready(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.as_deref() else {
        return;
    };
    let Some((network, nick, avatar_url)) =
        parse_whois_avatar_ready(payload, carrier_topic, identifier)
    else {
        persistence::log_line("whois_avatar_ready rejected: invalid carrier or payload");
        return;
    };
    // IRC's default mapping applies until the network's ISUPPORT says
    // otherwise.
    let casemapping = state
        .networks
        .isupport_by_network
        .get(&network)
        .map(|isupport| isupport.casemapping)
        .unwrap_or(cordiale_core::isupport::CaseMapping::Rfc1459);
    if !apply_whois_avatar_ready(
        &mut state.panels.whois_card,
        &network,
        &nick,
        avatar_url,
        casemapping,
    ) {
        return;
    }
    let Some(card) = state.panels.whois_card.as_ref() else {
        return;
    };
    let shown = state.panels.reply_view.as_ref().is_some_and(|view| {
        view.kind == "whois_bundle" && view.network == card.network && view.subject == card.target
    });
    if shown {
        let view = whois_bundle_view(card);
        let avatar_url = card.avatar_url.clone();
        push_reply_view(ui, &view, false);
        state.panels.reply_view = Some(view);
        if let Some(avatar_url) = avatar_url {
            load_whois_avatar(state, ui, avatar_url);
        }
    }
}

async fn handle_network_lifecycle(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
    lifecycle: NetworkLifecycleKind,
) {
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    let Some((network_id, network_slug)) = lifecycle.parse(payload, carrier_topic, &identifier)
    else {
        return;
    };

    // A detach must refer to the current projection before the refresh. An
    // attach is allowed to introduce a network that is not known locally yet;
    // its identity is checked against the refreshed authoritative snapshot
    // below instead.
    if lifecycle == NetworkLifecycleKind::Detached
        && state.networks.network_ids.get(&network_slug) != Some(&network_id)
    {
        persistence::log_line(&format!(
            "{} rejected: unknown or stale network",
            lifecycle.wire_name()
        ));
        return;
    }
    let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) else {
        return;
    };

    let boot = match client.fetch_boot(&token).await {
        Ok(boot) => boot,
        Err(error) => {
            persistence::log_line(&format!(
                "{} boot refresh failed; keeping existing state: {error:?}",
                lifecycle.wire_name()
            ));
            return;
        }
    };
    let me = match client.fetch_me(&token).await {
        Ok(me) => me,
        Err(error) => {
            persistence::log_line(&format!(
                "{} me refresh failed; keeping existing state: {error:?}",
                lifecycle.wire_name()
            ));
            return;
        }
    };

    // An attach may be the first local indication of a newly attached
    // network, but a replayed/stale signal must not cause a projection change
    // if the authoritative snapshot does not contain the same id/slug.
    if lifecycle == NetworkLifecycleKind::Attached
        && network_ids_from_entries(&boot.networks).get(&network_slug) != Some(&network_id)
    {
        persistence::log_line("network_attached rejected: unknown or stale network");
        return;
    }

    let actions = apply_network_rest_refresh(state, &identifier, &boot, &me);
    if let Some(session) = state.conn.session.as_ref() {
        for action in actions {
            match action {
                ChannelTopicAction::Leave(topic) => session.leave_topic(topic),
                ChannelTopicAction::Join(topic) => {
                    let is_own_listener =
                        own_nick_listener_network_for_topic(state, &topic).is_some();
                    let is_server_window = state.networks.network_ids.keys().any(|network| {
                        topic == channel_topic(&identifier, network, SERVER_WINDOW_NAME)
                    });
                    session.join_topic(topic, !(is_own_listener || is_server_window));
                }
            }
        }
    }

    let is_parked = state
        .networks
        .network_connection_states
        .get(&network_slug)
        .is_some_and(|snapshot| matches!(snapshot.status, NetworkConnectionStatus::Parked));
    if is_parked {
        collapse_if_parked(state, &network_slug);
    }
    if !state.networks.network_ids.contains_key(&network_slug) || is_parked {
        return_home_if_network_selected(state, ui, &network_slug);
    }

    refresh_network_groups(state, ui);
    load_featured_channels(state, ui).await;
    persistence::log_line(&format!(
        "{} refreshed authoritative state for {network_slug}",
        lifecycle.wire_name()
    ));
}

async fn handle_network_detached(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    handle_network_lifecycle(
        state,
        ui,
        carrier_topic,
        payload,
        NetworkLifecycleKind::Detached,
    )
    .await;
}

async fn handle_network_attached(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    handle_network_lifecycle(
        state,
        ui,
        carrier_topic,
        payload,
        NetworkLifecycleKind::Attached,
    )
    .await;
}

/// Parses the authoritative `query_windows_list` full snapshot. If any row
/// is malformed, has an unknown/mismatched network ID, duplicates another
/// query identity, or carries a non-RFC3339 `opened_at`, reject the whole
/// snapshot so a partial payload cannot erase known windows.
pub(crate) fn parse_query_windows_list(
    payload: &Value,
    network_slugs: &HashMap<i64, String>,
) -> Option<Vec<QueryWindow>> {
    if payload.get("kind")?.as_str()? != "query_windows_list" {
        return None;
    }
    let windows = payload.get("windows")?.as_object()?;
    let mut parsed = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (raw_network_id, entries) in windows {
        let network_id = raw_network_id.parse::<i64>().ok()?;
        if network_id <= 0 {
            return None;
        }
        let network = network_slugs.get(&network_id)?;
        for entry in entries.as_array()? {
            if entry.get("network_id").and_then(Value::as_i64) != Some(network_id) {
                return None;
            }
            let target_nick = entry.get("target_nick")?.as_str()?;
            if target_nick.trim().is_empty() {
                return None;
            }
            let opened_at = entry.get("opened_at")?.as_str()?;
            chrono::DateTime::parse_from_rfc3339(opened_at).ok()?;

            let query = QueryWindow {
                network: network.clone(),
                target_nick: target_nick.to_string(),
                opened_at: opened_at.to_string(),
                // Absent (server older than v34 or from v37 on) and null both
                // mean "no id": identity falls back to the nick.
                dm_conversation_id: entry.get("dm_conversation_id").and_then(Value::as_i64),
            };
            if !seen.insert(query_window_key(&query.network, &query.target_nick)) {
                return None;
            }
            parsed.push(query);
        }
    }

    // The server's per-network list is already oldest-first; preserve it for
    // the sidebar instead of replacing the user's established ordering.
    Some(parsed)
}

pub(crate) fn resolve_query_topic<'a>(
    windows: &'a [QueryWindow],
    stale_topics: &std::collections::HashSet<(String, String)>,
    network: &str,
    target: &str,
) -> QueryTopicResolution<'a> {
    if let Some(query) = find_query_window(windows, network, target) {
        QueryTopicResolution::Active(query)
    } else if stale_topics.contains(&query_window_key(network, target)) {
        QueryTopicResolution::Stale
    } else {
        QueryTopicResolution::Untracked
    }
}

fn same_rfc3339_instant(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (
        chrono::DateTime::parse_from_rfc3339(left),
        chrono::DateTime::parse_from_rfc3339(right),
    ) else {
        return false;
    };
    left.timestamp() == right.timestamp()
        && left.timestamp_subsec_nanos() == right.timestamp_subsec_nanos()
}

/// Whether a window that disappears while another appears may be a peer's
/// nick change. Servers below v37 rename the query window themselves; from
/// v37 on the old and the new window coexist, and inferring a rename would
/// at worst fuse two unrelated windows that share an opening instant. An
/// unknown version keeps the inference, like a pre-v37 server.
pub(crate) fn rename_inference_applies(server_protocol_version: Option<u32>) -> bool {
    server_protocol_version.is_none_or(|version| version < NICK_CHANGE_MOVES_NOTHING_PROTOCOL)
}

/// Infers only unambiguous renames among the windows that disappeared and
/// appeared. A window keeps its `dm_conversation_id` under the new nick, so
/// an id held by exactly one disappeared and one appeared window on the same
/// network is a rename. Windows without an id (older server) fall back to
/// the same validated opening instant. No list ordering or nickname
/// similarity is treated as identity.
pub(crate) fn query_window_renames(
    previous: &[QueryWindow],
    next: &[QueryWindow],
) -> Vec<(QueryWindow, QueryWindow)> {
    let removed: Vec<&QueryWindow> = previous
        .iter()
        .filter(|old| find_query_window(next, &old.network, &old.target_nick).is_none())
        .collect();
    let added: Vec<&QueryWindow> = next
        .iter()
        .filter(|new| find_query_window(previous, &new.network, &new.target_nick).is_none())
        .collect();

    let mut renames = Vec::new();
    for old in removed.iter().copied() {
        if let Some(id) = old.dm_conversation_id {
            let by_id: Vec<&QueryWindow> = added
                .iter()
                .copied()
                .filter(|new| new.network == old.network && new.dm_conversation_id == Some(id))
                .collect();
            if let [new] = by_id.as_slice() {
                renames.push((old.clone(), (*new).clone()));
                continue;
            }
        }
        let candidates: Vec<&QueryWindow> = added
            .iter()
            .copied()
            .filter(|new| {
                old.network == new.network
                    // Two different ids are two different conversations.
                    && (old.dm_conversation_id.is_none()
                        || new.dm_conversation_id.is_none()
                        || old.dm_conversation_id == new.dm_conversation_id)
                    && same_rfc3339_instant(&old.opened_at, &new.opened_at)
            })
            .collect();
        if candidates.len() != 1 {
            continue;
        }
        let new = candidates[0];
        let reverse_matches = removed
            .iter()
            .copied()
            .filter(|other| {
                other.network == new.network
                    && same_rfc3339_instant(&other.opened_at, &new.opened_at)
            })
            .count();
        if reverse_matches == 1 {
            renames.push((old.clone(), new.clone()));
        }
    }
    renames
}

fn move_query_window_cache(state: &mut WorkerState, old: &QueryWindow, new: &QueryWindow) {
    let from = (old.network.clone(), old.target_nick.clone());
    let to = (new.network.clone(), new.target_nick.clone());
    if from == to {
        return;
    }
    if let Some(lines) = state.transcript.messages.remove(&from) {
        merge_rendered_messages(
            state.transcript.messages.entry(to.clone()).or_default(),
            lines,
        );
    }
    if !state.transcript.drafts.contains_key(&to) {
        if let Some(draft) = state.transcript.drafts.remove(&from) {
            state.transcript.drafts.insert(to, draft);
        }
    }
    // A rename changes the canonical Phoenix topic. Keep old join/readiness
    // tracking because Cicchetto keeps obsolete topics joined for the session;
    // the new identity starts unready until its own join/history cycle.
}

/// Replaces local query state from a complete server snapshot. Returns true
/// only when the currently selected query was closed rather than retained or
/// unambiguously renamed. Renames are inferred only for servers that still
/// rename query windows themselves (`rename_inference_applies`).
pub(crate) fn apply_query_windows_snapshot(
    state: &mut WorkerState,
    snapshot: Vec<QueryWindow>,
) -> bool {
    let previous = state.transcript.query_windows.clone();
    // A case-only nick change retains the same query identity and topic, but
    // the rendered-message and draft maps use the displayed nick verbatim.
    // Move those exact-key caches before normal rename detection, which
    // deliberately treats this as the same identity.
    for new in &snapshot {
        if let Some(old) = find_query_window(&previous, &new.network, &new.target_nick) {
            if old.network != new.network || old.target_nick != new.target_nick {
                move_query_window_cache(state, old, new);
            }
        }
    }
    let renames = if rename_inference_applies(state.conn.server_protocol_version) {
        query_window_renames(&previous, &snapshot)
    } else {
        Vec::new()
    };
    for (old, new) in &renames {
        move_query_window_cache(state, old, new);
    }

    let mut selected_closed = false;
    if state.windows.current_query {
        if let Some((network, nick)) = state.windows.current_channel.clone() {
            let selected = find_query_window(&snapshot, &network, &nick)
                .cloned()
                .or_else(|| {
                    renames
                        .iter()
                        .find(|(old, _)| {
                            query_window_key(&old.network, &old.target_nick)
                                == query_window_key(&network, &nick)
                        })
                        .map(|(_, new)| new.clone())
                });
            if let Some(query) = selected {
                if let Some(old) = find_query_window(&previous, &network, &nick) {
                    move_query_window_cache(state, old, &query);
                }
                state.windows.current_channel = Some((query.network, query.target_nick));
            } else {
                state.windows.current_channel = None;
                state.windows.current_query = false;
                selected_closed = true;
            }
        } else {
            state.windows.current_query = false;
            selected_closed = true;
        }
    }

    state.transcript.query_windows = snapshot;
    selected_closed
}

/// Keeps the worker's query/topic lifecycle aligned with the latest complete
/// snapshot while retaining acknowledgements for topics Grappa/Cicchetto keep
/// joined after a query closes. Those acknowledgements allow a same-session
/// reopen to reuse the existing topic and load a fresh tail without a second
/// join.
pub(crate) fn reconcile_query_topic_tracking(state: &mut WorkerState, previous: &[QueryWindow]) {
    let active_queries: std::collections::HashSet<(String, String)> = state
        .transcript
        .query_windows
        .iter()
        .map(|query| query_window_key(&query.network, &query.target_nick))
        .collect();
    state
        .transcript
        .query_full_history_required
        .retain(|identity| active_queries.contains(identity));
    for query in previous {
        let identity = query_window_key(&query.network, &query.target_nick);
        if !active_queries.contains(&identity) {
            state.transcript.stale_query_topics.insert(identity);
            // The topic remains joined, but reopening must load its latest
            // tail before the composer is enabled again.
            state
                .transcript
                .query_ready
                .remove(&query_window_key(&query.network, &query.target_nick));
        }
    }
    for query in &state.transcript.query_windows {
        state
            .transcript
            .stale_query_topics
            .remove(&query_window_key(&query.network, &query.target_nick));
    }
    state.windows.current_query_ready = state.windows.current_query
        && state
            .windows
            .current_channel
            .as_ref()
            .is_some_and(|(network, nick)| {
                state
                    .transcript
                    .query_ready
                    .contains(&query_window_key(network, nick))
            });
}

fn handle_query_windows_list(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    carrier_topic: &str,
    payload: &Value,
) {
    let Some(identifier) = state.conn.identifier.clone() else {
        return;
    };
    if carrier_topic != format!("grappa:user:{identifier}") {
        return;
    }
    let Some(network_slugs) = network_slugs_by_id(&state.networks.network_ids) else {
        persistence::log_line("query_windows_list rejected: ambiguous network ID map");
        return;
    };
    let Some(snapshot) = parse_query_windows_list(payload, &network_slugs) else {
        persistence::log_line("query_windows_list rejected: invalid full snapshot");
        return;
    };

    let previous_queries = state.transcript.query_windows.clone();
    let selected_closed = apply_query_windows_snapshot(state, snapshot);
    retain_window_counts_for_open_windows(state);
    reconcile_query_topic_tracking(state, &previous_queries);
    drain_pending_own_nick_dms(state);
    if let Some(session) = state.conn.session.as_ref() {
        for query in &state.transcript.query_windows {
            let topic = query_topic(&identifier, &query.network, &query.target_nick);
            if state.conn.joined_topics.insert(topic.clone()) {
                // Query topics carry scrollback/messages, not the channel
                // presence stream used to populate the roster.
                session.join_topic(topic, false);
            }
        }
    }

    refresh_network_groups(state, ui);
    if state.windows.current_query {
        if let Some((network, nick)) = state.windows.current_channel.as_ref() {
            if let Some(query) =
                find_query_window(&state.transcript.query_windows, network, nick).cloned()
            {
                let key = (query.network.clone(), query.target_nick.clone());
                show_query_window(state, ui, &query, &key);
            }
        }
    } else if selected_closed {
        clear_closed_query_view(ui);
    }
}

fn clear_closed_query_view(ui: &slint::Weak<AppWindow>) {
    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
        ui.set_current_channel_label("".into());
        ui.set_current_topic("".into());
        ui.set_window_status("".into());
        ui.set_current_window_is_joined(false);
        ui.set_current_server_window(false);
        ui.set_has_selected_channel(false);
        ui.set_current_query(false);
        ui.set_current_query_ready(false);
        ui.set_can_moderate_members(false);
        ui.set_compose_text("".into());
        show_chat_lines(&ui, Vec::new());
        ui.set_channel_members(empty_members.into());
    });
}
