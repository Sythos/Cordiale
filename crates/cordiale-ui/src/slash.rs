use super::*;

use cordiale_core::slash::{self, SlashCommand};

/// Peels the longest leading PREFIX run whose remainder is still a channel.
/// `+` is both a voice marker and an IRC channel sigil, so a greedy peel must
/// keep walking: `@+#chan` is `@+` over `#chan`, while `@+chan` is `@` over the
/// modeless `+chan` channel. The server remains authoritative for STATUSMSG;
/// accepting a PREFIX symbol that it does not advertise simply yields its
/// normal 400 response.
pub(crate) fn peel_statusmsg_target(
    target: &str,
    prefix_symbols: &[String],
) -> Option<StatusmsgTarget> {
    let mut best = None;
    for (offset, character) in target.char_indices() {
        let symbol = character.to_string();
        if !prefix_symbols.iter().any(|prefix| prefix == &symbol) {
            break;
        }
        let remainder_start = offset + character.len_utf8();
        let channel = &target[remainder_start..];
        if slash::is_channel(channel) {
            best = Some(StatusmsgTarget {
                channel: channel.to_string(),
                level: target[..remainder_start].to_string(),
            });
        }
    }
    best
}

/// Runs a compose-line slash command (see `cordiale_core::slash`) against
/// the open window's network. REST calls report failure in the status bar;
/// WS verbs are fire-and-forget like the member context menu's, their
/// outcome arriving as server pushes. `label` is the command as typed.
pub(crate) async fn run_slash_command(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
    channel: String,
    command: SlashCommand,
    label: String,
) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    let in_channel = !state.current_query && slash::is_channel(&channel);
    let open_channel = || in_channel.then(|| channel.clone());
    if channel == SERVER_WINDOW_NAME
        && matches!(&command, SlashCommand::Say(_) | SlashCommand::Action(_))
    {
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_status_kind("server-window-commands-only".into());
        });
        return;
    }
    let result: Result<(), GrappaClientError> = match command {
        SlashCommand::Say(text) => {
            let request = SendMessageRequest::plain(text);
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::Action(text) => {
            let request = SendMessageRequest::plain(format!("\u{1}ACTION {text}\u{1}"));
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::Msg { target, text } => {
            let prefix_symbols = cordiale_core::isupport::prefix_symbol_order(
                state.networks.isupport_by_network.get(&network),
            );
            if let Some(statusmsg) = peel_statusmsg_target(&target, &prefix_symbols) {
                // STATUSMSG is delivered into the underlying channel window;
                // it is not a query target and must not create a phantom nick
                // row in the sidebar. The complete target is retained in the
                // request so Grappa can validate the advertised level.
                let request = SendMessageRequest::statusmsg(&target, text);
                post_message(&client, &token, &network, &statusmsg.channel, request).await
            } else {
                // Services answer in the window the command was typed in.
                if !slash::is_service_nick(&target) {
                    send_user_verb(
                        state,
                        &network,
                        "open_query_window",
                        serde_json::json!({ "target_nick": target }),
                    );
                }
                let request = SendMessageRequest::plain(text);
                post_message(&client, &token, &network, &target, request).await
            }
        }
        SlashCommand::Notice { target, text } => {
            let mut request = SendMessageRequest::plain(text);
            request.notice_target = Some(target);
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::Query(Some(nick)) => {
            send_user_verb(
                state,
                &network,
                "open_query_window",
                serde_json::json!({ "target_nick": nick }),
            );
            Ok(())
        }
        SlashCommand::Query(None) if state.current_query => {
            send_user_verb(
                state,
                &network,
                "close_query_window",
                serde_json::json!({ "target_nick": channel }),
            );
            Ok(())
        }
        SlashCommand::Query(None) => {
            return set_command_status(ui, "command-usage-hint", "/query <nick>".to_string());
        }
        SlashCommand::Join { channels, key } => {
            client
                .join_channel(&token, &network, &channels, key.as_deref())
                .await
        }
        SlashCommand::Part {
            channel: target,
            reason,
        } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            handle_part_channel(state, ui, network, target, reason).await;
            return;
        }
        SlashCommand::Cycle {
            channel: target,
            reason,
        } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            match client
                .part_channel(&token, &network, &target, reason.as_deref())
                .await
            {
                Ok(()) => client.join_channel(&token, &network, &target, None).await,
                Err(err) => Err(err),
            }
        }
        SlashCommand::TopicSet {
            channel: target,
            text,
        } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            client.set_topic(&token, &network, &target, &text).await
        }
        SlashCommand::TopicClear { channel: target } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            send_user_verb(
                state,
                &network,
                "topic_clear",
                serde_json::json!({ "channel": target }),
            );
            Ok(())
        }
        // Read from what the client already holds (the topic and the
        // `channel_modes_changed` snapshot); nothing goes to the server.
        SlashCommand::TopicShow { channel: target } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            return match state
                .topics
                .get(&(network.clone(), target.clone()))
                .filter(|topic| !topic.is_empty())
            {
                Some(topic) => {
                    set_command_status(ui, "command-topic", format!("{target}: {topic}"))
                }
                None => set_command_status(ui, "command-no-topic", target),
            };
        }
        SlashCommand::ModeShow { channel: target } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            let modes = state
                .channel_modes
                .get(&(network.clone(), target.clone()))
                .map(|snapshot| format_channel_modes(&snapshot.modes))
                .unwrap_or_default();
            return if modes.is_empty() {
                set_command_status(ui, "command-no-modes", target)
            } else {
                set_command_status(ui, "command-modes", format!("{target} {modes}"))
            };
        }
        SlashCommand::Nick(nick) => client.change_nick(&token, &network, &nick).await,
        // The one user-topic verb addressed by slug rather than `network_id`.
        SlashCommand::Away(reason) => {
            let payload = match reason {
                Some(reason) => {
                    serde_json::json!({ "action": "set", "network": network, "reason": reason })
                }
                None => serde_json::json!({ "action": "unset", "network": network }),
            };
            send_user_topic_verb(state, "away", payload);
            Ok(())
        }
        SlashCommand::Ctcp { target, verb, args } if verb == "ACTION" => {
            let text = args.unwrap_or_default();
            let request = SendMessageRequest::plain(format!("\u{1}ACTION {text}\u{1}"));
            post_message(&client, &token, &network, &target, request).await
        }
        SlashCommand::Ctcp { target, verb, args } => {
            let request = SendMessageRequest::ctcp(target, &verb, args.as_deref());
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::Ping(target) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis())
                .unwrap_or_default()
                .to_string();
            let request = SendMessageRequest::ctcp(target, "PING", Some(&now));
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::NickModes { verb, nicks } if in_channel => {
            send_user_verb(
                state,
                &network,
                verb,
                serde_json::json!({ "channel": channel, "nicks": nicks }),
            );
            Ok(())
        }
        SlashCommand::Kick { nick, reason } if in_channel => {
            send_user_verb(
                state,
                &network,
                "kick",
                serde_json::json!({ "channel": channel, "nick": nick, "reason": reason }),
            );
            Ok(())
        }
        SlashCommand::Ban(mask) if in_channel => {
            send_user_verb(
                state,
                &network,
                "ban",
                serde_json::json!({ "channel": channel, "mask": mask }),
            );
            Ok(())
        }
        SlashCommand::Unban(mask) if in_channel => {
            send_user_verb(
                state,
                &network,
                "unban",
                serde_json::json!({ "channel": channel, "mask": mask }),
            );
            Ok(())
        }
        SlashCommand::KickBan { nick, reason } if in_channel => {
            start_kickban(state, &network, channel.clone(), nick, reason);
            Ok(())
        }
        SlashCommand::NickModes { .. }
        | SlashCommand::KickBan { .. }
        | SlashCommand::Kick { .. }
        | SlashCommand::Ban(_)
        | SlashCommand::Unban(_) => {
            return set_command_status(ui, "command-needs-channel", label);
        }
        SlashCommand::Mode {
            target,
            modes,
            params,
        } => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            send_user_verb(
                state,
                &network,
                "mode",
                serde_json::json!({ "target": target, "modes": modes, "params": params }),
            );
            Ok(())
        }
        SlashCommand::NowPlaying => {
            let line = match now_playing_text(&radio_now_playing(), std::time::Instant::now()) {
                Ok(line) => line,
                Err((kind, station)) => return set_command_status(ui, kind, station),
            };
            let request = SendMessageRequest::plain(format!("\u{1}ACTION {line}\u{1}"));
            post_message(&client, &token, &network, &channel, request).await
        }
        SlashCommand::UmodeShow => {
            state.networks.umode_view_network = Some(network.clone());
            push_umode_view(state, ui, true);
            return;
        }
        SlashCommand::Umode(modes) => {
            send_user_verb(
                state,
                &network,
                "umode",
                serde_json::json!({ "modes": modes }),
            );
            Ok(())
        }
        SlashCommand::Names(target) => {
            let Some(target) = target.or_else(open_channel) else {
                return set_command_status(ui, "command-needs-channel", label);
            };
            send_user_verb(
                state,
                &network,
                "names",
                serde_json::json!({ "channel": target }),
            );
            Ok(())
        }
        SlashCommand::Raw(line) => {
            send_user_verb(state, &network, "raw", serde_json::json!({ "line": line }));
            Ok(())
        }
        SlashCommand::Oper { name, password } => {
            send_user_verb(
                state,
                &network,
                "oper",
                serde_json::json!({ "name": name, "password": password }),
            );
            Ok(())
        }
        SlashCommand::Connect(target) => {
            client
                .set_connection_state(&token, &target, "connected", None)
                .await
        }
        SlashCommand::Disconnect {
            network: target,
            reason,
        } => {
            let target = target.unwrap_or(network);
            client
                .set_connection_state(&token, &target, "parked", reason.as_deref())
                .await
        }
        SlashCommand::Reconnect {
            network: target,
            reason,
        } => {
            let target = target.unwrap_or(network);
            match client
                .set_connection_state(&token, &target, "parked", reason.as_deref())
                .await
            {
                Ok(()) => {
                    client
                        .set_connection_state(&token, &target, "connected", None)
                        .await
                }
                Err(err) => Err(err),
            }
        }
        // Parks every network (a failure on one doesn't stop the others,
        // as in Cicchetto), then signs out like the Disconnect button.
        SlashCommand::Quit(reason) => {
            let networks: Vec<String> = state.networks.network_ids.keys().cloned().collect();
            for target in networks {
                if let Err(err) = client
                    .set_connection_state(&token, &target, "parked", reason.as_deref())
                    .await
                {
                    persistence::log_line(&format!("quit: park failed: {err:?}"));
                }
            }
            let _ = ui.upgrade_in_event_loop(|ui| ui.invoke_disconnect_requested());
            return;
        }
        SlashCommand::Highlight { add, pattern } => {
            let action = if add { "add" } else { "del" };
            send_user_topic_verb(
                state,
                "watchlist",
                serde_json::json!({ "action": action, "pattern": pattern }),
            );
            if !add {
                state
                    .prefs
                    .watch_patterns
                    .retain(|existing| existing != &pattern);
            } else if !state.prefs.watch_patterns.contains(&pattern) {
                state.prefs.watch_patterns.push(pattern);
            }
            push_watch_patterns(state, ui);
            Ok(())
        }
        SlashCommand::Ignore {
            add,
            mask,
            text_pattern,
        } => {
            let result = if add {
                client
                    .add_ignore(&token, &network, &mask, text_pattern.as_deref())
                    .await
            } else {
                client
                    .remove_ignore(&token, &network, &mask, text_pattern.as_deref())
                    .await
            };
            // Grappa answers with the resulting list: an open ignore list for
            // the same network shows it at once, like Cicchetto's mirror.
            match result {
                Ok(response) => {
                    if state.prefs.settings_network.as_deref() == Some(network.as_str()) {
                        push_ignore_entries(ui, response.entries(), "");
                    }
                    Ok(())
                }
                Err(err) => {
                    persistence::log_line(&format!("{label} failed: {err:?}"));
                    let kind = match ignore_error_key(&err) {
                        "invalid-text-pattern" => "ignore-invalid-text-pattern",
                        "invalid-mask" => "ignore-invalid-mask",
                        _ => "command-failed",
                    };
                    return set_command_status(ui, kind, label);
                }
            }
        }
        SlashCommand::Notify(nicks) => client.add_notify_nicks(&token, &network, nicks).await,
        SlashCommand::Beep(None) => {
            if state.prefs.notification_prefs.is_none() {
                handle_load_notification_prefs(state, ui).await;
            }
            let sound = state
                .prefs
                .notification_prefs
                .as_ref()
                .and_then(|prefs| prefs.get("notification_sound"))
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_string();
            return set_command_status(ui, "beep-current", sound);
        }
        SlashCommand::Beep(Some(sound)) => {
            if !NOTIFICATION_SOUNDS.contains(&sound.as_str()) {
                return set_command_status(ui, "beep-unknown", NOTIFICATION_SOUNDS.join(", "));
            }
            handle_notification_edit(state, ui, NotificationEdit::Sound(sound.clone())).await;
            return set_command_status(ui, "beep-set", sound);
        }
        SlashCommand::AliasDefine { name, expansion } => {
            handle_alias_upsert(state, ui, Some((name, expansion))).await;
            state.prefs.aliases = None;
            Ok(())
        }
        SlashCommand::Unalias(name) => {
            handle_alias_remove(state, ui, name).await;
            state.prefs.aliases = None;
            Ok(())
        }
        // One message per joined channel; a failure on one doesn't stop the
        // others, and is reported once.
        SlashCommand::FanOut { action, text } => {
            let body = if action {
                format!("\u{1}ACTION {text}\u{1}")
            } else {
                text
            };
            let mut result = Ok(());
            for target in joined_channels(state, &network) {
                let request = SendMessageRequest::plain(body.clone());
                if let Err(err) = post_message(&client, &token, &network, &target, request).await {
                    result = Err(err);
                }
            }
            result
        }
        SlashCommand::Usage(hint) => {
            return set_command_status(ui, "command-usage-hint", hint.to_string());
        }
        SlashCommand::Unknown(name) => {
            return set_command_status(ui, "command-unknown", name);
        }
    };
    if let Err(err) = result {
        persistence::log_line(&format!("{label} failed: {err:?}"));
        set_command_status(ui, "command-failed", label);
    }
}

/// Joined channels of `network`, for `/ame` and `/amsg`.
pub(crate) fn joined_channels(state: &WorkerState, network: &str) -> Vec<String> {
    state
        .channel_entries
        .iter()
        .filter(|(entry_network, channel, _)| {
            entry_network == network
                && state
                    .window_states
                    .get(&window_state_key(entry_network, channel))
                    == Some(&ChannelWindowState::Joined)
        })
        .map(|(_, channel, _)| channel.clone())
        .collect()
}

/// Asks Grappa for the target's `user@host` (from its userhost cache); the
/// ban and kick follow in `finish_kickban` when the reply arrives.
fn start_kickban(
    state: &mut WorkerState,
    network: &str,
    channel: String,
    nick: String,
    reason: String,
) {
    let (Some(session), Some(identifier), Some(&network_id)) = (
        &state.session,
        &state.identifier,
        state.networks.network_ids.get(network),
    ) else {
        return;
    };
    let message_ref = session.send_tracked_command(
        format!("grappa:user:{identifier}"),
        "resolve_userhost",
        serde_json::json!({ "network_id": network_id, "nick": nick }),
    );
    state.panels.pending_kickbans.insert(
        message_ref,
        PendingKickBan {
            network: network.to_string(),
            channel,
            nick,
            reason,
        },
    );
}

/// Posts to `/networks/:slug/channels/:target/messages`.
async fn post_message(
    client: &GrappaClient,
    token: &str,
    network: &str,
    target: &str,
    request: SendMessageRequest,
) -> Result<(), GrappaClientError> {
    client
        .send_message(token, network, target, &request)
        .await
        .map(|_| ())
}

/// Pushes `verb` on the user topic with `payload` as is (no `network_id`).
fn send_user_topic_verb(state: &WorkerState, verb: &str, payload: Value) {
    if let (Some(session), Some(identifier)) = (&state.session, &state.identifier) {
        session.send_command(format!("grappa:user:{identifier}"), verb, payload);
    }
}

fn radio_now_playing() -> RadioNowPlaying {
    RADIO_NOW_PLAYING
        .lock()
        .ok()
        .and_then(|now| now.clone())
        .unwrap_or_default()
}

/// The `/np` action text, or the status explaining why there's none (as
/// Cicchetto: idle, a station without track information, a feed that
/// hasn't answered, a track over three minutes old). Stations without a
/// feed fall back to the title in the stream itself.
pub(crate) fn now_playing_text(
    now: &RadioNowPlaying,
    at: std::time::Instant,
) -> Result<String, (&'static str, String)> {
    use cordiale_core::radio::{now_playing_line, Track, NOW_PLAYING_STALE_SECS};
    let Some(station) = now.station.clone() else {
        return Err(("np-idle", String::new()));
    };
    if let Some((track, read_at)) = &now.track {
        if at.duration_since(*read_at).as_secs() > NOW_PLAYING_STALE_SECS {
            return Err(("np-stale", station));
        }
        return Ok(now_playing_line(track, &station));
    }
    if let Some(title) = &now.stream_title {
        let track = Track {
            artist: None,
            title: title.clone(),
        };
        return Ok(now_playing_line(&track, &station));
    }
    Err(if now.has_feed {
        ("np-unanswered", station)
    } else {
        ("np-unsupported", station)
    })
}
