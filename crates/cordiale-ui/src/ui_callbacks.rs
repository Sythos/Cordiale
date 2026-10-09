use super::*;

/// Radio playback and stations, plus the font size setting.
pub(crate) fn register_radio_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_radio_tune = worker_tx.clone();
    ui.on_radio_tune(move |key| {
        let _ = tx_for_radio_tune.send(WorkerCommand::RadioTune(key.to_string()));
    });

    let tx_for_radio_stop = worker_tx.clone();
    ui.on_radio_stop(move || {
        let _ = tx_for_radio_stop.send(WorkerCommand::RadioStop);
    });

    let tx_for_radio_volume = worker_tx.clone();
    ui.on_radio_volume_changed(move |volume| {
        let volume = volume.clamp(0, 100);
        let mut settings = persistence::load_settings().unwrap_or_default();
        settings.radio_volume = u8::try_from(volume).unwrap_or(100);
        let _ = persistence::save_settings(&settings);
        let _ = tx_for_radio_volume.send(WorkerCommand::RadioVolume(volume));
    });

    let weak_for_shrink_pref = ui.as_weak();
    ui.on_shrink_pref_changed(move || {
        let Some(ui) = weak_for_shrink_pref.upgrade() else {
            return;
        };
        let mut settings = persistence::load_settings().unwrap_or_default();
        settings.shrink_videos = ui.get_pref_shrink_videos();
        let _ = persistence::save_settings(&settings);
    });

    ui.on_font_size_changed(move |percent| {
        let mut settings = persistence::load_settings().unwrap_or_default();
        settings.font_size_percent = u8::try_from(percent.clamp(50, 150)).unwrap_or(100);
        let _ = persistence::save_settings(&settings);
    });

    let tx_for_ban_type = worker_tx.clone();
    ui.on_ban_type_changed(move |index| {
        let _ = tx_for_ban_type.send(WorkerCommand::BanTypeSave(
            cordiale_core::ban::BanType::from_index(index),
        ));
    });

    let weak_for_radio_save = ui.as_weak();
    ui.on_radio_station_save(move |index, name, url, codec_index| {
        let Some(ui) = weak_for_radio_save.upgrade() else {
            return;
        };
        let Some(station) = custom_radio_station(&name, &url, codec_index) else {
            ui.set_status_kind("radio-station-invalid".into());
            return;
        };
        let mut settings = persistence::load_settings().unwrap_or_default();
        match usize::try_from(index)
            .ok()
            .filter(|index| *index < settings.radio_stations.len())
        {
            Some(index) => settings.radio_stations[index] = station,
            None => settings.radio_stations.push(station),
        }
        let _ = persistence::save_settings(&settings);
        push_radio_stations(&ui, &settings.radio_stations);
        ui.set_radio_edit_index(-1);
        ui.set_radio_form_name("".into());
        ui.set_radio_form_url("".into());
        ui.set_radio_form_codec(0);
    });

    let weak_for_radio_delete = ui.as_weak();
    ui.on_radio_station_delete(move |index| {
        let Some(ui) = weak_for_radio_delete.upgrade() else {
            return;
        };
        let mut settings = persistence::load_settings().unwrap_or_default();
        if let Some(index) = usize::try_from(index)
            .ok()
            .filter(|index| *index < settings.radio_stations.len())
        {
            settings.radio_stations.remove(index);
            let _ = persistence::save_settings(&settings);
        }
        push_radio_stations(&ui, &settings.radio_stations);
        ui.set_radio_edit_index(-1);
    });
}

/// Language and server pickers, the passkey origin editor, and the connect, TOTP, share-link and recovery sign-in flows.
pub(crate) fn register_connect_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let weak_for_language = ui.as_weak();
    ui.on_language_selected(move |code| {
        if let Some(language) = language_from_code(&code) {
            let mut settings = persistence::load_settings().unwrap_or_default();
            settings.language = Some(language);
            let _ = persistence::save_settings(&settings);
            let _ = slint::select_bundled_translation(language_code(language));
            dates::set_language(Some(language));
        }
        if let Some(ui) = weak_for_language.upgrade() {
            push_date_format_examples(&ui);
            ui.set_screen("connect".into());
        }
    });

    let weak_for_server = ui.as_weak();
    ui.on_server_selected(move |server_url| {
        if let Some(ui) = weak_for_server.upgrade() {
            ui.set_server_url(server_url.clone());
            ui.set_identifier("".into());
            ui.set_password("".into());
            ui.set_saved_profile_identifier("".into());
            ui.set_saved_profile_server_url("".into());
            prefill_remembered_profile(&ui, &server_url);
        }
    });

    ui.on_passkey_origin_preview(|server_url, origin| {
        passkey_origin(&server_url, Some(origin.as_str())).into()
    });
    ui.on_passkey_origin_valid(|origin| !matches!(check_override(&origin), OverrideCheck::Invalid));
    ui.on_cleartext_key(|server_url, origin| {
        cleartext::confirmation_key(&server_url, &origin).into()
    });
    let weak_for_origin = ui.as_weak();
    ui.on_passkey_origin_reload(move |server_url| {
        if let Some(ui) = weak_for_origin.upgrade() {
            load_passkey_origin_field(&ui, &server_url);
        }
    });
    let weak_for_origin = ui.as_weak();
    ui.on_passkey_origin_save(move |server_url, origin| {
        let saved =
            persistence::save_passkey_origin_override(&server_url, &check_override(&origin))
                .is_ok();
        if let Some(ui) = weak_for_origin.upgrade() {
            ui.set_passkey_origin_saved(saved);
        }
    });

    let tx_for_connect = worker_tx.clone();
    let weak_for_connect = ui.as_weak();
    ui.on_connect_requested(move |server_url, identifier, password| {
        let server_url = normalize_server_url(&server_url);
        if let Some(ui) = weak_for_connect.upgrade() {
            save_passkey_origin_field(&ui, &server_url);
            ui.set_server_url(server_url.clone().into());
            ui.set_connecting(true);
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
        }
        let _ = tx_for_connect.send(WorkerCommand::Connect {
            server_url: server_url.to_string(),
            identifier: identifier.to_string(),
            credential: ConnectCredential::FormValue(password.to_string()),
        });
    });

    let tx_for_totp = worker_tx.clone();
    let weak_for_totp = ui.as_weak();
    ui.on_totp_verify_requested(move |code| {
        if let Some(ui) = weak_for_totp.upgrade() {
            ui.set_connecting(true);
            ui.set_status_kind("".into());
        }
        let _ = tx_for_totp.send(WorkerCommand::TotpVerify(code.to_string()));
    });
    let tx_for_totp_cancel = worker_tx.clone();
    ui.on_totp_cancel_requested(move || {
        let _ = tx_for_totp_cancel.send(WorkerCommand::TotpCancel);
    });

    let tx_for_share = worker_tx.clone();
    let weak_for_share = ui.as_weak();
    ui.on_share_consume_requested(move |server_url, input| {
        let server_url = normalize_server_url(&server_url);
        if let Some(ui) = weak_for_share.upgrade() {
            ui.set_server_url(server_url.clone().into());
            ui.set_connecting(true);
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
        }
        let _ = tx_for_share.send(WorkerCommand::ShareConsume {
            server_url,
            input: input.to_string(),
        });
    });
    let weak_for_share_screen = ui.as_weak();
    ui.on_share_screen_requested(move |open| {
        if let Some(ui) = weak_for_share_screen.upgrade() {
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
            if !open {
                ui.set_share_token_input("".into());
            }
            let screen = if open { "share" } else { "connect" };
            ui.set_screen(screen.into());
        }
    });

    let tx_for_recovery = worker_tx.clone();
    let weak_for_recovery = ui.as_weak();
    ui.on_recovery_sign_in_requested(move |server_url, identifier, code| {
        let server_url = normalize_server_url(&server_url);
        if let Some(ui) = weak_for_recovery.upgrade() {
            ui.set_server_url(server_url.clone().into());
            // The code is single use and a credential: it leaves the field
            // as soon as it is sent.
            ui.set_recovery_code_input("".into());
            ui.set_connecting(true);
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
        }
        let _ = tx_for_recovery.send(WorkerCommand::RecoverySignIn {
            server_url,
            identifier: identifier.to_string(),
            code: code.to_string(),
        });
    });
    let weak_for_recovery_screen = ui.as_weak();
    ui.on_recovery_screen_requested(move |open| {
        if let Some(ui) = weak_for_recovery_screen.upgrade() {
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
            if !open {
                ui.set_recovery_code_input("".into());
            }
            let screen = if open { "recover" } else { "connect" };
            ui.set_screen(screen.into());
        }
    });
}

/// The Security screen: TOTP, share links and passkey deletion.
pub(crate) fn register_security_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_security = worker_tx.clone();
    let weak_for_security = ui.as_weak();
    ui.on_security_totp_requested(move || {
        // Coming back to Security never shows an old share link.
        if let Some(ui) = weak_for_security.upgrade() {
            clear_share_link(&ui);
        }
        let _ = tx_for_security.send(WorkerCommand::SecurityTotpRefresh);
    });
    let tx_for_security = worker_tx.clone();
    ui.on_security_share_requested(move || {
        let _ = tx_for_security.send(WorkerCommand::SecurityShareMint);
    });
    let weak_for_security = ui.as_weak();
    ui.on_security_share_done(move || {
        if let Some(ui) = weak_for_security.upgrade() {
            clear_share_link(&ui);
        }
    });
    let tx_for_security = worker_tx.clone();
    ui.on_security_totp_start(move |password| {
        let _ = tx_for_security.send(WorkerCommand::SecurityTotpStart(password.to_string()));
    });
    let tx_for_security = worker_tx.clone();
    ui.on_security_totp_confirm(move |code| {
        let _ = tx_for_security.send(WorkerCommand::SecurityTotpConfirm(code.to_string()));
    });
    let tx_for_security = worker_tx.clone();
    ui.on_security_totp_disable(move |password| {
        let _ = tx_for_security.send(WorkerCommand::SecurityTotpDisable(password.to_string()));
    });
    let tx_for_security = worker_tx.clone();
    ui.on_security_totp_done(move || {
        let _ = tx_for_security.send(WorkerCommand::SecurityTotpDone);
    });
    let tx_for_security = worker_tx.clone();
    ui.on_security_passkeys_requested(move || {
        let _ = tx_for_security.send(WorkerCommand::SecurityPasskeysRefresh);
    });
    let tx_for_security = worker_tx.clone();
    ui.on_security_passkey_delete(move |id, password| {
        let _ = tx_for_security.send(WorkerCommand::SecurityPasskeyDelete {
            id: id.to_string(),
            password: password.to_string(),
        });
    });
}

/// Passkey sign-in and management, passwordless setup, and the copy actions for the codes.
pub(crate) fn register_passkey_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_passkey = worker_tx.clone();
    let weak_for_passkey = ui.as_weak();
    ui.on_passkey_second_factor_requested(move || {
        if let Some(ui) = weak_for_passkey.upgrade() {
            ui.set_connecting(true);
            ui.set_status_kind("".into());
        }
        let _ = tx_for_passkey.send(WorkerCommand::PasskeySignIn(PasskeySignIn::SecondFactor));
    });
    let tx_for_passkey = worker_tx.clone();
    let weak_for_passkey = ui.as_weak();
    ui.on_passkey_login_requested(move |server_url, identifier| {
        let server_url = normalize_server_url(&server_url);
        if let Some(ui) = weak_for_passkey.upgrade() {
            save_passkey_origin_field(&ui, &server_url);
            ui.set_server_url(server_url.clone().into());
            ui.set_connecting(true);
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
        }
        let _ = tx_for_passkey.send(WorkerCommand::PasskeySignIn(PasskeySignIn::Passwordless {
            server_url,
            identifier: identifier.to_string(),
        }));
    });
    let tx_for_passkey = worker_tx.clone();
    ui.on_security_passkey_add(move |name, password| {
        let _ = tx_for_passkey.send(WorkerCommand::SecurityPasskeyAdd {
            name: name.trim().to_string(),
            password: password.to_string(),
        });
    });
    let tx_for_passkey = worker_tx.clone();
    ui.on_security_passkey_mode_change(move |mode, password| {
        if let Some(mode) = passkeys::settable_mode(&mode) {
            let _ = tx_for_passkey.send(WorkerCommand::SecurityPasskeyMode {
                mode,
                password: password.to_string(),
            });
        }
    });
    let tx_for_passkey = worker_tx.clone();
    ui.on_security_passwordless_prepare(move |password| {
        let _ = tx_for_passkey.send(WorkerCommand::SecurityPasswordlessPrepare(
            password.to_string(),
        ));
    });
    let tx_for_passkey = worker_tx.clone();
    ui.on_security_passwordless_activate(move || {
        let _ = tx_for_passkey.send(WorkerCommand::SecurityPasswordlessActivate);
    });
    let tx_for_passkey = worker_tx.clone();
    ui.on_security_passwordless_cancel(move || {
        let _ = tx_for_passkey.send(WorkerCommand::SecurityPasswordlessCancel);
    });
    let weak_for_passkey = ui.as_weak();
    ui.on_security_copy_passwordless_codes(move || {
        if let Some(ui) = weak_for_passkey.upgrade() {
            use slint::Model as _;
            let codes: Vec<String> = ui
                .get_security_passwordless_codes()
                .iter()
                .map(|code| code.to_string())
                .collect();
            copy_text(&codes.join("\n"));
        }
    });
    ui.on_copy_text_requested(|text| copy_text(&text));
    let weak_for_codes = ui.as_weak();
    ui.on_security_copy_recovery_codes(move || {
        if let Some(ui) = weak_for_codes.upgrade() {
            use slint::Model as _;
            let codes: Vec<String> = ui
                .get_security_recovery_codes()
                .iter()
                .map(|code| code.to_string())
                .collect();
            copy_text(&codes.join("\n"));
        }
    });
}

/// Signing in with the saved profile.
pub(crate) fn register_saved_profile_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_saved_profile = worker_tx.clone();
    let weak_for_saved_profile = ui.as_weak();
    ui.on_saved_profile_connect_requested(move |server_url, identifier| {
        let server_url = normalize_server_url(&server_url);
        if let Some(ui) = weak_for_saved_profile.upgrade() {
            save_passkey_origin_field(&ui, &server_url);
            ui.set_server_url(server_url.clone().into());
            ui.set_connecting(true);
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
        }
        let _ = tx_for_saved_profile.send(WorkerCommand::Connect {
            server_url: server_url.to_string(),
            identifier: identifier.to_string(),
            credential: ConnectCredential::SavedProfile,
        });
    });
}

/// Disconnecting, older history, resuming the chat scroll position and going Home.
pub(crate) fn register_navigation_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_disconnect = worker_tx.clone();
    let weak_for_disconnect = ui.as_weak();
    ui.on_disconnect_requested(move || {
        let _ = tx_for_disconnect.send(WorkerCommand::Disconnect);
        if let Some(ui) = weak_for_disconnect.upgrade() {
            clear_share_link(&ui);
            ui.set_screen("connect".into());
            ui.set_status_kind("".into());
            ui.set_status_message("".into());
            let empty_groups = Rc::new(slint::VecModel::from(Vec::<NetworkGroup>::new()));
            ui.set_network_groups(empty_groups.into());
            show_chat_lines(&ui, Vec::new());
            let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
            ui.set_channel_members(empty_members.into());
            ui.set_current_topic("".into());
            ui.set_window_status("".into());
            ui.set_current_window_is_joined(false);
            ui.set_current_server_window(false);
            ui.set_has_selected_channel(false);
            ui.set_current_query(false);
            ui.set_current_query_ready(false);
            ui.set_can_moderate_members(false);
            ui.set_window_invite_banner("".into());
            ui.set_window_invite_network("".into());
            ui.set_window_invite_channel("".into());
            ui.set_window_invite_inviter("".into());
            ui.set_recover_visible(false);
            ui.set_dcc_offers(slint::ModelRc::default());
            ui.set_personal_prefs_loaded(false);
            ui.set_server_upload_limits_known(false);
        }
    });

    let tx_for_older_history = worker_tx.clone();
    ui.on_older_history_requested(move || {
        let _ = tx_for_older_history.send(WorkerCommand::LoadOlderHistory);
    });

    let tx_for_mention = worker_tx.clone();
    ui.on_mention_open_requested(move |index| {
        if let Ok(index) = usize::try_from(index) {
            let _ = tx_for_mention.send(WorkerCommand::OpenMention(index));
        }
    });

    // A chat pane rebuilt after a round trip through another screen (the
    // media viewer, settings...) asks here where the reader was. The line
    // is picked from the saved scroll state right away, but only put back
    // once the new `ListView` has measured its rows (`chat-resume-landed`).
    let pending_resume = Rc::new(std::cell::Cell::new(None::<ChatAnchor>));
    let weak_for_resume = ui.as_weak();
    let pending_for_request = pending_resume.clone();
    ui.on_chat_resume_requested(move || {
        use slint::Model as _;
        let Some(ui) = weak_for_resume.upgrade() else {
            return false;
        };
        let anchor = resume_scroll_anchor(
            ui.get_chat_follow_bottom(),
            ui.get_chat_scroll_y(),
            ui.get_chat_content_height(),
            usize::try_from(ui.get_chat_content_rows()).unwrap_or(0),
            ui.get_chat_lines().row_count(),
        );
        pending_for_request.set(anchor);
        anchor.is_some()
    });
    let weak_for_landed = ui.as_weak();
    ui.on_chat_resume_landed(move || {
        use slint::Model as _;
        let Some(ui) = weak_for_landed.upgrade() else {
            return;
        };
        let Some(mut anchor) = pending_resume.take() else {
            return;
        };
        let rows = ui.get_chat_lines().row_count();
        let content_height = ui.get_chat_content_height();
        if rows == 0 || content_height <= 0.0 {
            return;
        }
        anchor.row_height = content_height / rows as f32;
        restore_chat_anchor(&ui, anchor);
    });

    let tx_for_home = worker_tx.clone();
    let weak_for_home = ui.as_weak();
    ui.on_home_requested(move || {
        let _ = tx_for_home.send(WorkerCommand::GoHome);
        if let Some(ui) = weak_for_home.upgrade() {
            ui.set_screen("connected".into());
            show_chat_lines(&ui, Vec::new());
            let empty_members = Rc::new(slint::VecModel::from(Vec::<MemberRow>::new()));
            ui.set_channel_members(empty_members.into());
            ui.set_current_topic("".into());
            ui.set_window_status("".into());
            ui.set_current_channel_label("".into());
            ui.set_current_window_is_joined(false);
            ui.set_current_server_window(false);
            ui.set_has_selected_channel(false);
            ui.set_current_query(false);
            ui.set_current_query_ready(false);
            ui.set_can_moderate_members(false);
        }
    });
}

/// Member list actions.
pub(crate) fn register_member_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_mode_action = worker_tx.clone();
    ui.on_member_mode_action_requested(move |verb, nick| {
        let _ = tx_for_mode_action.send(WorkerCommand::MemberModeAction {
            verb: verb.to_string(),
            nick: nick.to_string(),
        });
    });

    let tx_for_kick = worker_tx.clone();
    ui.on_member_kick_requested(move |nick| {
        let _ = tx_for_kick.send(WorkerCommand::MemberKick(nick.to_string()));
    });

    let tx_for_ban = worker_tx.clone();
    ui.on_member_ban_requested(move |nick| {
        let _ = tx_for_ban.send(WorkerCommand::MemberBan(nick.to_string()));
    });

    let tx_for_ban_host = worker_tx.clone();
    ui.on_member_ban_host_requested(move |nick| {
        let _ = tx_for_ban_host.send(WorkerCommand::MemberBanHost(nick.to_string()));
    });

    let tx_for_kickban = worker_tx.clone();
    ui.on_member_kickban_requested(move |nick| {
        let _ = tx_for_kickban.send(WorkerCommand::MemberKickBan(nick.to_string()));
    });

    let tx_for_whois = worker_tx.clone();
    ui.on_member_whois_requested(move |nick| {
        let _ = tx_for_whois.send(WorkerCommand::MemberWhois(nick.to_string()));
    });

    let tx_for_ctcp = worker_tx.clone();
    ui.on_member_ctcp_requested(move |nick, verb| {
        let _ = tx_for_ctcp.send(WorkerCommand::MemberCtcp {
            nick: nick.to_string(),
            verb: verb.to_string(),
        });
    });

    let tx_for_query = worker_tx.clone();
    ui.on_member_query_requested(move |nick| {
        let _ = tx_for_query.send(WorkerCommand::MemberQuery(nick.to_string()));
    });
}

/// Channel, network and query selection, the Home network actions, invites and dismissals.
pub(crate) fn register_channel_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_channel = worker_tx.clone();
    ui.on_channel_selected(move |network, channel| {
        let _ = tx_for_channel.send(WorkerCommand::SelectChannel {
            network: network.to_string(),
            channel: channel.to_string(),
        });
    });

    let tx_for_network = worker_tx.clone();
    ui.on_network_selected(move |network| {
        let _ = tx_for_network.send(WorkerCommand::SelectNetwork(network.to_string()));
    });

    let tx_for_home = worker_tx.clone();
    ui.on_home_network_disconnect(move |network| {
        let _ = tx_for_home.send(WorkerCommand::HomeDisconnect(network.to_string()));
    });
    let tx_for_home = worker_tx.clone();
    ui.on_home_network_reconnect(move |network| {
        let _ = tx_for_home.send(WorkerCommand::HomeReconnect(network.to_string()));
    });
    let tx_for_home = worker_tx.clone();
    ui.on_home_network_remove(move |network| {
        let _ = tx_for_home.send(WorkerCommand::HomeRemove(network.to_string()));
    });
    let tx_for_home = worker_tx.clone();
    ui.on_home_network_recover(move |network| {
        let _ = tx_for_home.send(WorkerCommand::HomeRecover(network.to_string()));
    });
    let tx_for_home = worker_tx.clone();
    ui.on_home_network_connect(move |network| {
        let _ = tx_for_home.send(WorkerCommand::HomeConnect(network.to_string()));
    });
    let tx_for_home = worker_tx.clone();
    ui.on_home_featured_open(move |network, channel| {
        let _ = tx_for_home.send(WorkerCommand::HomeFeaturedOpen {
            network: network.to_string(),
            channel: channel.to_string(),
        });
    });

    let tx_for_part = worker_tx.clone();
    ui.on_channel_part_requested(move |network, channel| {
        let _ = tx_for_part.send(WorkerCommand::PartChannel {
            network: network.to_string(),
            channel: channel.to_string(),
        });
    });

    let tx_for_query_window = worker_tx.clone();
    ui.on_query_selected(move |network, nick| {
        let _ = tx_for_query_window.send(WorkerCommand::SelectQuery {
            network: network.to_string(),
            nick: nick.to_string(),
        });
    });

    // The invitation banner deliberately does not auto-focus a window. Its
    // explicit Join action only opens the invited row; the server remains the
    // authority for the subsequent pending/joined transition.
    let tx_for_window_invite = worker_tx.clone();
    ui.on_window_invite_join_requested(move |network, channel| {
        let _ = tx_for_window_invite.send(WorkerCommand::SelectChannel {
            network: network.to_string(),
            channel: channel.to_string(),
        });
    });

    let tx_for_decline_invite = worker_tx.clone();
    ui.on_window_invite_decline_requested(move |network, channel| {
        let _ = tx_for_decline_invite.send(WorkerCommand::DeclineInvite {
            network: network.to_string(),
            channel: channel.to_string(),
        });
    });

    let tx_for_dismiss_kicked_channel = worker_tx.clone();
    ui.on_kicked_channel_dismiss_requested(move |network, channel| {
        let _ = tx_for_dismiss_kicked_channel.send(WorkerCommand::DismissKickedChannel {
            network: network.to_string(),
            channel: channel.to_string(),
        });
    });

    let tx_for_dismiss_recover = worker_tx.clone();
    ui.on_recover_dismiss_requested(move || {
        let _ = tx_for_dismiss_recover.send(WorkerCommand::DismissRecover);
    });
}

/// The channel directory.
pub(crate) fn register_directory_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_directory_refresh = worker_tx.clone();
    ui.on_directory_refresh_requested(move || {
        let _ = tx_for_directory_refresh.send(WorkerCommand::DirectoryRefresh);
    });

    let tx_for_directory_load_more = worker_tx.clone();
    ui.on_directory_load_more_requested(move || {
        let _ = tx_for_directory_load_more.send(WorkerCommand::DirectoryLoadMore);
    });

    let tx_for_directory_sort = worker_tx.clone();
    ui.on_directory_sort_requested(move |sort| {
        let _ = tx_for_directory_sort.send(WorkerCommand::DirectorySort(sort.to_string()));
    });

    let tx_for_directory_search = worker_tx.clone();
    ui.on_directory_search_requested(move |query| {
        let _ = tx_for_directory_search.send(WorkerCommand::DirectorySearch(query.to_string()));
    });

    let tx_for_directory_close = worker_tx.clone();
    ui.on_directory_closed(move || {
        let _ = tx_for_directory_close.send(WorkerCommand::DirectoryClose);
    });

    let tx_for_directory_open = worker_tx.clone();
    ui.on_directory_open_requested(move |network| {
        let _ = tx_for_directory_open.send(WorkerCommand::DirectoryOpen(network.to_string()));
    });

    let tx_for_directory_activate = worker_tx.clone();
    ui.on_directory_channel_activated(move |channel| {
        let _ =
            tx_for_directory_activate.send(WorkerCommand::DirectoryActivate(channel.to_string()));
    });

    let weak_for_directory_age = ui.as_weak();
    ui.on_directory_age_tick(move || {
        if let Some(ui) = weak_for_directory_age.upgrade() {
            let age = directory_age_seconds(
                &ui.get_directory_captured_epoch(),
                chrono::Utc::now().timestamp(),
            );
            ui.set_directory_age_seconds(age);
        }
    });
}

/// DCC offers and archive deletion.
pub(crate) fn register_dcc_archive_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_dcc_accept = worker_tx.clone();
    ui.on_dcc_offer_accept_requested(move |network, offer_id| {
        let _ = tx_for_dcc_accept.send(WorkerCommand::DccOfferAnswer {
            network: network.to_string(),
            offer_id: offer_id.to_string(),
            accept: true,
        });
    });

    let tx_for_dcc_refuse = worker_tx.clone();
    ui.on_dcc_offer_refuse_requested(move |network, offer_id| {
        let _ = tx_for_dcc_refuse.send(WorkerCommand::DccOfferAnswer {
            network: network.to_string(),
            offer_id: offer_id.to_string(),
            accept: false,
        });
    });

    let tx_for_archive_delete = worker_tx.clone();
    ui.on_archive_delete_requested(move |target| {
        let _ = tx_for_archive_delete.send(WorkerCommand::ArchiveDelete(target.to_string()));
    });
}

/// Opening links, the media viewer, credits, debug info and the release page.
pub(crate) fn register_link_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_link = worker_tx.clone();
    ui.on_chat_link_clicked(move |href| {
        let _ = tx_for_link.send(WorkerCommand::OpenLink(href.to_string()));
    });

    let weak_for_media_browser = ui.as_weak();
    ui.on_media_open_in_browser(move || {
        if let Some(ui) = weak_for_media_browser.upgrade() {
            open_in_browser(&ui.get_media_url());
        }
    });

    ui.on_credits_link_clicked(|href| open_in_browser(&href));

    let weak_for_debug = ui.as_weak();
    ui.on_debug_requested(move || {
        if let Some(ui) = weak_for_debug.upgrade() {
            let language = persistence::load_settings()
                .ok()
                .and_then(|settings| settings.language)
                .map(language_code);
            ui.set_debug_report(debug_info::report(ui.window(), language).into());
        }
    });
    ui.on_debug_open_data_folder(|| {
        if let Some(dir) = persistence::config_dir() {
            open_folder(&dir);
        }
    });
    ui.on_update_release_open(|| {
        open_in_browser(cordiale_core::release::LATEST_RELEASE_PAGE);
    });
}

/// Closing the archive and user-mode views, the menu command, peer-away dismissal and network collapse.
pub(crate) fn register_view_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_archive_close = worker_tx.clone();
    ui.on_archive_closed(move || {
        let _ = tx_for_archive_close.send(WorkerCommand::ArchiveClose);
    });

    let tx_for_umode_toggle = worker_tx.clone();
    ui.on_umode_toggle_requested(move |letter| {
        let _ = tx_for_umode_toggle.send(WorkerCommand::UmodeToggle(letter.to_string()));
    });

    let tx_for_umode_close = worker_tx.clone();
    ui.on_umode_view_closed(move || {
        let _ = tx_for_umode_close.send(WorkerCommand::UmodeClose);
    });

    // Actions menu entries that run a slash command on the open window,
    // leaving the composer's draft alone.
    let tx_for_menu_command = worker_tx.clone();
    ui.on_menu_command(move |body| {
        let _ = tx_for_menu_command.send(WorkerCommand::SendMessage {
            body: body.to_string(),
        });
    });

    let tx_for_peer_away_dismiss = worker_tx.clone();
    ui.on_peer_away_dismiss_requested(move || {
        let _ = tx_for_peer_away_dismiss.send(WorkerCommand::DismissPeerAway);
    });

    let tx_for_network_toggle = worker_tx.clone();
    ui.on_network_toggle_requested(move |network| {
        let _ = tx_for_network_toggle.send(WorkerCommand::ToggleNetwork(network.to_string()));
    });
}

/// Attaching files through the picker and by dropping them on the window.
pub(crate) fn register_attach_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_attach = worker_tx.clone();
    let weak_for_attach = ui.as_weak();
    ui.on_attach_file_requested(move || {
        let Some(ui) = weak_for_attach.upgrade() else {
            return;
        };
        // The native file picker and the confirmation are modal and must run
        // on the UI thread (a requirement on macOS); the upload itself
        // happens in the worker.
        let Some(path) = rfd::FileDialog::new().pick_file() else {
            return;
        };
        confirm_and_attach(&ui, &tx_for_attach, path);
    });

    let tx_for_confirm = worker_tx.clone();
    let weak_for_confirm = ui.as_weak();
    ui.on_upload_confirm_accepted(move || {
        if let Some(ui) = weak_for_confirm.upgrade() {
            finish_upload_confirm(&ui, &tx_for_confirm, true);
        }
    });
    let tx_for_cancel = worker_tx.clone();
    let weak_for_cancel = ui.as_weak();
    ui.on_upload_confirm_cancelled(move || {
        if let Some(ui) = weak_for_cancel.upgrade() {
            finish_upload_confirm(&ui, &tx_for_cancel, false);
        }
    });

    // Files dropped on the window go through the paperclip's flow, like
    // Cicchetto's drop zone. Winit reports them (Windows, macOS, X11);
    // the confirmation runs once the event has been handled.
    {
        use slint::winit_030::{winit::event::WindowEvent, EventResult, WinitWindowAccessor};
        let tx_for_drop = worker_tx.clone();
        let weak_for_drop = ui.as_weak();
        ui.window().on_winit_window_event(move |_, event| {
            let WindowEvent::DroppedFile(path) = event else {
                return EventResult::Propagate;
            };
            let path = path.clone();
            let tx = tx_for_drop.clone();
            let weak = weak_for_drop.clone();
            slint::Timer::single_shot(std::time::Duration::ZERO, move || {
                if let Some(ui) = weak.upgrade() {
                    confirm_and_attach(&ui, &tx, path);
                }
            });
            EventResult::PreventDefault
        });
    }
}

/// Paste, upload preferences, sending, draft sync, replies and nick completion.
pub(crate) fn register_composer_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    // Ctrl+V (Cmd+V) in the compose box: an image on the clipboard is
    // uploaded like a picked file, and a multi-line text can go up as a .txt
    // instead of being flattened into one message. Plain text pastes as
    // usual.
    let tx_for_paste = worker_tx.clone();
    let weak_for_paste = ui.as_weak();
    ui.on_paste_requested(move || {
        let Some(ui) = weak_for_paste.upgrade() else {
            return false;
        };
        let Some(path) = clipboard_upload(&ui) else {
            return false;
        };
        confirm_and_attach(&ui, &tx_for_paste, path);
        true
    });

    let tx_for_upload_prefs = worker_tx.clone();
    let weak_for_upload_prefs = ui.as_weak();
    ui.on_upload_prefs_changed(move || {
        if let Some(ui) = weak_for_upload_prefs.upgrade() {
            let _ = tx_for_upload_prefs.send(WorkerCommand::UploadPrefsChanged {
                ttl: upload_ttl_for_index(ui.get_pref_upload_ttl_index()),
                confirm: ui.get_pref_upload_confirm(),
            });
        }
    });

    let tx_for_send = worker_tx.clone();
    let weak_for_send = ui.as_weak();
    ui.on_send_chat_message(move |body| {
        let body = body.to_string();
        if body.trim().is_empty() {
            return;
        }
        let _ = tx_for_send.send(WorkerCommand::SendMessage { body });
        if let Some(ui) = weak_for_send.upgrade() {
            ui.set_compose_text("".into());
        }
    });

    let tx_for_draft = worker_tx.clone();
    ui.on_compose_text_changed(move |text| {
        let _ = tx_for_draft.send(WorkerCommand::ComposeTextChanged(text.to_string()));
    });

    let tx_for_reply = worker_tx.clone();
    ui.on_reply_to_message_requested(move |nick, body, id| {
        // The worker owns the draft mirror and the roster the quote needs.
        let _ = tx_for_reply.send(WorkerCommand::ReplyToMessage {
            nick: nick.to_string(),
            body: body.to_string(),
            id: id.to_string(),
        });
    });

    // Tab-completion cycle state (see `NickCompletionCycle`): UI-thread only,
    // reset by any compose-box edit that doesn't come from this same
    // callback, so a plain `RefCell` local to this closure is enough — no
    // worker involvement needed to decide what the next Tab press does.
    let tx_for_nick_complete = worker_tx.clone();
    let weak_for_nick_complete = ui.as_weak();
    let nick_completion_cycle: RefCell<Option<NickCompletionCycle>> = RefCell::new(None);
    ui.on_nick_complete_requested(move |forward| {
        let Some(ui) = weak_for_nick_complete.upgrade() else {
            return slint::SharedString::default();
        };
        let text = ui.get_compose_text();
        let candidates = nick_completion_candidates(&ui);
        let mut cycle = nick_completion_cycle.borrow_mut();
        match complete_nick(text.as_str(), &candidates, forward, cycle.as_ref()) {
            Some((new_text, new_cycle)) => {
                *cycle = Some(new_cycle);
                // Setting `compose-text` from Rust doesn't fire the
                // LineEdit's `edited` callback (that only fires on direct
                // user input), so the draft has to be saved explicitly here
                // — same command `compose-text-changed` sends for a typed
                // edit.
                let _ =
                    tx_for_nick_complete.send(WorkerCommand::ComposeTextChanged(new_text.clone()));
                new_text.into()
            }
            None => {
                *cycle = None;
                text
            }
        }
    });
}

/// Theme toggle, the taskbar badge, color themes and the theme editor.
pub(crate) fn register_theme_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_theme = worker_tx.clone();
    ui.on_theme_toggle_requested(move || {
        let _ = tx_for_theme.send(WorkerCommand::ToggleTheme);
    });

    let weak_for_badge = ui.as_weak();
    ui.on_taskbar_badge_changed(move |count, description| {
        if let Some(ui) = weak_for_badge.upgrade() {
            taskbar::set_badge(ui.window(), count, &description);
        }
    });

    let tx_for_color_theme = worker_tx.clone();
    ui.on_color_theme_requested(move |key| {
        let _ = tx_for_color_theme.send(WorkerCommand::SelectColorTheme(key.to_string()));
    });

    let tx_for_theme_edit = worker_tx.clone();
    ui.on_theme_edit_requested(move |key| {
        let _ = tx_for_theme_edit.send(WorkerCommand::ThemeEdit(key.to_string()));
    });

    let tx_for_theme_delete = worker_tx.clone();
    let weak_for_theme_delete = ui.as_weak();
    ui.on_theme_delete_requested(move |key, name| {
        let (Some(ui), Some(theme_id)) = (weak_for_theme_delete.upgrade(), server_theme_id(&key))
        else {
            return;
        };
        let answer = rfd::MessageDialog::new()
            .set_title(ui.get_theme_delete_title().as_str())
            .set_description(ui.invoke_theme_delete_text(name).as_str())
            .set_buttons(rfd::MessageButtons::YesNo)
            .show();
        if matches!(answer, rfd::MessageDialogResult::Yes) {
            let _ = tx_for_theme_delete.send(WorkerCommand::ThemeDelete(theme_id));
        }
    });

    let tx_for_theme_publish = worker_tx.clone();
    ui.on_theme_publish_requested(move |key, published| {
        if let Some(theme_id) = server_theme_id(&key) {
            let _ = tx_for_theme_publish.send(WorkerCommand::ThemePublish(theme_id, published));
        }
    });

    let tx_for_theme_copy = worker_tx.clone();
    ui.on_theme_copy_requested(move |key| {
        if let Some(theme_id) = server_theme_id(&key) {
            let _ = tx_for_theme_copy.send(WorkerCommand::ThemeCopy(theme_id));
        }
    });

    let weak_for_editor_color = ui.as_weak();
    ui.on_editor_color_edited(move |index, value| {
        use slint::Model as _;
        let Some(ui) = weak_for_editor_color.upgrade() else {
            return;
        };
        let colors = ui.get_editor_colors();
        let Some(mut row) = usize::try_from(index)
            .ok()
            .and_then(|index| colors.row_data(index))
        else {
            return;
        };
        let parsed = cordiale_core::theme::parse_hex(value.trim());
        row.value = value;
        row.valid = parsed.is_some();
        if let Some(rgb) = parsed {
            row.color = slint_color(rgb);
        }
        if let Ok(index) = usize::try_from(index) {
            colors.set_row_data(index, row);
        }
        preview_editor_theme(&ui);
    });

    let weak_for_editor_font = ui.as_weak();
    ui.on_editor_font_changed(move || {
        if let Some(ui) = weak_for_editor_font.upgrade() {
            preview_editor_theme(&ui);
        }
    });

    let tx_for_editor_save = worker_tx.clone();
    let weak_for_editor_save = ui.as_weak();
    ui.on_editor_save(move || {
        let Some(ui) = weak_for_editor_save.upgrade() else {
            return;
        };
        let name = ui.get_editor_name().trim().to_string();
        let payload = editor_payload(&ui);
        match payload {
            Some(payload) if !name.is_empty() && name.chars().count() <= 60 => {
                let theme_id = i64::from(ui.get_editor_theme_id());
                let _ = tx_for_editor_save.send(WorkerCommand::ThemeSave {
                    theme_id: (theme_id >= 0).then_some(theme_id),
                    name,
                    payload,
                });
            }
            _ => ui.set_status_kind("theme-invalid".into()),
        }
    });

    let tx_for_editor_cancel = worker_tx.clone();
    ui.on_editor_cancel(move || {
        let _ = tx_for_editor_cancel.send(WorkerCommand::ThemeEditorCancel);
    });

    let tx_for_editor_background = worker_tx.clone();
    ui.on_editor_pick_background(move || {
        let picked = rfd::FileDialog::new()
            .add_filter("image", &["png", "jpg", "jpeg", "webp", "gif", "bmp"])
            .pick_file();
        if let Some(path) = picked {
            let _ = tx_for_editor_background.send(WorkerCommand::ThemeBackgroundUpload(path));
        }
    });

    let tx_for_night_theme = worker_tx.clone();
    ui.on_night_theme_requested(move |key| {
        let _ = tx_for_night_theme.send(WorkerCommand::SelectNightTheme(key.to_string()));
    });

    watch_system_scheme(worker_tx.clone());
}

/// Display and notification preferences, muting and denoise.
pub(crate) fn register_notification_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_prefs = worker_tx.clone();
    let weak_for_prefs = ui.as_weak();
    ui.on_display_prefs_changed(move || {
        if let Some(ui) = weak_for_prefs.upgrade() {
            let prefs = DisplayPrefs {
                colored_nicklist: Some(ui.get_pref_colored_nicklist()),
                show_bottom_bar: Some(ui.get_pref_show_bottom_bar()),
                strip_formatting: Some(ui.get_pref_strip_formatting()),
                show_event_badge: Some(ui.get_pref_show_event_badge()),
                bold_mentions: Some(ui.get_pref_bold_mentions()),
                date_format: ui.get_pref_date_format_set().then(|| {
                    let index = usize::try_from(ui.get_pref_date_format_index()).unwrap_or(0);
                    DateFormat::ALL[index.min(DateFormat::ALL.len() - 1)]
                }),
            };
            let _ = tx_for_prefs.send(WorkerCommand::SaveDisplayPrefs(prefs));
        }
    });

    let tx_for_notify_load = worker_tx.clone();
    ui.on_notification_prefs_requested(move || {
        let _ = tx_for_notify_load.send(WorkerCommand::LoadNotificationPrefs);
    });

    let tx_for_notify_list_add = worker_tx.clone();
    ui.on_notification_list_add(move |list, value| {
        let value = value.trim().to_string();
        if !value.is_empty() {
            let _ = tx_for_notify_list_add.send(WorkerCommand::EditNotificationPrefs(
                NotificationEdit::AddToList(list.to_string(), value),
            ));
        }
    });

    let tx_for_notify_list_remove = worker_tx.clone();
    ui.on_notification_list_remove(move |list, value| {
        let _ = tx_for_notify_list_remove.send(WorkerCommand::EditNotificationPrefs(
            NotificationEdit::RemoveFromList(list.to_string(), value.to_string()),
        ));
    });

    let tx_for_notify_unmute = worker_tx.clone();
    ui.on_notification_unmute(move |key| {
        let _ = tx_for_notify_unmute.send(WorkerCommand::EditNotificationPrefs(
            NotificationEdit::Unmute(key.to_string()),
        ));
    });

    let tx_for_notify_sound = worker_tx.clone();
    let weak_for_notify_sound = ui.as_weak();
    ui.on_notification_sound_changed(move || {
        if let Some(ui) = weak_for_notify_sound.upgrade() {
            let sound = usize::try_from(ui.get_notify_sound_index())
                .ok()
                .and_then(|index| NOTIFICATION_SOUNDS.get(index))
                .copied()
                .unwrap_or("none");
            let _ = tx_for_notify_sound.send(WorkerCommand::EditNotificationPrefs(
                NotificationEdit::Sound(sound.to_string()),
            ));
        }
    });

    let tx_for_mute_current = worker_tx.clone();
    ui.on_mute_current_requested(move |seconds| {
        let _ = tx_for_mute_current.send(WorkerCommand::MuteCurrentWindow(seconds));
    });

    let weak_for_mute_tick = ui.as_weak();
    ui.on_mute_countdown_tick(move || {
        if let Some(ui) = weak_for_mute_tick.upgrade() {
            update_mute_countdown(&ui, chrono::Utc::now().timestamp());
        }
    });

    let tx_for_denoise = worker_tx.clone();
    ui.on_denoise_requested(move || {
        let _ = tx_for_denoise.send(WorkerCommand::ToggleDenoise);
    });

    let tx_for_notify_save = worker_tx.clone();
    let weak_for_notify = ui.as_weak();
    ui.on_notification_prefs_changed(move || {
        if let Some(ui) = weak_for_notify.upgrade() {
            let _ = tx_for_notify_save.send(WorkerCommand::SaveNotificationPrefs(
                NotificationToggles {
                    channel_mentions: ui.get_notify_channel_mentions(),
                    channel_messages_all: ui.get_notify_channel_all(),
                    private_messages_all: ui.get_notify_private_all(),
                    presence_online: ui.get_notify_presence_online(),
                    presence_offline: ui.get_notify_presence_offline(),
                },
            ));
        }
    });
}

/// Admin: sessions, the links graph, users, uploads and visitors.
pub(crate) fn register_admin_user_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_admin_refresh = worker_tx.clone();
    ui.on_admin_refresh_requested(move || {
        let _ = tx_for_admin_refresh.send(WorkerCommand::AdminRefresh);
    });

    let tx_for_admin_disconnect = worker_tx.clone();
    ui.on_admin_disconnect_session(move |session_id| {
        let _ = tx_for_admin_disconnect.send(WorkerCommand::AdminDisconnectSession(
            session_id.to_string(),
        ));
    });

    let tx_for_admin_reconnect = worker_tx.clone();
    ui.on_admin_reconnect_session(move |session_id| {
        let _ = tx_for_admin_reconnect
            .send(WorkerCommand::AdminReconnectSession(session_id.to_string()));
    });

    let tx_for_admin_terminate = worker_tx.clone();
    ui.on_admin_terminate_session(move |session_id| {
        let _ = tx_for_admin_terminate
            .send(WorkerCommand::AdminTerminateSession(session_id.to_string()));
    });

    // Lazily created, reused across requests rather than spawning a new
    // OS window every click. Only ever touched from this callback, which
    // Slint guarantees runs on the UI thread — safe to be a plain `Rc`.
    let graph_window: Rc<RefCell<Option<LinksGraphWindow>>> = Rc::new(RefCell::new(None));
    let weak_for_graph = ui.as_weak();
    ui.on_links_graph_requested(move || {
        let Some(ui) = weak_for_graph.upgrade() else {
            return;
        };
        let mut slot = graph_window.borrow_mut();
        if slot.is_none() {
            let Ok(window) = LinksGraphWindow::new() else {
                return;
            };
            *slot = Some(window);
        }
        let window = slot.as_ref().expect("just ensured present above");
        window.set_network_label(ui.get_links_network_label());
        window.set_edges_commands(ui.get_links_graph_edges_commands());
        window.set_nodes(ui.get_links_graph_nodes());
        window.set_canvas_size(ui.get_links_graph_canvas_size());
        let _ = window.show();
    });

    let tx_for_user_toggle = worker_tx.clone();
    ui.on_admin_user_toggle_admin(move |user_id, is_admin| {
        let _ = tx_for_user_toggle.send(WorkerCommand::AdminUserToggleAdmin(
            user_id.to_string(),
            is_admin,
        ));
    });

    let tx_for_user_delete = worker_tx.clone();
    ui.on_admin_user_delete(move |user_id| {
        let _ = tx_for_user_delete.send(WorkerCommand::AdminUserDelete(user_id.to_string()));
    });

    let tx_for_uploads = worker_tx.clone();
    ui.on_admin_uploads_requested(move || {
        let _ = tx_for_uploads.send(WorkerCommand::AdminUploadsRefresh);
    });
    let tx_for_upload_delete = worker_tx.clone();
    ui.on_admin_upload_delete(move |upload_id| {
        let _ = tx_for_upload_delete.send(WorkerCommand::AdminUploadDelete(upload_id.to_string()));
    });

    let tx_for_visitor_delete = worker_tx.clone();
    ui.on_admin_visitor_delete(move |visitor_id| {
        let _ =
            tx_for_visitor_delete.send(WorkerCommand::AdminVisitorDelete(visitor_id.to_string()));
    });

    let tx_for_admin_user_create = worker_tx.clone();
    let weak_for_admin_user_create = ui.as_weak();
    ui.on_admin_user_create(move || {
        if let Some(ui) = weak_for_admin_user_create.upgrade() {
            let _ = tx_for_admin_user_create.send(WorkerCommand::AdminUserCreate {
                name: ui.get_admin_new_user_name().trim().to_string(),
                password: ui.get_admin_new_user_password().to_string(),
                is_admin: ui.get_admin_new_user_is_admin(),
            });
        }
    });

    let tx_for_admin_password = worker_tx.clone();
    let weak_for_admin_password = ui.as_weak();
    ui.on_admin_user_set_password(move |user_id| {
        if let Some(ui) = weak_for_admin_password.upgrade() {
            let _ = tx_for_admin_password.send(WorkerCommand::AdminUserSetPassword {
                user_id: user_id.to_string(),
                password: ui.get_admin_new_user_password().to_string(),
            });
        }
    });
}

/// Admin: networks, servers and featured channels.
pub(crate) fn register_admin_network_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_admin_network_create = worker_tx.clone();
    ui.on_admin_network_create(move |slug| {
        let _ = tx_for_admin_network_create
            .send(WorkerCommand::AdminNetworkCreate(slug.trim().to_string()));
    });

    let tx_for_admin_servers = worker_tx.clone();
    ui.on_admin_servers_requested(move |network_id| {
        let _ = tx_for_admin_servers.send(WorkerCommand::AdminServersLoad(network_id.to_string()));
    });

    let tx_for_admin_server_add = worker_tx.clone();
    let weak_for_admin_server_add = ui.as_weak();
    ui.on_admin_server_add(move || {
        if let Some(ui) = weak_for_admin_server_add.upgrade() {
            let _ = tx_for_admin_server_add.send(WorkerCommand::AdminServerAdd {
                network_id: ui.get_admin_edit_network_id().to_string(),
                host: ui.get_admin_new_server_host().trim().to_string(),
                port: ui.get_admin_new_server_port().trim().to_string(),
                tls: ui.get_admin_new_server_tls(),
            });
        }
    });

    let tx_for_admin_server_delete = worker_tx.clone();
    let weak_for_admin_server_delete = ui.as_weak();
    ui.on_admin_server_delete(move |server_id| {
        if let Some(ui) = weak_for_admin_server_delete.upgrade() {
            let _ = tx_for_admin_server_delete.send(WorkerCommand::AdminServerDelete {
                network_id: ui.get_admin_edit_network_id().to_string(),
                server_id: server_id.to_string(),
            });
        }
    });

    let tx_for_admin_server_save = worker_tx.clone();
    let weak_for_admin_server_save = ui.as_weak();
    ui.on_admin_server_save(move || {
        if let Some(ui) = weak_for_admin_server_save.upgrade() {
            let _ = tx_for_admin_server_save.send(WorkerCommand::AdminServerEdit {
                network_id: ui.get_admin_edit_network_id().to_string(),
                server_id: ui.get_admin_edit_server_id().to_string(),
                host: ui.get_admin_edit_server_host().to_string(),
                port: ui.get_admin_edit_server_port().to_string(),
                tls: ui.get_admin_edit_server_tls(),
                enabled: ui.get_admin_edit_server_enabled(),
            });
        }
    });

    let tx_for_featured_add = worker_tx.clone();
    let weak_for_featured_add = ui.as_weak();
    ui.on_admin_featured_add(move || {
        if let Some(ui) = weak_for_featured_add.upgrade() {
            let _ = tx_for_featured_add.send(WorkerCommand::AdminFeaturedAdd {
                network_id: ui.get_admin_edit_network_id().to_string(),
                name: ui.get_admin_new_featured_name().to_string(),
                description: ui.get_admin_new_featured_description().to_string(),
            });
        }
    });

    let tx_for_featured_set = worker_tx.clone();
    let weak_for_featured_set = ui.as_weak();
    ui.on_admin_featured_set(move |featured_id, enabled| {
        if let Some(ui) = weak_for_featured_set.upgrade() {
            let _ = tx_for_featured_set.send(WorkerCommand::AdminFeaturedSet {
                network_id: ui.get_admin_edit_network_id().to_string(),
                featured_id: featured_id.to_string(),
                enabled,
            });
        }
    });

    let tx_for_featured_delete = worker_tx.clone();
    let weak_for_featured_delete = ui.as_weak();
    ui.on_admin_featured_delete(move |featured_id| {
        if let Some(ui) = weak_for_featured_delete.upgrade() {
            let _ = tx_for_featured_delete.send(WorkerCommand::AdminFeaturedDelete {
                network_id: ui.get_admin_edit_network_id().to_string(),
                featured_id: featured_id.to_string(),
            });
        }
    });

    let tx_for_network_count = worker_tx.clone();
    ui.on_admin_network_count_requested(move |network_id| {
        let _ = tx_for_network_count.send(WorkerCommand::AdminNetworkCount(network_id.to_string()));
    });
}

/// Admin: credentials, vhosts and grants.
pub(crate) fn register_admin_access_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_credential_save = worker_tx.clone();
    let weak_for_credential_save = ui.as_weak();
    ui.on_admin_credential_save(move || {
        if let Some(ui) = weak_for_credential_save.upgrade() {
            let _ = tx_for_credential_save.send(WorkerCommand::AdminCredentialEdit {
                user_id: ui.get_admin_edit_cred_user_id().to_string(),
                network_id: ui.get_admin_edit_cred_network_id().to_string(),
                nick: ui.get_admin_edit_cred_nick().to_string(),
                ident: ui.get_admin_edit_cred_ident().to_string(),
                realname: ui.get_admin_edit_cred_realname().to_string(),
                sasl_user: ui.get_admin_edit_cred_sasl_user().to_string(),
                password: ui.get_admin_edit_cred_password().to_string(),
            });
        }
    });

    let tx_for_admin_bind = worker_tx.clone();
    let weak_for_admin_bind = ui.as_weak();
    ui.on_admin_credential_bind(move || {
        use slint::Model as _;
        let Some(ui) = weak_for_admin_bind.upgrade() else {
            return;
        };
        let user = usize::try_from(ui.get_admin_cred_user_index())
            .ok()
            .and_then(|index| ui.get_admin_users().row_data(index));
        let network = usize::try_from(ui.get_admin_cred_network_index())
            .ok()
            .and_then(|index| ui.get_admin_networks().row_data(index));
        let auth_method = usize::try_from(ui.get_admin_cred_auth_index())
            .ok()
            .and_then(|index| cordiale_core::admin::CREDENTIAL_AUTH_METHODS.get(index))
            .copied()
            .unwrap_or("auto");
        if let (Some(user), Some(network)) = (user, network) {
            let _ = tx_for_admin_bind.send(WorkerCommand::AdminCredentialBind {
                user_id: user.user_id.to_string(),
                network_id: network.network_id.to_string(),
                nick: ui.get_admin_cred_nick().trim().to_string(),
                auth_method: auth_method.to_string(),
                password: ui.get_admin_cred_password().to_string(),
            });
        }
    });

    let tx_for_admin_unbind = worker_tx.clone();
    ui.on_admin_credential_unbind(move |user_id, network_id| {
        let _ = tx_for_admin_unbind.send(WorkerCommand::AdminCredentialUnbind {
            user_id: user_id.to_string(),
            network_id: network_id.to_string(),
        });
    });

    let tx_for_admin_vhost_add = worker_tx.clone();
    let weak_for_admin_vhost_add = ui.as_weak();
    ui.on_admin_vhost_add(move || {
        if let Some(ui) = weak_for_admin_vhost_add.upgrade() {
            let _ = tx_for_admin_vhost_add.send(WorkerCommand::AdminVhostAdd {
                address: ui.get_admin_new_vhost_address().trim().to_string(),
                in_pool: ui.get_admin_new_vhost_in_pool(),
            });
        }
    });

    let tx_for_admin_vhost_set = worker_tx.clone();
    ui.on_admin_vhost_set(move |vhost_id, field, value| {
        let _ = tx_for_admin_vhost_set.send(WorkerCommand::AdminVhostSet {
            vhost_id: vhost_id.to_string(),
            field: field.to_string(),
            value,
        });
    });

    let tx_for_admin_vhost_delete = worker_tx.clone();
    ui.on_admin_vhost_delete(move |vhost_id| {
        let _ =
            tx_for_admin_vhost_delete.send(WorkerCommand::AdminVhostDelete(vhost_id.to_string()));
    });

    let tx_for_admin_grant = worker_tx.clone();
    let weak_for_admin_grant = ui.as_weak();
    ui.on_admin_grant_add(move || {
        use slint::Model as _;
        let Some(ui) = weak_for_admin_grant.upgrade() else {
            return;
        };
        let vhost = usize::try_from(ui.get_admin_grant_vhost_index())
            .ok()
            .and_then(|index| ui.get_admin_vhosts().row_data(index));
        let user = usize::try_from(ui.get_admin_grant_user_index())
            .ok()
            .and_then(|index| ui.get_admin_users().row_data(index));
        if let (Some(vhost), Some(user)) = (vhost, user) {
            let _ = tx_for_admin_grant.send(WorkerCommand::AdminGrantAdd {
                vhost_id: vhost.vhost_id.to_string(),
                subject_type: "user".to_string(),
                subject_id: user.user_id.to_string(),
            });
        }
    });

    let tx_for_subject_grant = worker_tx.clone();
    let weak_for_subject_grant = ui.as_weak();
    ui.on_admin_subject_grant(move |subject_type, subject_id| {
        use slint::Model as _;
        let Some(ui) = weak_for_subject_grant.upgrade() else {
            return;
        };
        let vhost = usize::try_from(ui.get_admin_grant_vhost_index())
            .ok()
            .and_then(|index| ui.get_admin_vhosts().row_data(index));
        if let Some(vhost) = vhost {
            let _ = tx_for_subject_grant.send(WorkerCommand::AdminGrantAdd {
                vhost_id: vhost.vhost_id.to_string(),
                subject_type: subject_type.to_string(),
                subject_id: subject_id.to_string(),
            });
        }
    });

    let tx_for_subject_search = worker_tx.clone();
    ui.on_admin_subject_search(move |query| {
        let query = query.trim().to_string();
        if !query.is_empty() {
            let _ = tx_for_subject_search.send(WorkerCommand::AdminSubjectSearch(query));
        }
    });

    let tx_for_admin_revoke = worker_tx.clone();
    ui.on_admin_grant_revoke(move |grant_id| {
        let _ = tx_for_admin_revoke.send(WorkerCommand::AdminGrantRevoke(grant_id.to_string()));
    });
}

/// Admin: server settings, network delete and save, circuit reset and the reaper.
pub(crate) fn register_admin_settings_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_admin_settings = worker_tx.clone();
    ui.on_admin_settings_requested(move || {
        let _ = tx_for_admin_settings.send(WorkerCommand::AdminSettingsLoad);
    });

    let tx_for_admin_settings_save = worker_tx.clone();
    let weak_for_admin_settings_save = ui.as_weak();
    ui.on_admin_settings_save(move || {
        if let Some(ui) = weak_for_admin_settings_save.upgrade() {
            use slint::Model as _;
            let sizes = ui
                .get_admin_setting_sizes()
                .iter()
                .map(|size| size.to_string())
                .collect();
            let _ = tx_for_admin_settings_save.send(WorkerCommand::AdminSettingsSave(
                AdminSettingsForm {
                    host_index: ui.get_admin_setting_host_index(),
                    sizes,
                    video_seconds: ui.get_admin_setting_video_seconds().to_string(),
                    mode_index: ui.get_admin_setting_mode_index(),
                    prefix: ui.get_admin_setting_prefix().to_string(),
                },
            ));
        }
    });

    let tx_for_admin_network_delete = worker_tx.clone();
    ui.on_admin_network_delete(move |network_id| {
        let _ = tx_for_admin_network_delete
            .send(WorkerCommand::AdminNetworkDelete(network_id.to_string()));
    });

    let tx_for_admin_network_save = worker_tx.clone();
    let weak_for_admin_network_save = ui.as_weak();
    ui.on_admin_network_save(move || {
        if let Some(ui) = weak_for_admin_network_save.upgrade() {
            let _ = tx_for_admin_network_save.send(WorkerCommand::AdminNetworkSave {
                slug: ui.get_admin_edit_network().to_string(),
                visitor_enabled: ui.get_admin_edit_visitor_enabled(),
                visitor_cap: ui.get_admin_edit_visitor_cap().to_string(),
                user_cap: ui.get_admin_edit_user_cap().to_string(),
                ip_cap: ui.get_admin_edit_ip_cap().to_string(),
            });
        }
    });

    let tx_for_circuit_reset = worker_tx.clone();
    ui.on_admin_network_reset_circuit(move |network_id| {
        let _ = tx_for_circuit_reset.send(WorkerCommand::AdminNetworkResetCircuit(
            network_id.to_string(),
        ));
    });

    let tx_for_reaper = worker_tx.clone();
    ui.on_admin_reaper_run(move || {
        let _ = tx_for_reaper.send(WorkerCommand::AdminReaperRun);
    });
}

/// The settings screens: identity, profile, avatar, ignore list, aliases, notify and watch lists.
pub(crate) fn register_settings_callbacks(
    ui: &AppWindow,
    worker_tx: &mpsc::UnboundedSender<WorkerCommand>,
) {
    let tx_for_network_selected = worker_tx.clone();
    ui.on_settings_network_selected(move |network| {
        let _ = tx_for_network_selected
            .send(WorkerCommand::SettingsNetworkSelected(network.to_string()));
    });

    let tx_for_identity = worker_tx.clone();
    let weak_for_identity = ui.as_weak();
    ui.on_identity_save_requested(move || {
        if let Some(ui) = weak_for_identity.upgrade() {
            let _ = tx_for_identity.send(WorkerCommand::IdentitySave {
                nick: ui.get_identity_nick().to_string(),
                ident: ui.get_identity_ident().to_string(),
                realname: ui.get_identity_realname().to_string(),
            });
        }
    });

    let tx_for_profile = worker_tx.clone();
    let weak_for_profile = ui.as_weak();
    ui.on_profile_save_requested(move || {
        if let Some(ui) = weak_for_profile.upgrade() {
            let index = usize::try_from(ui.get_profile_gender_index()).unwrap_or(0);
            let _ = tx_for_profile.send(WorkerCommand::ProfileSave(ProfileFields {
                age: ui.get_profile_age().trim().to_string(),
                gender: gender_for_index(index).to_string(),
                location: ui.get_profile_location().trim().to_string(),
                languages: ui.get_profile_languages().trim().to_string(),
                custom: ui.get_profile_custom().trim().to_string(),
            }));
        }
    });

    // The native file picker is modal and runs on the UI thread, like the
    // paperclip's; the upload happens in the worker.
    let tx_for_avatar_pick = worker_tx.clone();
    ui.on_avatar_pick_requested(move || {
        let picked = rfd::FileDialog::new()
            .add_filter("image", &["png", "jpg", "jpeg", "gif", "webp", "apng"])
            .pick_file();
        if let Some(path) = picked {
            let _ = tx_for_avatar_pick.send(WorkerCommand::AvatarUpload(path));
        }
    });

    let tx_for_avatar_remove = worker_tx.clone();
    ui.on_avatar_remove_requested(move || {
        let _ = tx_for_avatar_remove.send(WorkerCommand::AvatarRemove);
    });

    let tx_for_personal = worker_tx.clone();
    let weak_for_personal = ui.as_weak();
    ui.on_personal_prefs_save_requested(move || {
        if let Some(ui) = weak_for_personal.upgrade() {
            let _ = tx_for_personal.send(WorkerCommand::PersonalPrefsSave {
                leave_message: ui.get_edit_leave_message().to_string(),
                away_message: ui.get_edit_away_message().to_string(),
                away_delay: ui.get_edit_away_delay().to_string(),
                show_peer_profiles: ui.get_pref_show_peer_profiles(),
                away_nick_suffix: ui
                    .get_away_nick_suffix_supported()
                    .then(|| ui.get_edit_away_nick_suffix().to_string()),
            });
        }
    });

    let tx_for_dcc_auto = worker_tx.clone();
    ui.on_dcc_auto_accept_toggled(move |enabled| {
        let _ = tx_for_dcc_auto.send(WorkerCommand::DccAutoAcceptToggle(enabled));
    });

    let tx_for_ignore_add = worker_tx.clone();
    ui.on_ignore_add_requested(move |mask, pattern| {
        let _ = tx_for_ignore_add.send(WorkerCommand::IgnoreAdd {
            mask: mask.trim().to_string(),
            text_pattern: ignore_pattern_from_ui(&pattern),
        });
    });

    let tx_for_ignore_remove = worker_tx.clone();
    ui.on_ignore_remove_requested(move |mask, pattern| {
        let _ = tx_for_ignore_remove.send(WorkerCommand::IgnoreRemove {
            mask: mask.to_string(),
            text_pattern: (!pattern.is_empty()).then(|| pattern.to_string()),
        });
    });

    let tx_for_perform_save = worker_tx.clone();
    ui.on_perform_save_requested(move |text| {
        let _ = tx_for_perform_save.send(WorkerCommand::PerformSave(text.to_string()));
    });

    let tx_for_alias_add = worker_tx.clone();
    ui.on_alias_add_requested(move |command, expansion| {
        let _ = tx_for_alias_add.send(WorkerCommand::AliasAdd {
            command: command.to_string(),
            expansion: expansion.to_string(),
        });
    });

    let tx_for_alias_remove = worker_tx.clone();
    ui.on_alias_remove_requested(move |command| {
        let _ = tx_for_alias_remove.send(WorkerCommand::AliasRemove(command.to_string()));
    });

    let tx_for_vhost_toggle = worker_tx.clone();
    ui.on_vhost_toggle_requested(move |address| {
        let _ = tx_for_vhost_toggle.send(WorkerCommand::VhostToggle(address.to_string()));
    });

    let tx_for_notify_add = worker_tx.clone();
    ui.on_notify_add_requested(move |nick| {
        let _ = tx_for_notify_add.send(WorkerCommand::NotifyAdd(nick.to_string()));
    });

    let tx_for_notify_remove = worker_tx.clone();
    ui.on_notify_remove_requested(move |nick| {
        let _ = tx_for_notify_remove.send(WorkerCommand::NotifyRemove(nick.to_string()));
    });

    let tx_for_watch_add = worker_tx.clone();
    ui.on_watch_pattern_add_requested(move |pattern| {
        let _ = tx_for_watch_add.send(WorkerCommand::WatchPatternAdd(pattern.to_string()));
    });

    let tx_for_watch_remove = worker_tx.clone();
    ui.on_watch_pattern_remove_requested(move |pattern| {
        let _ = tx_for_watch_remove.send(WorkerCommand::WatchPatternRemove(pattern.to_string()));
    });
}
