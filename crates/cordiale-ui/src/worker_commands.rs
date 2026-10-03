use super::*;

/// Body of the `WorkerCommand::SecurityTotpDone` arm of `run_worker`.
pub(crate) fn run_security_totp_done(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    state.conn.totp_enrollment = None;
    let _ = ui.upgrade_in_event_loop(|ui| {
        ui.set_security_totp_step("".into());
        ui.set_security_totp_secret("".into());
        ui.set_security_totp_uri("".into());
        ui.set_security_totp_code("".into());
        ui.set_security_totp_qr(slint::Image::default());
        ui.set_security_recovery_codes(slint::ModelRc::default());
        ui.set_security_totp_error("".into());
    });
}

/// Body of the `WorkerCommand::SelectNetwork` arm of `run_worker`.
pub(crate) async fn run_select_network(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
) {
    if state.networks.network_ids.contains_key(&network) {
        write_back_read_cursor(state);
        handle_select_channel(state, ui, network, SERVER_WINDOW_NAME.to_string()).await;
    }
}

/// Body of the `WorkerCommand::DirectoryOpen` arm of `run_worker`.
pub(crate) async fn run_directory_open(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network: String,
) {
    if state.networks.network_ids.contains_key(&network) {
        let reopen = state
            .panels
            .directory
            .as_ref()
            .is_some_and(|view| view.network == network);
        if reopen {
            push_directory(state, ui, true);
        } else {
            open_directory(state, ui, network, String::new()).await;
        }
    }
}

/// Body of the `WorkerCommand::UploadPrefsChanged` arm of `run_worker`.
pub(crate) async fn run_upload_prefs_changed(
    state: &mut WorkerState,
    ttl: Option<i64>,
    confirm: bool,
) {
    if let (Some(client), Some(token)) = (&state.conn.client, &state.conn.token) {
        if let Err(err) = client.set_upload_ttl(token, ttl).await {
            persistence::log_line(&format!("upload ttl save failed: {err:?}"));
        }
        if let Err(err) = client.set_upload_confirm(token, confirm).await {
            persistence::log_line(&format!("upload confirm save failed: {err:?}"));
        }
    }
}

/// Body of the `WorkerCommand::ThemeCopy` arm of `run_worker`.
pub(crate) async fn run_theme_copy(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    theme_id: i64,
) {
    if let (Some(client), Some(token)) = (state.conn.client.clone(), state.conn.token.clone()) {
        match client.copy_theme(&token, theme_id).await {
            Ok(copy) => {
                load_color_themes(state, ui).await;
                let key = format!("server:{}", copy.id);
                open_theme_editor(state, ui, &key).await;
            }
            Err(err) => report_theme_action(ui, Some(err)),
        }
    }
}

/// Body of the `WorkerCommand::AdminRefresh` arm of `run_worker`.
pub(crate) async fn run_admin_refresh(state: &mut WorkerState, ui: &slint::Weak<AppWindow>) {
    // The live feed needs a full web session, like the
    // rest of /admin; a refused join just leaves it empty.
    let topic = cordiale_core::admin::ADMIN_EVENTS_TOPIC.to_string();
    if let Some(session) = &state.conn.session {
        if state.conn.joined_topics.insert(topic.clone()) {
            session.join_topic(topic, false);
        }
    }
    handle_admin_refresh(state, ui).await;
    handle_admin_uploads_refresh(state, ui, None).await;
}

/// Body of the `WorkerCommand::AdminCredentialBind` arm of `run_worker`.
pub(crate) async fn run_admin_credential_bind(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    user_id: String,
    network_id: String,
    nick: String,
    auth_method: String,
    password: String,
) {
    match network_id.parse::<i64>() {
        Ok(network_id) if !nick.is_empty() => {
            let mut body = serde_json::json!({
                "user_id": user_id,
                "network_id": network_id,
                "nick": nick,
                "auth_method": auth_method,
            });
            if !password.is_empty() {
                body["password"] = Value::from(password);
            }
            handle_admin_write(state, ui, AdminWrite::BindCredential(body)).await;
        }
        _ => {
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_status_kind("admin-credential-invalid".into());
            });
        }
    }
}

/// Body of the `WorkerCommand::AdminCredentialUnbind` arm of `run_worker`.
pub(crate) async fn run_admin_credential_unbind(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    user_id: String,
    network_id: String,
) {
    handle_admin_write(
        state,
        ui,
        AdminWrite::UnbindCredential {
            user_id,
            network_id,
        },
    )
    .await;
}

/// Body of the `WorkerCommand::AdminVhostSet` arm of `run_worker`.
pub(crate) async fn run_admin_vhost_set(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    vhost_id: String,
    field: String,
    value: bool,
) {
    // Only the two flags the panel toggles are sent.
    if field == "in_pool" || field == "generally_available" {
        let mut changes = serde_json::Map::new();
        changes.insert(field, Value::Bool(value));
        handle_admin_write(
            state,
            ui,
            AdminWrite::UpdateVhost {
                vhost_id,
                changes: Value::Object(changes),
            },
        )
        .await;
    }
}

/// Body of the `WorkerCommand::AdminGrantAdd` arm of `run_worker`.
pub(crate) async fn run_admin_grant_add(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    vhost_id: String,
    subject_type: String,
    subject_id: String,
) {
    let write = AdminWrite::GrantVhost {
        vhost_id,
        subject_type,
        subject_id,
    };
    handle_admin_write(state, ui, write).await;
}

/// Body of the `WorkerCommand::AdminFeaturedAdd` arm of `run_worker`.
pub(crate) async fn run_admin_featured_add(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network_id: String,
    name: String,
    description: String,
) {
    if let Some(body) = cordiale_core::admin::admin_featured_body(&name, &description) {
        handle_admin_write(
            state,
            ui,
            AdminWrite::AddFeatured {
                network_id: network_id.clone(),
                body,
            },
        )
        .await;
        push_admin_featured(state, ui, &network_id).await;
    }
}

/// Body of the `WorkerCommand::AdminFeaturedSet` arm of `run_worker`.
pub(crate) async fn run_admin_featured_set(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network_id: String,
    featured_id: String,
    enabled: bool,
) {
    handle_admin_write(
        state,
        ui,
        AdminWrite::SetFeatured {
            network_id: network_id.clone(),
            featured_id,
            enabled,
        },
    )
    .await;
    push_admin_featured(state, ui, &network_id).await;
}

/// Body of the `WorkerCommand::AdminFeaturedDelete` arm of `run_worker`.
pub(crate) async fn run_admin_featured_delete(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network_id: String,
    featured_id: String,
) {
    handle_admin_write(
        state,
        ui,
        AdminWrite::DeleteFeatured {
            network_id: network_id.clone(),
            featured_id,
        },
    )
    .await;
    push_admin_featured(state, ui, &network_id).await;
}

/// Body of the `WorkerCommand::AdminServerAdd` arm of `run_worker`.
pub(crate) async fn run_admin_server_add(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network_id: String,
    host: String,
    port: String,
    tls: bool,
) {
    match port.parse::<u16>() {
        Ok(port) if !host.is_empty() => {
            handle_admin_write(
                state,
                ui,
                AdminWrite::AddServer {
                    network_id: network_id.clone(),
                    host,
                    port,
                    tls,
                },
            )
            .await;
            push_admin_servers(state, ui, &network_id).await;
        }
        _ => {
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_status_kind("admin-server-invalid".into());
            });
        }
    }
}

/// Body of the `WorkerCommand::AdminServerDelete` arm of `run_worker`.
pub(crate) async fn run_admin_server_delete(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    network_id: String,
    server_id: String,
) {
    handle_admin_write(
        state,
        ui,
        AdminWrite::DeleteServer {
            network_id: network_id.clone(),
            server_id,
        },
    )
    .await;
    push_admin_servers(state, ui, &network_id).await;
}

/// Body of the `WorkerCommand::AdminSettingsSave` arm of `run_worker`.
pub(crate) async fn run_admin_settings_save(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    form: AdminSettingsForm,
) {
    match admin_settings_body(&form, state.panels.admin_settings.as_ref()) {
        Some(settings) => {
            handle_admin_write(state, ui, AdminWrite::UpdateSettings(settings)).await;
            handle_admin_settings_load(state, ui).await;
        }
        None => {
            let _ = ui.upgrade_in_event_loop(|ui| {
                ui.set_status_kind("admin-setting-invalid".into());
            });
        }
    }
}

/// Body of the `WorkerCommand::AdminNetworkSave` arm of `run_worker`.
pub(crate) async fn run_admin_network_save(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    slug: String,
    visitor_enabled: bool,
    visitor_cap: String,
    user_cap: String,
    ip_cap: String,
) {
    let caps = [
        ("max_concurrent_visitor_sessions", visitor_cap),
        ("max_concurrent_user_sessions", user_cap),
        ("max_per_ip", ip_cap),
    ];
    let mut settings = serde_json::Map::new();
    settings.insert("visitor_enabled".to_string(), Value::Bool(visitor_enabled));
    let mut valid = true;
    for (key, text) in caps {
        match cordiale_core::admin::parse_admin_cap(&text) {
            Some(value) => {
                settings.insert(key.to_string(), value);
            }
            None => valid = false,
        }
    }
    if valid {
        handle_admin_write(
            state,
            ui,
            AdminWrite::UpdateNetwork {
                slug,
                settings: Value::Object(settings),
            },
        )
        .await;
    } else {
        let _ = ui.upgrade_in_event_loop(|ui| {
            ui.set_status_kind("admin-cap-invalid".into());
        });
    }
}

/// Body of the `WorkerCommand::PersonalPrefsSave` arm of `run_worker`.
pub(crate) async fn run_personal_prefs_save(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    leave_message: String,
    away_message: String,
    away_delay: String,
    show_peer_profiles: bool,
    away_nick_suffix: Option<String>,
) {
    handle_personal_prefs_save(
        state,
        ui,
        leave_message,
        away_message,
        away_delay,
        show_peer_profiles,
        away_nick_suffix,
    )
    .await;
}

/// Body of the `WorkerCommand::DccAutoAcceptToggle` arm of `run_worker`.
pub(crate) async fn run_dcc_auto_accept_toggle(state: &mut WorkerState, enabled: bool) {
    if let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) {
        if let Err(err) = client.set_dcc_auto_accept(token, network, enabled).await {
            persistence::log_line(&format!("dcc auto-accept save failed: {err:?}"));
        }
    }
}

/// Body of the `WorkerCommand::IgnoreAdd` arm of `run_worker`.
pub(crate) async fn run_ignore_add(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    mask: String,
    text_pattern: Option<String>,
) {
    if let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) {
        let result = client
            .add_ignore(token, network, &mask, text_pattern.as_deref())
            .await;
        push_ignore_mutation(ui, result);
    }
}

/// Body of the `WorkerCommand::IgnoreRemove` arm of `run_worker`.
pub(crate) async fn run_ignore_remove(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    mask: String,
    text_pattern: Option<String>,
) {
    if let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) {
        let result = client
            .remove_ignore(token, network, &mask, text_pattern.as_deref())
            .await;
        push_ignore_mutation(ui, result);
    }
}

/// Body of the `WorkerCommand::PerformSave` arm of `run_worker`.
pub(crate) async fn run_perform_save(state: &mut WorkerState, text: String) {
    if let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) {
        let request = cordiale_core::profile::PerformUpdateRequest {
            perform_list: Some(text),
            oper_pass: None,
        };
        let _ = client.update_perform(token, network, &request).await;
    }
}

/// Body of the `WorkerCommand::NotifyAdd` arm of `run_worker`.
pub(crate) async fn run_notify_add(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    nick: String,
) {
    if let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) {
        let network_id = state.networks.network_ids.get(network).copied();
        if client
            .add_notify_nicks(token, network, vec![nick.clone()])
            .await
            .is_ok()
        {
            if let Some(network_id) = network_id {
                let nicks = state.networks.notify_lists.entry(network_id).or_default();
                if !nicks.contains(&nick) {
                    nicks.push(nick);
                }
            }
        }
    }
    push_notify_nicks(state, ui);
}

/// Body of the `WorkerCommand::NotifyRemove` arm of `run_worker`.
pub(crate) async fn run_notify_remove(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    nick: String,
) {
    if let (Some(client), Some(token), Some(network)) = (
        &state.conn.client,
        &state.conn.token,
        &state.prefs.settings_network,
    ) {
        let network_id = state.networks.network_ids.get(network).copied();
        if client
            .remove_notify_nick(token, network, &nick)
            .await
            .is_ok()
        {
            if let Some(nicks) = network_id.and_then(|id| state.networks.notify_lists.get_mut(&id))
            {
                nicks.retain(|existing| existing != &nick);
            }
        }
    }
    push_notify_nicks(state, ui);
}

/// Body of the `WorkerCommand::WatchPatternAdd` arm of `run_worker`.
pub(crate) fn run_watch_pattern_add(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    pattern: String,
) {
    if let (Some(session), Some(identifier)) = (&state.conn.session, &state.conn.identifier) {
        session.send_command(
            format!("grappa:user:{identifier}"),
            "watchlist",
            serde_json::json!({"action": "add", "pattern": pattern}),
        );
    }
    if !state.prefs.watch_patterns.contains(&pattern) {
        state.prefs.watch_patterns.push(pattern);
    }
    push_watch_patterns(state, ui);
}

/// Body of the `WorkerCommand::WatchPatternRemove` arm of `run_worker`.
pub(crate) fn run_watch_pattern_remove(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    pattern: String,
) {
    if let (Some(session), Some(identifier)) = (&state.conn.session, &state.conn.identifier) {
        session.send_command(
            format!("grappa:user:{identifier}"),
            "watchlist",
            serde_json::json!({"action": "del", "pattern": pattern}),
        );
    }
    state
        .prefs
        .watch_patterns
        .retain(|existing| existing != &pattern);
    push_watch_patterns(state, ui);
}
