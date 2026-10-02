use super::*;

/// The status line for a refused admin write. 403 is a session without the
/// admin console (not an administrator, or a per-client token), and a
/// network delete answers 409 while accounts are still bound to it.
pub(crate) fn admin_failure_kind(status: Option<u16>, network_delete: bool) -> &'static str {
    match status {
        Some(403) => "admin-forbidden",
        Some(409) if network_delete => "admin-network-in-use",
        _ => "admin-action-failed",
    }
}

/// One `subject_search` row: `(type, id, network, nick)`, `network` empty
/// for an account.
pub(crate) fn admin_subject_row(row: &Value) -> Option<(String, String, String, String)> {
    let text = |field: &str| row.get(field).and_then(Value::as_str);
    let kind = text("type").filter(|kind| matches!(*kind, "user" | "visitor"))?;
    Some((
        kind.to_string(),
        text("id")?.to_string(),
        text("network").unwrap_or_default().to_string(),
        text("nick")?.to_string(),
    ))
}

/// Finds accounts and visitors for a vhost grant, like Cicchetto's
/// autocomplete.
pub(crate) async fn handle_admin_subject_search(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    query: &str,
) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };
    match client.search_admin_subjects(token, query).await {
        Ok(rows) => {
            let rows: Vec<(String, String, String, String)> =
                rows.iter().filter_map(admin_subject_row).collect();
            let _ = ui.upgrade_in_event_loop(move |ui| {
                let rows: Vec<AdminSubjectRow> = rows
                    .into_iter()
                    .map(|(kind, id, network, nick)| AdminSubjectRow {
                        kind: kind.into(),
                        subject_id: id.into(),
                        network: network.into(),
                        nick: nick.into(),
                    })
                    .collect();
                ui.set_admin_subject_searched(true);
                ui.set_admin_subject_results(Rc::new(slint::VecModel::from(rows)).into());
            });
        }
        Err(err) => {
            let status = err
                .status()
                .map(|status| status.as_u16().to_string())
                .unwrap_or_else(|| "network error".to_string());
            persistence::log_line(&format!("admin subject search failed: {status}"));
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_status_command_hint(status.into());
                ui.set_status_kind("admin-action-failed".into());
            });
        }
    }
}

/// Runs an admin write, then refreshes the panel. Success clears the
/// form it came from; a refusal shows the HTTP status (409 for a duplicate
/// or a network still in use, 422 for invalid values).
pub(crate) async fn handle_admin_write(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    write: AdminWrite,
) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };
    let (result, clears) = match &write {
        AdminWrite::CreateUser {
            name,
            password,
            is_admin,
        } => (
            client
                .create_admin_user(token, name, password, *is_admin)
                .await,
            "user",
        ),
        AdminWrite::SetPassword { user_id, password } => (
            client
                .set_admin_user_password(token, user_id, password)
                .await,
            "password",
        ),
        AdminWrite::CreateNetwork(slug) => {
            (client.create_admin_network(token, slug).await, "network")
        }
        AdminWrite::UpdateNetwork { slug, settings } => (
            client.update_admin_network(token, slug, settings).await,
            "edit",
        ),
        AdminWrite::DeleteNetwork(network_id) => {
            (client.delete_admin_network(token, network_id).await, "")
        }
        AdminWrite::AddServer {
            network_id,
            host,
            port,
            tls,
        } => (
            client
                .add_admin_server(token, network_id, host, *port, *tls)
                .await,
            "server",
        ),
        AdminWrite::DeleteServer {
            network_id,
            server_id,
        } => (
            client
                .delete_admin_server(token, network_id, server_id)
                .await,
            "",
        ),
        AdminWrite::UpdateSettings(settings) => {
            (client.update_admin_settings(token, settings).await, "")
        }
        AdminWrite::BindCredential(credential) => (
            client.create_admin_credential(token, credential).await,
            "credential",
        ),
        AdminWrite::UnbindCredential {
            user_id,
            network_id,
        } => (
            client
                .delete_admin_credential(token, user_id, network_id)
                .await,
            "",
        ),
        AdminWrite::AddVhost { address, in_pool } => (
            client.create_admin_vhost(token, address, *in_pool).await,
            "vhost",
        ),
        AdminWrite::UpdateVhost { vhost_id, changes } => (
            client.update_admin_vhost(token, vhost_id, changes).await,
            "",
        ),
        AdminWrite::DeleteVhost(vhost_id) => (client.delete_admin_vhost(token, vhost_id).await, ""),
        AdminWrite::GrantVhost {
            vhost_id,
            subject_type,
            subject_id,
        } => (
            client
                .grant_admin_vhost(token, vhost_id, subject_type, subject_id)
                .await,
            "",
        ),
        AdminWrite::RevokeGrant(grant_id) => {
            (client.revoke_admin_vhost_grant(token, grant_id).await, "")
        }
        AdminWrite::ReconnectSession(session_id) => {
            (client.reconnect_admin_session(token, session_id).await, "")
        }
        AdminWrite::TerminateSession(session_id) => {
            (client.terminate_admin_session(token, session_id).await, "")
        }
        AdminWrite::EditServer {
            network_id,
            server_id,
            changes,
        } => (
            client
                .update_admin_server(token, network_id, server_id, changes)
                .await,
            "edit-server",
        ),
        AdminWrite::AddFeatured { network_id, body } => (
            client
                .add_admin_featured_channel(token, network_id, body)
                .await,
            "featured",
        ),
        AdminWrite::SetFeatured {
            network_id,
            featured_id,
            enabled,
        } => (
            client
                .update_admin_featured_channel(
                    token,
                    network_id,
                    featured_id,
                    &serde_json::json!({ "enabled": enabled }),
                )
                .await,
            "",
        ),
        AdminWrite::DeleteFeatured {
            network_id,
            featured_id,
        } => (
            client
                .delete_admin_featured_channel(token, network_id, featured_id)
                .await,
            "",
        ),
        AdminWrite::EditCredential {
            user_id,
            network_id,
            changes,
        } => match client
            .update_admin_credential(token, user_id, network_id, changes)
            .await
        {
            Ok(true) => (Ok(()), "edit-credential-stopped"),
            Ok(false) => (Ok(()), "edit-credential"),
            Err(err) => (Err(err), ""),
        },
    };
    match result {
        Ok(()) => {
            let _ = ui.upgrade_in_event_loop(move |ui| {
                match clears {
                    "user" => {
                        ui.set_admin_new_user_name("".into());
                        ui.set_admin_new_user_password("".into());
                        ui.set_admin_new_user_is_admin(false);
                    }
                    "password" => ui.set_admin_new_user_password("".into()),
                    "network" => ui.set_admin_new_network_slug("".into()),
                    "edit" => ui.set_admin_edit_network("".into()),
                    "credential" => {
                        ui.set_admin_cred_nick("".into());
                        ui.set_admin_cred_password("".into());
                    }
                    "vhost" => ui.set_admin_new_vhost_address("".into()),
                    "server" => {
                        ui.set_admin_new_server_host("".into());
                        ui.set_admin_new_server_port("6697".into());
                    }
                    "edit-server" => ui.set_admin_edit_server_id("".into()),
                    "featured" => {
                        ui.set_admin_new_featured_name("".into());
                        ui.set_admin_new_featured_description("".into());
                    }
                    "edit-credential" | "edit-credential-stopped" => {
                        ui.set_admin_edit_cred_user_id("".into());
                        ui.set_admin_edit_cred_password("".into());
                    }
                    _ => {}
                }
                let done = if clears == "edit-credential-stopped" {
                    "admin-credential-stopped"
                } else {
                    "admin-action-done"
                };
                ui.set_status_kind(done.into());
            });
        }
        Err(err) => {
            let status = err
                .status()
                .map(|status| status.as_u16().to_string())
                .unwrap_or_else(|| "network error".to_string());
            persistence::log_line(&format!("admin write failed: {status}"));
            let kind = admin_failure_kind(
                err.status().map(|status| status.as_u16()),
                matches!(write, AdminWrite::DeleteNetwork(_)),
            );
            let _ = ui.upgrade_in_event_loop(move |ui| {
                ui.set_status_command_hint(status.into());
                ui.set_status_kind(kind.into());
            });
        }
    }
    handle_admin_refresh(state, ui).await;
}

/// The editor's view of `GET /admin/settings`.
pub(crate) fn admin_settings_form(settings: &Value) -> AdminSettingsForm {
    let text = |subtree: &str, key: &str| {
        settings
            .get(subtree)
            .and_then(|tree| tree.get(key))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let bytes = |subtree: &str, key: &str| {
        settings
            .get(subtree)
            .and_then(|tree| tree.get(key))
            .and_then(Value::as_u64)
    };
    let index_of = |options: &[&str], value: &str| {
        options
            .iter()
            .position(|option| *option == value)
            .and_then(|index| i32::try_from(index).ok())
            .unwrap_or(0)
    };
    AdminSettingsForm {
        host_index: index_of(&UPLOAD_HOSTS, &text("upload", "active_host")),
        sizes: ADMIN_SIZE_SETTINGS
            .iter()
            .map(|(subtree, key)| cordiale_core::admin::bytes_to_mib_text(bytes(subtree, key)))
            .collect(),
        video_seconds: bytes("upload", "video_max_duration_seconds")
            .map(|seconds| seconds.to_string())
            .unwrap_or_default(),
        mode_index: index_of(&ADDRESSING_MODES, &text("addressing", "mode")),
        prefix: text("addressing", "static_mapping_prefix"),
    }
}

/// The `PUT /admin/settings` body for an edited form: every filled-in
/// upload and DCC field, and the addressing subtree only when it changed
/// (Grappa probes a new mode before accepting it). `None` when a field
/// isn't a positive number.
pub(crate) fn admin_settings_body(
    form: &AdminSettingsForm,
    loaded: Option<&Value>,
) -> Option<Value> {
    let mut upload = serde_json::Map::new();
    let mut dcc = serde_json::Map::new();
    let host = usize::try_from(form.host_index)
        .ok()
        .and_then(|index| UPLOAD_HOSTS.get(index))?;
    upload.insert("active_host".to_string(), Value::from(*host));
    for ((subtree, key), text) in ADMIN_SIZE_SETTINGS.iter().zip(&form.sizes) {
        if text.trim().is_empty() {
            continue;
        }
        let bytes = cordiale_core::admin::mib_text_to_bytes(text)?;
        let tree = if *subtree == "upload" {
            &mut upload
        } else {
            &mut dcc
        };
        tree.insert((*key).to_string(), Value::from(bytes));
    }
    if !form.video_seconds.trim().is_empty() {
        let seconds: u64 = form
            .video_seconds
            .trim()
            .parse()
            .ok()
            .filter(|seconds| *seconds > 0)?;
        upload.insert(
            "video_max_duration_seconds".to_string(),
            Value::from(seconds),
        );
    }
    let mut body = serde_json::Map::new();
    body.insert("upload".to_string(), Value::Object(upload));
    if !dcc.is_empty() {
        body.insert("dcc".to_string(), Value::Object(dcc));
    }
    let mode = usize::try_from(form.mode_index)
        .ok()
        .and_then(|index| ADDRESSING_MODES.get(index))?;
    let loaded_form = loaded.map(admin_settings_form);
    let addressing_changed = loaded_form.as_ref().is_none_or(|loaded| {
        loaded.mode_index != form.mode_index || loaded.prefix.trim() != form.prefix.trim()
    });
    if addressing_changed {
        let mut addressing = serde_json::Map::new();
        addressing.insert("mode".to_string(), Value::from(*mode));
        if !form.prefix.trim().is_empty() {
            addressing.insert(
                "static_mapping_prefix".to_string(),
                Value::from(form.prefix.trim()),
            );
        }
        body.insert("addressing".to_string(), Value::Object(addressing));
    }
    Some(Value::Object(body))
}

pub(crate) async fn handle_admin_settings_load(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    let settings = match client.fetch_admin_settings(&token).await {
        Ok(settings) => settings,
        Err(err) => {
            persistence::log_line(&format!("admin settings load failed: {err:?}"));
            return;
        }
    };
    let form = admin_settings_form(&settings);
    state.admin_settings = Some(settings);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let sizes: Vec<slint::SharedString> = form.sizes.into_iter().map(Into::into).collect();
        ui.set_admin_setting_host_index(form.host_index);
        ui.set_admin_setting_sizes(Rc::new(slint::VecModel::from(sizes)).into());
        ui.set_admin_setting_video_seconds(form.video_seconds.into());
        ui.set_admin_setting_mode_index(form.mode_index);
        ui.set_admin_setting_prefix(form.prefix.into());
        ui.set_admin_settings_loaded(true);
    });
}

/// Vhost rows `(label, id, in_pool, generally_available)` and grant rows
/// `(address → account, id)` from `GET /admin/vhosts`.
#[allow(clippy::type_complexity)]
pub(crate) fn admin_vhost_rows(
    view: &Value,
) -> (Vec<(String, String, bool, bool)>, Vec<(String, String)>) {
    let id_of = |entry: &Value| {
        entry
            .get("id")
            .and_then(Value::as_i64)
            .map(|id| id.to_string())
            .unwrap_or_default()
    };
    let list = |key: &str| {
        view.get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let vhosts = list("vhosts");
    let address_of = |vhost_id: Option<i64>| {
        vhosts
            .iter()
            .find(|vhost| vhost.get("id").and_then(Value::as_i64) == vhost_id)
            .and_then(|vhost| vhost.get("address").and_then(Value::as_str))
            .unwrap_or("?")
            .to_string()
    };
    let vhost_rows = vhosts
        .iter()
        .map(|entry| {
            let flag = |key: &str| entry.get(key).and_then(Value::as_bool) == Some(true);
            (
                cordiale_core::admin::admin_vhost_label(entry),
                id_of(entry),
                flag("in_pool"),
                flag("generally_available"),
            )
        })
        .collect();
    let grant_rows = list("grants")
        .iter()
        .map(|grant| {
            let subject = grant
                .get("subject_label")
                .and_then(Value::as_str)
                .or_else(|| grant.get("subject_id").and_then(Value::as_str))
                .unwrap_or("?");
            (
                format!(
                    "{} → {subject}",
                    address_of(grant.get("vhost_id").and_then(Value::as_i64))
                ),
                id_of(grant),
            )
        })
        .collect();
    (vhost_rows, grant_rows)
}

pub(crate) async fn push_admin_servers(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    network_id: &str,
) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };
    let servers = match client.fetch_admin_servers(token, network_id).await {
        Ok(servers) => servers,
        Err(err) => {
            persistence::log_line(&format!("admin servers load failed: {err:?}"));
            Vec::new()
        }
    };
    let rows: Vec<AdminServerRow> = servers
        .iter()
        .map(|entry| {
            let id = entry
                .get("id")
                .and_then(Value::as_i64)
                .map(|id| id.to_string())
                .unwrap_or_default();
            let (host, port, tls, enabled) = cordiale_core::admin::admin_server_fields(entry);
            AdminServerRow {
                label: cordiale_core::admin::admin_server_label(entry).into(),
                server_id: id.into(),
                host: host.into(),
                port: port.into(),
                tls,
                enabled,
            }
        })
        .collect();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_admin_servers(Rc::new(slint::VecModel::from(rows)).into());
    });
}

/// Loads the featured channels of the network being edited.
pub(crate) async fn push_admin_featured(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    network_id: &str,
) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };
    let channels = match client
        .fetch_admin_featured_channels(token, network_id)
        .await
    {
        Ok(channels) => channels,
        Err(err) => {
            persistence::log_line(&format!("admin featured channels load failed: {err:?}"));
            Vec::new()
        }
    };
    let rows: Vec<AdminFeaturedRow> = channels
        .iter()
        .filter_map(|entry| {
            let (featured_id, enabled) = cordiale_core::admin::admin_featured_state(entry)?;
            Some(AdminFeaturedRow {
                label: cordiale_core::admin::admin_featured_label(entry).into(),
                featured_id: featured_id.into(),
                enabled,
            })
        })
        .collect();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_admin_featured(Rc::new(slint::VecModel::from(rows)).into());
    });
}

/// Asks how many messages deleting a network would take with it, for the
/// confirmation. A 404 or any failure is "can't say", never zero, and the
/// answer is dropped if the confirmation moved on to another network.
pub(crate) async fn handle_admin_network_count(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    network_id: String,
) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };
    let count = match client
        .fetch_admin_network_message_count(token, &network_id)
        .await
    {
        Ok(count) => count,
        Err(err) => {
            persistence::log_line(&format!("admin network message count failed: {err:?}"));
            None
        }
    };
    let _ = ui.upgrade_in_event_loop(move |ui| {
        if ui.get_admin_network_confirm_id() != network_id.as_str() {
            return;
        }
        match count {
            Some(count) => {
                ui.set_admin_network_count(count.to_string().into());
                ui.set_admin_network_count_state("known".into());
            }
            None => ui.set_admin_network_count_state("unknown".into()),
        }
    });
}

pub(crate) fn admin_overview_text(overview: &cordiale_core::admin::AdminOverview) -> String {
    format!(
        "{} session(s) · {}/{} visitors live · {} · v{}",
        overview.sessions,
        overview.visitors.live,
        overview.visitors.total,
        overview.hostname,
        overview.version
    )
}

pub(crate) async fn handle_admin_refresh(state: &WorkerState, ui: &slint::Weak<AppWindow>) {
    let (Some(client), Some(token)) = (&state.client, &state.token) else {
        return;
    };

    let ui_for_loading = ui.clone();
    let _ = ui_for_loading.upgrade_in_event_loop(|ui| ui.set_admin_loading(true));

    let overview = client.fetch_admin_overview(token).await.ok();
    let sessions = client.fetch_admin_sessions(token).await.unwrap_or_default();
    let users = client.fetch_admin_users(token).await.unwrap_or_default();
    let networks = client.fetch_admin_networks(token).await.unwrap_or_default();
    let visitors = client.fetch_admin_visitors(token).await.unwrap_or_default();
    let credentials = client
        .fetch_admin_credentials(token)
        .await
        .unwrap_or_default();
    let vhost_view = client.fetch_admin_vhosts(token).await.unwrap_or_default();
    let (vhost_rows, grant_rows) = admin_vhost_rows(&vhost_view);
    let credential_rows: Vec<AdminCredentialRow> = credentials
        .iter()
        .map(|entry| {
            let id = |key: &str| {
                entry
                    .get(key)
                    .map(|value| match value {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_default()
            };
            let (nick, ident, realname, sasl_user) =
                cordiale_core::admin::admin_credential_fields(entry);
            AdminCredentialRow {
                label: cordiale_core::admin::admin_credential_label(entry).into(),
                user_id: id("user_id").into(),
                network_id: id("network_id").into(),
                nick: nick.into(),
                ident: ident.into(),
                realname: realname.into(),
                sasl_user: sasl_user.into(),
            }
        })
        .collect();
    let session_log = client
        .fetch_admin_session_log(token, 50)
        .await
        .unwrap_or_default();

    let overview_text = overview.as_ref().map(admin_overview_text);

    let session_rows: Vec<AdminSessionRow> = sessions
        .iter()
        .map(|entry| AdminSessionRow {
            label: cordiale_core::admin::admin_session_label(entry).into(),
            alive: cordiale_core::admin::admin_session_is_alive(entry),
            session_id: cordiale_core::admin::admin_session_id(entry)
                .unwrap_or_default()
                .into(),
            is_user: cordiale_core::admin::admin_session_is_user(entry),
        })
        .collect();

    let user_rows: Vec<AdminUserRow> = users
        .iter()
        .map(|entry| AdminUserRow {
            label: cordiale_core::admin::admin_user_label(entry).into(),
            is_admin: cordiale_core::admin::admin_user_is_admin(entry),
            user_id: cordiale_core::admin::admin_user_id(entry)
                .unwrap_or_default()
                .into(),
        })
        .collect();

    let network_rows: Vec<AdminNetworkRow> = networks
        .iter()
        .map(|entry| {
            let label = format!(
                "{}{}",
                cordiale_core::admin::admin_network_label(entry),
                cordiale_core::admin::admin_network_status(entry)
            );
            let network_id = cordiale_core::admin::admin_network_id(entry).unwrap_or_default();
            let (visitor_enabled, visitor_cap, user_cap, ip_cap) =
                cordiale_core::admin::admin_network_settings(entry);
            AdminNetworkRow {
                label: label.into(),
                network_id: network_id.into(),
                slug: cordiale_core::admin::admin_network_label(entry).into(),
                visitor_enabled,
                visitor_cap: visitor_cap.into(),
                user_cap: user_cap.into(),
                ip_cap: ip_cap.into(),
            }
        })
        .collect();

    let visitor_rows: Vec<AdminVisitorRow> = visitors
        .iter()
        .map(|entry| AdminVisitorRow {
            label: cordiale_core::admin::admin_visitor_label(entry).into(),
            visitor_id: cordiale_core::admin::admin_visitor_id(entry)
                .unwrap_or_default()
                .into(),
        })
        .collect();

    let visitor_session_rows: Vec<AdminVisitorSessionRow> = visitors
        .iter()
        .flat_map(cordiale_core::admin::admin_visitor_sessions)
        .map(|session| AdminVisitorSessionRow {
            label: session.label.into(),
            session_id: session.session_id.into(),
            alive: session.alive,
        })
        .collect();

    let session_log_lines: Vec<slint::SharedString> = session_log
        .iter()
        .map(|entry| cordiale_core::admin::admin_session_log_line(entry).into())
        .collect();

    let ui = ui.clone();
    let _ = ui.upgrade_in_event_loop(move |ui| {
        ui.set_admin_loading(false);
        ui.set_admin_overview_text(overview_text.unwrap_or_default().into());
        ui.set_admin_sessions(Rc::new(slint::VecModel::from(session_rows)).into());
        let user_names: Vec<slint::SharedString> =
            user_rows.iter().map(|row| row.label.clone()).collect();
        let network_names: Vec<slint::SharedString> =
            network_rows.iter().map(|row| row.slug.clone()).collect();
        ui.set_admin_user_names(Rc::new(slint::VecModel::from(user_names)).into());
        ui.set_admin_network_names(Rc::new(slint::VecModel::from(network_names)).into());
        ui.set_admin_users(Rc::new(slint::VecModel::from(user_rows)).into());
        ui.set_admin_networks(Rc::new(slint::VecModel::from(network_rows)).into());
        ui.set_admin_credentials(Rc::new(slint::VecModel::from(credential_rows)).into());
        let vhost_names: Vec<slint::SharedString> = vhost_rows
            .iter()
            .map(|(label, _, _, _)| label.clone().into())
            .collect();
        ui.set_admin_vhost_names(Rc::new(slint::VecModel::from(vhost_names)).into());
        let vhost_rows: Vec<AdminVhostRow> = vhost_rows
            .into_iter()
            .map(
                |(label, vhost_id, in_pool, generally_available)| AdminVhostRow {
                    label: label.into(),
                    vhost_id: vhost_id.into(),
                    in_pool,
                    generally_available,
                },
            )
            .collect();
        ui.set_admin_vhosts(Rc::new(slint::VecModel::from(vhost_rows)).into());
        let grant_rows: Vec<AdminGrantRow> = grant_rows
            .into_iter()
            .map(|(label, grant_id)| AdminGrantRow {
                label: label.into(),
                grant_id: grant_id.into(),
            })
            .collect();
        ui.set_admin_grants(Rc::new(slint::VecModel::from(grant_rows)).into());
        ui.set_admin_visitors(Rc::new(slint::VecModel::from(visitor_rows)).into());
        ui.set_admin_visitor_sessions(Rc::new(slint::VecModel::from(visitor_session_rows)).into());
        ui.set_admin_session_log(Rc::new(slint::VecModel::from(session_log_lines)).into());
    });
}

/// Loads Admin > Uploads. `error` is shown instead of the load's own
/// outcome when a delete just failed, so the refreshed list still says so.
pub(crate) async fn handle_admin_uploads_refresh(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    error: Option<&'static str>,
) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    let (view, load_error) = match client.fetch_admin_uploads(&token).await {
        Ok(view) => (Some(view), ""),
        Err(err) => {
            persistence::log_line(&format!("admin uploads load failed: {err:?}"));
            let key =
                admin_uploads::error_key(err.status().map(|status| status.as_u16()), "failed");
            (None, key)
        }
    };
    state.admin_uploads = view.clone();
    let error = error.unwrap_or(load_error);
    let rows = view
        .as_ref()
        .map(|view| admin_uploads::upload_rows(view, format_file_size, format_iso_timestamp))
        .unwrap_or_default();
    let budget = view.as_ref().map(admin_uploads::budget);
    let _ = ui.upgrade_in_event_loop(move |ui| {
        let rows: Vec<AdminUploadRow> = rows
            .into_iter()
            .map(|row| AdminUploadRow {
                id: row.id.into(),
                name: row.name.into(),
                slug: row.slug.into(),
                mime: row.mime.into(),
                size: row.size.into(),
                subject: row.subject.into(),
                expires: row.expires.into(),
                deleted: row.deleted.into(),
                live: row.live,
            })
            .collect();
        ui.set_admin_uploads(Rc::new(slint::VecModel::from(rows)).into());
        ui.set_admin_uploads_loaded(budget.is_some());
        if let Some((used, cap, share)) = budget {
            ui.set_admin_uploads_used(format_file_size(used).into());
            ui.set_admin_uploads_cap(format_file_size(cap).into());
            ui.set_admin_uploads_share(
                share.map_or(-1, |share| i32::try_from(share).unwrap_or(i32::MAX)),
            );
        }
        ui.set_admin_uploads_error(error.into());
        ui.set_admin_upload_confirm_id("".into());
        ui.set_admin_upload_confirm_name("".into());
    });
}

/// Deletes a live upload before its expiry, then re-reads the registry:
/// the row stays, now with its deletion time and no Delete button.
pub(crate) async fn handle_admin_upload_delete(
    state: &mut WorkerState,
    ui: &slint::Weak<AppWindow>,
    upload_id: String,
) {
    let (Some(client), Some(token)) = (state.client.clone(), state.token.clone()) else {
        return;
    };
    if !admin_uploads::can_delete(state.admin_uploads.as_ref(), &upload_id) {
        return;
    }
    let error = match client.delete_admin_upload(&token, &upload_id).await {
        Ok(()) => None,
        Err(err) => {
            persistence::log_line(&format!("admin upload delete failed: {err:?}"));
            Some(admin_uploads::error_key(
                err.status().map(|status| status.as_u16()),
                "delete-failed",
            ))
        }
    };
    handle_admin_uploads_refresh(state, ui, error).await;
}

pub(crate) async fn handle_admin_disconnect_session(
    state: &WorkerState,
    ui: &slint::Weak<AppWindow>,
    session_id: String,
) {
    if let (Some(client), Some(token)) = (&state.client, &state.token) {
        let _ = client.disconnect_admin_session(token, &session_id).await;
    }
    handle_admin_refresh(state, ui).await;
}
