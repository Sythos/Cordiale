use super::*;

#[test]
fn statusmsg_targets_peel_the_longest_prefix_run() {
    let prefixes = cordiale_core::isupport::prefix_symbol_order(None);
    assert_eq!(
        peel_statusmsg_target("+#rust", &prefixes),
        Some(StatusmsgTarget {
            channel: "#rust".to_string(),
            level: "+".to_string(),
        })
    );
    assert_eq!(
        peel_statusmsg_target("@#rust", &prefixes),
        Some(StatusmsgTarget {
            channel: "#rust".to_string(),
            level: "@".to_string(),
        })
    );
    assert_eq!(
        peel_statusmsg_target("@+#rust", &prefixes),
        Some(StatusmsgTarget {
            channel: "#rust".to_string(),
            level: "@+".to_string(),
        })
    );
    assert_eq!(peel_statusmsg_target("+rust", &prefixes), None);
    assert_eq!(peel_statusmsg_target("#rust", &prefixes), None);
    assert_eq!(peel_statusmsg_target("alice", &prefixes), None);
}

#[test]
fn foreground_needs_focus_and_no_minimize() {
    assert!(window_in_foreground(true, Some(false)));
    assert!(window_in_foreground(true, None));
    assert!(!window_in_foreground(true, Some(true)));
    assert!(!window_in_foreground(false, Some(false)));
    assert!(!window_in_foreground(false, None));
}

#[test]
fn guest_login_refusals_get_their_own_status() {
    assert_eq!(
        login_refusal_kind("anon_collision"),
        Some("guest-nick-taken")
    );
    assert_eq!(login_refusal_kind("nick_in_use"), Some("guest-nick-in-use"));
    assert_eq!(
        login_refusal_kind("malformed_nick"),
        Some("guest-nick-invalid")
    );
    assert_eq!(
        login_refusal_kind("captcha_required"),
        Some("guest-captcha-required")
    );
    assert_eq!(login_refusal_kind("internal"), None);
    assert_eq!(
        login_refusal_kind("too_many_sessions"),
        Some("guest-too-many-sessions")
    );
}

#[test]
fn blank_connect_form_is_guest_but_saved_profile_is_explicit() {
    assert!(ConnectCredential::FormValue(String::new()).is_guest_attempt());
    assert!(!ConnectCredential::FormValue("new-password".into()).is_guest_attempt());
    assert!(!ConnectCredential::SavedProfile.is_guest_attempt());
}

#[test]
fn guest_bearers_have_a_separate_server_scoped_credential_namespace() {
    let first = guest_bearer_service("https://one.example");
    let second = guest_bearer_service("https://two.example");
    assert_ne!(first, second);
    assert_ne!(first, "https://one.example");
    assert_ne!(first, login_password_service("https://one.example"));
}

#[test]
fn transient_guest_login_failures_preserve_the_previous_bearer() {
    let refused = |status: &str, code: &str| {
        BootstrapError::Login(LoginError::Refused {
            status: status.parse().expect("valid HTTP status"),
            code: Some(code.to_string()),
            retry_after: None,
        })
    };
    assert!(!stale_guest_bearer(&refused("503", "too_many_sessions")));
    assert!(!stale_guest_bearer(&refused("429", "too_many_attempts")));
    assert!(stale_guest_bearer(&refused("409", "anon_collision")));
    assert!(stale_guest_bearer(&BootstrapError::Login(
        LoginError::InvalidCredentials
    )));
}

#[test]
fn current_year_is_in_a_sane_range() {
    // Not pinned to an exact year (the test suite outlives any single
    // year): just guards against a unit mixup collapsing everything
    // to 1970 or overflowing wildly.
    let year = current_year();
    assert!((2020..2100).contains(&year));
}

#[test]
fn channel_topic_has_the_documented_shape() {
    assert_eq!(
        channel_topic("vjt", "libera", "#rust"),
        "grappa:user:vjt/network:libera/channel:#rust"
    );
}

#[test]
fn query_topic_uses_the_channel_segment_and_ascii_folded_nick() {
    assert_eq!(
        query_topic("vjt", "libera", "FrIeNd"),
        "grappa:user:vjt/network:libera/channel:friend"
    );
    assert_eq!(
        query_from_topic("vjt", "grappa:user:vjt/network:libera/channel:friend"),
        Some(("libera".to_string(), "friend".to_string()))
    );
    assert_eq!(
        query_from_topic("other", "grappa:user:vjt/network:libera/channel:friend"),
        None
    );
    assert_eq!(
        query_from_topic("vjt", "grappa:user:vjt/network:libera/channel:#rust"),
        Some(("libera".to_string(), "#rust".to_string()))
    );
    assert_eq!(
        query_from_topic("vjt", "grappa:user:vjt/network:libera/channel:"),
        None
    );
    assert_eq!(
        query_from_topic("vjt", "grappa:user:vjt/network:libera/channel:friend/extra"),
        None
    );
}

#[test]
fn boot_seeds_current_nicks_per_network_and_skips_missing_or_blank_values() {
    let nicks = network_nicks_from_entries(&[
        serde_json::json!({"slug": "libera", "nick": "OldNick"}),
        serde_json::json!({"slug": "azzurra", "nick": "  "}),
        serde_json::json!({"slug": "oftc"}),
        serde_json::json!({"nick": "orphan"}),
    ]);

    let expected: HashMap<String, String> = [("libera".to_string(), "OldNick".to_string())]
        .into_iter()
        .collect();
    assert_eq!(nicks, expected);
}

#[test]
fn own_nick_changed_maps_only_known_positive_network_ids() {
    let network_slugs: HashMap<i64, String> =
        [(7, "libera".to_string()), (9, "azzurra".to_string())]
            .into_iter()
            .collect();
    let valid = serde_json::json!({
        "kind": "own_nick_changed",
        "network_id": 7,
        "nick": "NewNick",
        "future_field": true
    });
    assert_eq!(
        parse_own_nick_changed(&valid, &network_slugs),
        Some(("libera".to_string(), "NewNick".to_string()))
    );

    for invalid in [
        serde_json::json!({"kind": "own_nick_changed", "network_id": 77, "nick": "NewNick"}),
        serde_json::json!({"kind": "own_nick_changed", "network_id": 0, "nick": "NewNick"}),
        serde_json::json!({"kind": "own_nick_changed", "network_id": 7, "nick": "  "}),
        serde_json::json!({"kind": "other_kind", "network_id": 7, "nick": "NewNick"}),
    ] {
        assert_eq!(parse_own_nick_changed(&invalid, &network_slugs), None);
    }
}

#[test]
fn away_confirmed_maps_present_and_away_for_known_networks() {
    let known_networks: HashMap<String, i64> =
        [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
            .into_iter()
            .collect();

    for (state, expected) in [("present", AwayStatus::Present), ("away", AwayStatus::Away)] {
        let payload = serde_json::json!({
            "kind": "away_confirmed",
            "network": "libera",
            "state": state,
            "future_field": true
        });
        assert_eq!(
            parse_away_confirmed(&payload, &known_networks),
            Some(("libera".to_string(), expected))
        );
    }
}

#[test]
fn away_confirmed_rejects_unknown_network_and_invalid_state() {
    let known_networks: HashMap<String, i64> = [("libera".to_string(), 7)].into_iter().collect();

    for invalid in [
        serde_json::json!({
            "kind": "away_confirmed",
            "network": "unknown",
            "state": "away"
        }),
        serde_json::json!({
            "kind": "away_confirmed",
            "network": "libera",
            "state": "unknown"
        }),
        serde_json::json!({
            "kind": "away_confirmed",
            "network": "libera",
            "state": "awayish"
        }),
        serde_json::json!({
            "kind": "other_kind",
            "network": "libera",
            "state": "away"
        }),
        serde_json::json!({
            "kind": "away_confirmed",
            "network": "   ",
            "state": "present"
        }),
    ] {
        assert_eq!(parse_away_confirmed(&invalid, &known_networks), None);
    }
}

#[test]
fn session_identity_changed_preserves_true_with_null_account() {
    let network_slugs: HashMap<i64, String> = [(7, "libera".to_string())].into_iter().collect();
    let payload = serde_json::json!({
        "kind": "session_identity_changed",
        "network_id": 7,
        "identified": true,
        "account": null,
        "future_field": {"is_ignored": true}
    });

    assert_eq!(
        parse_session_identity_changed(&payload, &network_slugs),
        Some((
            "libera".to_string(),
            SessionIdentity {
                identified: true,
                account: None,
            }
        ))
    );
}

#[test]
fn session_identity_changed_rejects_unknown_network_and_invalid_fields() {
    let network_slugs: HashMap<i64, String> = [(7, "libera".to_string())].into_iter().collect();

    for invalid in [
        serde_json::json!({
            "kind": "session_identity_changed",
            "network_id": 8,
            "identified": true,
            "account": "vjt"
        }),
        serde_json::json!({
            "kind": "session_identity_changed",
            "network_id": "7",
            "identified": true,
            "account": "vjt"
        }),
        serde_json::json!({
            "kind": "session_identity_changed",
            "network_id": 7,
            "identified": "true",
            "account": "vjt"
        }),
        serde_json::json!({
            "kind": "session_identity_changed",
            "network_id": 7,
            "identified": true
        }),
        serde_json::json!({
            "kind": "session_identity_changed",
            "network_id": 7,
            "identified": true,
            "account": 42
        }),
        serde_json::json!({
            "kind": "other_kind",
            "network_id": 7,
            "identified": true,
            "account": null
        }),
    ] {
        assert_eq!(
            parse_session_identity_changed(&invalid, &network_slugs),
            None
        );
    }
}

#[test]
fn session_identity_changed_is_user_carrier_scoped_and_per_network() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state.networks.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
        .into_iter()
        .collect();
    let message_key = ("libera".to_string(), "#rust".to_string());
    state.transcript.messages.insert(
        message_key.clone(),
        vec![render_message(
            &serde_json::json!({"kind": "privmsg", "sender": "Alice", "body": "hello"}),
            None,
        )],
    );
    let identified_without_account = serde_json::json!({
        "kind": "session_identity_changed",
        "network_id": 7,
        "identified": true,
        "account": null
    });

    handle_session_identity_changed(
        &mut state,
        "grappa:user:vjt/network:libera/channel:#rust",
        &identified_without_account,
    );
    assert!(state.networks.session_identities.is_empty());

    handle_session_identity_changed(
        &mut state,
        "grappa:user:vjt",
        &serde_json::json!({
            "kind": "session_identity_changed",
            "network_id": 99,
            "identified": true,
            "account": "unknown"
        }),
    );
    assert!(state.networks.session_identities.is_empty());

    handle_session_identity_changed(&mut state, "grappa:user:vjt", &identified_without_account);
    handle_session_identity_changed(
        &mut state,
        "grappa:user:vjt",
        &serde_json::json!({
            "kind": "session_identity_changed",
            "network_id": 9,
            "identified": false,
            "account": "descriptive-account"
        }),
    );

    assert_eq!(
        state.networks.session_identities.get("libera"),
        Some(&SessionIdentity {
            identified: true,
            account: None,
        })
    );
    assert_eq!(
        state.networks.session_identities.get("azzurra"),
        Some(&SessionIdentity {
            identified: false,
            account: Some("descriptive-account".to_string()),
        })
    );
    assert_eq!(
        state.transcript.messages.get(&message_key).map(Vec::len),
        Some(1)
    );
}

fn isupport_payload(network_id: i64, casemapping: &str, frame_budget_base: u64) -> Value {
    serde_json::json!({
        "kind": "isupport_changed",
        "network_id": network_id,
        "chanmodes_a": ["b"],
        "chanmodes_b": ["k"],
        "chanmodes_c": ["l"],
        "chanmodes_d": ["i", "m"],
        "list_modes_queryable": ["b"],
        "prefix": {"o": "@", "v": "+"},
        "prefix_order": ["o", "v"],
        "chantypes": ["#"],
        "casemapping": casemapping,
        "maxlist": {"b": 100},
        "nicklen": 30,
        "channellen": null,
        "topiclen": 390,
        "frame_budget_base": frame_budget_base,
        "future_field": ["ignored"]
    })
}

#[test]
fn isupport_changed_is_user_carrier_scoped_and_replaces_only_its_network() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state.networks.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
        .into_iter()
        .collect();

    handle_isupport_changed(
        &mut state,
        "grappa:user:vjt",
        &isupport_payload(7, "rfc1459", 4096),
    );
    handle_isupport_changed(
        &mut state,
        "grappa:user:vjt",
        &isupport_payload(9, "ascii", 2048),
    );
    let azzurra = state
        .networks
        .isupport_by_network
        .get("azzurra")
        .expect("second network snapshot")
        .clone();

    handle_isupport_changed(
        &mut state,
        "grappa:user:vjt",
        &isupport_payload(7, "rfc1459_strict", 8192),
    );

    assert_eq!(
        state
            .networks
            .isupport_by_network
            .get("libera")
            .map(|state| state.frame_budget_base),
        Some(8192)
    );
    assert_eq!(
        state.networks.isupport_by_network.get("azzurra"),
        Some(&azzurra)
    );
}

#[test]
fn isupport_changed_rejects_bad_carrier_network_and_payload_without_mutation() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state.networks.network_ids = [("libera".to_string(), 7)].into_iter().collect();

    handle_isupport_changed(
        &mut state,
        "grappa:user:vjt/network:libera/channel:#rust",
        &isupport_payload(7, "rfc1459", 4096),
    );
    handle_isupport_changed(
        &mut state,
        "grappa:user:vjt",
        &isupport_payload(99, "rfc1459", 4096),
    );
    handle_isupport_changed(
        &mut state,
        "grappa:user:vjt",
        &isupport_payload(7, "unicode", 4096),
    );

    assert!(state.networks.isupport_by_network.is_empty());

    handle_isupport_changed(
        &mut state,
        "grappa:user:vjt",
        &isupport_payload(7, "rfc1459", 4096),
    );
    let accepted = state.networks.isupport_by_network.clone();
    let mut invalid = isupport_payload(7, "rfc1459", 4096);
    invalid["maxlist"] = serde_json::json!({"b": 0});
    handle_isupport_changed(&mut state, "grappa:user:vjt", &invalid);

    assert_eq!(state.networks.isupport_by_network, accepted);
}

#[test]
fn umode_changed_preserves_ordered_set_and_replays_as_replacement() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state.networks.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
        .into_iter()
        .collect();

    let libera = serde_json::json!({
        "kind": "umode_changed",
        "network_id": 7,
        "modes": ["i", "w", "s"],
        "future_field": true
    });
    handle_umode_changed(&mut state, "grappa:user:vjt", &libera);
    handle_umode_changed(&mut state, "grappa:user:vjt", &libera);
    handle_umode_changed(
        &mut state,
        "grappa:user:vjt",
        &serde_json::json!({
            "kind": "umode_changed",
            "network_id": 9,
            "modes": ["w", "i"]
        }),
    );

    assert_eq!(state.networks.user_modes_by_network.len(), 2);
    assert_eq!(
        state.networks.user_modes_by_network["libera"],
        ["i", "w", "s"]
    );
    assert_eq!(state.networks.user_modes_by_network["azzurra"], ["w", "i"]);

    handle_umode_changed(
        &mut state,
        "grappa:user:vjt",
        &serde_json::json!({
            "kind": "umode_changed",
            "network_id": 7,
            "modes": []
        }),
    );
    assert!(state.networks.user_modes_by_network["libera"].is_empty());
    assert_eq!(state.networks.user_modes_by_network["azzurra"], ["w", "i"]);
}

#[test]
fn umode_changed_rejects_bad_carrier_network_and_payload_without_mutation() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state.networks.network_ids = [("libera".to_string(), 7)].into_iter().collect();
    let accepted = serde_json::json!({
        "kind": "umode_changed",
        "network_id": 7,
        "modes": ["i", "w"]
    });

    handle_umode_changed(
        &mut state,
        "grappa:user:vjt/network:libera/channel:#rust",
        &accepted,
    );
    assert!(state.networks.user_modes_by_network.is_empty());

    handle_umode_changed(&mut state, "grappa:user:vjt", &accepted);
    let original = state.networks.user_modes_by_network.clone();
    for invalid in [
        serde_json::json!({"kind": "umode_changed", "network_id": 99, "modes": ["i"]}),
        serde_json::json!({"kind": "umode_changed", "network_id": 0, "modes": ["i"]}),
        serde_json::json!({"kind": "umode_changed", "network_id": "7", "modes": ["i"]}),
        serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": "iw"}),
        serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": ["i", 1]}),
        serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": ["i", "i"]}),
        serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": ["+i"]}),
        serde_json::json!({"kind": "umode_changed", "network_id": 7, "modes": [""]}),
        serde_json::json!({"kind": "other_kind", "network_id": 7, "modes": ["s"]}),
    ] {
        handle_umode_changed(&mut state, "grappa:user:vjt", &invalid);
        assert_eq!(state.networks.user_modes_by_network, original);
    }
}

#[test]
fn supported_umodes_changed_is_separate_ordered_per_network_and_replays_as_replacement() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state.networks.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
        .into_iter()
        .collect();

    handle_umode_changed(
        &mut state,
        "grappa:user:vjt",
        &serde_json::json!({
            "kind": "umode_changed",
            "network_id": 7,
            "modes": ["i"]
        }),
    );
    let libera = serde_json::json!({
        "kind": "supported_umodes_changed",
        "network_id": 7,
        "modes": ["i", "w", "s"],
        "future_field": true
    });
    handle_supported_umodes_changed(&mut state, "grappa:user:vjt", &libera);
    handle_supported_umodes_changed(&mut state, "grappa:user:vjt", &libera);
    handle_supported_umodes_changed(
        &mut state,
        "grappa:user:vjt",
        &serde_json::json!({
            "kind": "supported_umodes_changed",
            "network_id": 9,
            "modes": ["w", "i"]
        }),
    );

    assert_eq!(state.networks.supported_user_modes_by_network.len(), 2);
    assert_eq!(
        state.networks.supported_user_modes_by_network["libera"],
        ["i", "w", "s"]
    );
    assert_eq!(
        state.networks.supported_user_modes_by_network["azzurra"],
        ["w", "i"]
    );
    assert_eq!(state.networks.user_modes_by_network["libera"], ["i"]);

    handle_supported_umodes_changed(
        &mut state,
        "grappa:user:vjt",
        &serde_json::json!({
            "kind": "supported_umodes_changed",
            "network_id": 7,
            "modes": []
        }),
    );
    assert!(state.networks.supported_user_modes_by_network["libera"].is_empty());
    assert_eq!(
        state.networks.supported_user_modes_by_network["azzurra"],
        ["w", "i"]
    );
    assert_eq!(state.networks.user_modes_by_network["libera"], ["i"]);
}

#[test]
fn supported_umodes_changed_rejects_bad_carrier_network_and_payload_without_mutation() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state.networks.network_ids = [("libera".to_string(), 7)].into_iter().collect();
    let accepted = serde_json::json!({
        "kind": "supported_umodes_changed",
        "network_id": 7,
        "modes": ["i", "w"]
    });

    handle_supported_umodes_changed(
        &mut state,
        "grappa:user:vjt/network:libera/channel:#rust",
        &accepted,
    );
    assert!(state.networks.supported_user_modes_by_network.is_empty());

    handle_supported_umodes_changed(&mut state, "grappa:user:vjt", &accepted);
    let original = state.networks.supported_user_modes_by_network.clone();
    for invalid in [
        serde_json::json!({"kind": "supported_umodes_changed", "network_id": 99, "modes": ["i"]}),
        serde_json::json!({"kind": "supported_umodes_changed", "network_id": 0, "modes": ["i"]}),
        serde_json::json!({"kind": "supported_umodes_changed", "network_id": "7", "modes": ["i"]}),
        serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": "iw"}),
        serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": ["i", 1]}),
        serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": ["i", "i"]}),
        serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": ["+i"]}),
        serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": ["-i"]}),
        serde_json::json!({"kind": "supported_umodes_changed", "network_id": 7, "modes": [""]}),
        serde_json::json!({"kind": "other_kind", "network_id": 7, "modes": ["s"]}),
    ] {
        handle_supported_umodes_changed(&mut state, "grappa:user:vjt", &invalid);
        assert_eq!(state.networks.supported_user_modes_by_network, original);
    }
}

#[test]
fn late_away_confirmation_updates_one_network_without_resetting_other_state() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state.networks.network_ids = [("libera".to_string(), 7), ("azzurra".to_string(), 9)]
        .into_iter()
        .collect();
    state
        .networks
        .away_states
        .insert("azzurra".to_string(), AwayStatus::Present);

    // `mentions_bundle` remains an independent gap. This models existing
    // message state and ensures an away ACK can't clear broader UI state.
    let message_key = ("libera".to_string(), "#rust".to_string());
    let existing_messages = vec![render_message(
        &serde_json::json!({"kind": "privmsg", "sender": "Alice", "body": "hello"}),
        None,
    )];
    state
        .transcript
        .messages
        .insert(message_key.clone(), existing_messages.clone());

    let away_payload = serde_json::json!({
        "kind": "away_confirmed",
        "network": "libera",
        "state": "away"
    });
    handle_away_confirmed(
        &mut state,
        "grappa:user:vjt/network:libera/channel:#rust",
        &away_payload,
    );
    assert!(!state.networks.away_states.contains_key("libera"));

    handle_away_confirmed(&mut state, "grappa:user:vjt", &away_payload);

    assert_eq!(
        state.networks.away_states.get("libera"),
        Some(&AwayStatus::Away)
    );
    assert_eq!(
        state.networks.away_states.get("azzurra"),
        Some(&AwayStatus::Present)
    );
    assert_eq!(
        state.transcript.messages.get(&message_key).map(Vec::len),
        Some(existing_messages.len())
    );
    assert_eq!(
        state
            .transcript
            .messages
            .get(&message_key)
            .and_then(|messages| messages.first())
            .map(|message| message.text.as_str()),
        Some("hello")
    );

    // A late repeat is idempotent; a later server-confirmed return to
    // present is a normal per-network state transition.
    assert!(!apply_away_confirmed(
        &mut state.networks.away_states,
        "libera",
        AwayStatus::Away
    ));
    assert!(apply_away_confirmed(
        &mut state.networks.away_states,
        "libera",
        AwayStatus::Present
    ));
    assert_eq!(
        state.networks.away_states.get("libera"),
        Some(&AwayStatus::Present)
    );
    assert_eq!(
        state.transcript.messages.get(&message_key).map(Vec::len),
        Some(existing_messages.len())
    );
    assert_eq!(
        state
            .transcript
            .messages
            .get(&message_key)
            .and_then(|messages| messages.first())
            .map(|message| message.text.as_str()),
        Some("hello")
    );
}

#[test]
fn channels_changed_signal_requires_exact_kind_and_user_topic() {
    let payload = serde_json::json!({"kind": "channels_changed"});
    assert!(is_channels_changed_signal(
        "vjt",
        "grappa:user:vjt",
        &payload
    ));
    assert!(!is_channels_changed_signal(
        "vjt",
        "grappa:user:someone-else",
        &payload
    ));
    assert!(!is_channels_changed_signal(
        "vjt",
        "grappa:user:vjt/network:libera/channel:#rust",
        &payload
    ));
    assert!(!is_channels_changed_signal(
        "vjt",
        "grappa:user:vjt",
        &serde_json::json!({"kind": "message"})
    ));
}

#[test]
fn channels_changed_reconciles_authoritative_topics_idempotently() {
    let entry = |channel: &str| {
        (
            "libera".to_string(),
            channel.to_string(),
            channel.to_string(),
        )
    };
    let user = "vjt";
    let mut state = WorkerState::new();
    let initial = vec![entry("#alpha"), entry("#beta")];

    assert_eq!(
        reconcile_channel_entries(&mut state, user, initial.clone()),
        vec![
            ChannelTopicAction::Join(channel_topic(user, "libera", "#alpha")),
            ChannelTopicAction::Join(channel_topic(user, "libera", "#beta")),
        ]
    );
    assert_eq!(state.windows.channel_entries, initial);
    assert!(reconcile_channel_entries(&mut state, user, initial).is_empty());

    let updated = vec![entry("#beta"), entry("#gamma")];
    assert_eq!(
        reconcile_channel_entries(&mut state, user, updated.clone()),
        vec![
            ChannelTopicAction::Leave(channel_topic(user, "libera", "#alpha")),
            ChannelTopicAction::Join(channel_topic(user, "libera", "#gamma")),
        ]
    );
    assert_eq!(state.windows.channel_entries, updated);
    assert_eq!(state.windows.channel_topics.len(), 2);
    assert!(reconcile_channel_entries(&mut state, user, updated).is_empty());
}

#[test]
fn channels_changed_keeps_topics_owned_by_queries_and_own_nick_listener() {
    let user = "vjt";
    let mut state = WorkerState::new();
    state.transcript.query_windows.push(QueryWindow {
        network: "libera".to_string(),
        target_nick: "Peer".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    });
    state
        .transcript
        .stale_query_topics
        .insert(query_window_key("libera", "FormerPeer"));
    state
        .networks
        .own_nicks
        .insert("libera".to_string(), "OwnNick".to_string());

    let active_query_topic = query_topic(user, "libera", "Peer");
    let stale_query_topic = query_topic(user, "libera", "FormerPeer");
    let own_topic = own_nick_listener_topic(user, "libera", "OwnNick");
    let channel_only_topic = channel_topic(user, "libera", "orphan");
    state.windows.channel_topics.extend([
        active_query_topic.clone(),
        stale_query_topic.clone(),
        own_topic.clone(),
        channel_only_topic.clone(),
    ]);
    state.conn.joined_topics = state.windows.channel_topics.clone();

    assert_eq!(
        reconcile_channel_entries(&mut state, user, Vec::new()),
        vec![ChannelTopicAction::Leave(channel_only_topic.clone())]
    );
    assert!(state.conn.joined_topics.contains(&active_query_topic));
    assert!(state.conn.joined_topics.contains(&stale_query_topic));
    assert!(state.conn.joined_topics.contains(&own_topic));
    assert!(!state.conn.joined_topics.contains(&channel_only_topic));
    assert!(state.windows.channel_topics.is_empty());
}

#[test]
fn own_nick_rename_leaves_old_topic_before_joining_new_topic() {
    let mut state = WorkerState::new();
    state
        .networks
        .own_nicks
        .insert("libera".to_string(), "OldNick".to_string());
    state
        .networks
        .own_nicks
        .insert("azzurra".to_string(), "AwayNick".to_string());
    let old_topic = own_nick_listener_topic("vjt", "libera", "OldNick");
    let new_topic = own_nick_listener_topic("vjt", "libera", "NewNick");
    let other_topic = own_nick_listener_topic("vjt", "azzurra", "AwayNick");
    state
        .conn
        .joined_topics
        .extend([old_topic.clone(), other_topic.clone()]);
    state.conn.own_listener_ready.insert(old_topic.clone());
    state.conn.own_listener_ready.insert(other_topic.clone());

    let actions = apply_own_nick_change(&mut state, "vjt", "libera", "NewNick");

    assert_eq!(
        actions,
        vec![
            OwnNickListenerAction::Leave(old_topic.clone()),
            OwnNickListenerAction::Join(new_topic.clone()),
        ]
    );
    assert!(!state.conn.joined_topics.contains(&old_topic));
    assert!(state.conn.joined_topics.contains(&new_topic));
    assert!(!state.conn.own_listener_ready.contains(&old_topic));
    assert!(!state.conn.own_listener_ready.contains(&new_topic));
    assert!(state.conn.joined_topics.contains(&other_topic));
    assert!(state.conn.own_listener_ready.contains(&other_topic));
    assert_eq!(
        state.networks.own_nicks.get("libera").map(String::as_str),
        Some("NewNick")
    );
    assert_eq!(
        state.networks.own_nicks.get("azzurra").map(String::as_str),
        Some("AwayNick")
    );
}

#[test]
fn own_nick_rename_keeps_old_topic_when_an_open_query_owns_it() {
    let mut state = WorkerState::new();
    state
        .networks
        .own_nicks
        .insert("libera".to_string(), "OldNick".to_string());
    state.conn.identifier = Some("vjt".to_string());
    state.transcript.query_windows.push(QueryWindow {
        network: "libera".to_string(),
        target_nick: "OldNick".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    });
    let old_topic = own_nick_listener_topic("vjt", "libera", "OldNick");
    let new_topic = own_nick_listener_topic("vjt", "libera", "NewNick");
    let old_query = query_window_key("libera", "OldNick");
    state.conn.joined_topics.insert(old_topic.clone());
    state.conn.own_listener_ready.insert(old_topic.clone());
    state.transcript.query_joined.insert(old_query.clone());
    state.transcript.query_ready.insert(old_query.clone());

    let actions = apply_own_nick_change(&mut state, "vjt", "libera", "NewNick");

    assert_eq!(
        actions,
        vec![OwnNickListenerAction::Join(new_topic.clone())]
    );
    assert!(state.conn.joined_topics.contains(&old_topic));
    assert!(!state.conn.own_listener_ready.contains(&old_topic));
    assert!(state.conn.joined_topics.contains(&new_topic));
    assert!(!state.conn.own_listener_ready.contains(&new_topic));
    assert!(state.transcript.query_joined.contains(&old_query));
    assert!(state.transcript.query_ready.contains(&old_query));
    assert_eq!(
        own_nick_listener_network_for_topic(&state, &old_topic),
        None
    );
    assert!(matches!(
        resolve_query_topic(
            &state.transcript.query_windows,
            &state.transcript.stale_query_topics,
            "libera",
            "OldNick"
        ),
        QueryTopicResolution::Active(_)
    ));
}

#[test]
fn own_nick_case_only_change_updates_spelling_without_rejoining() {
    let mut state = WorkerState::new();
    state
        .networks
        .own_nicks
        .insert("libera".to_string(), "Foo".to_string());
    let topic = own_nick_listener_topic("vjt", "libera", "Foo");
    state.conn.joined_topics.insert(topic.clone());
    state.conn.own_listener_ready.insert(topic.clone());

    let actions = apply_own_nick_change(&mut state, "vjt", "libera", "fOO");

    assert!(actions.is_empty());
    assert_eq!(
        state.networks.own_nicks.get("libera").map(String::as_str),
        Some("fOO")
    );
    assert!(state.conn.joined_topics.contains(&topic));
    assert!(state.conn.own_listener_ready.contains(&topic));
}

#[test]
fn own_nick_listener_readiness_requires_ack_and_fails_closed_without_it() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state
        .networks
        .own_nicks
        .insert("libera".to_string(), "OldNick".to_string());
    let old_topic = own_nick_listener_topic("vjt", "libera", "OldNick");
    let new_topic = own_nick_listener_topic("vjt", "libera", "NewNick");
    state.conn.joined_topics.insert(old_topic.clone());
    state.conn.own_listener_ready.insert(old_topic.clone());

    assert_eq!(
        apply_own_nick_change(&mut state, "vjt", "libera", "NewNick"),
        vec![
            OwnNickListenerAction::Leave(old_topic.clone()),
            OwnNickListenerAction::Join(new_topic.clone()),
        ]
    );
    // A join with no reply (including a timeout) never reaches the
    // positive-ACK transition and must remain unusable for DM routing.
    assert!(!state.conn.own_listener_ready.contains(&new_topic));
    assert_eq!(
        handle_own_nick_listener_join_reply(&mut state, &new_topic, Some("error")),
        OwnNickListenerJoinReply::Rejected
    );
    assert!(!state.conn.own_listener_ready.contains(&new_topic));
    assert_eq!(
        handle_own_nick_listener_join_reply(&mut state, &new_topic, None),
        OwnNickListenerJoinReply::Rejected
    );
    assert!(!state.conn.own_listener_ready.contains(&new_topic));
    assert_eq!(
        handle_own_nick_listener_join_reply(&mut state, &new_topic, Some("ok")),
        OwnNickListenerJoinReply::Accepted
    );
    assert!(state.conn.own_listener_ready.contains(&new_topic));
    assert_eq!(
        handle_own_nick_listener_join_reply(&mut state, &old_topic, Some("ok")),
        OwnNickListenerJoinReply::Untracked
    );
    assert!(!state.conn.own_listener_ready.contains(&old_topic));
}

#[test]
fn own_nick_listener_accepts_privmsg_and_action() {
    assert!(own_nick_listener_accepts_inbound_dm(&serde_json::json!({
        "kind": "privmsg"
    })));
    assert!(own_nick_listener_accepts_inbound_dm(&serde_json::json!({
        "kind": "action"
    })));
}

#[test]
fn own_nick_listener_rejects_non_dm_kinds() {
    assert!(!own_nick_listener_accepts_inbound_dm(&serde_json::json!({
        "kind": "notice"
    })));
}

#[test]
fn own_nick_dm_is_appended_only_to_an_authoritative_existing_query() {
    let mut state = WorkerState::new();
    state.transcript.query_windows = vec![QueryWindow {
        network: "libera".to_string(),
        target_nick: "Peer".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    }];
    let inbound = serde_json::json!({
        "kind": "privmsg",
        "sender": "peer",
        "body": "inbound DM",
        "id": 41
    });

    let key = own_nick_dm_query_key(&state, "libera", &inbound).unwrap();
    assert_eq!(key, ("libera".to_string(), "Peer".to_string()));
    let identity = query_window_key(&key.0, &key.1);
    require_query_full_history_if_unready(&mut state, &key);
    assert!(append_query_live_message(&mut state, &key, &inbound, Some("message")).is_some());
    assert_eq!(
        state.transcript.messages.get(&key).unwrap()[0]
            .text
            .as_str(),
        "inbound DM"
    );
    assert_eq!(
        query_history_fetch_window(&state, &identity, &key),
        (None, None)
    );

    let unknown_sender = serde_json::json!({
        "kind": "privmsg",
        "sender": "not-listed",
        "body": "do not invent a query",
        "id": 42
    });
    assert_eq!(
        own_nick_dm_query_key(&state, "libera", &unknown_sender),
        None
    );
    assert_eq!(own_nick_dm_query_key(&state, "azzurra", &inbound), None);
    assert_eq!(state.transcript.query_windows.len(), 1);
    assert_eq!(state.transcript.messages.len(), 1);
}

#[test]
fn own_nick_dm_fifo_waits_for_snapshot_then_merges_with_history_by_id() {
    let mut state = WorkerState::new();
    let first = serde_json::json!({
        "kind": "privmsg",
        "sender": "peer",
        "body": "first buffered",
        "id": 41,
        "server_time": 2_000
    });
    let second = serde_json::json!({
        "kind": "privmsg",
        "sender": "peer",
        "body": "second buffered",
        "id": 42,
        "server_time": 3_000
    });

    assert_eq!(own_nick_dm_query_key(&state, "libera", &first), None);
    buffer_pending_own_nick_dm(&mut state, "libera", &first, "message");
    buffer_pending_own_nick_dm(&mut state, "libera", &second, "message");
    assert_eq!(state.transcript.pending_own_nick_dms.len(), 2);
    assert!(state.transcript.messages.is_empty());

    let query = QueryWindow {
        network: "libera".to_string(),
        target_nick: "Peer".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    assert!(!apply_query_windows_snapshot(&mut state, vec![query]));
    drain_pending_own_nick_dms(&mut state);

    let key = ("libera".to_string(), "Peer".to_string());
    let identity = query_window_key(&key.0, &key.1);
    assert!(state.transcript.pending_own_nick_dms.is_empty());
    assert!(state
        .transcript
        .query_full_history_required
        .contains(&identity));
    assert_eq!(
        query_history_fetch_window(&state, &identity, &key),
        (None, None)
    );
    assert_eq!(
        state.transcript.messages[&key]
            .iter()
            .filter_map(|message| message.message_id)
            .collect::<Vec<_>>(),
        vec![41, 42]
    );

    merge_query_history(
        &mut state,
        &key,
        &[
            serde_json::json!({
                "kind": "privmsg",
                "sender": "peer",
                "body": "older history",
                "id": 40,
                "server_time": 1_000
            }),
            serde_json::json!({
                "kind": "privmsg",
                "sender": "peer",
                "body": "duplicate history row",
                "id": 41,
                "server_time": 2_000
            }),
        ],
    );

    let messages = &state.transcript.messages[&key];
    assert_eq!(
        messages
            .iter()
            .filter_map(|message| message.message_id)
            .collect::<Vec<_>>(),
        vec![40, 41, 42]
    );
    assert_eq!(messages[1].text, "first buffered");
    state
        .transcript
        .query_full_history_required
        .remove(&identity);
    assert_eq!(
        query_history_fetch_window(&state, &identity, &key),
        (Some(42), Some(200))
    );
}

#[test]
fn own_nick_dm_buffer_is_bounded_and_unconfirmed_queries_are_discarded() {
    let mut state = WorkerState::new();
    for id in 0..(MAX_PENDING_OWN_NICK_DMS + 2) {
        let payload = serde_json::json!({
            "kind": "privmsg",
            "sender": "unlisted",
            "body": format!("message {id}"),
            "id": id as i64,
            "server_time": id as i64
        });
        buffer_pending_own_nick_dm(&mut state, "libera", &payload, "message");
    }
    assert_eq!(
        state.transcript.pending_own_nick_dms.len(),
        MAX_PENDING_OWN_NICK_DMS
    );
    assert_eq!(
        state
            .transcript
            .pending_own_nick_dms
            .front()
            .unwrap()
            .payload["id"]
            .as_i64(),
        Some(2)
    );
    // The overflow is recovered from history if the query opens.
    let identity = query_window_key("libera", "unlisted");
    assert!(state
        .transcript
        .query_full_history_required
        .contains(&identity));

    assert!(!apply_query_windows_snapshot(&mut state, Vec::new()));
    drain_pending_own_nick_dms(&mut state);
    assert!(state.transcript.pending_own_nick_dms.is_empty());
    assert!(!state
        .transcript
        .query_full_history_required
        .contains(&identity));
    assert!(state.transcript.query_windows.is_empty());
    assert!(state.transcript.messages.is_empty());
}

#[test]
fn channel_shaped_topics_distinguish_active_stale_and_normal_windows() {
    let active = QueryWindow {
        network: "libera".to_string(),
        target_nick: "peer".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let stale: std::collections::HashSet<(String, String)> =
        [query_window_key("libera", "oldpeer")]
            .into_iter()
            .collect();
    let windows = vec![active.clone()];

    assert!(matches!(
        resolve_query_topic(&windows, &stale, "libera", "PEER"),
        QueryTopicResolution::Active(query) if query == &active
    ));
    assert!(matches!(
        resolve_query_topic(&windows, &stale, "libera", "oldpeer"),
        QueryTopicResolution::Stale
    ));
    assert!(matches!(
        resolve_query_topic(&windows, &stale, "libera", "#rust"),
        QueryTopicResolution::Untracked
    ));
}

#[test]
fn query_windows_snapshot_maps_ids_and_preserves_server_order() {
    let network_slugs: HashMap<i64, String> =
        [(1, "libera".to_string()), (2, "azzurra".to_string())]
            .into_iter()
            .collect();
    let payload = serde_json::json!({
        "kind": "query_windows_list",
        "windows": {
            "1": [
                {"network_id": 1, "target_nick": "older", "opened_at": "2026-09-21T10:00:00Z"},
                {"network_id": 1, "target_nick": "newer", "opened_at": "2026-09-21T11:00:00Z"}
            ],
            "2": [
                {"network_id": 2, "target_nick": "peer", "opened_at": "2026-09-21T12:00:00+02:00"}
            ]
        },
        "future_field": true
    });

    let queries = parse_query_windows_list(&payload, &network_slugs).unwrap();
    assert_eq!(queries.len(), 3);
    assert_eq!(queries[0].network, "libera");
    assert_eq!(queries[0].target_nick, "older");
    assert_eq!(queries[1].target_nick, "newer");
    assert_eq!(queries[2].network, "azzurra");

    let grouped = network_groups_data(
        &[],
        &queries,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
    );
    let libera = grouped.iter().find(|group| group.0 == "libera").unwrap();
    assert_eq!(libera.3[0].0, "older");
    assert_eq!(libera.3[1].0, "newer");
}

#[test]
fn query_windows_snapshot_accepts_empty_and_rejects_invalid_rows_atomically() {
    let network_slugs: HashMap<i64, String> = [(1, "libera".to_string())].into_iter().collect();
    let empty = serde_json::json!({"kind": "query_windows_list", "windows": {}});
    assert_eq!(
        parse_query_windows_list(&empty, &network_slugs),
        Some(Vec::new())
    );

    let bad_timestamp = serde_json::json!({
        "kind": "query_windows_list",
        "windows": {"1": [{
            "network_id": 1,
            "target_nick": "peer",
            "opened_at": "not-rfc3339"
        }]}
    });
    assert_eq!(
        parse_query_windows_list(&bad_timestamp, &network_slugs),
        None
    );

    let mismatched_id = serde_json::json!({
        "kind": "query_windows_list",
        "windows": {"1": [{
            "network_id": 2,
            "target_nick": "peer",
            "opened_at": "2026-09-21T10:00:00Z"
        }]}
    });
    assert_eq!(
        parse_query_windows_list(&mismatched_id, &network_slugs),
        None
    );

    let unknown_network = serde_json::json!({
        "kind": "query_windows_list",
        "windows": {"9": []}
    });
    assert_eq!(
        parse_query_windows_list(&unknown_network, &network_slugs),
        None
    );

    let duplicate_folded_nick = serde_json::json!({
        "kind": "query_windows_list",
        "windows": {"1": [
            {"network_id": 1, "target_nick": "Peer", "opened_at": "2026-09-21T10:00:00Z"},
            {"network_id": 1, "target_nick": "peer", "opened_at": "2026-09-21T11:00:00Z"}
        ]}
    });
    assert_eq!(
        parse_query_windows_list(&duplicate_folded_nick, &network_slugs),
        None
    );
}

#[test]
fn query_windows_snapshot_replaces_state_and_migrates_unambiguous_rename() {
    let old = QueryWindow {
        network: "libera".to_string(),
        target_nick: "oldnick".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let renamed = QueryWindow {
        network: "libera".to_string(),
        target_nick: "newnick".to_string(),
        opened_at: "2026-09-21T12:00:00+02:00".to_string(),
        dm_conversation_id: None,
    };
    let old_key = (old.network.clone(), old.target_nick.clone());
    let new_key = (renamed.network.clone(), renamed.target_nick.clone());
    let mut state = WorkerState::new();
    state.transcript.query_windows = vec![old.clone()];
    state
        .transcript
        .query_joined
        .insert(query_window_key(&old.network, &old.target_nick));
    state
        .transcript
        .query_ready
        .insert(query_window_key(&old.network, &old.target_nick));
    state.windows.current_query = true;
    state.windows.current_query_ready = true;
    state.windows.current_channel = Some(old_key.clone());
    state
        .transcript
        .messages
        .insert(old_key.clone(), Vec::new());
    state
        .transcript
        .drafts
        .insert(old_key.clone(), "unsent draft".to_string());

    let previous = state.transcript.query_windows.clone();
    assert!(!apply_query_windows_snapshot(
        &mut state,
        vec![renamed.clone()]
    ));
    reconcile_query_topic_tracking(&mut state, &previous);
    assert_eq!(state.transcript.query_windows, vec![renamed]);
    assert_eq!(state.windows.current_channel, Some(new_key.clone()));
    assert!(!state.windows.current_query_ready);
    assert!(state
        .transcript
        .query_joined
        .contains(&query_window_key(&old.network, &old.target_nick)));
    assert!(!state
        .transcript
        .query_ready
        .contains(&query_window_key(&old.network, &old.target_nick)));
    assert!(state
        .transcript
        .stale_query_topics
        .contains(&query_window_key(&old.network, &old.target_nick)));
    assert!(state.transcript.messages.contains_key(&new_key));
    assert_eq!(
        state.transcript.drafts.get(&new_key).map(String::as_str),
        Some("unsent draft")
    );

    let previous = state.transcript.query_windows.clone();
    assert!(apply_query_windows_snapshot(&mut state, Vec::new()));
    reconcile_query_topic_tracking(&mut state, &previous);
    assert!(state.transcript.query_windows.is_empty());
    assert!(!state.windows.current_query);
    assert_eq!(state.windows.current_channel, None);
}

#[test]
fn query_windows_snapshot_migrates_cache_on_case_only_nick_change() {
    let old = QueryWindow {
        network: "libera".to_string(),
        target_nick: "foo".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let recased = QueryWindow {
        network: "libera".to_string(),
        target_nick: "Foo".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let old_key = (old.network.clone(), old.target_nick.clone());
    let recased_key = (recased.network.clone(), recased.target_nick.clone());
    let identity = query_window_key(&old.network, &old.target_nick);
    let topic = query_topic("vjt", &old.network, &old.target_nick);
    let mut state = WorkerState::new();
    state.transcript.query_windows = vec![old.clone()];
    state.transcript.query_joined.insert(identity.clone());
    state.transcript.query_ready.insert(identity.clone());
    state.conn.joined_topics.insert(topic.clone());
    state.transcript.messages.insert(
        old_key.clone(),
        vec![RenderedMessage {
            timestamp: "10:00".to_string(),
            nick: Some("foo".to_string()),
            text: "retained history".to_string(),
            italic: false,
            message_id: Some(1),
            server_time: Some(1),
            presence_noise: false,
        }],
    );
    state
        .transcript
        .drafts
        .insert(old_key.clone(), "unsent draft".to_string());

    let previous = state.transcript.query_windows.clone();
    assert!(!apply_query_windows_snapshot(
        &mut state,
        vec![recased.clone()]
    ));
    reconcile_query_topic_tracking(&mut state, &previous);

    assert_eq!(state.transcript.query_windows, vec![recased]);
    assert!(!state.transcript.messages.contains_key(&old_key));
    assert_eq!(
        state.transcript.messages[&recased_key][0].text,
        "retained history"
    );
    assert!(!state.transcript.drafts.contains_key(&old_key));
    assert_eq!(
        state
            .transcript
            .drafts
            .get(&recased_key)
            .map(String::as_str),
        Some("unsent draft")
    );
    assert!(state.transcript.query_joined.contains(&identity));
    assert!(state.transcript.query_ready.contains(&identity));
    assert!(state.conn.joined_topics.contains(&topic));
    assert!(!state.transcript.stale_query_topics.contains(&identity));
}

#[test]
fn query_window_rename_matching_refuses_ambiguous_open_times() {
    let old_one = QueryWindow {
        network: "libera".to_string(),
        target_nick: "old-one".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let old_two = QueryWindow {
        network: "libera".to_string(),
        target_nick: "old-two".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let new_one = QueryWindow {
        network: "libera".to_string(),
        target_nick: "new-one".to_string(),
        opened_at: "2026-09-21T12:00:00+02:00".to_string(),
        dm_conversation_id: None,
    };
    let new_two = QueryWindow {
        network: "libera".to_string(),
        target_nick: "new-two".to_string(),
        opened_at: "2026-09-21T12:00:00+02:00".to_string(),
        dm_conversation_id: None,
    };

    assert!(query_window_renames(&[old_one, old_two], &[new_one, new_two]).is_empty());
}

#[test]
fn query_window_rename_matching_uses_conversation_id_over_open_time() {
    let window = |nick: &str, id: Option<i64>| QueryWindow {
        network: "libera".to_string(),
        target_nick: nick.to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: id,
    };
    // Same opening instant makes these ambiguous without ids.
    let previous = [window("old-one", Some(1)), window("old-two", Some(2))];
    let next = [window("new-one", Some(1)), window("new-two", Some(2))];
    let renames = query_window_renames(&previous, &next);
    assert_eq!(renames.len(), 2);
    assert!(renames
        .iter()
        .any(|(old, new)| old.target_nick == "old-one" && new.target_nick == "new-one"));
    assert!(renames
        .iter()
        .any(|(old, new)| old.target_nick == "old-two" && new.target_nick == "new-two"));

    // A different id under the same opening instant is not a rename.
    assert!(query_window_renames(&[window("old", Some(1))], &[window("new", Some(2))]).is_empty());
    // A window without an id still falls back to the opening instant.
    assert_eq!(
        query_window_renames(&[window("old", None)], &[window("new", Some(3))]).len(),
        1
    );
}

#[test]
fn rename_inference_applies_below_protocol_37_and_when_unknown() {
    assert!(rename_inference_applies(None));
    assert!(rename_inference_applies(Some(1)));
    assert!(rename_inference_applies(Some(34)));
    assert!(rename_inference_applies(Some(36)));
    assert!(!rename_inference_applies(Some(37)));
    assert!(!rename_inference_applies(Some(38)));
}

/// A state holding one selected query for `old_nick` with a cached line
/// and a draft, as the snapshot tests below start from.
fn state_with_selected_query(
    old: &QueryWindow,
    server_protocol_version: Option<u32>,
) -> WorkerState {
    let old_key = (old.network.clone(), old.target_nick.clone());
    let mut state = WorkerState::new();
    state.conn.server_protocol_version = server_protocol_version;
    state.transcript.query_windows = vec![old.clone()];
    state.windows.current_query = true;
    state.windows.current_channel = Some(old_key.clone());
    state.transcript.messages.insert(
        old_key.clone(),
        vec![RenderedMessage {
            timestamp: "10:00".to_string(),
            nick: Some(old.target_nick.clone()),
            text: "history under the old nick".to_string(),
            italic: false,
            message_id: Some(1),
            server_time: Some(1),
            presence_noise: false,
        }],
    );
    state
        .transcript
        .drafts
        .insert(old_key, "unsent draft".to_string());
    state
}

#[test]
fn protocol_37_snapshot_keeps_old_and_new_window_of_a_renamed_peer() {
    let window = |nick: &str, id: Option<i64>| QueryWindow {
        network: "libera".to_string(),
        target_nick: nick.to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: id,
    };
    // Even with the same opening instant (and a stray id) that would
    // read as a rename on an older server, nothing moves from v37 on.
    let old = window("alice", Some(7));
    let new = window("alice_", Some(7));
    let old_key = ("libera".to_string(), "alice".to_string());
    let new_key = ("libera".to_string(), "alice_".to_string());
    let mut state = state_with_selected_query(&old, Some(37));

    assert!(!apply_query_windows_snapshot(
        &mut state,
        vec![old.clone(), new.clone()]
    ));
    assert_eq!(state.transcript.query_windows, vec![old, new]);
    assert_eq!(state.windows.current_channel, Some(old_key.clone()));
    assert!(state.windows.current_query);
    assert_eq!(
        state.transcript.messages[&old_key][0].text,
        "history under the old nick"
    );
    assert!(!state.transcript.messages.contains_key(&new_key));
    assert_eq!(
        state.transcript.drafts.get(&old_key).map(String::as_str),
        Some("unsent draft")
    );
    assert!(!state.transcript.drafts.contains_key(&new_key));
}

#[test]
fn protocol_37_snapshot_does_not_follow_a_vanished_selection_to_a_new_window() {
    let window = |nick: &str| QueryWindow {
        network: "libera".to_string(),
        target_nick: nick.to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let old = window("alice");
    let mut state = state_with_selected_query(&old, Some(37));

    // The old window is really closed and another one opens in the same
    // second: a real close, so the selection is dropped, not moved.
    assert!(apply_query_windows_snapshot(
        &mut state,
        vec![window("bob")]
    ));
    assert_eq!(state.windows.current_channel, None);
    assert!(!state.windows.current_query);
    let bob_key = ("libera".to_string(), "bob".to_string());
    assert!(!state.transcript.messages.contains_key(&bob_key));
    assert!(!state.transcript.drafts.contains_key(&bob_key));
}

#[test]
fn protocol_37_snapshot_still_moves_a_case_only_change() {
    let window = |nick: &str| QueryWindow {
        network: "libera".to_string(),
        target_nick: nick.to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let old = window("foo");
    let recased_key = ("libera".to_string(), "Foo".to_string());
    let mut state = state_with_selected_query(&old, Some(37));

    assert!(!apply_query_windows_snapshot(
        &mut state,
        vec![window("Foo")]
    ));
    assert_eq!(state.windows.current_channel, Some(recased_key.clone()));
    assert_eq!(
        state.transcript.messages[&recased_key][0].text,
        "history under the old nick"
    );
    assert_eq!(
        state
            .transcript
            .drafts
            .get(&recased_key)
            .map(String::as_str),
        Some("unsent draft")
    );
}

#[test]
fn pre_37_and_unknown_servers_still_follow_an_id_based_rename() {
    let window = |nick: &str, id: Option<i64>, opened_at: &str| QueryWindow {
        network: "libera".to_string(),
        target_nick: nick.to_string(),
        opened_at: opened_at.to_string(),
        dm_conversation_id: id,
    };
    for version in [None, Some(34), Some(36)] {
        let old = window("alice", Some(7), "2026-09-21T10:00:00Z");
        // A different opening instant: only the id ties the two together.
        let new = window("alice_", Some(7), "2026-09-21T10:30:00Z");
        let new_key = ("libera".to_string(), "alice_".to_string());
        let mut state = state_with_selected_query(&old, version);

        assert!(!apply_query_windows_snapshot(&mut state, vec![new.clone()]));
        assert_eq!(state.transcript.query_windows, vec![new]);
        assert_eq!(state.windows.current_channel, Some(new_key.clone()));
        assert_eq!(
            state.transcript.messages[&new_key][0].text,
            "history under the old nick"
        );
        assert_eq!(
            state.transcript.drafts.get(&new_key).map(String::as_str),
            Some("unsent draft")
        );
    }
}

#[test]
fn pre_37_and_unknown_servers_still_fall_back_to_the_opening_instant() {
    let window = |nick: &str| QueryWindow {
        network: "libera".to_string(),
        target_nick: nick.to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    for version in [None, Some(33), Some(35)] {
        let old = window("alice");
        let new = window("alice_");
        let new_key = ("libera".to_string(), "alice_".to_string());
        let mut state = state_with_selected_query(&old, version);

        assert!(!apply_query_windows_snapshot(&mut state, vec![new.clone()]));
        assert_eq!(state.windows.current_channel, Some(new_key.clone()));
        assert_eq!(state.transcript.messages[&new_key].len(), 1);
        assert_eq!(
            state.transcript.drafts.get(&new_key).map(String::as_str),
            Some("unsent draft")
        );
    }
}

#[test]
fn query_windows_list_reads_optional_conversation_id() {
    let network_slugs = HashMap::from([(1, "libera".to_string())]);
    let payload = serde_json::json!({
        "kind": "query_windows_list",
        "windows": {"1": [
            {"network_id": 1, "target_nick": "with", "opened_at": "2026-09-21T10:00:00Z", "dm_conversation_id": 42},
            {"network_id": 1, "target_nick": "null", "opened_at": "2026-09-21T10:00:00Z", "dm_conversation_id": null},
            {"network_id": 1, "target_nick": "absent", "opened_at": "2026-09-21T10:00:00Z"}
        ]}
    });
    let queries = parse_query_windows_list(&payload, &network_slugs).unwrap();
    let ids: Vec<Option<i64>> = queries.iter().map(|q| q.dm_conversation_id).collect();
    assert_eq!(ids, vec![Some(42), None, None]);
}

#[test]
fn closing_and_reopening_query_reuses_join_but_reloads_tail_before_ready() {
    let query = QueryWindow {
        network: "libera".to_string(),
        target_nick: "peer".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let identity = query_window_key(&query.network, &query.target_nick);
    let topic = query_topic("vjt", &query.network, &query.target_nick);
    let mut state = WorkerState::new();
    state.transcript.query_windows = vec![query.clone()];
    state.conn.joined_topics.insert(topic.clone());
    record_query_join_success(&mut state, &identity);
    state.transcript.query_ready.insert(identity.clone());

    let previous = state.transcript.query_windows.clone();
    assert!(!apply_query_windows_snapshot(&mut state, Vec::new()));
    reconcile_query_topic_tracking(&mut state, &previous);
    assert!(state.transcript.stale_query_topics.contains(&identity));
    assert!(state.conn.joined_topics.contains(&topic));
    assert!(state.transcript.query_joined.contains(&identity));
    assert!(!state.transcript.query_ready.contains(&identity));

    let previous = state.transcript.query_windows.clone();
    assert!(!apply_query_windows_snapshot(
        &mut state,
        vec![query.clone()]
    ));
    reconcile_query_topic_tracking(&mut state, &previous);
    assert!(!state.transcript.stale_query_topics.contains(&identity));
    assert!(state.conn.joined_topics.contains(&topic));
    assert!(state.transcript.query_joined.contains(&identity));
    assert!(!state.transcript.query_ready.contains(&identity));
    state.windows.current_query = true;
    state.windows.current_channel = Some(("libera".to_string(), "peer".to_string()));
    mark_query_ready_after_history(&mut state, &identity);
    assert!(state.transcript.query_ready.contains(&identity));
    assert!(state.windows.current_query_ready);
}

#[test]
fn reopening_query_after_reconnect_waits_for_ack_and_history_again() {
    let query = QueryWindow {
        network: "libera".to_string(),
        target_nick: "peer".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    };
    let identity = query_window_key(&query.network, &query.target_nick);
    let topic = query_topic("vjt", &query.network, &query.target_nick);
    let mut state = WorkerState::new();
    state.transcript.query_windows = vec![query.clone()];
    state.conn.joined_topics.insert(topic);
    record_query_join_success(&mut state, &identity);
    state.transcript.query_ready.insert(identity.clone());

    let previous = state.transcript.query_windows.clone();
    assert!(!apply_query_windows_snapshot(&mut state, Vec::new()));
    reconcile_query_topic_tracking(&mut state, &previous);
    reset_query_session_readiness(&mut state);
    assert!(state.transcript.query_joined.is_empty());
    assert!(state.transcript.query_ready.is_empty());

    // The session rejoins the retained stale topic after reconnect; its
    // successful ACK is remembered even though the snapshot still omits it.
    record_query_join_success(&mut state, &identity);
    let previous = state.transcript.query_windows.clone();
    assert!(!apply_query_windows_snapshot(&mut state, vec![query]));
    reconcile_query_topic_tracking(&mut state, &previous);
    assert!(state.transcript.query_joined.contains(&identity));
    assert!(!state.transcript.query_ready.contains(&identity));

    state.windows.current_query = true;
    state.windows.current_channel = Some(("libera".to_string(), "peer".to_string()));
    mark_query_ready_after_history(&mut state, &identity);
    assert!(state.transcript.query_ready.contains(&identity));
    assert!(state.windows.current_query_ready);
}

#[test]
fn failed_query_join_clears_readiness_and_allows_a_retry() {
    let identity = query_window_key("libera", "peer");
    let topic = query_topic("vjt", "libera", "peer");
    let mut state = WorkerState::new();
    state.conn.joined_topics.insert(topic.clone());
    state.transcript.query_joined.insert(identity.clone());
    state.transcript.query_ready.insert(identity.clone());
    state.windows.current_query = true;
    state.windows.current_query_ready = true;
    state.windows.current_channel = Some(("libera".to_string(), "peer".to_string()));

    assert!(reset_query_join_failure(&mut state, &identity, &topic));
    assert!(!state.transcript.query_joined.contains(&identity));
    assert!(!state.transcript.query_ready.contains(&identity));
    assert!(!state.conn.joined_topics.contains(&topic));
    assert!(!state.windows.current_query_ready);
}

#[test]
fn query_history_merges_tail_and_after_pages_by_time_then_id() {
    let key = ("libera".to_string(), "peer".to_string());
    let mut state = WorkerState::new();
    let tail = vec![
        serde_json::json!({
            "id": 12,
            "server_time": 200,
            "kind": "privmsg",
            "sender": "peer",
            "body": "second"
        }),
        serde_json::json!({
            "id": 10,
            "server_time": 100,
            "kind": "privmsg",
            "sender": "peer",
            "body": "first"
        }),
    ];
    merge_query_history(&mut state, &key, &tail);

    let live = serde_json::json!({
        "id": 13,
        "server_time": 300,
        "kind": "privmsg",
        "sender": "peer",
        "body": "third"
    });
    assert_eq!(
        append_query_live_message(&mut state, &key, &live, None),
        Some(LiveInsert::Appended)
    );
    let after = vec![
        live,
        serde_json::json!({
            "id": 14,
            "server_time": 300,
            "kind": "privmsg",
            "sender": "peer",
            "body": "fourth"
        }),
    ];
    merge_query_history(&mut state, &key, &after);

    let messages = &state.transcript.messages[&key];
    assert_eq!(
        messages
            .iter()
            .filter_map(|message| message.message_id)
            .collect::<Vec<_>>(),
        vec![10, 12, 13, 14]
    );
    assert_eq!(query_high_water_id(&state, &key), Some(14));
}

#[test]
fn channel_from_topic_round_trips_a_channel_topic() {
    let topic = channel_topic("vjt", "libera", "#rust");
    assert_eq!(
        channel_from_topic(&topic),
        Some(("libera".to_string(), "#rust".to_string()))
    );
}

#[test]
fn channel_from_topic_rejects_the_user_topic() {
    assert_eq!(channel_from_topic("grappa:user:vjt"), None);
}

#[test]
fn normalize_server_url_strips_a_trailing_slash() {
    assert_eq!(
        normalize_server_url("https://irc.sythos.dev/"),
        "https://irc.sythos.dev"
    );
}

#[test]
fn normalize_server_url_strips_whitespace_and_multiple_slashes() {
    assert_eq!(
        normalize_server_url("  https://irc.sythos.dev//  "),
        "https://irc.sythos.dev"
    );
}

#[test]
fn parse_topic_changed_reads_the_nested_text_field() {
    // Real shape, confirmed via a live frame and
    // github.com/vjt/grappa-irc/issues/2260 — `topic` is an object,
    // not the plain string an earlier version of this code assumed.
    let payload = serde_json::json!({
        "channel": "#grappa",
        "kind": "topic_changed",
        "network": "azzurra",
        "topic": {
            "set_at": "2026-09-14T21:42:44Z",
            "set_by": "vjt",
            "text": "Welcome to #grappa"
        }
    });
    assert_eq!(
        parse_topic_changed(&payload),
        Some((
            ("azzurra".to_string(), "#grappa".to_string()),
            "Welcome to #grappa".to_string()
        ))
    );
}

#[test]
fn parse_topic_changed_rejects_a_plain_string_topic() {
    let payload = serde_json::json!({
        "channel": "#grappa",
        "network": "azzurra",
        "topic": "not an object"
    });
    assert_eq!(parse_topic_changed(&payload), None);
}

#[test]
fn channel_modes_changed_replaces_the_complete_channel_snapshot() {
    let mut state = WorkerState::new();
    let first = serde_json::json!({
        "kind": "channel_modes_changed",
        "network": "libera",
        "channel": "#cordiale",
        "modes": {"modes": ["n", "t", "k"], "params": {"k": "secret", "l": null}},
        "future_field": true
    });
    assert_eq!(
        apply_channel_modes_changed(
            &mut state,
            &channel_topic("sythos", "libera", "#cordiale"),
            &first
        ),
        Some((
            ("libera".to_string(), "#cordiale".to_string()),
            "+ntk".to_string(),
        ))
    );
    let key = ("libera".to_string(), "#cordiale".to_string());
    assert_eq!(
        state.transcript.channel_modes[&key].params.get("k"),
        Some(&Some("secret".to_string()))
    );
    assert_eq!(
        state.transcript.channel_modes[&key].params.get("l"),
        Some(&None)
    );

    let replacement = serde_json::json!({
        "kind": "channel_modes_changed",
        "network": "libera",
        "channel": "#cordiale",
        "modes": {"modes": ["i"], "params": {}}
    });
    assert_eq!(
        apply_channel_modes_changed(
            &mut state,
            &channel_topic("sythos", "libera", "#cordiale"),
            &replacement
        ),
        Some((
            ("libera".to_string(), "#cordiale".to_string()),
            "+i".to_string(),
        ))
    );
    assert_eq!(state.transcript.channel_modes.len(), 1);
    assert_eq!(
        state.transcript.channel_modes[&key].modes,
        vec!["i".to_string()]
    );
    assert!(state.transcript.channel_modes[&key].params.is_empty());
}

#[test]
fn channel_modes_changed_preserves_known_empty_and_rejects_bad_params() {
    let mut state = WorkerState::new();
    let empty = serde_json::json!({
        "network": "libera",
        "channel": "#empty",
        "modes": {"modes": [], "params": {}}
    });
    assert_eq!(
        apply_channel_modes_changed(
            &mut state,
            &channel_topic("sythos", "libera", "#empty"),
            &empty
        ),
        Some((("libera".to_string(), "#empty".to_string()), String::new(),))
    );
    assert!(state
        .transcript
        .channel_modes
        .contains_key(&("libera".to_string(), "#empty".to_string())));

    let malformed = serde_json::json!({
        "network": "libera",
        "channel": "#empty",
        "modes": {"modes": ["n"], "params": {"limit": 42}}
    });
    assert_eq!(
        apply_channel_modes_changed(
            &mut state,
            &channel_topic("sythos", "libera", "#empty"),
            &malformed
        ),
        None
    );
    assert!(
        state.transcript.channel_modes[&("libera".to_string(), "#empty".to_string())]
            .modes
            .is_empty()
    );
}

#[test]
fn channel_modes_changed_requires_the_matching_channel_topic() {
    let payload = serde_json::json!({
        "network": "libera",
        "channel": "#cordiale",
        "modes": {"modes": ["n"], "params": {}}
    });
    let mut state = WorkerState::new();

    assert_eq!(
        apply_channel_modes_changed(&mut state, "grappa:user:sythos", &payload),
        None
    );
    assert_eq!(
        apply_channel_modes_changed(
            &mut state,
            &channel_topic("sythos", "libera", "#different"),
            &payload
        ),
        None
    );
    assert!(state.transcript.channel_modes.is_empty());
}

#[test]
fn window_counts_updates_messages_and_mentions_for_each_known_window() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("sythos".to_string());
    state.windows.channel_entries = vec![(
        "libera".to_string(),
        "#Cordiale".to_string(),
        "#Cordiale".to_string(),
    )];
    state.transcript.query_windows = vec![QueryWindow {
        network: "libera".to_string(),
        target_nick: "Peer".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    }];

    let channel_payload = serde_json::json!({
        "kind": "window_counts",
        "channel": "#CORDIALE",
        "messages": 9,
        "mentions": 3,
        "events": 2,
        "severity": "mention",
        "future_field": "ignored"
    });
    assert!(apply_window_counts(
        &mut state,
        &channel_topic("sythos", "libera", "#cordiale"),
        &channel_payload
    ));
    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "#cordiale")),
        Some(&3)
    );
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "#cordiale")),
        Some(&9)
    );

    let query_payload = serde_json::json!({
        "kind": "window_counts",
        "channel": "peer",
        "messages": 4,
        "mentions": 1,
        "events": 0,
        "severity": "mention"
    });
    assert!(apply_window_counts(
        &mut state,
        &query_topic("sythos", "libera", "PEER"),
        &query_payload
    ));
    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "Peer")),
        Some(&1)
    );
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "Peer")),
        Some(&4)
    );
    assert_eq!(state.windows.window_mentions.len(), 2);
    assert_eq!(state.windows.window_messages.len(), 2);

    // Snapshots are absolute and last-arrival-wins, even when the count
    // decreases (for example, when an older queued snapshot arrives late).
    let lower_snapshot = serde_json::json!({
        "kind": "window_counts",
        "channel": "#cordiale",
        "messages": 2,
        "mentions": 2,
        "events": 1,
        "severity": "none"
    });
    assert!(apply_window_counts(
        &mut state,
        &channel_topic("sythos", "libera", "#cordiale"),
        &lower_snapshot
    ));
    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "#cordiale")),
        Some(&2)
    );
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "#cordiale")),
        Some(&2)
    );

    let cleared = serde_json::json!({
        "kind": "window_counts",
        "channel": "#cordiale",
        "messages": 0,
        "mentions": 0,
        "events": 0,
        "severity": "none"
    });
    assert!(apply_window_counts(
        &mut state,
        &channel_topic("sythos", "libera", "#cordiale"),
        &cleared
    ));
    assert!(!state
        .windows
        .window_mentions
        .contains_key(&window_counts_key("libera", "#cordiale")));
    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "Peer")),
        Some(&1)
    );
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "#cordiale")),
        Some(&0)
    );
    assert_eq!(mention_count_labels(0), (String::new(), String::new()));
    assert_eq!(
        mention_count_labels(3),
        (" (3)".to_string(), " — 3 mentions".to_string())
    );
    assert_eq!(
        unread_message_count_labels(None),
        (String::new(), String::new())
    );
    assert_eq!(
        unread_message_count_labels(Some(0)),
        (String::new(), "0 unread messages".to_string())
    );
    assert_eq!(
        unread_message_count_labels(Some(12)),
        ("12".to_string(), "12 unread messages".to_string())
    );
}

#[test]
fn window_counts_from_me_seeds_channel_and_query_counts() {
    let unread_counts = serde_json::json!({
        "libera": {
            "#Cordiale": {
                "messages": 12,
                "mentions": 4,
                "events": 2,
                "severity": "mention"
            },
            "Peer": {
                "messages": 3,
                "mentions": 1,
                "events": 0,
                "severity": "message"
            },
            "#invalid": {
                "messages": 1,
                "mentions": -1,
                "events": 0,
                "severity": "mention"
            }
        },
        "": {
            "#ignored": {
                "messages": 1,
                "mentions": 1,
                "events": 0,
                "severity": "mention"
            }
        }
    });

    let mentions = window_mentions_from_me(&unread_counts);
    assert_eq!(mentions.len(), 2);
    assert_eq!(
        mentions.get(&window_counts_key("libera", "#cordiale")),
        Some(&4)
    );
    assert_eq!(mentions.get(&window_counts_key("libera", "peer")), Some(&1));
    let messages = window_messages_from_me(&unread_counts);
    assert_eq!(messages.len(), 2);
    assert_eq!(
        messages.get(&window_counts_key("libera", "#cordiale")),
        Some(&12)
    );
    assert_eq!(messages.get(&window_counts_key("libera", "peer")), Some(&3));
}

#[test]
fn window_counts_seed_from_channel_query_and_own_nick_join_replies() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("sythos".to_string());
    state
        .networks
        .own_nicks
        .insert("libera".to_string(), "Sythos".to_string());
    state
        .windows
        .window_mentions
        .insert(window_counts_key("libera", "#cordiale"), 8);

    let reply = serde_json::json!({
        "status": "ok",
        "response": {
            "read_cursor": 17,
            "window_counts": {
                "messages": 9,
                "mentions": 3,
                "events": 2,
                "severity": "mention"
            }
        }
    });
    for topic in [
        channel_topic("sythos", "libera", "#Cordiale"),
        query_topic("sythos", "libera", "Peer"),
        own_nick_listener_topic("sythos", "libera", "Sythos"),
    ] {
        assert!(apply_window_counts_join_reply(
            &mut state,
            &topic,
            &reply,
            Some("ok")
        ));
    }

    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "#cordiale")),
        Some(&3)
    );
    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "Peer")),
        Some(&3)
    );
    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "Sythos")),
        Some(&3)
    );
    for target in ["#cordiale", "Peer", "Sythos"] {
        assert_eq!(
            state
                .windows
                .window_messages
                .get(&window_counts_key("libera", target)),
            Some(&9)
        );
    }

    let no_counts = serde_json::json!({"status": "ok", "response": {}});
    assert!(apply_window_counts_join_reply(
        &mut state,
        &query_topic("sythos", "libera", "Peer"),
        &no_counts,
        Some("ok")
    ));
    assert!(!state
        .windows
        .window_mentions
        .contains_key(&window_counts_key("libera", "Peer")));
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "Peer")),
        Some(&0)
    );

    assert!(!apply_window_counts_join_reply(
        &mut state,
        &channel_topic("someone-else", "libera", "#Cordiale"),
        &reply,
        Some("ok")
    ));
    assert!(!apply_window_counts_join_reply(
        &mut state,
        &channel_topic("sythos", "libera", "#Cordiale"),
        &reply,
        Some("error")
    ));
}

#[test]
fn window_counts_on_own_nick_listener_updates_only_own_nick_window() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("sythos".to_string());
    state
        .networks
        .own_nicks
        .insert("libera".to_string(), "Sythos".to_string());
    state.transcript.query_windows = vec![QueryWindow {
        network: "libera".to_string(),
        target_nick: "Peer".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    }];
    state
        .windows
        .window_mentions
        .insert(window_counts_key("libera", "Sythos"), 1);
    state
        .windows
        .window_mentions
        .insert(window_counts_key("libera", "Peer"), 2);
    let payload = serde_json::json!({
        "kind": "window_counts",
        "channel": "sythos",
        "messages": 1,
        "mentions": 0,
        "events": 0,
        "severity": "message"
    });
    let own_nick_topic = own_nick_listener_topic("sythos", "libera", "Sythos");

    assert!(apply_window_counts(&mut state, &own_nick_topic, &payload));
    assert!(!state
        .windows
        .window_mentions
        .contains_key(&window_counts_key("libera", "Sythos")));
    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "Peer")),
        Some(&2)
    );
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "Sythos")),
        Some(&1)
    );

    let unrelated = serde_json::json!({
        "kind": "window_counts",
        "channel": "Peer",
        "messages": 1,
        "mentions": 1,
        "events": 0,
        "severity": "mention"
    });
    assert!(!apply_window_counts(
        &mut state,
        &own_nick_topic,
        &unrelated
    ));
    assert_eq!(state.windows.window_mentions.len(), 1);
}

#[test]
fn window_counts_rejects_invalid_or_unrelated_snapshots() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("sythos".to_string());
    state.windows.channel_entries = vec![(
        "libera".to_string(),
        "#cordiale".to_string(),
        "#cordiale".to_string(),
    )];

    let valid = serde_json::json!({
        "kind": "window_counts",
        "channel": "#cordiale",
        "messages": 3,
        "mentions": 2,
        "events": 1,
        "severity": "mention"
    });
    for (topic, payload) in [
        (
            channel_topic("someone-else", "libera", "#cordiale"),
            valid.clone(),
        ),
        (
            channel_topic("sythos", "libera", "#different"),
            valid.clone(),
        ),
        (
            channel_topic("sythos", "libera", "#cordiale"),
            serde_json::json!({
                "kind": "window_counts",
                "channel": "#cordiale",
                "messages": -1,
                "mentions": 2,
                "events": 1,
                "severity": "mention"
            }),
        ),
        (
            channel_topic("sythos", "libera", "#cordiale"),
            serde_json::json!({
                "kind": "window_counts",
                "channel": "#cordiale",
                "messages": 3,
                "mentions": -1,
                "events": 1,
                "severity": "mention"
            }),
        ),
        (
            channel_topic("sythos", "libera", "#cordiale"),
            serde_json::json!({
                "kind": "window_counts",
                "channel": "#cordiale",
                "messages": 3,
                "mentions": 2,
                "events": 1,
                "severity": 42
            }),
        ),
        (
            channel_topic("sythos", "libera", "#cordiale"),
            serde_json::json!({
                "kind": "window_counts",
                "channel": "#cordiale",
                "messages": 3,
                "mentions": 2,
                "severity": "mention"
            }),
        ),
        (
            channel_topic("sythos", "libera", "#not-open"),
            serde_json::json!({
                "kind": "window_counts",
                "channel": "#not-open",
                "messages": 3,
                "mentions": 2,
                "events": 1,
                "severity": "mention"
            }),
        ),
    ] {
        assert!(
            !apply_window_counts(&mut state, &topic, &payload),
            "unrelated or malformed window_counts payload must be ignored"
        );
    }
    assert!(state.windows.window_mentions.is_empty());
    assert!(state.windows.window_messages.is_empty());
}

#[test]
fn window_counts_preserves_mentions_when_severity_is_missing_or_unknown() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("sythos".to_string());
    state.windows.channel_entries = vec![
        (
            "libera".to_string(),
            "#unknown-severity".to_string(),
            "#unknown-severity".to_string(),
        ),
        (
            "libera".to_string(),
            "#missing-severity".to_string(),
            "#missing-severity".to_string(),
        ),
    ];

    let unknown = serde_json::json!({
        "kind": "window_counts",
        "channel": "#unknown-severity",
        "messages": 3,
        "mentions": 2,
        "events": 1,
        "severity": "future-severity"
    });
    assert!(apply_window_counts(
        &mut state,
        &channel_topic("sythos", "libera", "#unknown-severity"),
        &unknown
    ));

    let missing = serde_json::json!({
        "kind": "window_counts",
        "channel": "#missing-severity",
        "messages": 5,
        "mentions": 4,
        "events": 2
    });
    assert!(apply_window_counts(
        &mut state,
        &channel_topic("sythos", "libera", "#missing-severity"),
        &missing
    ));

    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "#unknown-severity")),
        Some(&2)
    );
    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "#missing-severity")),
        Some(&4)
    );
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "#unknown-severity")),
        Some(&3)
    );
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "#missing-severity")),
        Some(&5)
    );
}

#[test]
fn window_counts_removes_closed_query_counters_but_keeps_channels() {
    let mut state = WorkerState::new();
    state
        .networks
        .own_nicks
        .insert("libera".to_string(), "Sythos".to_string());
    state.windows.channel_entries = vec![(
        "libera".to_string(),
        "#cordiale".to_string(),
        "#cordiale".to_string(),
    )];
    state.transcript.query_windows = vec![QueryWindow {
        network: "libera".to_string(),
        target_nick: "Peer".to_string(),
        opened_at: "2026-09-21T10:00:00Z".to_string(),
        dm_conversation_id: None,
    }];
    state
        .windows
        .window_mentions
        .insert(window_counts_key("libera", "#cordiale"), 2);
    state
        .windows
        .window_mentions
        .insert(window_counts_key("libera", "Peer"), 1);
    state
        .windows
        .window_mentions
        .insert(window_counts_key("libera", "Sythos"), 2);
    state
        .windows
        .window_messages
        .insert(window_counts_key("libera", "#cordiale"), 9);
    state
        .windows
        .window_messages
        .insert(window_counts_key("libera", "Peer"), 3);
    state
        .windows
        .window_messages
        .insert(window_counts_key("libera", "Sythos"), 4);

    state.transcript.query_windows.clear();
    retain_window_counts_for_open_windows(&mut state);

    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "#cordiale")),
        Some(&2)
    );
    assert!(!state
        .windows
        .window_mentions
        .contains_key(&window_counts_key("libera", "Peer")));
    assert_eq!(
        state
            .windows
            .window_mentions
            .get(&window_counts_key("libera", "Sythos")),
        Some(&2)
    );
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "#cordiale")),
        Some(&9)
    );
    assert!(!state
        .windows
        .window_messages
        .contains_key(&window_counts_key("libera", "Peer")));
    assert_eq!(
        state
            .windows
            .window_messages
            .get(&window_counts_key("libera", "Sythos")),
        Some(&4)
    );
}

#[test]
fn parse_joined_event_accepts_live_and_channel_snapshot_topics() {
    let payload = serde_json::json!({
        "kind": "joined",
        "network": "libera",
        "channel": "#cordiale",
        "state": "joined",
        "future_field": true
    });
    let expected = Some(("libera".to_string(), "#cordiale".to_string()));

    assert_eq!(
        parse_joined_event(&payload, "grappa:user:sythos", "sythos"),
        expected
    );
    assert_eq!(
        parse_joined_event(
            &payload,
            &channel_topic("sythos", "libera", "#CoRdIaLe"),
            "sythos"
        ),
        expected
    );
    assert_eq!(ascii_fold_channel("#CAFÉ[1]"), "#cafÉ[1]");
}

#[test]
fn parse_window_pending_accepts_only_live_user_topic_and_exact_fields() {
    let payload = serde_json::json!({
        "kind": "window_pending",
        "network": "libera",
        "channel": "#cordiale",
        "state": "pending",
        "future_field": true
    });
    let expected = Some(("libera".to_string(), "#cordiale".to_string()));

    assert_eq!(
        parse_window_pending_event(&payload, "grappa:user:sythos", "sythos"),
        expected
    );
    assert_eq!(
        parse_window_pending_event(
            &payload,
            &channel_topic("sythos", "libera", "#cordiale"),
            "sythos"
        ),
        None
    );
    assert_eq!(
        parse_window_pending_event(&payload, "grappa:user:other", "sythos"),
        None
    );

    for malformed in [
        serde_json::json!({
            "kind": "window_pending",
            "network": "libera",
            "channel": "#cordiale",
            "state": "joined"
        }),
        serde_json::json!({
            "kind": "window_pending",
            "network": "libera",
            "state": "pending"
        }),
        serde_json::json!({
            "kind": "window_pending",
            "network": 7,
            "channel": "#cordiale",
            "state": "pending"
        }),
        serde_json::json!({
            "kind": "window_pending",
            "network": "libera",
            "channel": "",
            "state": "pending"
        }),
    ] {
        assert_eq!(
            parse_window_pending_event(&malformed, "grappa:user:sythos", "sythos"),
            None
        );
    }
}

#[test]
fn parse_window_invited_accepts_only_the_user_topic_and_required_fields() {
    let payload = serde_json::json!({
        "kind": "window_invited",
        "network": "libera",
        "channel": "#cordiale",
        "state": "invited",
        "inviter": "*",
        "future_field": true
    });
    let expected = Some((
        "libera".to_string(),
        "#cordiale".to_string(),
        "*".to_string(),
    ));

    assert_eq!(
        parse_window_invited_event(&payload, "grappa:user:sythos", "sythos"),
        expected
    );
    assert_eq!(
        parse_window_invited_event(
            &payload,
            &channel_topic("sythos", "libera", "#cordiale"),
            "sythos"
        ),
        None
    );
    assert_eq!(
        parse_window_invited_event(&payload, "grappa:user:other", "sythos"),
        None
    );

    for malformed in [
        serde_json::json!({
            "kind": "window_invited",
            "network": "libera",
            "channel": "#cordiale",
            "state": "pending",
            "inviter": "ChanServ"
        }),
        serde_json::json!({
            "kind": "window_invited",
            "network": "libera",
            "channel": "#cordiale",
            "state": "invited"
        }),
        serde_json::json!({
            "kind": "window_invited",
            "network": "libera",
            "channel": "#cordiale",
            "state": "invited",
            "inviter": null
        }),
        serde_json::json!({
            "kind": "window_invited",
            "network": "",
            "channel": "#cordiale",
            "state": "invited",
            "inviter": "ChanServ"
        }),
        serde_json::json!({
            "kind": "window_invited",
            "network": "libera",
            "channel": "",
            "state": "invited",
            "inviter": "ChanServ"
        }),
        serde_json::json!({
            "kind": "window_invited",
            "network": "libera",
            "channel": "#cordiale",
            "state": "invited",
            "inviter": ""
        }),
        serde_json::json!({
            "kind": "window_invited",
            "network": 7,
            "channel": "#cordiale",
            "state": "invited",
            "inviter": "ChanServ"
        }),
    ] {
        assert_eq!(
            parse_window_invited_event(&malformed, "grappa:user:sythos", "sythos"),
            None
        );
    }
}

#[test]
fn parse_window_invite_declined_accepts_only_the_user_topic_without_state() {
    let payload = serde_json::json!({
        "kind": "window_invite_declined",
        "network": "libera",
        "channel": "#cordiale",
        "future_field": true
    });
    let expected = Some(("libera".to_string(), "#cordiale".to_string()));

    assert_eq!(
        parse_window_invite_declined_event(&payload, "grappa:user:sythos", "sythos"),
        expected
    );
    assert_eq!(
        parse_window_invite_declined_event(
            &payload,
            &channel_topic("sythos", "libera", "#cordiale"),
            "sythos"
        ),
        None
    );
    assert_eq!(
        parse_window_invite_declined_event(&payload, "grappa:user:other", "sythos"),
        None
    );

    for malformed in [
        serde_json::json!({
            "kind": "window_invited",
            "network": "libera",
            "channel": "#cordiale"
        }),
        serde_json::json!({
            "kind": "window_invite_declined",
            "channel": "#cordiale"
        }),
        serde_json::json!({
            "kind": "window_invite_declined",
            "network": "libera"
        }),
        serde_json::json!({
            "kind": "window_invite_declined",
            "network": 7,
            "channel": "#cordiale"
        }),
        serde_json::json!({
            "kind": "window_invite_declined",
            "network": "   ",
            "channel": "#cordiale"
        }),
        serde_json::json!({
            "kind": "window_invite_declined",
            "network": "libera",
            "channel": ""
        }),
    ] {
        assert_eq!(
            parse_window_invite_declined_event(&malformed, "grappa:user:sythos", "sythos"),
            None
        );
    }
}

#[test]
fn invited_window_is_idempotent_and_replaces_stale_state() {
    let key = window_state_key("libera", "#cordiale");
    let mut states = HashMap::from([(key.clone(), ChannelWindowState::Failed)]);
    let mut failures = HashMap::from([(
        key.clone(),
        WindowFailure {
            reason: Some("old failure".to_string()),
            numeric: Some(Number::from(473)),
        },
    )]);
    let mut kicks = HashMap::from([(
        key.clone(),
        WindowKick {
            by: Some("old actor".to_string()),
            reason: None,
        },
    )]);
    let mut invited_by = HashMap::new();
    let mut joined_topics = std::collections::HashSet::new();
    let mut channel_topics = std::collections::HashSet::new();
    let topic = channel_topic("sythos", "libera", "#cordiale");

    assert!(set_invited_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#CoRdIaLe",
        "ChanServ".to_string(),
    ));
    assert_eq!(states.get(&key), Some(&ChannelWindowState::Invited));
    assert!(failures.is_empty());
    assert!(kicks.is_empty());
    assert_eq!(invited_by.get(&key).map(String::as_str), Some("ChanServ"));
    assert!(register_pending_channel_topic(
        &mut joined_topics,
        &mut channel_topics,
        topic.clone()
    ));
    assert!(!register_pending_channel_topic(
        &mut joined_topics,
        &mut channel_topics,
        topic.clone()
    ));
    assert_eq!(
        joined_topics,
        std::collections::HashSet::from([topic.clone()])
    );
    assert_eq!(channel_topics, std::collections::HashSet::from([topic]));

    assert!(!set_invited_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#cordiale",
        "ChanServ".to_string(),
    ));
    assert_eq!(invited_by.get(&key).map(String::as_str), Some("ChanServ"));

    // A later inviter value is a real state replacement, not a duplicate;
    // the required banner metadata follows the latest server frame.
    assert!(set_invited_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#cordiale",
        "*".to_string(),
    ));
    assert_eq!(invited_by.get(&key).map(String::as_str), Some("*"));
}

#[test]
fn declined_window_removes_invited_and_pending_state_and_sidebar_row() {
    let key = window_state_key("libera", "#cordiale");
    let mut state = WorkerState::new();
    state
        .windows
        .window_states
        .insert(key.clone(), ChannelWindowState::Pending);
    state.windows.window_failures.insert(
        key.clone(),
        WindowFailure {
            reason: Some("stale failure".to_string()),
            numeric: Some(Number::from(473)),
        },
    );
    state.windows.window_kicks.insert(
        key.clone(),
        WindowKick {
            by: Some("stale actor".to_string()),
            reason: Some("stale reason".to_string()),
        },
    );
    state
        .windows
        .invited_by
        .insert(key.clone(), "ChanServ".to_string());
    state.windows.channel_entries.push((
        "libera".to_string(),
        "#cordiale".to_string(),
        "#cordiale".to_string(),
    ));
    state
        .transcript
        .members
        .insert(key.clone(), vec![("sythos".to_string(), "@".to_string())]);
    state.transcript.messages.insert(key.clone(), Vec::new());
    state
        .transcript
        .drafts
        .insert(key.clone(), "draft".to_string());
    state
        .transcript
        .topics
        .insert(key.clone(), "topic".to_string());
    let topic = channel_topic("sythos", "libera", "#cordiale");
    state.windows.channel_topics.insert(topic.clone());
    state.conn.joined_topics.insert(topic.clone());

    assert!(remove_declined_window(&mut state, "libera", "#CoRdIaLe"));
    assert!(!state.windows.window_states.contains_key(&key));
    assert!(!state.windows.window_failures.contains_key(&key));
    assert!(!state.windows.window_kicks.contains_key(&key));
    assert!(!state.windows.invited_by.contains_key(&key));
    assert!(state.windows.channel_entries.is_empty());
    // Lifecycle cleanup does not discard cached content or topic data.
    assert!(state.transcript.members.contains_key(&key));
    assert!(state.transcript.messages.contains_key(&key));
    assert_eq!(
        state.transcript.drafts.get(&key).map(String::as_str),
        Some("draft")
    );
    assert_eq!(
        state.transcript.topics.get(&key).map(String::as_str),
        Some("topic")
    );
    assert!(remove_declined_channel_subscription(
        &mut state,
        "sythos",
        "libera",
        "#CoRdIaLe"
    ));
    assert!(state.windows.channel_topics.is_empty());
    assert!(state.conn.joined_topics.is_empty());

    assert!(!remove_declined_window(&mut state, "libera", "#cordiale"));
    assert!(!remove_declined_channel_subscription(
        &mut state,
        "sythos",
        "libera",
        "#cordiale"
    ));
}

#[test]
fn pending_window_is_idempotent_subscribes_once_and_transitions_to_joined() {
    let key = window_state_key("libera", "#cordiale");
    let mut states = HashMap::from([(key.clone(), ChannelWindowState::Failed)]);
    let mut failures = HashMap::from([(
        key.clone(),
        WindowFailure {
            reason: Some("old failure".to_string()),
            numeric: Some(Number::from(473)),
        },
    )]);
    let mut kicks = HashMap::from([(
        key.clone(),
        WindowKick {
            by: Some("old actor".to_string()),
            reason: None,
        },
    )]);
    let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);
    let mut joined_topics = std::collections::HashSet::new();
    let mut channel_topics = std::collections::HashSet::new();
    let topic = channel_topic("sythos", "libera", "#cordiale");

    assert!(set_pending_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#CoRdIaLe"
    ));
    assert_eq!(states.get(&key), Some(&ChannelWindowState::Pending));
    assert!(failures.is_empty());
    assert!(kicks.is_empty());
    assert!(invited_by.is_empty());
    assert!(register_pending_channel_topic(
        &mut joined_topics,
        &mut channel_topics,
        topic.clone()
    ));

    assert!(!set_pending_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#cordiale"
    ));
    assert!(!register_pending_channel_topic(
        &mut joined_topics,
        &mut channel_topics,
        topic.clone()
    ));
    assert_eq!(
        joined_topics,
        std::collections::HashSet::from([topic.clone()])
    );
    assert_eq!(channel_topics, std::collections::HashSet::from([topic]));

    assert!(set_joined_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#cordiale"
    ));
    assert_eq!(states.get(&key), Some(&ChannelWindowState::Joined));
}

#[test]
fn boot_seeds_only_channels_with_an_explicit_true_joined_flag() {
    let channels = HashMap::from([(
        "libera".to_string(),
        vec![
            serde_json::json!({"name": "#ACTIVE-AUTOJOIN", "joined": true, "source": "autojoin"}),
            serde_json::json!({"name": "#active-dynamic", "joined": true, "source": "joined"}),
            serde_json::json!({"name": "#configured-only", "joined": false, "source": "autojoin"}),
            serde_json::json!({"name": "#missing-joined", "source": "joined"}),
            serde_json::json!({"name": "#malformed-joined", "joined": "true"}),
            serde_json::json!({"joined": true, "source": "joined"}),
        ],
    )]);

    let states = joined_window_states_from_boot_channels(&channels);
    let expected = HashMap::from([
        (
            ("libera".to_string(), "#active-autojoin".to_string()),
            ChannelWindowState::Joined,
        ),
        (
            ("libera".to_string(), "#active-dynamic".to_string()),
            ChannelWindowState::Joined,
        ),
    ]);

    assert_eq!(states, expected);
}

#[test]
fn parse_joined_event_rejects_malformed_state_and_unrelated_topics() {
    let valid = serde_json::json!({
        "kind": "joined",
        "network": "libera",
        "channel": "#cordiale",
        "state": "joined"
    });
    assert_eq!(
        parse_joined_event(&valid, "grappa:user:someone-else", "sythos"),
        None
    );
    assert_eq!(
        parse_joined_event(
            &valid,
            &channel_topic("sythos", "libera", "#other"),
            "sythos"
        ),
        None
    );

    let wrong_state = serde_json::json!({
        "kind": "joined",
        "network": "libera",
        "channel": "#cordiale",
        "state": "pending"
    });
    assert_eq!(
        parse_joined_event(&wrong_state, "grappa:user:sythos", "sythos"),
        None
    );

    let missing_channel = serde_json::json!({
        "kind": "joined",
        "network": "libera",
        "state": "joined"
    });
    assert_eq!(
        parse_joined_event(&missing_channel, "grappa:user:sythos", "sythos"),
        None
    );
}

#[test]
fn parse_join_failed_accepts_live_and_matching_channel_snapshot_topics() {
    let payload = serde_json::json!({
        "kind": "join_failed",
        "network": "libera",
        "channel": "#cordiale",
        "state": "failed",
        "reason": "invite only",
        "numeric": 473,
        "future_field": true
    });
    let expected = Some((
        "libera".to_string(),
        "#cordiale".to_string(),
        WindowFailure {
            reason: Some("invite only".to_string()),
            numeric: Some(Number::from(473)),
        },
    ));

    assert_eq!(
        parse_join_failed_event(&payload, "grappa:user:sythos", "sythos"),
        expected
    );
    assert_eq!(
        parse_join_failed_event(
            &payload,
            &channel_topic("sythos", "libera", "#CoRdIaLe"),
            "sythos"
        ),
        expected
    );
}

#[test]
fn parse_join_failed_preserves_required_nullable_fields_and_rejects_bad_payloads() {
    let nullable = serde_json::json!({
        "kind": "join_failed",
        "network": "libera",
        "channel": "#cordiale",
        "state": "failed",
        "reason": null,
        "numeric": null
    });
    assert_eq!(
        parse_join_failed_event(&nullable, "grappa:user:sythos", "sythos"),
        Some((
            "libera".to_string(),
            "#cordiale".to_string(),
            WindowFailure {
                reason: None,
                numeric: None,
            },
        ))
    );

    let wrong_state = serde_json::json!({
        "kind": "join_failed",
        "network": "libera",
        "channel": "#cordiale",
        "state": "joined",
        "reason": null,
        "numeric": null
    });
    assert_eq!(
        parse_join_failed_event(&wrong_state, "grappa:user:sythos", "sythos"),
        None
    );

    let missing_reason = serde_json::json!({
        "kind": "join_failed",
        "network": "libera",
        "channel": "#cordiale",
        "state": "failed",
        "numeric": null
    });
    assert_eq!(
        parse_join_failed_event(&missing_reason, "grappa:user:sythos", "sythos"),
        None
    );

    let malformed_numeric = serde_json::json!({
        "kind": "join_failed",
        "network": "libera",
        "channel": "#cordiale",
        "state": "failed",
        "reason": null,
        "numeric": "473"
    });
    assert_eq!(
        parse_join_failed_event(&malformed_numeric, "grappa:user:sythos", "sythos"),
        None
    );

    assert_eq!(
        parse_join_failed_event(&nullable, "grappa:user:other", "sythos"),
        None
    );
    assert_eq!(
        parse_join_failed_event(
            &nullable,
            &channel_topic("sythos", "libera", "#other"),
            "sythos"
        ),
        None
    );
    assert_eq!(
        parse_join_failed_event(
            &nullable,
            "grappa:user:sythos/network:libera/query:friend",
            "sythos"
        ),
        None
    );
}

#[test]
fn parse_kicked_accepts_live_and_matching_channel_snapshot_topics() {
    let payload = serde_json::json!({
        "kind": "kicked",
        "network": "libera",
        "channel": "#cordiale",
        "state": "kicked",
        "by": "ChanServ",
        "reason": "policy",
        "future_field": true
    });
    let expected = Some((
        "libera".to_string(),
        "#cordiale".to_string(),
        WindowKick {
            by: Some("ChanServ".to_string()),
            reason: Some("policy".to_string()),
        },
    ));

    assert_eq!(
        parse_kicked_event(&payload, "grappa:user:sythos", "sythos"),
        expected
    );
    assert_eq!(
        parse_kicked_event(
            &payload,
            &channel_topic("sythos", "libera", "#CoRdIaLe"),
            "sythos"
        ),
        expected
    );
}

#[test]
fn parse_kicked_preserves_required_nullable_fields_and_rejects_bad_payloads() {
    let nullable = serde_json::json!({
        "kind": "kicked",
        "network": "libera",
        "channel": "#cordiale",
        "state": "kicked",
        "by": null,
        "reason": null
    });
    assert_eq!(
        parse_kicked_event(&nullable, "grappa:user:sythos", "sythos"),
        Some((
            "libera".to_string(),
            "#cordiale".to_string(),
            WindowKick {
                by: None,
                reason: None,
            },
        ))
    );

    let wrong_state = serde_json::json!({
        "kind": "kicked",
        "network": "libera",
        "channel": "#cordiale",
        "state": "joined",
        "by": null,
        "reason": null
    });
    assert_eq!(
        parse_kicked_event(&wrong_state, "grappa:user:sythos", "sythos"),
        None
    );

    let missing_by = serde_json::json!({
        "kind": "kicked",
        "network": "libera",
        "channel": "#cordiale",
        "state": "kicked",
        "reason": null
    });
    assert_eq!(
        parse_kicked_event(&missing_by, "grappa:user:sythos", "sythos"),
        None
    );

    let missing_reason = serde_json::json!({
        "kind": "kicked",
        "network": "libera",
        "channel": "#cordiale",
        "state": "kicked",
        "by": null
    });
    assert_eq!(
        parse_kicked_event(&missing_reason, "grappa:user:sythos", "sythos"),
        None
    );

    let malformed_by = serde_json::json!({
        "kind": "kicked",
        "network": "libera",
        "channel": "#cordiale",
        "state": "kicked",
        "by": 7,
        "reason": null
    });
    assert_eq!(
        parse_kicked_event(&malformed_by, "grappa:user:sythos", "sythos"),
        None
    );

    let malformed_reason = serde_json::json!({
        "kind": "kicked",
        "network": "libera",
        "channel": "#cordiale",
        "state": "kicked",
        "by": null,
        "reason": false
    });
    assert_eq!(
        parse_kicked_event(&malformed_reason, "grappa:user:sythos", "sythos"),
        None
    );

    assert_eq!(
        parse_kicked_event(&nullable, "grappa:user:other", "sythos"),
        None
    );
    assert_eq!(
        parse_kicked_event(
            &nullable,
            &channel_topic("sythos", "libera", "#other"),
            "sythos"
        ),
        None
    );
    assert_eq!(
        parse_kicked_event(
            &nullable,
            "grappa:user:sythos/network:libera/query:friend",
            "sythos"
        ),
        None
    );
}

#[test]
fn upsert_channel_entry_is_idempotent_for_live_and_snapshot_delivery() {
    let mut entries = vec![(
        "libera".to_string(),
        "#cordiale".to_string(),
        "#cordiale".to_string(),
    )];

    assert!(!upsert_channel_entry(
        &mut entries,
        "libera".to_string(),
        "#CoRdIaLe".to_string()
    ));
    assert!(upsert_channel_entry(
        &mut entries,
        "libera".to_string(),
        "#rust".to_string()
    ));
    assert!(!upsert_channel_entry(
        &mut entries,
        "libera".to_string(),
        "#rust".to_string()
    ));
    assert_eq!(
        entries,
        vec![
            (
                "libera".to_string(),
                "#cordiale".to_string(),
                "#cordiale".to_string()
            ),
            (
                "libera".to_string(),
                "#rust".to_string(),
                "#rust".to_string()
            )
        ]
    );
}

#[test]
fn set_joined_window_state_records_transition_and_deduplicates_delivery() {
    let key = window_state_key("libera", "#cordiale");
    let mut states = HashMap::new();
    let mut failures = HashMap::from([(
        key.clone(),
        WindowFailure {
            reason: Some("old failure".to_string()),
            numeric: Some(Number::from(473)),
        },
    )]);
    let mut kicks = HashMap::from([(
        key.clone(),
        WindowKick {
            by: Some("old actor".to_string()),
            reason: None,
        },
    )]);
    let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);

    assert!(set_joined_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        &key.0,
        "#CoRdIaLe"
    ));
    assert_eq!(states.get(&key), Some(&ChannelWindowState::Joined));
    assert!(!failures.contains_key(&key));
    assert!(!kicks.contains_key(&key));
    assert!(!invited_by.contains_key(&key));

    assert!(!set_joined_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        &key.0,
        &key.1
    ));
    assert_eq!(states.len(), 1);
    assert_eq!(states.get(&key), Some(&ChannelWindowState::Joined));
}

#[test]
fn set_failed_window_state_keeps_metadata_clears_invite_and_is_idempotent() {
    let key = window_state_key("libera", "#cordiale");
    let failure = WindowFailure {
        reason: Some("invite only".to_string()),
        numeric: Some(Number::from(473)),
    };
    let mut states = HashMap::from([(key.clone(), ChannelWindowState::Joined)]);
    let mut failures = HashMap::new();
    let mut kicks = HashMap::from([(
        key.clone(),
        WindowKick {
            by: None,
            reason: Some("stale".to_string()),
        },
    )]);
    let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);

    assert!(set_failed_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#CoRdIaLe",
        failure.clone()
    ));
    assert_eq!(states.get(&key), Some(&ChannelWindowState::Failed));
    assert!(window_is_failed(&states, "libera", "#CoRdIaLe"));
    assert_eq!(failures.get(&key), Some(&failure));
    assert!(!kicks.contains_key(&key));
    assert!(!invited_by.contains_key(&key));

    assert!(!set_failed_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#cordiale",
        failure
    ));
}

#[test]
fn set_kicked_window_state_keeps_metadata_clears_prior_state_and_is_idempotent() {
    let key = window_state_key("libera", "#cordiale");
    let kick = WindowKick {
        by: Some("ChanServ".to_string()),
        reason: Some("policy".to_string()),
    };
    let mut states = HashMap::from([(key.clone(), ChannelWindowState::Failed)]);
    let mut failures = HashMap::from([(
        key.clone(),
        WindowFailure {
            reason: Some("old failure".to_string()),
            numeric: Some(Number::from(473)),
        },
    )]);
    let mut kicks = HashMap::new();
    let mut invited_by = HashMap::from([(key.clone(), "ChanServ".to_string())]);

    assert!(set_kicked_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#CoRdIaLe",
        kick.clone(),
    ));
    assert_eq!(states.get(&key), Some(&ChannelWindowState::Kicked));
    assert!(window_is_kicked(&states, "libera", "#CoRdIaLe"));
    assert!(!failures.contains_key(&key));
    assert_eq!(kicks.get(&key), Some(&kick));
    assert!(!invited_by.contains_key(&key));

    assert!(!set_kicked_window_state(
        &mut states,
        &mut failures,
        &mut kicks,
        &mut invited_by,
        "libera",
        "#cordiale",
        kick,
    ));
}

#[test]
fn force_parted_kicked_window_clears_only_lifecycle_metadata() {
    let key = window_state_key("libera", "#cordiale");
    let mut state = WorkerState::new();
    state
        .windows
        .window_states
        .insert(key.clone(), ChannelWindowState::Kicked);
    state.windows.window_failures.insert(
        key.clone(),
        WindowFailure {
            reason: Some("old failure".to_string()),
            numeric: Some(Number::from(473)),
        },
    );
    state.windows.window_kicks.insert(
        key.clone(),
        WindowKick {
            by: Some("ChanServ".to_string()),
            reason: Some("policy".to_string()),
        },
    );
    state
        .windows
        .invited_by
        .insert(key.clone(), "ChanServ".to_string());
    state.windows.channel_entries.push((
        "libera".to_string(),
        "#cordiale".to_string(),
        "#cordiale".to_string(),
    ));
    state
        .transcript
        .members
        .insert(key.clone(), vec![("sythos".to_string(), "@".to_string())]);
    state.transcript.messages.insert(key.clone(), Vec::new());
    state
        .transcript
        .drafts
        .insert(key.clone(), "draft".to_string());
    state
        .transcript
        .topics
        .insert(key.clone(), "topic".to_string());
    state.transcript.channel_modes.insert(
        key.clone(),
        ChannelModes {
            modes: vec!["n".to_string()],
            params: HashMap::new(),
        },
    );
    state
        .windows
        .recent_channels
        .push(("libera".to_string(), "#cordiale".to_string()));

    assert!(force_parted_kicked_window(
        &mut state,
        "libera",
        "#CoRdIaLe"
    ));
    assert!(!state.windows.window_states.contains_key(&key));
    assert!(!state.windows.window_failures.contains_key(&key));
    assert!(!state.windows.window_kicks.contains_key(&key));
    assert!(!state.windows.invited_by.contains_key(&key));
    assert!(!state.transcript.channel_modes.contains_key(&key));
    assert_eq!(state.windows.channel_entries.len(), 1);
    assert!(state.transcript.members.contains_key(&key));
    assert!(state.transcript.messages.contains_key(&key));
    assert_eq!(
        state.transcript.drafts.get(&key).map(String::as_str),
        Some("draft")
    );
    assert_eq!(
        state.transcript.topics.get(&key).map(String::as_str),
        Some("topic")
    );
    assert_eq!(state.windows.recent_channels.len(), 1);
}

#[test]
fn force_parted_kicked_window_is_a_noop_for_other_window_states() {
    let key = window_state_key("libera", "#cordiale");
    let mut state = WorkerState::new();
    state
        .windows
        .window_states
        .insert(key.clone(), ChannelWindowState::Failed);
    state.windows.window_failures.insert(
        key.clone(),
        WindowFailure {
            reason: Some("invite only".to_string()),
            numeric: Some(Number::from(473)),
        },
    );
    state.windows.window_kicks.insert(
        key.clone(),
        WindowKick {
            by: Some("ChanServ".to_string()),
            reason: Some("stale".to_string()),
        },
    );
    state
        .windows
        .invited_by
        .insert(key.clone(), "ChanServ".to_string());
    let expected_states = state.windows.window_states.clone();
    let expected_failures = state.windows.window_failures.clone();
    let expected_kicks = state.windows.window_kicks.clone();
    let expected_invites = state.windows.invited_by.clone();

    assert!(!force_parted_kicked_window(
        &mut state,
        "libera",
        "#cordiale"
    ));
    assert_eq!(state.windows.window_states, expected_states);
    assert_eq!(state.windows.window_failures, expected_failures);
    assert_eq!(state.windows.window_kicks, expected_kicks);
    assert_eq!(state.windows.invited_by, expected_invites);
}

#[test]
fn dismiss_kicked_window_locally_removes_row_and_preserves_selection_state() {
    let key = window_state_key("libera", "#cordiale");
    let mut state = WorkerState::new();
    state
        .windows
        .window_states
        .insert(key.clone(), ChannelWindowState::Kicked);
    state.windows.window_kicks.insert(
        key.clone(),
        WindowKick {
            by: Some("ChanServ".to_string()),
            reason: Some("policy".to_string()),
        },
    );
    state
        .windows
        .invited_by
        .insert(key.clone(), "ChanServ".to_string());
    state.windows.channel_entries.push((
        "libera".to_string(),
        "#cordiale".to_string(),
        "#cordiale".to_string(),
    ));
    state.windows.current_channel = Some(key.clone());
    state.windows.recent_channels.push(key.clone());
    state
        .transcript
        .members
        .insert(key.clone(), vec![("sythos".to_string(), "@".to_string())]);

    assert_eq!(
        dismiss_kicked_window_locally(&mut state, "libera", "#CoRdIaLe"),
        Some(true)
    );
    assert!(state.windows.channel_entries.is_empty());
    assert!(!state.windows.window_states.contains_key(&key));
    assert!(!state.windows.window_failures.contains_key(&key));
    assert!(!state.windows.window_kicks.contains_key(&key));
    assert!(!state.windows.invited_by.contains_key(&key));
    assert_eq!(state.windows.current_channel, Some(key.clone()));
    assert_eq!(state.windows.recent_channels, vec![key.clone()]);
    assert!(state.transcript.members.contains_key(&key));
}

fn channel_row(network: &str, channel: &str) -> (String, String, String) {
    (
        network.to_string(),
        channel.to_string(),
        channel.to_string(),
    )
}

fn empty_me() -> MeResponse {
    MeResponse {
        read_cursors: serde_json::json!({}),
        unread_counts: serde_json::json!({}),
        badge_count: serde_json::json!(0),
        is_admin: false,
        kind: None,
        id: None,
        name: None,
        registered: None,
        home_data: None,
    }
}

#[test]
fn kicked_row_survives_a_channel_list_refresh_until_dismissed() {
    let user = "sythos";
    let mut state = WorkerState::new();
    state.networks.network_ids.insert("libera".to_string(), 7);
    let kicked_topic = channel_topic(user, "libera", "#Cordiale");
    reconcile_channel_entries(
        &mut state,
        user,
        vec![
            channel_row("libera", "#alpha"),
            channel_row("libera", "#Cordiale"),
        ],
    );
    set_joined_window_state(
        &mut state.windows.window_states,
        &mut state.windows.window_failures,
        &mut state.windows.window_kicks,
        &mut state.windows.invited_by,
        "libera",
        "#Cordiale",
    );

    // Grappa pushes `kicked`, then `channels_changed`, and the REST list
    // no longer has the channel: it was not an autojoin one.
    let kick = WindowKick {
        by: Some("ChanServ".to_string()),
        reason: Some("policy".to_string()),
    };
    set_kicked_window_state(
        &mut state.windows.window_states,
        &mut state.windows.window_failures,
        &mut state.windows.window_kicks,
        &mut state.windows.invited_by,
        "libera",
        "#cordiale",
        kick.clone(),
    );
    let actions =
        reconcile_channel_entries(&mut state, user, vec![channel_row("libera", "#alpha")]);

    assert!(actions.is_empty(), "no topic is left for a kicked row");
    assert_eq!(
        state.windows.channel_entries,
        vec![
            channel_row("libera", "#alpha"),
            channel_row("libera", "#Cordiale")
        ]
    );
    let key = window_state_key("libera", "#cordiale");
    assert_eq!(
        state.windows.window_states.get(&key),
        Some(&ChannelWindowState::Kicked)
    );
    assert_eq!(state.windows.window_kicks.get(&key), Some(&kick));
    assert!(state.windows.channel_topics.contains(&kicked_topic));
    assert!(state.conn.joined_topics.contains(&kicked_topic));
    let groups = network_groups_data(
        &state.windows.channel_entries,
        &state.transcript.query_windows,
        &state.windows.expanded_networks,
        &state.networks.network_connection_states,
        &state.networks.network_ids,
    );
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0].2,
        vec![
            ("#Cordiale".to_string(), "#Cordiale".to_string()),
            ("#alpha".to_string(), "#alpha".to_string()),
        ]
    );

    // A second refresh changes nothing.
    assert!(
        reconcile_channel_entries(&mut state, user, vec![channel_row("libera", "#alpha")],)
            .is_empty()
    );
    assert_eq!(state.windows.channel_entries.len(), 2);

    // The x removes the row; the next refresh then drops its topic.
    assert_eq!(
        dismiss_kicked_window_locally(&mut state, "libera", "#cordiale"),
        Some(false)
    );
    assert_eq!(
        state.windows.channel_entries,
        vec![channel_row("libera", "#alpha")]
    );
    assert_eq!(
        reconcile_channel_entries(&mut state, user, vec![channel_row("libera", "#alpha")]),
        vec![ChannelTopicAction::Leave(kicked_topic)]
    );
    assert_eq!(
        state.windows.channel_entries,
        vec![channel_row("libera", "#alpha")]
    );
}

#[test]
fn pending_invited_and_failed_rows_survive_a_channel_list_refresh() {
    let user = "sythos";
    let mut state = WorkerState::new();
    state.networks.network_ids.insert("libera".to_string(), 7);
    for (channel, window_state) in [
        ("#pending", ChannelWindowState::Pending),
        ("#invited", ChannelWindowState::Invited),
        ("#failed", ChannelWindowState::Failed),
        ("#joined", ChannelWindowState::Joined),
    ] {
        state
            .windows
            .channel_entries
            .push(channel_row("libera", channel));
        state
            .windows
            .window_states
            .insert(window_state_key("libera", channel), window_state);
    }
    // A row of a network the account no longer has is not kept.
    state
        .windows
        .channel_entries
        .push(channel_row("gone", "#failed"));
    state.windows.window_states.insert(
        window_state_key("gone", "#failed"),
        ChannelWindowState::Failed,
    );

    reconcile_channel_entries(&mut state, user, vec![channel_row("libera", "#alpha")]);

    assert_eq!(
        state.windows.channel_entries,
        vec![
            channel_row("libera", "#alpha"),
            channel_row("libera", "#pending"),
            channel_row("libera", "#invited"),
            channel_row("libera", "#failed"),
        ]
    );
}

#[test]
fn network_refresh_keeps_kicked_failed_and_invited_windows_of_remaining_networks() {
    let user = "sythos";
    let mut state = WorkerState::new();
    state.conn.identifier = Some(user.to_string());
    state.networks.network_ids.insert("libera".to_string(), 7);
    state.networks.network_ids.insert("gone".to_string(), 9);
    let kicked = window_state_key("libera", "#kicked");
    let failed = window_state_key("libera", "#failed");
    let invited = window_state_key("libera", "#invited");
    let rejoined = window_state_key("libera", "#rejoined");
    let gone = window_state_key("gone", "#kicked");
    let kick = WindowKick {
        by: Some("ChanServ".to_string()),
        reason: Some("policy".to_string()),
    };
    let failure = WindowFailure {
        reason: Some("banned".to_string()),
        numeric: None,
    };
    for (key, window_state) in [
        (&kicked, ChannelWindowState::Kicked),
        (&failed, ChannelWindowState::Failed),
        (&invited, ChannelWindowState::Invited),
        (&rejoined, ChannelWindowState::Kicked),
        (&gone, ChannelWindowState::Kicked),
    ] {
        state
            .windows
            .window_states
            .insert(key.clone(), window_state);
        state
            .windows
            .channel_entries
            .push(channel_row(&key.0, &key.1));
    }
    state
        .windows
        .window_kicks
        .insert(kicked.clone(), kick.clone());
    state
        .windows
        .window_kicks
        .insert(rejoined.clone(), kick.clone());
    state
        .windows
        .window_kicks
        .insert(gone.clone(), kick.clone());
    state
        .windows
        .window_failures
        .insert(failed.clone(), failure.clone());
    state
        .windows
        .invited_by
        .insert(invited.clone(), "alice".to_string());
    let boot = BootResponse {
        networks: vec![serde_json::json!({"id": 7, "slug": "libera", "nick": "sythos"})],
        channels: HashMap::from([(
            "libera".to_string(),
            vec![serde_json::json!({"name": "#rejoined", "joined": true})],
        )]),
        heads: HashMap::new(),
    };

    apply_network_rest_refresh(&mut state, user, &boot, &empty_me());

    assert_eq!(
        state.windows.window_states.get(&kicked),
        Some(&ChannelWindowState::Kicked)
    );
    assert_eq!(state.windows.window_kicks.get(&kicked), Some(&kick));
    assert_eq!(
        state.windows.window_states.get(&failed),
        Some(&ChannelWindowState::Failed)
    );
    assert_eq!(state.windows.window_failures.get(&failed), Some(&failure));
    assert_eq!(
        state.windows.window_states.get(&invited),
        Some(&ChannelWindowState::Invited)
    );
    assert_eq!(
        state.windows.invited_by.get(&invited),
        Some(&"alice".to_string())
    );
    // The boot snapshot has the channel joined again: it wins.
    assert_eq!(
        state.windows.window_states.get(&rejoined),
        Some(&ChannelWindowState::Joined)
    );
    assert!(!state.windows.window_kicks.contains_key(&rejoined));
    // A removed network takes its windows with it.
    assert!(!state.windows.window_states.contains_key(&gone));
    assert!(!state.windows.window_kicks.contains_key(&gone));
    let mut rows = state.windows.channel_entries.clone();
    rows.sort();
    assert_eq!(
        rows,
        vec![
            channel_row("libera", "#failed"),
            channel_row("libera", "#invited"),
            channel_row("libera", "#kicked"),
            channel_row("libera", "#rejoined"),
        ]
    );
    for channel in ["#kicked", "#failed", "#invited"] {
        assert!(state
            .windows
            .channel_topics
            .contains(&channel_topic(user, "libera", channel)));
    }
}

#[test]
fn remove_sidebar_channel_entry_matches_only_network_and_ascii_folded_channel() {
    let mut entries = vec![
        (
            "libera".to_string(),
            "#cordiale".to_string(),
            "#cordiale".to_string(),
        ),
        (
            "other".to_string(),
            "#cordiale".to_string(),
            "#cordiale".to_string(),
        ),
        (
            "libera".to_string(),
            "#rust".to_string(),
            "#rust".to_string(),
        ),
    ];

    assert!(remove_sidebar_channel_entry(
        &mut entries,
        "libera",
        "#CoRdIaLe"
    ));
    assert_eq!(
        entries,
        vec![
            (
                "other".to_string(),
                "#cordiale".to_string(),
                "#cordiale".to_string()
            ),
            (
                "libera".to_string(),
                "#rust".to_string(),
                "#rust".to_string()
            )
        ]
    );
    assert!(!remove_sidebar_channel_entry(
        &mut entries,
        "libera",
        "#cordiale"
    ));
}

#[test]
fn render_message_reads_the_message_envelopes_inner_row() {
    // `handle_frame` unwraps `payload.message` before calling this —
    // this test locks in what that inner row looks like, confirmed
    // via a real live frame: {"kind": "message", "message": {"kind":
    // "privmsg", "sender", "body", ...}}.
    let inner = serde_json::json!({
        "kind": "privmsg",
        "sender": "vjt",
        "body": "hello from the real channel",
        "channel": "#grappa",
        "network": "azzurra",
        "id": 40172,
    });
    let rendered = render_message(&inner, None);
    assert_eq!(rendered.nick.as_deref(), Some("vjt"));
    assert_eq!(rendered.text, "hello from the real channel");
    assert!(!rendered.italic);
}

#[test]
fn render_message_reads_part_quit_and_kick_reasons_from_the_body() {
    let part = serde_json::json!({"kind": "part", "sender": "vjt", "body": "bye"});
    assert_eq!(render_message(&part, None).text, "← vjt left (bye)");
    let quit = serde_json::json!({"kind": "quit", "sender": "vjt", "body": ""});
    assert_eq!(render_message(&quit, None).text, "⇐ vjt quit");

    let kick = serde_json::json!({
        "kind": "kick",
        "sender": "op",
        "body": null,
        "meta": {"target": "spammer"}
    });
    let rendered = render_message(&kick, None);
    assert_eq!(rendered.text, "⊘ spammer was kicked by op");
    assert!(rendered.italic);
    let kick_with_reason = serde_json::json!({
        "kind": "kick",
        "sender": "op",
        "body": "flood",
        "meta": {"target": "spammer"}
    });
    assert_eq!(
        render_message(&kick_with_reason, None).text,
        "⊘ spammer was kicked by op (flood)"
    );
}

#[test]
fn render_message_formats_topic_and_server_events() {
    let topic = serde_json::json!({"kind": "topic", "sender": "vjt", "body": "Rust talk"});
    assert_eq!(
        render_message(&topic, None).text,
        "* vjt changed the topic to: Rust talk"
    );
    let cleared = serde_json::json!({"kind": "topic", "sender": "vjt", "body": ""});
    assert_eq!(
        render_message(&cleared, None).text,
        "* vjt cleared the topic"
    );

    let server_event = serde_json::json!({
        "kind": "server_event",
        "sender": "irc.example.org",
        "body": "Server going down"
    });
    let rendered = render_message(&server_event, None);
    assert_eq!(rendered.nick.as_deref(), Some("irc.example.org"));
    assert_eq!(rendered.text, "Server going down");
    assert!(rendered.italic);
}

#[test]
fn chat_nick_prefix_follows_the_current_channel_roster() {
    use cordiale_core::isupport::CaseMapping;

    let message = render_message(
        &serde_json::json!({"kind": "privmsg", "sender": "{alice}", "body": "hello"}),
        None,
    );
    let messages = vec![message];
    let mut members = vec![("[Alice]".to_string(), "@".to_string())];
    let original_nick = messages[0].nick.clone();

    let op = chat_lines_model_with_roster(&messages, false, &members, CaseMapping::Rfc1459, false);
    assert_eq!(op[0].nick.to_string(), "{alice}");
    assert_eq!(op[0].nick_prefix.to_string(), "@");

    members[0].1 = "+".to_string();
    let voice =
        chat_lines_model_with_roster(&messages, false, &members, CaseMapping::Rfc1459, false);
    assert_eq!(voice[0].nick_prefix.to_string(), "+");
    assert_eq!(messages[0].nick, original_nick);

    let ascii = chat_lines_model_with_roster(&messages, false, &members, CaseMapping::Ascii, false);
    assert_eq!(ascii[0].nick_prefix.to_string(), "");
    let query = chat_lines_model(&messages, false);
    assert_eq!(query[0].nick_prefix.to_string(), "");
}

fn presence_row(kind: &str) -> RenderedMessage {
    render_message(
        &serde_json::json!({"kind": kind, "sender": "alice", "body": "x", "id": 1}),
        None,
    )
}

#[test]
fn rendered_rows_know_whether_denoise_hides_them() {
    for kind in ["join", "part", "quit", "nick_change", "mode"] {
        assert!(presence_row(kind).presence_noise, "{kind}");
    }
    for kind in [
        "privmsg",
        "notice",
        "action",
        "topic",
        "kick",
        "server_event",
    ] {
        assert!(!presence_row(kind).presence_noise, "{kind}");
    }
    let structural = render_message(
        &serde_json::json!({"kind": "mode", "sender": "op", "meta": {"modes": "+b", "structural": true}}),
        None,
    );
    assert!(!structural.presence_noise);
    let status = render_message(
        &serde_json::json!({"kind": "mode", "sender": "op", "meta": {"modes": "+o", "structural": "yes"}}),
        None,
    );
    assert!(status.presence_noise);
}

#[test]
fn denoise_leaves_the_lines_out_of_the_model_but_keeps_them_stored() {
    use cordiale_core::isupport::CaseMapping;

    let messages = vec![
        presence_row("join"),
        presence_row("privmsg"),
        presence_row("quit"),
    ];
    let hidden = chat_lines_model_with_roster(&messages, false, &[], CaseMapping::Rfc1459, true);
    assert_eq!(hidden.len(), 1);
    assert_eq!(hidden[0].reply_body.to_string(), "x");
    let shown = chat_lines_model_with_roster(&messages, false, &[], CaseMapping::Rfc1459, false);
    assert_eq!(shown.len(), 3);
    assert_eq!(messages.len(), 3);
}

#[test]
fn denoise_follows_the_choice_then_the_channel_size() {
    let mut state = WorkerState::new();
    state.prefs.presence_pins.clear();
    let key = ("libera".to_string(), "#Rust".to_string());
    assert!(!state.denoise_active(&key));

    state.transcript.members.insert(
        key.clone(),
        vec![("nick".to_string(), String::new()); cordiale_core::presence::LARGE_CHANNEL_THRESHOLD],
    );
    assert!(state.denoise_active(&key));

    state
        .prefs
        .presence_pins
        .insert("libera #rust".to_string(), PresencePref::Show);
    assert!(!state.denoise_active(&key));

    state.transcript.members.remove(&key);
    state
        .prefs
        .presence_pins
        .insert("libera #rust".to_string(), PresencePref::Hide);
    assert!(state.denoise_active(&key));
    assert!(!state.denoise_active(&("libera".to_string(), "#other".to_string())));
}

#[test]
fn a_live_presence_line_reaches_the_transcript_only_without_denoise() {
    let mut state = WorkerState::new();
    state.prefs.presence_pins.clear();
    let key = ("libera".to_string(), "#rust".to_string());
    let join = presence_row("join");
    let chat = presence_row("privmsg");
    assert!(state.transcript_shows(&key, &join));

    state
        .prefs
        .presence_pins
        .insert("libera #rust".to_string(), PresencePref::Hide);
    assert!(!state.transcript_shows(&key, &join));
    assert!(state.transcript_shows(&key, &chat));

    state
        .prefs
        .presence_pins
        .insert("libera #rust".to_string(), PresencePref::Show);
    assert!(state.transcript_shows(&key, &join));
}

#[test]
fn theme_choices_need_a_complete_palette() {
    let builtins = builtin_theme_choices();
    assert_eq!(builtins[0].key, "builtin:irssi-dark");
    assert!(builtins.iter().any(|choice| choice.key == "builtin:sux"));

    let mut colors: HashMap<String, String> = HashMap::new();
    for (index, key) in cordiale_core::theme::BASE_COLOR_KEYS.iter().enumerate() {
        colors.insert(key.to_string(), format!("#{:02x}0000", index));
    }
    for index in 0..16 {
        colors.insert(format!("nick_{index}"), "#00ff00".to_string());
    }
    let mut theme = cordiale_core::rest::ThemeWire {
        id: 12,
        name: "custom".to_string(),
        author: "vjt".to_string(),
        built_in: false,
        payload: cordiale_core::rest::ThemePayloadWire {
            colors,
            font_family: "hack".to_string(),
            background: None,
        },
        mine: true,
        published: false,
    };
    let choice = server_theme_choice(&theme).expect("complete palette");
    assert_eq!(choice.key, "server:12");
    assert_eq!(choice.font_family, "hack");

    theme.payload.colors.remove("bg");
    assert!(server_theme_choice(&theme).is_none());
}

#[test]
fn widest_sidebar_label_picks_the_longest_row() {
    let channels = vec![
        ChannelEntry {
            label: "#rust".into(),
            ..Default::default()
        },
        ChannelEntry {
            label: "#a-much-longer-channel".into(),
            mention_badge: " (2)".into(),
            ..Default::default()
        },
    ];
    let groups = vec![
        NetworkGroup {
            network: "libera".into(),
            channels: Rc::new(slint::VecModel::from(channels)).into(),
            ..Default::default()
        },
        NetworkGroup {
            network: "azzurra".into(),
            parked: true,
            ..Default::default()
        },
    ];
    assert_eq!(widest_sidebar_label(&groups), "#a-much-longer-channel (2)");
    assert_eq!(widest_sidebar_label(&[]), "");
}

#[test]
fn members_average_probe_counts_the_bracketed_prefix() {
    assert_eq!(members_average_probe(&[]), "");
    let rows = vec![
        MemberRow {
            name: "Sythos".into(),
            prefix: "@".into(),
            ..Default::default()
        },
        MemberRow {
            name: "vjt".into(),
            ..Default::default()
        },
    ];
    // "[@] Sythos" is 10 characters and "vjt" 3: the average rounds up to 7.
    assert_eq!(members_average_probe(&rows), "nnnnnnn");
}

#[test]
fn away_delay_text_round_trips() {
    assert_eq!(away_delay_text(None), "");
    assert_eq!(away_delay_text(Some(0)), "0");
    assert_eq!(parse_away_delay(" "), Ok(None));
    assert_eq!(parse_away_delay("300"), Ok(Some(300)));
    assert_eq!(parse_away_delay("0"), Ok(Some(0)));
    assert_eq!(parse_away_delay("-5"), Err(()));
    assert_eq!(parse_away_delay("soon"), Err(()));
    assert_eq!(AutoAwayDebounce::Disabled.edit_text(), "0");
    assert_eq!(AutoAwayDebounce::ServerDefault.edit_text(), "");
}

#[test]
fn upload_ttl_menu_maps_both_ways() {
    assert_eq!(upload_ttl_for_index(0), None);
    assert_eq!(upload_ttl_for_index(3), Some(86_400));
    assert_eq!(upload_ttl_for_index(9), None);
    assert_eq!(upload_ttl_for_index(-1), None);
    assert_eq!(upload_ttl_index(Some(43_200)), 2);
    assert_eq!(upload_ttl_index(Some(7)), 0);
    assert_eq!(upload_ttl_index(None), 0);
}

#[test]
fn window_note_explains_a_kick_or_a_failed_join() {
    let mut state = WorkerState::new();
    assert_eq!(window_note(&state), ("", String::new(), String::new()));
    state.windows.current_channel = Some(("libera".to_string(), "#Rust".to_string()));
    state.windows.window_kicks.insert(
        window_state_key("libera", "#Rust"),
        WindowKick {
            by: Some("op".to_string()),
            reason: None,
        },
    );
    assert_eq!(
        window_note(&state),
        ("kicked", "op".to_string(), String::new())
    );
    state.windows.window_kicks.clear();
    state.windows.window_failures.insert(
        window_state_key("libera", "#rust"),
        WindowFailure {
            reason: None,
            numeric: Some(Number::from(474)),
        },
    );
    assert_eq!(
        window_note(&state),
        ("failed", String::new(), "474".to_string())
    );
    state.windows.current_query = true;
    assert_eq!(window_note(&state), ("", String::new(), String::new()));
}

#[test]
fn notification_toggles_keep_the_rest_of_the_map() {
    let mut prefs = serde_json::json!({
        "channel_mentions": true,
        "channel_messages_only": ["#rust"],
        "notification_sound": "chime"
    })
    .as_object()
    .cloned()
    .unwrap();
    let toggles = NotificationToggles::from_prefs(&prefs);
    assert!(toggles.channel_mentions && toggles.private_messages_all);
    assert!(!toggles.presence_online);
    NotificationToggles {
        presence_online: true,
        ..toggles
    }
    .apply_to(&mut prefs);
    assert_eq!(prefs["presence_online"], serde_json::json!(true));
    assert_eq!(prefs["private_messages_all"], serde_json::json!(true));
    assert_eq!(prefs["notification_sound"], serde_json::json!("chime"));
    assert_eq!(prefs["channel_messages_only"], serde_json::json!(["#rust"]));
}

#[test]
fn only_refused_user_topic_commands_are_reported() {
    let frame = |topic: &str, message_ref: Option<&str>, payload: Value| {
        cordiale_core::phoenix::PhoenixMessage {
            join_ref: Some("1".to_string()),
            message_ref: message_ref.map(str::to_string),
            topic: topic.to_string(),
            event: "phx_reply".to_string(),
            payload,
        }
    };
    let refused = serde_json::json!({"status": "error", "response": {"error": "no_session"}});
    assert_eq!(
        command_error_reason(&frame("grappa:user:vjt", Some("7"), refused.clone()), "vjt"),
        Some("no_session".to_string())
    );
    // The join reply, other topics and successes are not command errors.
    assert_eq!(
        command_error_reason(&frame("grappa:user:vjt", Some("1"), refused.clone()), "vjt"),
        None
    );
    assert_eq!(
        command_error_reason(&frame("grappa:user:other", Some("7"), refused), "vjt"),
        None
    );
    assert_eq!(
        command_error_reason(
            &frame(
                "grappa:user:vjt",
                Some("7"),
                serde_json::json!({"status": "ok", "response": {}})
            ),
            "vjt"
        ),
        None
    );
    assert_eq!(
        command_error_reason(
            &frame(
                "grappa:user:vjt",
                Some("8"),
                serde_json::json!({"status": "error"})
            ),
            "vjt"
        ),
        Some("error".to_string())
    );
}

#[test]
fn fan_out_reaches_only_joined_channels_of_the_network() {
    let mut state = WorkerState::new();
    state.windows.channel_entries = vec![
        ("libera".to_string(), "#a".to_string(), String::new()),
        ("libera".to_string(), "#b".to_string(), String::new()),
        ("oftc".to_string(), "#c".to_string(), String::new()),
    ];
    for (network, channel) in [("libera", "#a"), ("oftc", "#c")] {
        state.windows.window_states.insert(
            window_state_key(network, channel),
            ChannelWindowState::Joined,
        );
    }
    assert_eq!(joined_channels(&state, "libera"), vec!["#a".to_string()]);
}

#[test]
fn vhost_rows_name_their_grants() {
    let (vhosts, grants) = admin_vhost_rows(&serde_json::json!({
        "vhosts": [{"id": 4, "address": "10.0.0.4", "in_pool": true}],
        "grants": [{"id": 9, "vhost_id": 4, "subject_label": "ada"}]
    }));
    assert_eq!(
        vhosts,
        vec![("10.0.0.4 · pool".to_string(), "4".to_string(), true, false)]
    );
    assert_eq!(
        grants,
        vec![("10.0.0.4 → ada".to_string(), "9".to_string())]
    );
}

#[test]
fn admin_settings_round_trip_and_leave_addressing_alone() {
    let loaded = serde_json::json!({
        "upload": {"active_host": "litterbox", "image_per_file_cap_bytes": 10485760},
        "dcc": {"max_transfer_bytes": 1048576},
        "addressing": {"mode": "pool_with_reservations", "static_mapping_prefix": null}
    });
    let mut form = admin_settings_form(&loaded);
    assert_eq!(form.host_index, 1);
    assert_eq!(form.sizes[0], "10");
    assert_eq!(form.sizes[7], "1");
    form.sizes[7] = "2".to_string();
    let body = admin_settings_body(&form, Some(&loaded)).expect("valid");
    assert_eq!(body["dcc"]["max_transfer_bytes"], 2 * 1024 * 1024);
    assert_eq!(body["upload"]["active_host"], "litterbox");
    assert!(body.get("addressing").is_none());
    form.mode_index = 1;
    form.prefix = "64".to_string();
    let body = admin_settings_body(&form, Some(&loaded)).expect("valid");
    assert_eq!(
        body["addressing"]["mode"],
        "static_mapping_with_reservations"
    );
    form.sizes[0] = "-1".to_string();
    assert!(admin_settings_body(&form, Some(&loaded)).is_none());
}

#[test]
fn a_refused_admin_write_is_told_apart() {
    assert_eq!(admin_failure_kind(Some(403), false), "admin-forbidden");
    assert_eq!(admin_failure_kind(Some(403), true), "admin-forbidden");
    assert_eq!(admin_failure_kind(Some(409), true), "admin-network-in-use");
    // A 409 elsewhere is a duplicate, not a network in use.
    assert_eq!(admin_failure_kind(Some(409), false), "admin-action-failed");
    assert_eq!(admin_failure_kind(Some(422), false), "admin-action-failed");
    assert_eq!(admin_failure_kind(None, true), "admin-action-failed");
}

#[test]
fn kickban_mask_needs_a_resolved_host() {
    assert_eq!(
        kickban_mask(&serde_json::json!({
            "status": "ok",
            "response": {"user": "~u", "host": "spam.example"}
        })),
        Some("*!*@spam.example".to_string())
    );
    assert_eq!(
        kickban_mask(&serde_json::json!({
            "status": "error",
            "response": {"error": "not_cached"}
        })),
        None
    );
}

#[test]
fn mentions_follow_cicchettos_word_rule() {
    let context = MentionContext {
        own_nick: Some("Sythos".to_string()),
        patterns: vec!["cordiale".to_string(), "c++".to_string()],
    };
    assert!(is_mention("hey sythos, ping", Some("ada"), &context));
    assert!(is_mention("\u{2}Sythos\u{2}: look", Some("ada"), &context));
    assert!(!is_mention("sythosian ideas", Some("ada"), &context));
    assert!(!is_mention("sythos said hi", Some("SYTHOS"), &context));
    assert!(is_mention("the Cordiale client", None, &context));
    assert!(is_mention("I like c++.", Some("ada"), &context));
    assert!(!is_mention(
        "anything",
        Some("ada"),
        &MentionContext::default()
    ));
    assert!(contains_word("a_b sythos", "sythos"));
    assert!(!contains_word("a_sythos", "sythos"));
}

#[test]
fn chat_links_become_markdown_links() {
    let markdown = linked_markdown("see https://x.io/a_b. now");
    assert!(markdown.starts_with("see ["));
    assert!(markdown.contains("](<https://x.io/a_b>)"));
    assert!(markdown.ends_with(". now"));
    assert!(slint::StyledText::from_markdown(&markdown).is_ok());
    let runs = vec![("www.rust-lang.org!".to_string(), (0, 0, 0), true)];
    let bold = message_markdown(&runs, false);
    assert!(bold.contains("**["));
    assert!(bold.contains("](<https://www.rust-lang.org>)"));
    assert!(slint::StyledText::from_markdown(&bold).is_ok());
}

#[test]
fn theme_backgrounds_resolve_like_cicchetto() {
    use cordiale_core::rest::ThemeBackgroundWire;
    let builtin = ThemeBackgroundWire {
        builtin: Some("aurora".to_string()),
        image_id: Some("01hzzzzzzzzzzzzzzzzzzzzzzz".to_string()),
        size: Some("repeat".to_string()),
        opacity: serde_json::Number::from_f64(0.35),
    };
    assert_eq!(
        theme_background(Some(&builtin)),
        Some(ThemeBackground {
            path: "/backgrounds/aurora.webp".to_string(),
            tile: true,
            opacity: 35,
        })
    );
    let upload = ThemeBackgroundWire {
        image_id: Some("01habc".to_string()),
        ..ThemeBackgroundWire::default()
    };
    let resolved = theme_background(Some(&upload)).expect("an upload");
    assert_eq!(resolved.path, "/uploads/01habc");
    assert!(!resolved.tile);
    assert_eq!(resolved.opacity, 100);
    let unsafe_key = ThemeBackgroundWire {
        builtin: Some("../etc".to_string()),
        ..ThemeBackgroundWire::default()
    };
    assert_eq!(theme_background(Some(&unsafe_key)), None);
    assert_eq!(theme_background(None), None);
}

#[test]
fn avatar_extension_follows_the_content_type() {
    assert_eq!(avatar_extension(Some("image/png")), Some("png"));
    assert_eq!(
        avatar_extension(Some("image/jpeg; charset=binary")),
        Some("jpg")
    );
    assert_eq!(avatar_extension(Some("image/webp")), Some("webp"));
    assert_eq!(avatar_extension(Some("image/gif")), Some("gif"));
    assert_eq!(avatar_extension(Some("image/svg+xml")), None);
    assert_eq!(avatar_extension(None), None);
}

#[test]
fn message_markdown_escapes_text_and_keeps_every_run() {
    let runs = vec![
        (
            "# 1. *not* <b>markup</b> & [x](y) ".to_string(),
            (255, 0, 0),
            false,
        ),
        ("bold!".to_string(), (0, 0, 0), true),
        ("   ".to_string(), (0, 0, 0), false),
        ("- tail_\u{e541}".to_string(), (0, 128, 0), false),
    ];
    let markdown = message_markdown(&runs, false);
    assert!(markdown.starts_with("<font color=\"#ff0000\">\\# 1\\. \\*not\\*"));
    assert!(markdown.contains("<font color=\"#000000\">**bold\\!**</font>"));
    assert!(!markdown.contains('\u{e541}'));
    assert!(slint::StyledText::from_markdown(&markdown).is_ok());
    let italic = message_markdown(&runs, true);
    assert!(italic.contains("***bold\\!***"));
    assert!(slint::StyledText::from_markdown(&italic).is_ok());
    let multiline = message_markdown(&[("a\n    b".to_string(), (0, 0, 0), false)], false);
    assert!(slint::StyledText::from_markdown(&multiline).is_ok());
}

#[test]
fn member_prefixes_keep_every_role_highest_first() {
    let order: Vec<String> = ["@", "%", "+"].iter().map(|s| s.to_string()).collect();
    assert_eq!(update_member_prefix("+", "@", true, &order), "@+");
    assert_eq!(update_member_prefix("@+", "@", false, &order), "+");
    assert_eq!(update_member_prefix("@", "@", true, &order), "@");
    assert_eq!(highest_prefix("@+"), "@");
    assert_eq!(highest_prefix(""), "");
    assert_eq!(
        member_from_entry(&serde_json::json!("@+ada"), &order, None),
        Some(("ada".to_string(), "@+".to_string()))
    );
}

#[test]
fn member_from_entry_reads_sigils_from_modes() {
    // Real wire shape: `modes` holds role sigils (`~&@%+`), not mode
    // letters — see Grappa's `Session.Wire.member/1`. Fall back to the
    // default `~&@%+` order, same as before any ISUPPORT snapshot.
    let order = cordiale_core::isupport::prefix_symbol_order(None);
    assert_eq!(
        member_from_entry(
            &serde_json::json!({"nick": "bob", "modes": ["+", "@"]}),
            &order,
            None
        ),
        Some(("bob".to_string(), "@+".to_string()))
    );
    assert_eq!(
        member_from_entry(
            &serde_json::json!({"nick": "ann", "modes": []}),
            &order,
            None
        ),
        Some(("ann".to_string(), String::new()))
    );
    assert_eq!(
        member_from_entry(
            &serde_json::json!({"nick": "eve", "modes": ["~"]}),
            &order,
            None
        ),
        Some(("eve".to_string(), "~".to_string()))
    );
    // Mode letters are still accepted for backwards compatibility.
    assert_eq!(
        member_from_entry(
            &serde_json::json!({"nick": "cy", "modes": ["v", "o"]}),
            &order,
            None
        ),
        Some(("cy".to_string(), "@+".to_string()))
    );
    // Unknown entries in `modes` are ignored rather than kept verbatim.
    assert_eq!(
        member_from_entry(
            &serde_json::json!({"nick": "gus", "modes": ["x"]}),
            &order,
            None
        ),
        Some(("gus".to_string(), String::new()))
    );
}

#[test]
fn member_from_entry_maps_owner_and_admin_letters_before_a_snapshot() {
    let order = cordiale_core::isupport::prefix_symbol_order(None);
    assert_eq!(
        member_from_entry(
            &serde_json::json!({"nick": "own", "modes": ["o", "a", "q"]}),
            &order,
            None
        ),
        Some(("own".to_string(), "~&@".to_string()))
    );
}

/// A snapshot whose PREFIX holds exactly these `(letter, symbol)` pairs,
/// highest first.
fn network_with_prefix(pairs: &[(&str, &str)]) -> IsupportState {
    let mut state = parse_isupport_changed(&isupport_payload(7, "rfc1459", 4096))
        .expect("valid snapshot")
        .state;
    state.prefix = pairs
        .iter()
        .map(|(letter, symbol)| (letter.to_string(), symbol.to_string()))
        .collect();
    state.prefix_order = pairs.iter().map(|(letter, _)| letter.to_string()).collect();
    state
}

/// Seeds `entries` through `members_seeded` on a network with this
/// snapshot and returns the stored roster.
fn seeded_roster(isupport: &IsupportState, entries: Value) -> Vec<MemberEntry> {
    let mut state = WorkerState::new();
    state
        .networks
        .isupport_by_network
        .insert("net".to_string(), isupport.clone());
    let key = apply_members_seeded(
        &mut state,
        &serde_json::json!({"network": "net", "channel": "#c", "members": entries}),
    )
    .expect("members_seeded applies");
    state
        .transcript
        .members
        .get(&key)
        .cloned()
        .unwrap_or_default()
}

fn roster(pairs: &[(&str, &str)]) -> Vec<MemberEntry> {
    pairs
        .iter()
        .map(|(name, prefix)| (name.to_string(), prefix.to_string()))
        .collect()
}

#[test]
fn member_roles_on_a_full_prefix_ladder() {
    let network =
        network_with_prefix(&[("q", "~"), ("a", "&"), ("o", "@"), ("h", "%"), ("v", "+")]);
    let members = seeded_roster(
        &network,
        serde_json::json!([
            {"nick": "zed", "modes": []},
            {"nick": "vic", "modes": ["+"]},
            {"nick": "hal", "modes": ["h"]},
            {"nick": "opy", "modes": ["+", "o"]},
            {"nick": "adm", "modes": ["&"]},
            {"nick": "own", "modes": ["q"]},
        ]),
    );
    assert_eq!(
        members,
        roster(&[
            ("own", "~"),
            ("adm", "&"),
            ("opy", "@+"),
            ("hal", "%"),
            ("vic", "+"),
            ("zed", ""),
        ])
    );
    let ranking = MemberRanking::new(Some(&network));
    for (nick, can_moderate) in [
        ("own", true),
        ("adm", true),
        ("opy", true),
        ("hal", false),
        ("vic", false),
        ("zed", false),
    ] {
        assert_eq!(
            is_own_nick_an_op(&members, nick, &ranking),
            can_moderate,
            "{nick}"
        );
    }
    let shown: Vec<&str> = members
        .iter()
        .map(|(_, prefix)| highest_prefix(prefix))
        .collect();
    assert_eq!(shown, ["~", "&", "@", "%", "+", ""]);
}

#[test]
fn member_roles_on_an_ohv_network_drop_levels_it_lacks() {
    let network = network_with_prefix(&[("o", "@"), ("h", "%"), ("v", "+")]);
    let members = seeded_roster(
        &network,
        serde_json::json!([
            {"nick": "own", "modes": ["~"]},
            {"nick": "qq", "modes": ["q"]},
            {"nick": "hal", "modes": ["%"]},
            {"nick": "opy", "modes": ["o"]},
        ]),
    );
    assert_eq!(
        members,
        roster(&[("opy", "@"), ("hal", "%"), ("own", ""), ("qq", "")])
    );
    let ranking = MemberRanking::new(Some(&network));
    assert!(is_own_nick_an_op(&members, "opy", &ranking));
    assert!(!is_own_nick_an_op(&members, "hal", &ranking));
    assert!(!is_own_nick_an_op(&members, "own", &ranking));
}

#[test]
fn member_roles_on_an_ov_network() {
    let network = network_with_prefix(&[("o", "@"), ("v", "+")]);
    let members = seeded_roster(
        &network,
        serde_json::json!([
            {"nick": "cy", "modes": ["h"]},
            {"nick": "ann", "modes": ["v"]},
            {"nick": "bob", "modes": ["@"]},
        ]),
    );
    assert_eq!(members, roster(&[("bob", "@"), ("ann", "+"), ("cy", "")]));
    let ranking = MemberRanking::new(Some(&network));
    assert!(is_own_nick_an_op(&members, "bob", &ranking));
    assert!(!is_own_nick_an_op(&members, "ann", &ranking));
    // `~` is not a role here, so it never reaches the moderation gate.
    assert!(!ranking.is_op_or_above("~"));
    let order = cordiale_core::isupport::prefix_symbol_order(Some(&network));
    assert_eq!(
        member_from_entry(&serde_json::json!("~@ada"), &order, Some(&network)),
        Some(("~@ada".to_string(), String::new()))
    );
}

#[test]
fn member_roles_on_a_network_with_an_extra_sigil() {
    let network = network_with_prefix(&[
        ("Y", "!"),
        ("q", "~"),
        ("a", "&"),
        ("o", "@"),
        ("h", "%"),
        ("v", "+"),
    ]);
    let members = seeded_roster(
        &network,
        serde_json::json!([
            {"nick": "plain", "modes": []},
            {"nick": "vic", "modes": ["+"]},
            {"nick": "opy", "modes": ["@"]},
            {"nick": "own", "modes": ["q"]},
            {"nick": "boss", "modes": ["~", "!"]},
            {"nick": "lord", "modes": ["Y"]},
            {"nick": "odd", "modes": ["x"]},
        ]),
    );
    assert_eq!(
        members,
        roster(&[
            ("boss", "!~"),
            ("lord", "!"),
            ("own", "~"),
            ("opy", "@"),
            ("vic", "+"),
            ("odd", ""),
            ("plain", ""),
        ])
    );
    assert_eq!(highest_prefix(&members[0].1), "!");
    let ranking = MemberRanking::new(Some(&network));
    assert!(is_own_nick_an_op(&members, "boss", &ranking));
    assert!(is_own_nick_an_op(&members, "lord", &ranking));
    assert!(is_own_nick_an_op(&members, "opy", &ranking));
    assert!(!is_own_nick_an_op(&members, "vic", &ranking));
    assert!(!ranking.is_op_or_above("x"));

    let order = cordiale_core::isupport::prefix_symbol_order(Some(&network));
    assert_eq!(
        member_from_entry(&serde_json::json!("!~@ada"), &order, Some(&network)),
        Some(("ada".to_string(), "!~@".to_string()))
    );

    // A live MODE grants the extra level and the member sorts above the ops.
    let key = ("net".to_string(), "#c".to_string());
    let mut state = WorkerState::new();
    state
        .networks
        .isupport_by_network
        .insert("net".to_string(), network);
    state
        .transcript
        .members
        .insert(key.clone(), roster(&[("opy", "@"), ("vic", "+")]));
    let mode = serde_json::json!({
        "kind": "mode",
        "meta": {"modes": "+Y", "args": ["vic"]}
    });
    assert!(update_members_from_frame(&mut state, &key, &mode));
    assert_eq!(
        state.transcript.members.get(&key),
        Some(&roster(&[("vic", "!+"), ("opy", "@")]))
    );
}

#[test]
fn live_mode_grants_owner_before_a_snapshot() {
    let key = ("net".to_string(), "#c".to_string());
    let mut state = WorkerState::new();
    state
        .transcript
        .members
        .insert(key.clone(), roster(&[("ann", ""), ("bob", "@")]));
    let mode = serde_json::json!({
        "kind": "mode",
        "meta": {"modes": "+q", "args": ["ann"]}
    });
    assert!(update_members_from_frame(&mut state, &key, &mode));
    assert_eq!(
        state.transcript.members.get(&key),
        Some(&roster(&[("ann", "~"), ("bob", "@")]))
    );
}

#[test]
fn sort_members_by_rank_groups_by_role_then_alphabetically() {
    let mut members: Vec<MemberEntry> = vec![
        ("bob".to_string(), String::new()),
        ("Zoe".to_string(), "@".to_string()),
        ("ada".to_string(), "@".to_string()),
        ("cy".to_string(), "+".to_string()),
        ("Hal".to_string(), "%".to_string()),
        ("root".to_string(), "~".to_string()),
        ("Amy".to_string(), String::new()),
    ];
    let order = cordiale_core::isupport::prefix_symbol_order(None);
    sort_members_by_rank(&mut members, &order);
    let names: Vec<&str> = members.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["root", "ada", "Zoe", "Hal", "cy", "Amy", "bob"]);
}

#[test]
fn theme_pair_follows_the_system_scheme() {
    let mut themes = builtin_theme_choices().into_iter();
    let day = themes.next().expect("a built-in theme");
    let night = themes.next().expect("a second built-in theme");
    let single = (day.clone(), None);
    assert_eq!(pair_theme_for(&single, true).key, day.key);
    let pair = (day.clone(), Some(night.clone()));
    assert_eq!(pair_theme_for(&pair, false).key, day.key);
    assert_eq!(pair_theme_for(&pair, true).key, night.key);
}

#[test]
fn umode_rows_follow_the_advertised_set() {
    let strings = |letters: &[&str]| -> Vec<String> {
        letters.iter().map(|letter| letter.to_string()).collect()
    };
    let rows = umode_rows(&strings(&["r", "i"]), &strings(&["o", "i", "w"]));
    assert_eq!(
        rows,
        vec![
            ("i".to_string(), true, true),
            ("w".to_string(), true, false),
            ("o".to_string(), false, false),
            ("r".to_string(), false, true),
        ]
    );
    let fallback = umode_rows(&[], &[]);
    assert_eq!(fallback.len(), KNOWN_UMODES.len());
    assert!(fallback[..SETTABLE_UMODES.len()].iter().all(|row| row.1));
}

#[test]
fn current_mute_reads_permanent_and_timed_entries() {
    let prefs = serde_json::json!({
        "muted_targets": {
            "libera #rust": {"until": null},
            "libera #slint": {"until": 5_000},
            "libera #bare": {},
            "libera #old": {"until": 900},
            "libera #bad": {"until": "soon"},
            "libera #flat": null
        }
    })
    .as_object()
    .cloned()
    .unwrap();
    let none = std::collections::BTreeMap::new();
    let mute = |key: &str| current_mute(&prefs, key, &none, 1_000);
    assert_eq!(
        mute("libera #rust"),
        Some(MuteBar {
            key: "libera #rust".to_string(),
            since: None,
            until: None
        })
    );
    assert_eq!(mute("libera #slint").unwrap().until, Some(5_000));
    assert_eq!(mute("libera #bare").unwrap().until, None);
    assert_eq!(mute("libera #old"), None);
    assert_eq!(mute("libera #bad"), None);
    assert_eq!(mute("libera #flat"), None);
    assert_eq!(mute("libera #missing"), None);
    assert_eq!(
        current_mute(&serde_json::Map::new(), "libera #rust", &none, 1),
        None
    );
}

#[test]
fn current_mute_uses_the_local_record_only_when_it_fits() {
    let prefs = serde_json::json!({
        "muted_targets": {
            "libera #rust": {"until": null},
            "libera #slint": {"until": 5_000}
        }
    })
    .as_object()
    .cloned()
    .unwrap();
    let since = |key: &str, at: i64| std::collections::BTreeMap::from([(key.to_string(), at)]);
    let found = |key: &str, at: i64| current_mute(&prefs, key, &since(key, at), 1_000);
    assert_eq!(found("libera #rust", 400).unwrap().since, Some(400));
    assert_eq!(found("libera #slint", 400).unwrap().since, Some(400));
    // From the future, or not before the end of the mute: not believed.
    assert_eq!(found("libera #rust", 1_001).unwrap().since, None);
    assert_eq!(found("libera #slint", 5_000).unwrap().since, None);
    // The record of another conversation is not this one's.
    assert_eq!(
        current_mute(&prefs, "libera #rust", &since("libera #slint", 400), 1_000)
            .unwrap()
            .since,
        None
    );
}

#[test]
fn mute_lookup_folds_the_target_like_the_stored_key() {
    let prefs = serde_json::json!({"muted_targets": {"libera #rust": {"until": null}}})
        .as_object()
        .cloned()
        .unwrap();
    let none = std::collections::BTreeMap::new();
    let key = muted_key("libera", "#RUST");
    assert_eq!(key, "libera #rust");
    assert!(current_mute(&prefs, &key, &none, 1).is_some());
}

#[test]
fn mute_remaining_rounds_up_and_switches_to_hours_after_an_hour() {
    assert_eq!(mute_remaining(100, 100), None);
    assert_eq!(mute_remaining(100, 200), None);
    assert_eq!(mute_remaining(101, 100), Some((0, 1)));
    assert_eq!(mute_remaining(160, 100), Some((0, 1)));
    assert_eq!(mute_remaining(161, 100), Some((0, 2)));
    assert_eq!(mute_remaining(3_599 + 100, 100), Some((0, 60)));
    assert_eq!(mute_remaining(3_600 + 100, 100), Some((0, 60)));
    assert_eq!(mute_remaining(3_601 + 100, 100), Some((1, 1)));
    assert_eq!(mute_remaining(7_200 + 100, 100), Some((2, 0)));
    assert_eq!(mute_remaining(28_800 + 100, 100), Some((8, 0)));
    assert_eq!(
        mute_remaining(i64::MAX, 0),
        Some((i32::MAX / 60, i32::MAX % 60))
    );
}

#[test]
fn local_clock_time_is_hours_and_minutes() {
    let text = local_clock_time(1_700_000_000);
    assert_eq!(text.len(), 5);
    assert_eq!(text.as_bytes()[2], b':');
    assert_eq!(local_clock_time(i64::MAX), "");
}

#[test]
fn lifted_mutes_lose_their_local_record() {
    let prefs = serde_json::json!({"muted_targets": {"libera #rust": {"until": null}}})
        .as_object()
        .cloned()
        .unwrap();
    let mut since = std::collections::BTreeMap::from([
        ("libera #rust".to_string(), 10),
        ("libera #gone".to_string(), 20),
    ]);
    assert!(forget_lifted_mutes(&mut since, &prefs));
    assert_eq!(since.len(), 1);
    assert!(since.contains_key("libera #rust"));
    assert!(!forget_lifted_mutes(&mut since, &prefs));
    assert!(forget_lifted_mutes(&mut since, &serde_json::Map::new()));
    assert!(since.is_empty());
}

#[test]
fn notification_edits_change_only_their_field() {
    let mut prefs = serde_json::json!({
        "channel_messages_only": ["#rust"],
        "muted_targets": {"libera #old": {"until": null}},
        "notification_sound": "none",
        "channel_mentions": true
    })
    .as_object()
    .cloned()
    .unwrap();
    assert!(apply_notification_edit(
        &mut prefs,
        &NotificationEdit::AddToList("channel".to_string(), " #Slint ".to_string())
    ));
    assert_eq!(
        prefs["channel_messages_only"],
        serde_json::json!(["#rust", "#slint"])
    );
    assert!(apply_notification_edit(
        &mut prefs,
        &NotificationEdit::RemoveFromList("channel".to_string(), "#rust".to_string())
    ));
    assert_eq!(
        prefs["channel_messages_only"],
        serde_json::json!(["#slint"])
    );
    assert!(apply_notification_edit(
        &mut prefs,
        &NotificationEdit::Mute(muted_key("libera", "#Rust"), Some(100))
    ));
    assert_eq!(prefs["muted_targets"]["libera #rust"]["until"], 100);
    assert!(apply_notification_edit(
        &mut prefs,
        &NotificationEdit::Unmute("libera #old".to_string())
    ));
    assert!(prefs["muted_targets"].get("libera #old").is_none());
    assert!(!apply_notification_edit(
        &mut prefs,
        &NotificationEdit::Sound("klaxon".to_string())
    ));
    assert!(apply_notification_edit(
        &mut prefs,
        &NotificationEdit::Sound("chime".to_string())
    ));
    assert_eq!(prefs["notification_sound"], "chime");
    assert_eq!(prefs["channel_mentions"], true);
    assert_eq!(muted_rows(&prefs)[0].1, "libera #rust");
}

#[test]
fn watchlist_reply_and_network_nick() {
    assert_eq!(
        watch_patterns_from_reply(&serde_json::json!({
            "status": "ok", "response": {"patterns": ["rust*", "cordiale"]}
        })),
        Some(vec!["rust*".to_string(), "cordiale".to_string()])
    );
    assert_eq!(
        watch_patterns_from_reply(&serde_json::json!({"status": "error"})),
        None
    );
    let networks = vec![
        serde_json::json!({"slug": "libera", "nick": "ada"}),
        serde_json::json!({"slug": "oftc", "nick": ""}),
    ];
    assert_eq!(network_nick(&networks, "libera"), Some("ada".to_string()));
    assert_eq!(network_nick(&networks, "oftc"), None);
    assert_eq!(network_nick(&networks, "efnet"), None);
}

#[test]
fn now_playing_text_follows_cicchetto_states() {
    use cordiale_core::radio::Track;
    let at = std::time::Instant::now();
    assert_eq!(
        now_playing_text(&RadioNowPlaying::default(), at),
        Err(("np-idle", String::new()))
    );
    let mut now = RadioNowPlaying {
        station: Some("Kohina".to_string()),
        has_feed: true,
        ..RadioNowPlaying::default()
    };
    assert_eq!(
        now_playing_text(&now, at),
        Err(("np-unanswered", "Kohina".to_string()))
    );
    now.track = Some((
        Track {
            artist: Some("Hubbard".to_string()),
            title: "Commando".to_string(),
        },
        at,
    ));
    assert_eq!(
        now_playing_text(&now, at).as_deref(),
        Ok("is now playing: Hubbard — Commando [Kohina]")
    );
    let later = at + std::time::Duration::from_secs(181);
    assert_eq!(
        now_playing_text(&now, later),
        Err(("np-stale", "Kohina".to_string()))
    );
    let icy = RadioNowPlaying {
        station: Some("KNAC".to_string()),
        stream_title: Some("Band - Song".to_string()),
        ..RadioNowPlaying::default()
    };
    assert_eq!(
        now_playing_text(&icy, at).as_deref(),
        Ok("is now playing: Band - Song [KNAC]")
    );
    let silent = RadioNowPlaying {
        station: Some("KNAC".to_string()),
        ..RadioNowPlaying::default()
    };
    assert_eq!(
        now_playing_text(&silent, at),
        Err(("np-unsupported", "KNAC".to_string()))
    );
}

#[test]
fn custom_stations_need_a_name_and_an_http_url() {
    let station = custom_radio_station(" Local ", "https://radio.example/live.ogg", 1)
        .expect("valid station");
    assert_eq!(station.name, "Local");
    assert_eq!(station.codec, "vorbis");
    assert_eq!(
        custom_radio_station("x", "https://radio.example/s.flac", 2).map(|station| station.codec),
        Some("flac".to_string())
    );
    assert!(custom_radio_station("", "https://radio.example/", 0).is_none());
    assert!(custom_radio_station("x", "ftp://radio.example/", 0).is_none());
    assert!(custom_radio_station("x", "https://", 0).is_none());
    assert!(custom_radio_station("x", "https://a b/", 0).is_none());
    assert_eq!(
        custom_radio_station("x", "http://radio.example/s", 0).map(|station| station.codec),
        Some("mp3".to_string())
    );
}

#[test]
fn admin_subject_rows_keep_accounts_and_visitors() {
    assert_eq!(
        admin_subject_row(&serde_json::json!({
            "type": "visitor", "id": "v-1", "network": "libera", "nick": "guest7"
        })),
        Some((
            "visitor".to_string(),
            "v-1".to_string(),
            "libera".to_string(),
            "guest7".to_string()
        ))
    );
    assert_eq!(
        admin_subject_row(&serde_json::json!({
            "type": "user", "id": "u-1", "network": null, "nick": "ada"
        }))
        .map(|row| row.2),
        Some(String::new())
    );
    assert_eq!(
        admin_subject_row(&serde_json::json!({"type": "bot", "id": "x", "nick": "y"})),
        None
    );
}

#[test]
fn realtime_identifier_follows_grappas_subject_label() {
    let me = |value: serde_json::Value| -> MeResponse {
        serde_json::from_value(value).expect("a /me body")
    };
    let visitor = me(serde_json::json!({
        "kind": "visitor", "id": "0b9c2f3e-1d2a-4c5b-9e8f-7a6b5c4d3e2f"
    }));
    assert_eq!(
        realtime_identifier(&visitor, true, "guest"),
        "visitor:0b9c2f3e-1d2a-4c5b-9e8f-7a6b5c4d3e2f"
    );
    let user = me(serde_json::json!({"kind": "user", "id": 3, "name": "Sythos"}));
    assert_eq!(realtime_identifier(&user, false, "sythos"), "Sythos");
    let silent = me(serde_json::json!({}));
    assert_eq!(realtime_identifier(&silent, true, "whatever"), "guest");
    assert_eq!(realtime_identifier(&silent, false, "ada"), "ada");
}

#[test]
fn attachment_caps_and_errors_follow_the_category() {
    let limits = UploadLimits {
        host: "embedded".to_string(),
        image_bytes: 10,
        video_bytes: 50,
        video_seconds: None,
        document_bytes: 20,
        audio_bytes: 25,
    };
    assert_eq!(upload_cap(&limits, UploadCategory::Image), 10);
    assert_eq!(upload_cap(&limits, UploadCategory::Video), 50);
    assert_eq!(upload_cap(&limits, UploadCategory::Document), 20);
    assert_eq!(upload_cap(&limits, UploadCategory::Audio), 25);
    assert_eq!(attachment_error_status(Some(413)), "attach-too-large");
    assert_eq!(
        attachment_error_status(Some(415)),
        "attach-unsupported-type"
    );
    assert_eq!(attachment_error_status(Some(507)), "attach-no-space");
    assert_eq!(attachment_error_status(None), "attach-failed");
}

/// A 507 can't say whether the instance or the subject's own cap is out
/// of space (protocol v26), so its copy must not blame the server, in
/// the UI or in any catalog.
#[test]
fn upload_507_copy_does_not_attribute_the_cause() {
    const MSGID: &str = "The upload of {} was refused for lack of space.";
    let slint = include_str!("../ui/appwindow.slint");
    let branch = slint
        .split("status-kind == \"attach-no-space\"")
        .nth(1)
        .and_then(|rest| rest.lines().nth(1))
        .expect("attach-no-space branch");
    assert!(branch.contains(&format!("@tr(\"{MSGID}\"")), "{branch}");

    for (lang, catalog) in [
        ("it", include_str!("../lang/it/LC_MESSAGES/cordiale-ui.po")),
        ("fr", include_str!("../lang/fr/LC_MESSAGES/cordiale-ui.po")),
        ("de", include_str!("../lang/de/LC_MESSAGES/cordiale-ui.po")),
        ("es", include_str!("../lang/es/LC_MESSAGES/cordiale-ui.po")),
    ] {
        // Line by line: a Windows checkout may turn the catalogs' line
        // endings into CRLF, which `lines()` strips like LF.
        let msgid = format!("msgid \"{MSGID}\"");
        let msgstr = catalog
            .lines()
            .skip_while(|line| *line != msgid)
            .nth(1)
            .unwrap_or_else(|| panic!("{lang}: missing msgid"));
        assert!(
            msgstr.starts_with("msgstr \"") && msgstr.len() > "msgstr \"\"".len(),
            "{lang}: {msgstr}"
        );
        assert!(msgstr.contains("{}"), "{lang}: {msgstr}");
        assert!(!catalog.contains("has no room left for {}"), "{lang}");
    }
}

#[test]
fn a_rejected_date_format_has_its_own_message() {
    assert_eq!(display_prefs_error_key(Some(422)), "display-prefs-rejected");
    assert_eq!(
        display_prefs_error_key(Some(500)),
        "display-prefs-save-failed"
    );
    assert_eq!(display_prefs_error_key(None), "display-prefs-save-failed");
}

#[test]
fn ignore_refusals_name_the_field_the_user_got_wrong() {
    let rejected = |code: Option<&str>| GrappaClientError::Rejected {
        status: cordiale_core::client::StatusCode::UNPROCESSABLE_ENTITY,
        code: code.map(str::to_string),
        retry_after: None,
    };
    assert_eq!(
        ignore_error_key(&rejected(Some("invalid_text_pattern"))),
        "invalid-text-pattern"
    );
    assert_eq!(
        ignore_error_key(&rejected(Some("invalid_mask"))),
        "invalid-mask"
    );
    assert_eq!(ignore_error_key(&rejected(None)), "failed");
    assert_eq!(
        ignore_error_key(&GrappaClientError::InvalidUrl("x".into())),
        "failed"
    );
}

#[test]
fn a_blank_settings_pattern_is_the_plain_mask_rule() {
    assert_eq!(ignore_pattern_from_ui(""), None);
    assert_eq!(ignore_pattern_from_ui("   "), None);
    assert_eq!(
        ignore_pattern_from_ui("  <Some Nick>  says * "),
        Some("<Some Nick>  says *".to_string())
    );
}

#[test]
fn window_status_line_joins_network_and_window_with_their_flags() {
    let modes = |letters: &[&str]| letters.iter().map(|m| m.to_string()).collect::<Vec<_>>();
    let user = modes(&["S", "i", "r"]);
    let channel = modes(&["r", "n", "t"]);
    assert_eq!(
        window_status_line("Azzurra", Some(&user), "#grappa", Some(&channel)),
        "Azzurra +Sir · #grappa +rnt"
    );
    // No snapshot yet, or an empty one: no invented `+`.
    assert_eq!(
        window_status_line("Azzurra", None, "#grappa", None),
        "Azzurra · #grappa"
    );
    assert_eq!(
        window_status_line("Azzurra", Some(&[]), "#grappa", Some(&[])),
        "Azzurra · #grappa"
    );
    // A DM or `$server` window carries the user modes only.
    assert_eq!(
        window_status_line("Azzurra", Some(&user), "vjt", None),
        "Azzurra +Sir · vjt"
    );
}

#[test]
fn window_status_follows_the_active_window_and_never_leaks_flags() {
    let mut state = WorkerState::new();
    state
        .networks
        .user_modes_by_network
        .insert("azzurra".into(), vec!["i".into(), "r".into()]);
    state.transcript.channel_modes.insert(
        ("azzurra".into(), "#grappa".into()),
        ChannelModes {
            modes: vec!["n".into(), "t".into()],
            params: HashMap::new(),
        },
    );
    assert_eq!(window_status_for(&state), "");

    state.windows.current_channel = Some(("azzurra".into(), "#grappa".into()));
    assert_eq!(window_status_for(&state), "azzurra +ir · #grappa +nt");

    // A live channel-mode snapshot replaces the old flags.
    state.transcript.channel_modes.insert(
        ("azzurra".into(), "#grappa".into()),
        ChannelModes {
            modes: vec!["m".into()],
            params: HashMap::new(),
        },
    );
    assert_eq!(window_status_for(&state), "azzurra +ir · #grappa +m");

    // Another network's window: its own (missing) snapshots, nothing
    // carried over from the last one.
    state.windows.current_channel = Some(("libera".into(), "#rust".into()));
    assert_eq!(window_status_for(&state), "libera · #rust");

    // The server window and a DM show no channel modes, even when a
    // channel of that name happens to hold a snapshot.
    state.windows.current_channel = Some(("azzurra".into(), SERVER_WINDOW_NAME.into()));
    assert_eq!(window_status_for(&state), "azzurra +ir · $server");
    state.transcript.channel_modes.insert(
        ("azzurra".into(), "vjt".into()),
        ChannelModes {
            modes: vec!["s".into()],
            params: HashMap::new(),
        },
    );
    state.windows.current_channel = Some(("azzurra".into(), "vjt".into()));
    state.windows.current_query = true;
    assert_eq!(window_status_for(&state), "azzurra +ir · vjt");
}

#[test]
fn render_message_formats_a_ctcp_action_as_a_sentence() {
    let inner = serde_json::json!({
        "kind": "action",
        "sender": "vjt",
        "body": "waves hello",
    });
    let rendered = render_message(&inner, None);
    assert_eq!(rendered.nick, None);
    assert_eq!(rendered.text, "* vjt waves hello");
    assert!(rendered.italic);
}

#[test]
fn only_message_envelopes_render_as_chat_lines() {
    assert!(renders_as_chat_line("message"));
    // Every other kind has its own handler or explicit no-op; none may
    // reach the chat-line path and leak as raw JSON.
    for kind in [
        "channel_created",
        "bundle_hash",
        "mentions_bundle",
        "members_seeded",
        "topic_changed",
        "joined",
        "server_settings_changed",
    ] {
        assert!(!renders_as_chat_line(kind), "{kind}");
    }
    // "parted" is confirmed never to be sent by the server, so it is
    // not a protocol kind at all.
    assert!(ClientEventKind::from_wire_name("parted").is_none());
    assert!(ClientEventKind::from_wire_name("channel_created").is_some());
}

#[test]
fn parse_connection_progress_accepts_only_the_user_topic_and_known_network() {
    let known: HashMap<String, i64> = HashMap::from([("libera".to_string(), 1)]);
    let topic = "grappa:user:vjt";
    let payload = serde_json::json!({
        "kind": "connection_progress",
        "network": "libera",
        "state": "connecting",
        "future_field": true
    });
    assert_eq!(
        parse_connection_progress(&payload, topic, "vjt", &known),
        Some(("libera".to_string(), ConnectionProgressState::Connecting))
    );
    let connected = serde_json::json!({
        "kind": "connection_progress",
        "network": "libera",
        "state": "connected"
    });
    assert_eq!(
        parse_connection_progress(&connected, topic, "vjt", &known),
        Some(("libera".to_string(), ConnectionProgressState::Connected))
    );

    // Wrong carrier: another user's topic, or a channel-shaped topic.
    assert_eq!(
        parse_connection_progress(&payload, "grappa:user:other", "vjt", &known),
        None
    );
    assert_eq!(
        parse_connection_progress(
            &payload,
            "grappa:user:vjt/network:libera/channel:#rust",
            "vjt",
            &known
        ),
        None
    );

    for invalid in [
        serde_json::json!({"kind": "connection_state_changed", "network": "libera", "state": "connecting"}),
        serde_json::json!({"kind": "connection_progress", "network": "oftc", "state": "connecting"}),
        serde_json::json!({"kind": "connection_progress", "network": "", "state": "connecting"}),
        serde_json::json!({"kind": "connection_progress", "network": "libera", "state": "failed"}),
        serde_json::json!({"kind": "connection_progress", "network": "libera"}),
        serde_json::json!({"kind": "connection_progress", "state": "connecting"}),
        serde_json::json!({"kind": "connection_progress", "network": 1, "state": "connecting"}),
    ] {
        assert_eq!(
            parse_connection_progress(&invalid, topic, "vjt", &known),
            None,
            "{invalid} must be rejected"
        );
    }
}

#[test]
fn connection_progress_toggles_the_badge_idempotently() {
    let mut connecting = std::collections::HashSet::new();
    assert!(apply_connection_progress(
        &mut connecting,
        "libera",
        ConnectionProgressState::Connecting
    ));
    assert!(!apply_connection_progress(
        &mut connecting,
        "libera",
        ConnectionProgressState::Connecting
    ));
    assert!(connecting.contains("libera"));
    assert!(apply_connection_progress(
        &mut connecting,
        "libera",
        ConnectionProgressState::Connected
    ));
    assert!(!apply_connection_progress(
        &mut connecting,
        "libera",
        ConnectionProgressState::Connected
    ));
    assert!(connecting.is_empty());
}

#[test]
fn parse_recover_progress_validates_carrier_enums_and_open_reason() {
    let topic = "grappa:user:vjt";
    let payload = serde_json::json!({
        "kind": "recover_progress",
        "network": "azzurra",
        "step": "identify",
        "status": "failed",
        "reason": "wrong_password",
        "future_field": 1
    });
    assert_eq!(
        parse_recover_progress(&payload, topic, "vjt"),
        Some((
            "azzurra".to_string(),
            RecoverStepEntry {
                step: RecoverStep::Identify,
                status: RecoverStepStatus::Failed,
                reason: Some("wrong_password".to_string()),
            }
        ))
    );
    // A reason token the client doesn't know yet is kept, not rejected.
    let future_reason = serde_json::json!({
        "kind": "recover_progress",
        "network": "azzurra",
        "step": "release",
        "status": "ok",
        "reason": "some_future_reason"
    });
    assert_eq!(
        parse_recover_progress(&future_reason, topic, "vjt").map(|(_, entry)| entry.reason),
        Some(Some("some_future_reason".to_string()))
    );
    let running = serde_json::json!({
        "kind": "recover_progress",
        "network": "azzurra",
        "step": "nick",
        "status": "running",
        "reason": null
    });
    assert_eq!(
        parse_recover_progress(&running, topic, "vjt").map(|(_, entry)| entry.status),
        Some(RecoverStepStatus::Running)
    );

    assert_eq!(
        parse_recover_progress(&payload, "grappa:user:other", "vjt"),
        None
    );
    for invalid in [
        serde_json::json!({"kind": "recover_result", "network": "azzurra", "step": "nick", "status": "ok", "reason": null}),
        serde_json::json!({"kind": "recover_progress", "network": "", "step": "nick", "status": "ok", "reason": null}),
        serde_json::json!({"kind": "recover_progress", "network": "azzurra", "step": "ghost", "status": "ok", "reason": null}),
        serde_json::json!({"kind": "recover_progress", "network": "azzurra", "step": "nick", "status": "done", "reason": null}),
        serde_json::json!({"kind": "recover_progress", "network": "azzurra", "step": "nick", "status": "ok"}),
        serde_json::json!({"kind": "recover_progress", "network": "azzurra", "step": "nick", "status": "ok", "reason": 3}),
    ] {
        assert_eq!(
            parse_recover_progress(&invalid, topic, "vjt"),
            None,
            "{invalid} must be rejected"
        );
    }
}

#[test]
fn recover_progress_opens_isolates_and_upserts_like_cicchetto() {
    let entry = |step, status| RecoverStepEntry {
        step,
        status,
        reason: None,
    };
    let mut panel = None;
    assert!(apply_recover_progress(
        &mut panel,
        "azzurra",
        entry(RecoverStep::Identify, RecoverStepStatus::Running)
    ));
    assert!(apply_recover_progress(
        &mut panel,
        "azzurra",
        entry(RecoverStep::Nick, RecoverStepStatus::Running)
    ));
    // A known step is replaced in place, keeping the original order.
    assert!(apply_recover_progress(
        &mut panel,
        "azzurra",
        entry(RecoverStep::Identify, RecoverStepStatus::Done)
    ));
    // Duplicates are no-ops.
    assert!(!apply_recover_progress(
        &mut panel,
        "azzurra",
        entry(RecoverStep::Identify, RecoverStepStatus::Done)
    ));
    // Another network never mixes into the open panel.
    assert!(!apply_recover_progress(
        &mut panel,
        "libera",
        entry(RecoverStep::Release, RecoverStepStatus::Failed)
    ));
    let open = panel.clone().unwrap();
    assert_eq!(open.network, "azzurra");
    assert_eq!(
        open.steps,
        vec![
            entry(RecoverStep::Identify, RecoverStepStatus::Done),
            entry(RecoverStep::Nick, RecoverStepStatus::Running),
        ]
    );

    // After a dismiss, the next progress event reopens a fresh panel.
    panel = None;
    assert!(apply_recover_progress(
        &mut panel,
        "libera",
        entry(RecoverStep::Register, RecoverStepStatus::Running)
    ));
    assert_eq!(panel.unwrap().network, "libera");
}

#[test]
fn parse_recover_result_keeps_the_terminal_event_with_any_reason() {
    let topic = "grappa:user:vjt";
    let failed = serde_json::json!({
        "kind": "recover_result",
        "network": "azzurra",
        "outcome": "failed",
        "reason": "a_reason_added_later",
        "future_field": []
    });
    assert_eq!(
        parse_recover_result(&failed, topic, "vjt"),
        Some((
            "azzurra".to_string(),
            RecoverOutcome::Failed,
            Some("a_reason_added_later".to_string())
        ))
    );
    let succeeded = serde_json::json!({
        "kind": "recover_result",
        "network": "azzurra",
        "outcome": "succeeded",
        "reason": null
    });
    assert_eq!(
        parse_recover_result(&succeeded, topic, "vjt"),
        Some(("azzurra".to_string(), RecoverOutcome::Succeeded, None))
    );
    assert_eq!(
        parse_recover_result(&succeeded, "grappa:user:other", "vjt"),
        None
    );
    for invalid in [
        serde_json::json!({"kind": "recover_progress", "network": "azzurra", "outcome": "failed", "reason": null}),
        serde_json::json!({"kind": "recover_result", "network": "", "outcome": "failed", "reason": null}),
        serde_json::json!({"kind": "recover_result", "network": "azzurra", "outcome": "partial", "reason": null}),
        serde_json::json!({"kind": "recover_result", "network": "azzurra", "outcome": "failed"}),
        serde_json::json!({"kind": "recover_result", "network": "azzurra", "outcome": "failed", "reason": false}),
    ] {
        assert_eq!(
            parse_recover_result(&invalid, topic, "vjt"),
            None,
            "{invalid} must be rejected"
        );
    }
}

#[test]
fn recover_result_only_concludes_the_open_panel_of_its_network() {
    // No panel open (dismissed, or progress never arrived): no-op.
    let mut panel = None;
    assert!(!apply_recover_result(
        &mut panel,
        "azzurra",
        RecoverOutcome::Succeeded,
        None
    ));
    assert!(panel.is_none());

    assert!(apply_recover_progress(
        &mut panel,
        "azzurra",
        RecoverStepEntry {
            step: RecoverStep::Identify,
            status: RecoverStepStatus::Failed,
            reason: Some("wrong_password".to_string()),
        }
    ));
    // Another network cannot conclude it.
    assert!(!apply_recover_result(
        &mut panel,
        "libera",
        RecoverOutcome::Succeeded,
        None
    ));
    assert_eq!(panel.as_ref().unwrap().outcome, None);

    assert!(apply_recover_result(
        &mut panel,
        "azzurra",
        RecoverOutcome::Failed,
        Some("wrong_password".to_string())
    ));
    // Replaying the same result is a no-op.
    assert!(!apply_recover_result(
        &mut panel,
        "azzurra",
        RecoverOutcome::Failed,
        Some("wrong_password".to_string())
    ));
    let open = panel.unwrap();
    assert_eq!(open.outcome, Some(RecoverOutcome::Failed));
    assert_eq!(open.outcome_reason.as_deref(), Some("wrong_password"));
    assert_eq!(open.steps.len(), 1);
}

#[test]
fn parse_web_session_severed_accepts_any_string_code_on_the_user_topic() {
    let topic = "grappa:user:vjt";
    let flood = serde_json::json!({
        "kind": "web_session_severed",
        "code": "rate_limit_flood",
        "future_field": true
    });
    assert_eq!(
        parse_web_session_severed(&flood, topic, "vjt").as_deref(),
        Some("rate_limit_flood")
    );
    // A code added by a later server still signs the client out.
    let future_code = serde_json::json!({"kind": "web_session_severed", "code": "admin_revoked"});
    assert_eq!(
        parse_web_session_severed(&future_code, topic, "vjt").as_deref(),
        Some("admin_revoked")
    );

    assert_eq!(
        parse_web_session_severed(&flood, "grappa:user:other", "vjt"),
        None
    );
    assert_eq!(
        parse_web_session_severed(
            &flood,
            "grappa:user:vjt/network:libera/channel:#rust",
            "vjt"
        ),
        None
    );
    for invalid in [
        serde_json::json!({"kind": "web_session_severed"}),
        serde_json::json!({"kind": "web_session_severed", "code": null}),
        serde_json::json!({"kind": "web_session_severed", "code": 429}),
        serde_json::json!({"kind": "connection_progress", "code": "rate_limit_flood"}),
    ] {
        assert_eq!(
            parse_web_session_severed(&invalid, topic, "vjt"),
            None,
            "{invalid} must be rejected"
        );
    }
}

fn who_user_json(nick: &str) -> Value {
    serde_json::json!({
        "nick": nick,
        "user": "~u",
        "host": "example.org",
        "server": "irc.example.org",
        "modes": "H@",
        "channel": "#rust",
        "hops": 0,
        "realname": "Real Name"
    })
}

#[test]
fn parse_who_reply_is_strict_per_row() {
    let topic = "grappa:user:vjt";
    let mut nulls = who_user_json("bob");
    nulls["hops"] = Value::Null;
    nulls["realname"] = Value::Null;
    let payload = serde_json::json!({
        "kind": "who_reply",
        "network": "libera",
        "target": "#rust",
        "users": [who_user_json("alice"), nulls],
        "future_field": 1
    });
    let reply = parse_who_reply(&payload, topic, "vjt").expect("valid who_reply");
    assert_eq!(reply.network, "libera");
    assert_eq!(reply.target, "#rust");
    assert_eq!(reply.users.len(), 2);
    assert_eq!(reply.users[0].hops, Some(0));
    assert_eq!(reply.users[1].hops, None);
    assert_eq!(reply.users[1].realname, None);

    let empty = serde_json::json!({
        "kind": "who_reply", "network": "libera", "target": "#rust", "users": []
    });
    let view = who_reply_view(&parse_who_reply(&empty, topic, "vjt").unwrap());
    assert_eq!(view.rows, vec![("who-empty".to_string(), String::new())]);

    assert!(parse_who_reply(&payload, "grappa:user:other", "vjt").is_none());
    // One malformed row drops the whole bundle.
    let mut bad_row = who_user_json("carol");
    bad_row["modes"] = Value::Null;
    let mut missing_realname = who_user_json("dave");
    missing_realname.as_object_mut().unwrap().remove("realname");
    let mut string_hops = who_user_json("erin");
    string_hops["hops"] = serde_json::json!("2");
    for bad in [bad_row, missing_realname, string_hops] {
        let payload = serde_json::json!({
            "kind": "who_reply",
            "network": "libera",
            "target": "#rust",
            "users": [who_user_json("alice"), bad]
        });
        assert!(parse_who_reply(&payload, topic, "vjt").is_none());
    }
    let no_users = serde_json::json!({"kind": "who_reply", "network": "libera", "target": "#rust"});
    assert!(parse_who_reply(&no_users, topic, "vjt").is_none());
}

#[test]
fn parse_server_reply_accepts_only_the_four_sources_and_string_lines() {
    let topic = "grappa:user:vjt";
    for source in ["info", "version", "motd", "admin"] {
        let payload = serde_json::json!({
            "kind": "server_reply",
            "network": "libera",
            "source": source,
            "lines": ["first line", "", "  indented"],
            "future_field": null
        });
        let (network, parsed, lines) =
            parse_server_reply(&payload, topic, "vjt").expect("valid server_reply");
        assert_eq!(network, "libera");
        assert_eq!(parsed, source);
        assert_eq!(lines, vec!["first line", "", "  indented"]);
    }
    let empty = serde_json::json!({
        "kind": "server_reply", "network": "libera", "source": "motd", "lines": []
    });
    let (network, source, lines) = parse_server_reply(&empty, topic, "vjt").unwrap();
    assert_eq!(
        server_reply_view(&network, source, &lines).rows,
        vec![("reply-empty".to_string(), String::new())]
    );
    for invalid in [
        serde_json::json!({"kind": "server_reply", "network": "libera", "source": "stats", "lines": []}),
        serde_json::json!({"kind": "server_reply", "network": "libera", "source": "motd", "lines": ["ok", 7]}),
        serde_json::json!({"kind": "server_reply", "network": "libera", "source": "motd"}),
        serde_json::json!({"kind": "server_reply", "network": "", "source": "motd", "lines": []}),
    ] {
        assert!(
            parse_server_reply(&invalid, topic, "vjt").is_none(),
            "{invalid}"
        );
    }
    assert!(parse_server_reply(&empty, "grappa:user:other", "vjt").is_none());
}

#[test]
fn server_reply_commands_map_to_their_verbs() {
    let request = |verb: &'static str, payload: Value| ReplyCommand::Request { verb, payload };
    assert_eq!(
        parse_reply_command("/info", "#rust"),
        Some(request("info", serde_json::json!({})))
    );
    assert_eq!(
        parse_reply_command("/version", "#rust"),
        Some(request("version", serde_json::json!({})))
    );
    assert_eq!(
        parse_reply_command("/motd", "#rust"),
        Some(request("motd", serde_json::json!({})))
    );
    assert_eq!(
        parse_reply_command("/motd irc.example.org", "#rust"),
        Some(request(
            "motd",
            serde_json::json!({"target": "irc.example.org"})
        ))
    );
    assert_eq!(
        parse_reply_command("/admin hub.example.org", "#rust"),
        Some(request(
            "admin",
            serde_json::json!({"target": "hub.example.org"})
        ))
    );
}

fn whois_bundle_json() -> Value {
    serde_json::json!({
        "kind": "whois_bundle",
        "network": "libera",
        "target": "alice",
        "source": "user",
        "user": "~alice",
        "host": "example.org",
        "realname": "Alice",
        "server": "irc.example.org",
        "server_info": "Example IRC",
        "is_operator": false,
        "oper_text": null,
        "idle_seconds": 3725,
        "signon": null,
        "channels": ["#rust", "@#cordiale"],
        "using_ssl": true,
        "is_registered": true,
        "is_admin": false,
        "is_services_admin": false,
        "is_helper": false,
        "is_chanop": false,
        "is_agent": false,
        "is_java": false,
        "umodes": null,
        "away_message": null,
        "actually_host": null,
        "actually_ip": null,
        "account": "alice",
        "secure": true,
        "secure_cipher": "TLS_AES_256_GCM_SHA384",
        "certfp": null,
        "extra_lines": [{"numeric": 320, "text": "is a bot"}],
        "avatar_url": null,
        "future_field": {}
    })
}

#[test]
fn parse_whois_bundle_is_strict_per_field() {
    let topic = "grappa:user:vjt";
    let bundle = parse_whois_bundle(&whois_bundle_json(), topic, "vjt").expect("valid bundle");
    assert_eq!(bundle.target, "alice");
    assert_eq!(bundle.idle_seconds, Some(3725));
    assert_eq!(
        bundle.channels,
        Some(vec!["#rust".to_string(), "@#cordiale".to_string()])
    );
    assert_eq!(
        bundle.extra_lines,
        Some(vec![(320, "is a bot".to_string())])
    );
    assert_eq!(bundle.avatar_url, None);

    let view = whois_bundle_view(&bundle);
    assert_eq!(view.kind, "whois_bundle");
    assert_eq!(view.subject, "alice");
    assert!(view.rows.contains(&(
        "whois-userhost".to_string(),
        "~alice@example.org".to_string()
    )));
    assert!(view
        .rows
        .contains(&("whois-idle".to_string(), "1:02:05".to_string())));
    assert!(view
        .rows
        .contains(&("whois-registered".to_string(), String::new())));
    assert!(view
        .rows
        .contains(&(String::new(), "320 is a bot".to_string())));

    // Tolerated: absent `source` (means user), `rail`, absent avatar.
    let mut tolerated = whois_bundle_json();
    let fields = tolerated.as_object_mut().unwrap();
    fields.remove("source");
    fields.remove("avatar_url");
    assert!(parse_whois_bundle(&tolerated, topic, "vjt").is_some());
    let mut rail = whois_bundle_json();
    rail["source"] = serde_json::json!("rail");
    assert!(parse_whois_bundle(&rail, topic, "vjt").is_some());

    assert!(parse_whois_bundle(&whois_bundle_json(), "grappa:user:other", "vjt").is_none());
    let breakers: [(&str, Option<Value>); 6] = [
        ("source", Some(serde_json::json!("sidebar"))),
        ("is_admin", None),
        ("realname", None),
        ("extra_lines", None),
        ("channels", Some(serde_json::json!(["#ok", 3]))),
        ("idle_seconds", Some(serde_json::json!("12"))),
    ];
    for (key, replacement) in breakers {
        let mut broken = whois_bundle_json();
        match replacement {
            Some(value) => broken[key] = value,
            None => {
                broken.as_object_mut().unwrap().remove(key);
            }
        }
        assert!(
            parse_whois_bundle(&broken, topic, "vjt").is_none(),
            "{key} must invalidate the bundle"
        );
    }
}

#[test]
fn whois_avatar_ready_patches_only_the_matching_open_card() {
    use cordiale_core::isupport::CaseMapping;
    let topic = "grappa:user:vjt";
    let payload = serde_json::json!({
        "kind": "whois_avatar_ready",
        "network": "libera",
        "nick": "ALICE",
        "avatar_url": "/networks/1/peer_avatar/alice"
    });
    let (network, nick, avatar_url) =
        parse_whois_avatar_ready(&payload, topic, "vjt").expect("valid avatar event");
    assert!(parse_whois_avatar_ready(&payload, "grappa:user:other", "vjt").is_none());
    for missing in ["network", "nick", "avatar_url"] {
        let mut broken = payload.clone();
        broken.as_object_mut().unwrap().remove(missing);
        assert!(parse_whois_avatar_ready(&broken, topic, "vjt").is_none());
    }

    // No open card: a late completion is a no-op.
    let mut card = None;
    assert!(!apply_whois_avatar_ready(
        &mut card,
        &network,
        &nick,
        avatar_url.clone(),
        CaseMapping::Rfc1459
    ));

    let mut bundle = parse_whois_bundle(&whois_bundle_json(), topic, "vjt").unwrap();
    bundle.target = "Alice[x]".to_string();
    card = Some(bundle);
    // A different network or nick never gets patched.
    assert!(!apply_whois_avatar_ready(
        &mut card,
        "oftc",
        "alice{x}",
        avatar_url.clone(),
        CaseMapping::Rfc1459
    ));
    assert!(!apply_whois_avatar_ready(
        &mut card,
        "libera",
        "bob",
        avatar_url.clone(),
        CaseMapping::Rfc1459
    ));
    // Same nick under the network's casemapping: patched once.
    assert!(apply_whois_avatar_ready(
        &mut card,
        "libera",
        "alice{x}",
        avatar_url.clone(),
        CaseMapping::Rfc1459
    ));
    assert!(!apply_whois_avatar_ready(
        &mut card,
        "libera",
        "alice{x}",
        avatar_url.clone(),
        CaseMapping::Rfc1459
    ));
    assert_eq!(
        card.unwrap().avatar_url.as_deref(),
        Some("/networks/1/peer_avatar/alice")
    );
}

#[test]
fn parse_whowas_bundle_separates_not_found_from_invalid() {
    let topic = "grappa:user:vjt";
    let found = serde_json::json!({
        "kind": "whowas_bundle",
        "network": "libera",
        "target": "oldnick",
        "user": "~old",
        "host": "example.org",
        "realname": "Old Nick",
        "server": "irc.example.org",
        "logoff_time": "Tue Sep 22 10:00:00 2026",
        "not_found": false
    });
    let view = parse_whowas_bundle(&found, topic, "vjt").expect("valid whowas");
    assert_eq!(view.kind, "whowas_bundle");
    assert_eq!(view.subject, "oldnick");
    assert_eq!(
        view.rows[0],
        ("whois-userhost".to_string(), "~old@example.org".to_string())
    );
    assert!(view.rows.contains(&(
        "whowas-logoff".to_string(),
        "Tue Sep 22 10:00:00 2026".to_string()
    )));

    let not_found = serde_json::json!({
        "kind": "whowas_bundle",
        "network": "libera",
        "target": "ghost",
        "user": null,
        "host": null,
        "realname": null,
        "server": null,
        "logoff_time": null,
        "not_found": true
    });
    assert_eq!(
        parse_whowas_bundle(&not_found, topic, "vjt").unwrap().rows,
        vec![("whowas-not-found".to_string(), String::new())]
    );

    assert!(parse_whowas_bundle(&found, "grappa:user:other", "vjt").is_none());
    for key in ["user", "logoff_time", "not_found", "target"] {
        let mut broken = found.clone();
        broken.as_object_mut().unwrap().remove(key);
        assert!(
            parse_whowas_bundle(&broken, topic, "vjt").is_none(),
            "{key}"
        );
    }
    let mut wrong_type = found.clone();
    wrong_type["not_found"] = serde_json::json!("no");
    assert!(parse_whowas_bundle(&wrong_type, topic, "vjt").is_none());

    assert_eq!(
        parse_reply_command("/whowas oldnick", "#rust"),
        Some(ReplyCommand::Request {
            verb: "whowas",
            payload: serde_json::json!({"nick": "oldnick"})
        })
    );
    assert_eq!(
        parse_reply_command("/whowas", "#rust"),
        Some(ReplyCommand::Usage)
    );
}

#[test]
fn parse_banlist_bundle_keeps_mode_and_entry_order() {
    let topic = "grappa:user:vjt";
    let payload = serde_json::json!({
        "kind": "banlist_bundle",
        "network": "libera",
        "channel": "#rust",
        "mode": "e",
        "entries": [
            {"mask": "*!*@a.example", "setter": "op", "set_ts": "1789900000"},
            {"mask": "*!*@b.example", "setter": null, "set_ts": null}
        ]
    });
    let view = parse_banlist_bundle(&payload, topic, "vjt").expect("valid banlist");
    assert_eq!(view.subject, "#rust +e");
    assert_eq!(
        view.rows,
        vec![
            (String::new(), "*!*@a.example — op 1789900000".to_string()),
            (String::new(), "*!*@b.example".to_string()),
        ]
    );
    let empty = serde_json::json!({
        "kind": "banlist_bundle", "network": "libera", "channel": "#rust",
        "mode": "b", "entries": []
    });
    assert_eq!(
        parse_banlist_bundle(&empty, topic, "vjt").unwrap().rows,
        vec![("banlist-empty".to_string(), String::new())]
    );
    assert!(parse_banlist_bundle(&payload, "grappa:user:other", "vjt").is_none());
    let mut no_mode = payload.clone();
    no_mode.as_object_mut().unwrap().remove("mode");
    assert!(parse_banlist_bundle(&no_mode, topic, "vjt").is_none());
    let mut bad_entry = payload.clone();
    bad_entry["entries"][1]["setter"] = serde_json::json!(5);
    assert!(parse_banlist_bundle(&bad_entry, topic, "vjt").is_none());
    let mut missing_ts = payload.clone();
    missing_ts["entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("set_ts");
    assert!(parse_banlist_bundle(&missing_ts, topic, "vjt").is_none());
}

#[test]
fn banlist_command_defaults_to_the_open_channel() {
    let request = |payload: Value| ReplyCommand::Request {
        verb: "banlist",
        payload,
    };
    assert_eq!(
        parse_reply_command("/banlist", "#rust"),
        Some(request(serde_json::json!({"channel": "#rust"})))
    );
    assert_eq!(
        parse_reply_command("/banlist +e", "#rust"),
        Some(request(
            serde_json::json!({"channel": "#rust", "mode": "e"})
        ))
    );
    assert_eq!(
        parse_reply_command("/banlist #other I", "#rust"),
        Some(request(
            serde_json::json!({"channel": "#other", "mode": "I"})
        ))
    );
    // In a query window there is no channel to default to.
    assert_eq!(
        parse_reply_command("/banlist", "alice"),
        Some(ReplyCommand::Usage)
    );
}

#[test]
fn parse_auto_away_debounce_keeps_null_and_zero_distinct() {
    let topic = "grappa:user:vjt";
    let payload = |value: Value| serde_json::json!({"kind": "auto_away_debounce_changed", "auto_away_debounce_seconds": value});
    assert_eq!(
        parse_auto_away_debounce_changed(&payload(Value::Null), topic, "vjt"),
        Some(AutoAwayDebounce::ServerDefault)
    );
    assert_eq!(
        parse_auto_away_debounce_changed(&payload(serde_json::json!(0)), topic, "vjt"),
        Some(AutoAwayDebounce::Disabled)
    );
    assert_eq!(
        parse_auto_away_debounce_changed(&payload(serde_json::json!(300)), topic, "vjt"),
        Some(AutoAwayDebounce::Seconds(300))
    );
    assert_eq!(AutoAwayDebounce::Seconds(300).edit_text(), "300");

    for invalid in [
        payload(serde_json::json!(-1)),
        payload(serde_json::json!(1.5)),
        payload(serde_json::json!("300")),
        serde_json::json!({"kind": "auto_away_debounce_changed"}),
    ] {
        assert_eq!(
            parse_auto_away_debounce_changed(&invalid, topic, "vjt"),
            None,
            "{invalid}"
        );
    }
    assert_eq!(
        parse_auto_away_debounce_changed(&payload(Value::Null), "grappa:user:other", "vjt"),
        None
    );
}

#[test]
fn list_command_takes_an_optional_search() {
    assert_eq!(parse_list_command("/list"), Some(String::new()));
    assert_eq!(
        parse_list_command("  /LIST  rust lang "),
        Some("rust lang".to_string())
    );
    assert_eq!(parse_list_command("/listen"), None);
    assert_eq!(parse_list_command("hello /list"), None);
}

#[test]
fn directory_age_counts_seconds_since_the_capture() {
    assert_eq!(directory_age_seconds("", 1_000), -1);
    assert_eq!(directory_age_seconds("not a number", 1_000), -1);
    assert_eq!(directory_age_seconds("400", 1_000), 600);
    // A local clock behind the server never reads as a negative age.
    assert_eq!(directory_age_seconds("2000", 1_000), 0);
}

#[test]
fn directory_rows_mark_joined_channels_and_strip_topic_formatting() {
    let page = DirectoryPage {
        entries: vec![
            cordiale_core::rest::DirectoryEntry {
                name: "#Rust".to_string(),
                topic: Some("\x02Welcome\x02 to \x0304rust".to_string()),
                user_count: 42,
                featured: true,
            },
            cordiale_core::rest::DirectoryEntry {
                name: "#other".to_string(),
                topic: None,
                user_count: 3,
                featured: false,
            },
        ],
        next_cursor: None,
        total: 2,
        captured_at: None,
        status: "fresh".to_string(),
    };
    let mut window_states = HashMap::new();
    // Window states are ASCII-folded; the directory keeps `LIST` casing.
    window_states.insert(
        window_state_key("libera", "#rust"),
        ChannelWindowState::Joined,
    );
    window_states.insert(
        window_state_key("libera", "#other"),
        ChannelWindowState::Pending,
    );

    let rows = directory_rows(&page, "libera", &window_states);

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name.as_str(), "#Rust");
    assert_eq!(rows[0].users.as_str(), "42");
    assert_eq!(rows[0].topic.as_str(), "Welcome to rust");
    assert!(rows[0].featured);
    assert!(rows[0].joined);
    assert_eq!(rows[1].topic.as_str(), "");
    assert!(!rows[1].joined);
    // Another network's window never marks this one's row.
    assert!(!directory_rows(&page, "oftc", &window_states)[0].joined);
}

#[test]
fn parse_directory_count_signal_checks_counter_and_network() {
    let topic = "grappa:user:vjt";
    let progress = |payload: &Value| {
        parse_directory_count_signal(payload, topic, "vjt", "directory_progress", "count")
    };
    let complete = |payload: &Value| {
        parse_directory_count_signal(payload, topic, "vjt", "directory_complete", "total")
    };
    assert_eq!(
        progress(
            &serde_json::json!({"kind": "directory_progress", "network": "libera", "count": 250})
        ),
        Some("libera".to_string())
    );
    assert_eq!(
        complete(
            &serde_json::json!({"kind": "directory_complete", "network": "libera", "total": 0})
        ),
        Some("libera".to_string())
    );
    for invalid in [
        serde_json::json!({"kind": "directory_progress", "network": "libera", "count": -1}),
        serde_json::json!({"kind": "directory_progress", "network": "libera"}),
        serde_json::json!({"kind": "directory_progress", "network": "", "count": 1}),
        serde_json::json!({"kind": "directory_complete", "network": "libera", "count": 1}),
    ] {
        assert_eq!(progress(&invalid), None, "{invalid}");
    }
    // `directory_complete` carries `total`, not `count`.
    assert_eq!(
        complete(
            &serde_json::json!({"kind": "directory_complete", "network": "libera", "count": 1})
        ),
        None
    );
    assert_eq!(
        parse_directory_count_signal(
            &serde_json::json!({"kind": "directory_progress", "network": "libera", "count": 1}),
            "grappa:user:other",
            "vjt",
            "directory_progress",
            "count"
        ),
        None
    );
}

#[test]
fn parse_directory_failed_keeps_any_reason() {
    let topic = "grappa:user:vjt";
    assert_eq!(
        parse_directory_failed(
            &serde_json::json!({"kind": "directory_failed", "network": "libera", "reason": "timeout"}),
            topic,
            "vjt"
        ),
        Some(("libera".to_string(), "timeout".to_string()))
    );
    // `reason` is an open set: a future token is kept, not rejected.
    assert_eq!(
        parse_directory_failed(
            &serde_json::json!({"kind": "directory_failed", "network": "libera", "reason": "flood"}),
            topic,
            "vjt"
        ),
        Some(("libera".to_string(), "flood".to_string()))
    );
    for invalid in [
        serde_json::json!({"kind": "directory_failed", "network": "libera"}),
        serde_json::json!({"kind": "directory_failed", "network": "libera", "reason": null}),
        serde_json::json!({"kind": "directory_failed", "network": "", "reason": "timeout"}),
    ] {
        assert_eq!(
            parse_directory_failed(&invalid, topic, "vjt"),
            None,
            "{invalid}"
        );
    }
    assert_eq!(
        parse_directory_failed(
            &serde_json::json!({"kind": "directory_failed", "network": "libera", "reason": "timeout"}),
            "grappa:user:other",
            "vjt"
        ),
        None
    );
}

fn dcc_offer_payload() -> Value {
    serde_json::json!({
        "kind": "dcc_offer",
        "network": "libera",
        "channel": "$server",
        "offer_id": "off-1",
        "from": "alice",
        "filename": "notes.txt",
        "size": 1536,
        "future_field": true
    })
}

#[test]
fn parse_dcc_offer_requires_every_field() {
    let topic = "grappa:user:vjt";
    let offer = parse_dcc_offer(&dcc_offer_payload(), topic, "vjt").expect("valid offer");
    assert_eq!(offer.offer_id, "off-1");
    assert_eq!(offer.channel, "$server");
    assert_eq!(offer.size, 1536);
    for key in ["network", "channel", "offer_id", "from", "filename", "size"] {
        let mut missing = dcc_offer_payload();
        missing.as_object_mut().expect("object").remove(key);
        assert_eq!(parse_dcc_offer(&missing, topic, "vjt"), None, "{key}");
    }
    for (key, invalid) in [
        ("size", serde_json::json!(-1)),
        ("size", serde_json::json!("1536")),
        ("offer_id", serde_json::json!("")),
        ("offer_id", serde_json::json!(7)),
        ("network", serde_json::json!(" ")),
    ] {
        let mut payload = dcc_offer_payload();
        payload[key] = invalid;
        assert_eq!(parse_dcc_offer(&payload, topic, "vjt"), None, "{key}");
    }
    assert_eq!(
        parse_dcc_offer(&dcc_offer_payload(), "grappa:user:other", "vjt"),
        None
    );
}

#[test]
fn apply_dcc_offer_replaces_by_offer_id() {
    let topic = "grappa:user:vjt";
    let offer = parse_dcc_offer(&dcc_offer_payload(), topic, "vjt").expect("valid offer");
    let mut offers = Vec::new();
    assert!(apply_dcc_offer(&mut offers, offer.clone()));
    // The subscribe backfill re-sends held offers: same offer, no change.
    assert!(!apply_dcc_offer(&mut offers, offer.clone()));
    let mut renamed = offer.clone();
    renamed.filename = "notes-v2.txt".to_string();
    assert!(apply_dcc_offer(&mut offers, renamed));
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].filename, "notes-v2.txt");
    let mut other = offer;
    other.offer_id = "off-2".to_string();
    assert!(apply_dcc_offer(&mut offers, other));
    assert_eq!(offers.len(), 2);
}

#[test]
fn dcc_offer_resolved_drops_only_a_held_offer() {
    let topic = "grappa:user:vjt";
    let resolved = |resolution: &str| {
        serde_json::json!({
            "kind": "dcc_offer_resolved",
            "network": "libera",
            "channel": "$server",
            "offer_id": "off-1",
            "resolution": resolution
        })
    };
    for (wire, expected) in [
        ("accepted", DccResolution::Accepted),
        ("refused", DccResolution::Refused),
        ("expired", DccResolution::Expired),
    ] {
        assert_eq!(
            parse_dcc_offer_resolved(&resolved(wire), topic, "vjt"),
            Some(("off-1".to_string(), expected))
        );
    }
    // A resolution this client doesn't know drops the event.
    assert_eq!(
        parse_dcc_offer_resolved(&resolved("cancelled"), topic, "vjt"),
        None
    );
    let mut missing_channel = resolved("accepted");
    missing_channel
        .as_object_mut()
        .expect("object")
        .remove("channel");
    assert_eq!(
        parse_dcc_offer_resolved(&missing_channel, topic, "vjt"),
        None
    );
    assert_eq!(
        parse_dcc_offer_resolved(&resolved("accepted"), "grappa:user:other", "vjt"),
        None
    );

    let offer = parse_dcc_offer(&dcc_offer_payload(), topic, "vjt").expect("valid offer");
    let mut offers = vec![offer];
    assert_eq!(apply_dcc_offer_resolved(&mut offers, "unknown"), None);
    assert_eq!(offers.len(), 1);
    let removed = apply_dcc_offer_resolved(&mut offers, "off-1").expect("held");
    assert_eq!(removed.filename, "notes.txt");
    assert!(offers.is_empty());
}

#[test]
fn format_file_size_uses_binary_units() {
    assert_eq!(format_file_size(0), "0 B");
    assert_eq!(format_file_size(1023), "1023 B");
    assert_eq!(format_file_size(1536), "1.5 KiB");
    assert_eq!(format_file_size(5 * 1024 * 1024), "5.0 MiB");
}

#[test]
fn decline_invite_errors_map_to_status_keys() {
    assert_eq!(decline_invite_error_status(Some(404)), None);
    assert_eq!(
        decline_invite_error_status(Some(500)),
        Some("invite-decline-failed")
    );
    assert_eq!(
        decline_invite_error_status(None),
        Some("invite-decline-failed")
    );
}

#[test]
fn dcc_answer_errors_map_to_status_keys() {
    assert_eq!(dcc_answer_error_status(Some(404)), "dcc-offer-gone");
    assert_eq!(dcc_answer_error_status(Some(429)), "dcc-rate-limited");
    assert_eq!(dcc_answer_error_status(Some(503)), "dcc-not-connected");
    assert_eq!(dcc_answer_error_status(Some(507)), "dcc-no-space");
    assert_eq!(dcc_answer_error_status(Some(500)), "dcc-action-failed");
    assert_eq!(dcc_answer_error_status(None), "dcc-action-failed");
}

#[test]
fn parse_archive_changed_reads_network_slug() {
    let topic = "grappa:user:vjt";
    assert_eq!(
        parse_archive_changed(
            &serde_json::json!({"kind": "archive_changed", "network_slug": "libera"}),
            topic,
            "vjt"
        ),
        Some("libera".to_string())
    );
    for invalid in [
        serde_json::json!({"kind": "archive_changed", "network": "libera"}),
        serde_json::json!({"kind": "archive_changed", "network_slug": ""}),
        serde_json::json!({"kind": "archive_purged", "network_slug": "libera"}),
    ] {
        assert_eq!(
            parse_archive_changed(&invalid, topic, "vjt"),
            None,
            "{invalid}"
        );
    }
    assert_eq!(
        parse_archive_changed(
            &serde_json::json!({"kind": "archive_changed", "network_slug": "libera"}),
            "grappa:user:other",
            "vjt"
        ),
        None
    );
}

#[test]
fn archive_purged_matches_the_target_case_insensitively() {
    let topic = "grappa:user:vjt";
    let payload =
        serde_json::json!({"kind": "archive_purged", "network_slug": "libera", "target": "#Old"});
    assert_eq!(
        parse_archive_purged(&payload, topic, "vjt"),
        Some(("libera".to_string(), "#Old".to_string()))
    );
    for invalid in [
        serde_json::json!({"kind": "archive_purged", "network_slug": "libera"}),
        serde_json::json!({"kind": "archive_purged", "network_slug": "libera", "target": ""}),
        serde_json::json!({"kind": "archive_purged", "network": "libera", "target": "#old"}),
    ] {
        assert_eq!(
            parse_archive_purged(&invalid, topic, "vjt"),
            None,
            "{invalid}"
        );
    }
    assert_eq!(
        parse_archive_purged(&payload, "grappa:user:other", "vjt"),
        None
    );

    let mapping = cordiale_core::isupport::CaseMapping::Rfc1459;
    let key = |network: &str, window: &str| (network.to_string(), window.to_string());
    assert!(is_purged_window(
        &key("libera", "#old"),
        "libera",
        "#Old",
        mapping
    ));
    assert!(is_purged_window(
        &key("libera", "Nick[a]"),
        "libera",
        "nick{a}",
        mapping
    ));
    assert!(!is_purged_window(
        &key("oftc", "#old"),
        "libera",
        "#Old",
        mapping
    ));
    assert!(!is_purged_window(
        &key("libera", "#older"),
        "libera",
        "#Old",
        mapping
    ));
}

#[test]
fn parse_notify_list_groups_nicks_by_network_id() {
    let topic = "grappa:user:vjt";
    let entry = |network_id: i64, nick: &str| serde_json::json!({"network_id": network_id, "nick": nick, "added_at": "2026-09-23T10:00:00Z"});
    let payload = serde_json::json!({
        "kind": "notify_list",
        "networks": {"7": [entry(7, "alice"), entry(7, "bob")], "9": []}
    });
    let lists = parse_notify_list(&payload, topic, "vjt").expect("valid snapshot");
    assert_eq!(
        lists.get(&7),
        Some(&vec!["alice".to_string(), "bob".to_string()])
    );
    assert_eq!(lists.get(&9), Some(&Vec::new()));
    // An empty snapshot is valid and clears every list.
    assert_eq!(
        parse_notify_list(
            &serde_json::json!({"kind": "notify_list", "networks": {}}),
            topic,
            "vjt"
        ),
        Some(HashMap::new())
    );
    for invalid in [
        serde_json::json!({"kind": "notify_list"}),
        serde_json::json!({"kind": "notify_list", "networks": {"libera": []}}),
        serde_json::json!({"kind": "notify_list", "networks": {"7": [{"network_id": 7, "nick": "alice"}]}}),
        serde_json::json!({"kind": "notify_list", "networks": {"7": [{"network_id": "7", "nick": "alice", "added_at": "x"}]}}),
    ] {
        assert_eq!(parse_notify_list(&invalid, topic, "vjt"), None, "{invalid}");
    }
    assert_eq!(
        parse_notify_list(&payload, "grappa:user:other", "vjt"),
        None
    );
}

#[test]
fn parse_presence_snapshot_keeps_unknown_distinct() {
    let topic = "grappa:user:vjt";
    let payload = serde_json::json!({
        "kind": "presence_snapshot",
        "network_id": 7,
        "nicks": {"alice": "online", "Bob": "offline", "carol": "unknown"}
    });
    let (network_id, nicks) =
        parse_presence_snapshot(&payload, topic, "vjt").expect("valid snapshot");
    assert_eq!(network_id, 7);
    assert_eq!(nicks.get("alice"), Some(&Presence::Online));
    assert_eq!(nicks.get("bob"), Some(&Presence::Offline));
    assert_eq!(nicks.get("carol"), Some(&Presence::Unknown));
    for invalid in [
        serde_json::json!({"kind": "presence_snapshot", "network_id": 7, "nicks": {"alice": "away"}}),
        serde_json::json!({"kind": "presence_snapshot", "network_id": "7", "nicks": {}}),
        serde_json::json!({"kind": "presence_snapshot", "network_id": 7}),
    ] {
        assert_eq!(
            parse_presence_snapshot(&invalid, topic, "vjt"),
            None,
            "{invalid}"
        );
    }
    assert_eq!(
        parse_presence_snapshot(&payload, "grappa:user:other", "vjt"),
        None
    );
    // ASCII folding only: IRC brackets are not folded for presence keys.
    assert_eq!(presence_key("Nick[A]"), "nick[a]");
}

#[test]
fn parse_presence_changed_validates_closed_sets() {
    let topic = "grappa:user:vjt";
    let payload = serde_json::json!({
        "kind": "presence_changed",
        "network_id": 7,
        "nick": "Alice",
        "presence": "online",
        "initial": false,
        "source": "monitor",
        "ts": "2026-09-23T10:00:00Z"
    });
    assert_eq!(
        parse_presence_changed(&payload, topic, "vjt"),
        Some(PresenceChange {
            network_id: 7,
            nick: "Alice".to_string(),
            presence: Presence::Online,
            initial: false,
        })
    );
    for (key, invalid) in [
        ("presence", serde_json::json!("unknown")),
        ("source", serde_json::json!("guess")),
        ("initial", serde_json::json!("false")),
        ("ts", serde_json::json!(1)),
        ("nick", serde_json::json!("")),
        ("network_id", serde_json::json!("7")),
    ] {
        let mut changed = payload.clone();
        changed[key] = invalid;
        assert_eq!(
            parse_presence_changed(&changed, topic, "vjt"),
            None,
            "{key}"
        );
    }
    assert_eq!(
        parse_presence_changed(&payload, "grappa:user:other", "vjt"),
        None
    );
}

#[test]
fn parse_presence_error_keeps_reason_open() {
    let topic = "grappa:user:vjt";
    let payload = |reason: &str| serde_json::json!({"kind": "presence_error", "network_id": 7, "reason": reason, "detail": "alice,bob"});
    assert_eq!(
        parse_presence_error(&payload("list_full"), topic, "vjt"),
        Some((7, "list_full".to_string(), "alice,bob".to_string()))
    );
    assert_eq!(
        parse_presence_error(&payload("target_rejected"), topic, "vjt"),
        Some((7, "target_rejected".to_string(), "alice,bob".to_string()))
    );
    let mut missing_detail = payload("list_full");
    missing_detail
        .as_object_mut()
        .expect("object")
        .remove("detail");
    assert_eq!(parse_presence_error(&missing_detail, topic, "vjt"), None);
    assert_eq!(
        parse_presence_error(&payload("list_full"), "grappa:user:other", "vjt"),
        None
    );
}

#[test]
fn parse_peer_away_allows_an_empty_message() {
    let topic = "grappa:user:vjt";
    let payload = |message: Value| serde_json::json!({"kind": "peer_away", "network": "libera", "peer": "Alice", "message": message});
    assert_eq!(
        parse_peer_away(&payload(serde_json::json!("lunch")), topic, "vjt"),
        Some((
            "libera".to_string(),
            "Alice".to_string(),
            "lunch".to_string()
        ))
    );
    assert_eq!(
        parse_peer_away(&payload(serde_json::json!("")), topic, "vjt"),
        Some(("libera".to_string(), "Alice".to_string(), String::new()))
    );
    assert_eq!(parse_peer_away(&payload(Value::Null), topic, "vjt"), None);
    assert_eq!(
        parse_peer_away(
            &serde_json::json!({"kind": "peer_away", "network": "libera", "peer": "", "message": "x"}),
            topic,
            "vjt"
        ),
        None
    );
    assert_eq!(
        parse_peer_away(
            &payload(serde_json::json!("lunch")),
            "grappa:user:other",
            "vjt"
        ),
        None
    );
}

#[test]
fn parse_mentions_bundle_labels_a_dm_mention_with_the_peer() {
    let row = |channel: &str, sender: &str, extra: Value| {
        let mut row = serde_json::json!({
            "server_time": 1790000000000_i64,
            "channel": channel,
            "sender": sender,
            "body": "hi",
            "kind": "privmsg"
        });
        if let (Some(row), Some(extra)) = (row.as_object_mut(), extra.as_object()) {
            row.extend(extra.clone());
        }
        row
    };
    let payload = serde_json::json!({
        "kind": "mentions_bundle",
        "network": "libera",
        "away_started_at": "2026-09-23T08:00:00Z",
        "away_ended_at": "2026-09-23T09:00:00Z",
        "away_reason": null,
        "messages": [
            // Inbound DM: `channel` is our own nick, `dm_with` the peer.
            row("vjt", "Alice", serde_json::json!({"id": 7, "dm_with": "Alice"})),
            // Channel row on a v35 server: `dm_with` is null.
            row("#rust", "bob", serde_json::json!({"id": 8, "dm_with": null})),
            // A server older than v35 sends neither key.
            row("#rust", "carol", serde_json::json!({})),
            // An empty or non-string `dm_with` falls back to `channel`.
            row("#rust", "dave", serde_json::json!({"dm_with": ""})),
            row("#rust", "erin", serde_json::json!({"dm_with": 5}))
        ]
    });
    let view = parse_mentions_bundle(&payload, "grappa:user:vjt", "vjt").expect("valid bundle");
    // Away period row first, then one row per message in order.
    assert_eq!(view.rows.len(), 6);
    assert!(view.rows[1].1.ends_with(" Alice <Alice> hi"));
    assert!(!view.rows[1].1.contains(" vjt <"));
    assert!(view.rows[2].1.ends_with(" #rust <bob> hi"));
    assert!(view.rows[3].1.ends_with(" #rust <carol> hi"));
    assert!(view.rows[4].1.ends_with(" #rust <dave> hi"));
    assert!(view.rows[5].1.ends_with(" #rust <erin> hi"));
}

#[test]
fn parse_mentions_bundle_keeps_order_and_null_bodies() {
    let topic = "grappa:user:vjt";
    let message = |kind: &str, body: Value| serde_json::json!({"server_time": 1790000000000_i64, "channel": "#rust", "sender": "alice", "body": body, "kind": kind});
    let payload = serde_json::json!({
        "kind": "mentions_bundle",
        "network": "libera",
        "away_started_at": "2026-09-23T08:00:00Z",
        "away_ended_at": "2026-09-23T09:00:00Z",
        "away_reason": null,
        "messages": [message("privmsg", serde_json::json!("vjt: ping")), message("action", Value::Null)]
    });
    let view = parse_mentions_bundle(&payload, topic, "vjt").expect("valid bundle");
    assert_eq!(view.kind, "mentions_bundle");
    assert_eq!(view.network, "libera");
    // Away period, then the two messages in order; no reason row for null.
    assert_eq!(view.rows.len(), 3);
    assert_eq!(view.rows[0].0, "mentions-away-period");
    assert!(view.rows[1].1.ends_with("#rust <alice> vjt: ping"));
    assert!(view.rows[2].1.ends_with("#rust * alice "));

    let mut with_reason = payload.clone();
    with_reason["away_reason"] = serde_json::json!("lunch");
    let view = parse_mentions_bundle(&with_reason, topic, "vjt").expect("valid bundle");
    assert_eq!(
        view.rows[1],
        ("mentions-away-reason".to_string(), "lunch".to_string())
    );

    for (key, invalid) in [
        (
            "messages",
            serde_json::json!([message("wallops", serde_json::json!("x"))]),
        ),
        (
            "messages",
            serde_json::json!([{"server_time": "1", "channel": "#rust", "sender": "a", "body": null, "kind": "privmsg"}]),
        ),
        ("away_reason", serde_json::json!(5)),
        ("away_ended_at", Value::Null),
    ] {
        let mut bad = payload.clone();
        bad[key] = invalid;
        assert!(parse_mentions_bundle(&bad, topic, "vjt").is_none(), "{key}");
    }
    assert!(parse_mentions_bundle(&payload, "grappa:user:other", "vjt").is_none());
}

#[test]
fn parse_server_settings_changed_requires_the_core_caps() {
    let topic = "grappa:user:vjt";
    let payload = serde_json::json!({
        "kind": "server_settings_changed",
        "upload": {
            "active_host": "embedded",
            "image_per_file_cap_bytes": 10485760,
            "video_per_file_cap_bytes": 52428800,
            "document_per_file_cap_bytes": 20971520,
            "audio_per_file_cap_bytes": 20971520,
            "global_cap_bytes": 1073741824,
            "per_user_cap_bytes": 104857600,
            "per_visitor_cap_bytes": 10485760,
            "video_max_duration_seconds": 120
        },
        "http_host_aliases": ["irc.example.org"]
    });
    let limits = parse_server_settings_changed(&payload, topic, "vjt").expect("valid snapshot");
    assert_eq!(limits.host, "embedded");
    assert_eq!(limits.image_bytes, 10485760);
    assert_eq!(limits.video_seconds, Some(120));

    // Optional fields may be missing without dropping the snapshot.
    let mut optional_missing = payload.clone();
    optional_missing["upload"]
        .as_object_mut()
        .expect("object")
        .remove("video_max_duration_seconds");
    optional_missing
        .as_object_mut()
        .expect("object")
        .remove("http_host_aliases");
    let limits =
        parse_server_settings_changed(&optional_missing, topic, "vjt").expect("still valid");
    assert_eq!(limits.video_seconds, None);

    for (key, invalid) in [
        ("active_host", serde_json::json!("s3")),
        ("image_per_file_cap_bytes", serde_json::json!(0)),
        ("global_cap_bytes", Value::Null),
        ("audio_per_file_cap_bytes", serde_json::json!("20971520")),
    ] {
        let mut bad = payload.clone();
        bad["upload"][key] = invalid;
        assert_eq!(
            parse_server_settings_changed(&bad, topic, "vjt"),
            None,
            "{key}"
        );
    }
    assert_eq!(
        parse_server_settings_changed(&payload, "grappa:user:other", "vjt"),
        None
    );
}

#[test]
fn parse_bundle_hash_treats_version_as_optional() {
    let topic = "grappa:user:vjt";
    assert_eq!(
        parse_bundle_hash(
            &serde_json::json!({"kind": "bundle_hash", "hash": "abc123", "version": "1.4.2"}),
            topic,
            "vjt"
        ),
        Some(("abc123".to_string(), Some("1.4.2".to_string())))
    );
    for version in [None, Some(Value::Null), Some(serde_json::json!(""))] {
        let mut payload = serde_json::json!({"kind": "bundle_hash", "hash": "abc123"});
        if let Some(version) = version {
            payload["version"] = version;
        }
        assert_eq!(
            parse_bundle_hash(&payload, topic, "vjt"),
            Some(("abc123".to_string(), None))
        );
    }
    for invalid in [
        serde_json::json!({"kind": "bundle_hash", "hash": ""}),
        serde_json::json!({"kind": "bundle_hash"}),
    ] {
        assert_eq!(parse_bundle_hash(&invalid, topic, "vjt"), None, "{invalid}");
    }
    assert_eq!(
        parse_bundle_hash(
            &serde_json::json!({"kind": "bundle_hash", "hash": "abc123"}),
            "grappa:user:other",
            "vjt"
        ),
        None
    );
}

#[test]
fn archive_errors_single_out_rate_limiting() {
    assert_eq!(
        archive_error_key(Some(429), "archive-fetch-failed"),
        "archive-rate-limited"
    );
    assert_eq!(
        archive_error_key(Some(500), "archive-fetch-failed"),
        "archive-fetch-failed"
    );
    assert_eq!(
        archive_error_key(None, "archive-delete-failed"),
        "archive-delete-failed"
    );
}

#[test]
fn invite_command_defaults_to_the_open_channel() {
    assert_eq!(
        parse_reply_command("/invite alice", "#rust"),
        Some(ReplyCommand::Request {
            verb: "invite",
            payload: serde_json::json!({"channel": "#rust", "nick": "alice"})
        })
    );
    assert_eq!(
        parse_reply_command("/invite alice #other", "bob"),
        Some(ReplyCommand::Request {
            verb: "invite",
            payload: serde_json::json!({"channel": "#other", "nick": "alice"})
        })
    );
    assert_eq!(
        parse_reply_command("/invite", "#rust"),
        Some(ReplyCommand::Usage)
    );
    // A query window has no channel to invite into.
    assert_eq!(
        parse_reply_command("/invite alice", "bob"),
        Some(ReplyCommand::Usage)
    );
}

#[test]
fn parse_invite_ack_requires_every_field() {
    let topic = "grappa:user:vjt";
    let payload = serde_json::json!({
        "kind": "invite_ack",
        "network": "azzurra",
        "channel": "#rust",
        "peer": "alice",
        "future_field": 1
    });
    assert_eq!(
        parse_invite_ack(&payload, topic, "vjt"),
        Some((
            "azzurra".to_string(),
            "#rust".to_string(),
            "alice".to_string()
        ))
    );
    for key in ["network", "channel", "peer"] {
        let mut missing = payload.clone();
        missing.as_object_mut().expect("object").remove(key);
        assert_eq!(parse_invite_ack(&missing, topic, "vjt"), None, "{key}");
        let mut empty = payload.clone();
        empty[key] = serde_json::json!("");
        assert_eq!(parse_invite_ack(&empty, topic, "vjt"), None, "{key}");
    }
    assert_eq!(parse_invite_ack(&payload, "grappa:user:other", "vjt"), None);
}

#[test]
fn lusers_command_sends_mask_and_server_only_when_given() {
    let request = |payload: Value| {
        Some(ReplyCommand::Request {
            verb: "lusers",
            payload,
        })
    };
    assert_eq!(
        parse_reply_command("/lusers", "#rust"),
        request(serde_json::json!({}))
    );
    assert_eq!(
        parse_reply_command("/lusers *", "#rust"),
        request(serde_json::json!({"mask": "*"}))
    );
    assert_eq!(
        parse_reply_command("/LUSERS * irc.example.org extra", "#rust"),
        request(serde_json::json!({"mask": "*", "server": "irc.example.org"}))
    );
}

#[test]
fn parse_lusers_bundle_shows_unknown_counters_without_dropping_the_rest() {
    let topic = "grappa:user:vjt";
    let payload = serde_json::json!({
        "kind": "lusers_bundle",
        "network": "azzurra",
        "total_users": 120,
        "invisible": 30,
        "servers": 4,
        "operators": 2,
        "unknown_connections": null,
        "channels_formed": 55,
        "local_clients": 40,
        "local_servers": 1,
        "current_local": 40,
        "max_local": 90,
        "current_global": "garbled",
        "future_field": true
    });
    let view = parse_lusers_bundle(&payload, topic, "vjt").expect("valid bundle");
    assert_eq!(view.kind, "lusers_bundle");
    assert_eq!(view.network, "azzurra");
    assert_eq!(view.rows.len(), 12);
    assert_eq!(
        view.rows[0],
        ("lusers-total-users".to_string(), "120".to_string())
    );
    assert_eq!(
        view.rows[4],
        ("lusers-unknown-connections".to_string(), "—".to_string())
    );
    // A non-integer counter and a missing one both read as unknown.
    assert_eq!(view.rows[10].1, "—");
    assert_eq!(view.rows[11].1, "—");

    for invalid in [
        serde_json::json!({"kind": "lusers_bundle", "total_users": 1}),
        serde_json::json!({"kind": "lusers_bundle", "network": ""}),
        serde_json::json!({"kind": "lusers_bundle", "network": 7}),
        serde_json::json!({"kind": "whowas_bundle", "network": "azzurra"}),
    ] {
        assert!(
            parse_lusers_bundle(&invalid, topic, "vjt").is_none(),
            "{invalid}"
        );
    }
    assert!(parse_lusers_bundle(&payload, "grappa:user:other", "vjt").is_none());
}

#[test]
fn away_nick_suffix_push_updates_the_setting_and_never_the_nick() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("vjt".to_string());
    state
        .networks
        .own_nicks
        .insert("libera".to_string(), "vjt".to_string());
    let topic = "grappa:user:vjt";
    let push = |value: Value| serde_json::json!({"kind": "away_nick_suffix_changed", "away_nick_suffix": value});

    // Another device sets a suffix: the setting follows...
    assert_eq!(
        apply_away_nick_suffix_changed(&mut state, topic, &push(serde_json::json!("|away"))),
        Some(Some("|away".to_string()))
    );
    // ...and the nick stays the one the nick events reported.
    assert_eq!(
        state.networks.own_nicks.get("libera").map(String::as_str),
        Some("vjt")
    );
    // The same value again is no change.
    assert_eq!(
        apply_away_nick_suffix_changed(&mut state, topic, &push(serde_json::json!("|away"))),
        None
    );
    // `null` is the rename switched off, not a missing value.
    assert_eq!(
        apply_away_nick_suffix_changed(&mut state, topic, &push(Value::Null)),
        Some(None)
    );
    // The key is always present; without it, or on another subject's
    // topic, the push is rejected.
    assert_eq!(
        apply_away_nick_suffix_changed(
            &mut state,
            topic,
            &serde_json::json!({"kind": "away_nick_suffix_changed"})
        ),
        None
    );
    assert_eq!(
        apply_away_nick_suffix_changed(
            &mut state,
            "grappa:user:other",
            &push(serde_json::json!("|x"))
        ),
        None
    );
    assert_eq!(state.prefs.away_nick_suffix, Some(None));
}

#[test]
fn a_refused_nick_suffix_has_its_own_message() {
    assert_eq!(
        away_nick_suffix_error_key(Some(422)),
        "away-nick-suffix-invalid"
    );
    assert_eq!(
        away_nick_suffix_error_key(Some(500)),
        "personal-prefs-failed"
    );
    assert_eq!(away_nick_suffix_error_key(None), "personal-prefs-failed");
}

#[test]
fn a_refused_profile_is_told_apart_from_a_failed_one() {
    assert_eq!(profile_error_status(Some(422)), "profile-invalid");
    assert_eq!(profile_error_status(Some(404)), "profile-failed");
    assert_eq!(profile_error_status(None), "profile-failed");
}

#[test]
fn parse_nullable_setting_echo_keeps_null_distinct_from_missing() {
    let topic = "grappa:user:vjt";
    let kind = "quit_part_reason_changed";
    let key = "quit_part_reason";
    let payload = |value: Value| serde_json::json!({"kind": kind, key: value});
    assert_eq!(
        parse_nullable_setting_echo(&payload(Value::Null), topic, "vjt", kind, key),
        Some(None)
    );
    assert_eq!(
        parse_nullable_setting_echo(&payload(serde_json::json!("bye")), topic, "vjt", kind, key),
        Some(Some("bye".to_string()))
    );
    assert_eq!(
        parse_nullable_setting_echo(&payload(serde_json::json!("")), topic, "vjt", kind, key),
        Some(Some(String::new()))
    );

    for invalid in [
        payload(serde_json::json!(1)),
        payload(serde_json::json!(["bye"])),
        serde_json::json!({"kind": kind}),
        serde_json::json!({"kind": "auto_away_reason_changed", key: "bye"}),
    ] {
        assert_eq!(
            parse_nullable_setting_echo(&invalid, topic, "vjt", kind, key),
            None,
            "{invalid}"
        );
    }
    assert_eq!(
        parse_nullable_setting_echo(&payload(Value::Null), "grappa:user:other", "vjt", kind, key),
        None
    );
    // The auto-away echo shares the shape under its own kind and key.
    assert_eq!(
        parse_nullable_setting_echo(
            &serde_json::json!({"kind": "auto_away_reason_changed", "auto_away_reason": null}),
            topic,
            "vjt",
            "auto_away_reason_changed",
            "auto_away_reason"
        ),
        Some(None)
    );
}

#[test]
fn whois_command_requires_a_nick() {
    assert_eq!(
        parse_reply_command("/whois alice", "#rust"),
        Some(ReplyCommand::Request {
            verb: "whois",
            payload: serde_json::json!({"nick": "alice", "server": null, "source": "user"})
        })
    );
    assert_eq!(
        parse_reply_command("/whois alice irc.example.org", "#rust"),
        Some(ReplyCommand::Request {
            verb: "whois",
            payload: serde_json::json!({
                "nick": "alice",
                "server": "irc.example.org",
                "source": "user"
            })
        })
    );
    assert_eq!(
        parse_reply_command("/whois", "#rust"),
        Some(ReplyCommand::Usage)
    );
    assert_eq!(format_idle(59), "0:00:59");
    assert_eq!(format_idle(-5), "0:00:00");
}

#[test]
fn who_command_defaults_to_the_open_window() {
    assert_eq!(
        parse_reply_command("/who", "#rust"),
        Some(ReplyCommand::Request {
            verb: "who",
            payload: serde_json::json!({"channel": "#rust"})
        })
    );
    assert_eq!(
        parse_reply_command("/WHO #other extra", "#rust"),
        Some(ReplyCommand::Request {
            verb: "who",
            payload: serde_json::json!({"channel": "#other"})
        })
    );
    assert_eq!(parse_reply_command("/who", ""), Some(ReplyCommand::Usage));
    assert_eq!(parse_reply_command("hello /who", "#rust"), None);
    assert_eq!(parse_reply_command("/whoever", "#rust"), None);
}

#[test]
fn connecting_label_outranks_the_durable_connection_label() {
    let entries = vec![
        (
            "libera".to_string(),
            "#rust".to_string(),
            "#rust".to_string(),
        ),
        (
            "oftc".to_string(),
            "#debian".to_string(),
            "#debian".to_string(),
        ),
    ];
    let connection_states = HashMap::from([(
        "libera".to_string(),
        NetworkConnectionSnapshot {
            status: NetworkConnectionStatus::Failing,
            reason: None,
            changed_at: None,
        },
    )]);
    let mut groups = network_groups_data(
        &entries,
        &[],
        &HashMap::new(),
        &connection_states,
        &HashMap::new(),
    );
    let connecting = std::collections::HashSet::from(["libera".to_string()]);
    apply_connecting_labels(&mut groups, &connecting);
    assert_eq!(groups[0].0, "libera");
    assert_eq!(groups[0].4, "connecting");
    assert_eq!(groups[1].0, "oftc");
    assert_eq!(groups[1].4, "");
}

#[test]
fn parse_network_detached_accepts_only_the_authenticated_user_topic() {
    let payload = serde_json::json!({
        "kind": "network_detached",
        "network_id": 7,
        "network_slug": "libera",
        "future_field": true
    });
    assert_eq!(
        parse_network_detached_event(&payload, "grappa:user:sythos", "sythos"),
        Some((7, "libera".to_string()))
    );
    assert_eq!(
        parse_network_detached_event(&payload, "grappa:user:other", "sythos"),
        None
    );
    assert_eq!(
        parse_network_detached_event(
            &payload,
            "grappa:user:sythos/network:libera/channel:#rust",
            "sythos"
        ),
        None
    );
}

#[test]
fn parse_network_detached_rejects_invalid_identity_fields() {
    for payload in [
        serde_json::json!({"kind": "network_detached", "network_id": 0, "network_slug": "libera"}),
        serde_json::json!({"kind": "network_detached", "network_id": -1, "network_slug": "libera"}),
        serde_json::json!({"kind": "network_detached", "network_id": 7, "network_slug": "  "}),
        serde_json::json!({"kind": "network_attached", "network_id": 7, "network_slug": "libera"}),
        serde_json::json!({"kind": "network_detached", "network_id": "7", "network_slug": "libera"}),
    ] {
        assert_eq!(
            parse_network_detached_event(&payload, "grappa:user:sythos", "sythos"),
            None
        );
    }
}

#[test]
fn parse_network_attached_accepts_only_the_authenticated_user_topic() {
    let payload = serde_json::json!({
        "kind": "network_attached",
        "network_id": 7,
        "network_slug": "libera",
        "future_field": true
    });
    assert_eq!(
        parse_network_attached_event(&payload, "grappa:user:sythos", "sythos"),
        Some((7, "libera".to_string()))
    );
    assert_eq!(
        parse_network_attached_event(&payload, "grappa:user:other", "sythos"),
        None
    );
    assert_eq!(
        parse_network_attached_event(
            &payload,
            "grappa:user:sythos/network:libera/channel:#rust",
            "sythos"
        ),
        None
    );
}

#[test]
fn parse_network_attached_rejects_invalid_identity_fields() {
    for payload in [
        serde_json::json!({"kind": "network_attached", "network_id": 0, "network_slug": "libera"}),
        serde_json::json!({"kind": "network_attached", "network_id": -1, "network_slug": "libera"}),
        serde_json::json!({"kind": "network_attached", "network_id": 7, "network_slug": "  "}),
        serde_json::json!({"kind": "network_detached", "network_id": 7, "network_slug": "libera"}),
        serde_json::json!({"kind": "network_attached", "network_id": "7", "network_slug": "libera"}),
    ] {
        assert_eq!(
            parse_network_attached_event(&payload, "grappa:user:sythos", "sythos"),
            None
        );
    }
}

#[test]
fn parse_connection_state_changed_accepts_guest_user_topic_and_additive_fields() {
    let payload = serde_json::json!({
        "kind": "connection_state_changed",
        "user_id": null,
        "network_id": 7,
        "network_slug": "libera",
        "from": "connected",
        "to": "failing",
        "reason": "connection lost",
        "at": "2026-09-22T10:20:30Z",
        "network": {
            "slug": "libera",
            "nick": "sythos",
            "connection_state": "failing",
            "connection_state_reason": "connection lost",
            "connection_state_changed_at": "2026-09-22T10:20:30Z",
            "future_field": true
        },
        "future_field": true
    });

    let transition = parse_connection_state_changed_event(&payload, "grappa:user:guest", "guest")
        .expect("valid visitor transition");
    assert_eq!(transition.network_id, 7);
    assert_eq!(transition.network_slug, "libera");
    assert_eq!(transition.from, NetworkConnectionStatus::Connected);
    assert_eq!(transition.snapshot.status, NetworkConnectionStatus::Failing);
    assert_eq!(
        transition.snapshot.reason.as_deref(),
        Some("connection lost")
    );
    assert_eq!(
        transition.snapshot.changed_at.as_deref(),
        Some("2026-09-22T10:20:30Z")
    );
}

#[test]
fn parse_connection_state_changed_rejects_invalid_or_mismatched_rows() {
    let valid = serde_json::json!({
        "kind": "connection_state_changed",
        "user_id": "user-1",
        "network_id": 7,
        "network_slug": "libera",
        "from": "failing",
        "to": "failed",
        "reason": null,
        "at": null,
        "network": {
            "id": 7,
            "slug": "libera",
            "connection_state": "failed",
            "connection_state_reason": null,
            "connection_state_changed_at": null
        }
    });
    assert!(parse_connection_state_changed_event(&valid, "grappa:user:sythos", "sythos").is_some());

    for (path, value) in [
        ("user_id", serde_json::json!(7)),
        ("network_id", serde_json::json!(0)),
        ("from", serde_json::json!("unknown")),
        ("to", serde_json::json!("unknown")),
        ("network_slug", serde_json::json!("other")),
    ] {
        let mut invalid = valid.clone();
        invalid[path] = value;
        assert!(
            parse_connection_state_changed_event(&invalid, "grappa:user:sythos", "sythos")
                .is_none()
        );
    }

    let mut mismatched_slug = valid.clone();
    mismatched_slug["network"]["slug"] = serde_json::json!("other");
    assert!(
        parse_connection_state_changed_event(&mismatched_slug, "grappa:user:sythos", "sythos")
            .is_none()
    );

    let mut mismatched_status = valid.clone();
    mismatched_status["network"]["connection_state"] = serde_json::json!("failing");
    assert!(parse_connection_state_changed_event(
        &mismatched_status,
        "grappa:user:sythos",
        "sythos"
    )
    .is_none());

    let mut mismatched_id = valid.clone();
    mismatched_id["network"]["id"] = serde_json::json!(9);
    assert!(
        parse_connection_state_changed_event(&mismatched_id, "grappa:user:sythos", "sythos")
            .is_none()
    );

    assert!(parse_connection_state_changed_event(&valid, "grappa:user:other", "sythos").is_none());
}

#[test]
fn network_connection_states_keep_failing_distinct_from_terminal_failure() {
    let states = network_connection_states_from_entries(&[
        serde_json::json!({"slug":"libera", "connection_state":"failing"}),
        serde_json::json!({"slug":"oftc", "connection_state":"failed"}),
        serde_json::json!({"slug":"bad", "connection_state":"future_state"}),
    ]);

    assert_eq!(states.len(), 2);
    assert_eq!(states["libera"].status.sidebar_label(), "reconnecting");
    assert_eq!(states["oftc"].status.sidebar_label(), "connection failed");
}

#[test]
fn network_connection_transition_returns_home_only_on_a_new_terminal_state() {
    let mut states = network_connection_states_from_entries(&[
        serde_json::json!({"slug":"libera", "connection_state":"connected"}),
        serde_json::json!({"slug":"oftc", "connection_state":"failing"}),
        serde_json::json!({"slug":"already-parked", "connection_state":"parked"}),
    ]);
    let parked = NetworkConnectionSnapshot {
        status: NetworkConnectionStatus::Parked,
        reason: None,
        changed_at: Some("2026-09-22T10:20:30Z".to_string()),
    };

    assert_eq!(
        record_network_connection_state(&mut states, "libera", parked.clone()),
        (true, true)
    );
    assert_eq!(
        record_network_connection_state(&mut states, "libera", parked.clone()),
        (false, false)
    );
    assert_eq!(
        record_network_connection_state(&mut states, "already-parked", parked.clone()),
        (false, false)
    );

    let failed = NetworkConnectionSnapshot {
        status: NetworkConnectionStatus::Failed,
        reason: None,
        changed_at: None,
    };
    assert_eq!(
        record_network_connection_state(&mut states, "oftc", failed),
        (true, true)
    );
}

#[test]
fn network_groups_show_per_network_connection_state() {
    let entries = vec![(
        "libera".to_string(),
        "#rust".to_string(),
        "#rust".to_string(),
    )];
    let connection_states = HashMap::from([(
        "libera".to_string(),
        NetworkConnectionSnapshot {
            status: NetworkConnectionStatus::Parked,
            reason: None,
            changed_at: None,
        },
    )]);
    let groups = network_groups_data(
        &entries,
        &[],
        &HashMap::new(),
        &connection_states,
        &HashMap::new(),
    );
    assert_eq!(groups[0].4, "paused");
    assert!(groups[0].5);
    assert!(!groups[0].1);
    let reopened = network_groups_data(
        &entries,
        &[],
        &HashMap::from([("libera".to_string(), true)]),
        &connection_states,
        &HashMap::new(),
    );
    assert!(reopened[0].1);
}

#[test]
fn a_network_remains_in_the_sidebar_after_its_last_channel_is_removed() {
    let networks = HashMap::from([("libera".to_string(), 7)]);
    let groups = network_groups_data(&[], &[], &HashMap::new(), &HashMap::new(), &networks);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].0, "libera");
    assert!(groups[0].2.is_empty());
}

#[test]
fn server_window_history_is_available_without_joined_channels() {
    let boot = BootResponse {
        networks: vec![serde_json::json!({"id": 7, "slug": "libera"})],
        channels: HashMap::new(),
        heads: HashMap::from([(
            "libera".to_string(),
            HashMap::from([(
                SERVER_WINDOW_NAME.to_string(),
                vec![serde_json::json!({
                    "id": 11,
                    "server_time": 100,
                    "kind": "notice",
                    "sender": "NickServ",
                    "body": "Welcome"
                })],
            )]),
        )]),
    };

    assert!(channel_entries_from_channels(&boot.channels).is_empty());
    let messages = messages_from_boot_response(&boot);
    assert_eq!(
        messages
            .get(&("libera".to_string(), SERVER_WINDOW_NAME.to_string()))
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        channel_topic("visitor:one", "libera", SERVER_WINDOW_NAME),
        "grappa:user:visitor:one/network:libera/channel:$server"
    );
    assert_eq!(
        channel_from_topic(&channel_topic("visitor:one", "libera", SERVER_WINDOW_NAME)),
        Some(("libera".to_string(), SERVER_WINDOW_NAME.to_string()))
    );
}

#[test]
fn server_window_history_merges_with_live_messages_without_duplicates() {
    let key = ("libera".to_string(), SERVER_WINDOW_NAME.to_string());
    let rows = [
        serde_json::json!({
            "id": 11, "server_time": 100, "kind": "notice",
            "sender": "NickServ", "body": "Welcome"
        }),
        serde_json::json!({
            "id": 12, "server_time": 200, "kind": "notice",
            "sender": "NickServ", "body": "Identified"
        }),
    ];
    let mut state = WorkerState::new();
    merge_query_history(&mut state, &key, &rows[1..]);
    assert_eq!(query_high_water_id(&state, &key), Some(12));
    merge_query_history(&mut state, &key, &rows);
    let ids: Vec<_> = state.transcript.messages[&key]
        .iter()
        .filter_map(|message| message.message_id)
        .collect();
    assert_eq!(ids, vec![11, 12]);
}

#[test]
fn network_attached_rest_refresh_is_idempotent() {
    let boot = BootResponse {
        networks: vec![serde_json::json!({
            "id": 7,
            "slug": "libera",
            "nick": "sythos"
        })],
        channels: HashMap::from([(
            "libera".to_string(),
            vec![serde_json::json!({
                "name": "#rust",
                "joined": true
            })],
        )]),
        heads: HashMap::from([(
            "libera".to_string(),
            HashMap::from([(
                "#rust".to_string(),
                vec![serde_json::json!({
                    "id": 11,
                    "server_time": 100,
                    "kind": "privmsg",
                    "sender": "alice",
                    "body": "hello"
                })],
            )]),
        )]),
    };
    let me = MeResponse {
        read_cursors: serde_json::json!({"libera": {"#rust": 10}}),
        unread_counts: serde_json::json!({
            "libera": {"#rust": {"messages": 2, "mentions": 1}}
        }),
        badge_count: serde_json::json!(2),
        is_admin: false,
        kind: None,
        id: None,
        name: None,
        registered: None,
        home_data: None,
    };

    let mut state = WorkerState::new();
    state.conn.identifier = Some("sythos".to_string());
    let first_actions = apply_network_rest_refresh(&mut state, "sythos", &boot, &me);
    let first_channel_entries = state.windows.channel_entries.clone();
    let first_joined_topics = state.conn.joined_topics.clone();
    let message_snapshot = |messages: &HashMap<(String, String), Vec<RenderedMessage>>| {
        let mut snapshot = messages
            .iter()
            .map(|(key, messages)| {
                (
                    key.clone(),
                    messages
                        .iter()
                        .map(|message| {
                            (
                                message.timestamp.clone(),
                                message.nick.clone(),
                                message.text.clone(),
                                message.italic,
                                message.message_id,
                                message.server_time,
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        snapshot
    };
    let first_messages = message_snapshot(&state.transcript.messages);
    let first_members = state.transcript.members.clone();
    let first_cursors = state.windows.read_cursors.clone();
    let first_counts = (
        state.windows.window_messages.clone(),
        state.windows.window_mentions.clone(),
    );

    let second_actions = apply_network_rest_refresh(&mut state, "sythos", &boot, &me);

    assert_eq!(first_actions.len(), 3);
    assert!(
        first_actions.contains(&ChannelTopicAction::Join(channel_topic(
            "sythos",
            "libera",
            SERVER_WINDOW_NAME
        )))
    );
    assert!(second_actions.is_empty());
    assert_eq!(state.windows.channel_entries, first_channel_entries);
    assert_eq!(state.conn.joined_topics, first_joined_topics);
    assert_eq!(message_snapshot(&state.transcript.messages), first_messages);
    assert_eq!(state.transcript.members, first_members);
    assert_eq!(state.windows.read_cursors, first_cursors);
    assert_eq!(
        (
            &state.windows.window_messages,
            &state.windows.window_mentions
        ),
        (&first_counts.0, &first_counts.1)
    );
    assert_eq!(state.networks.network_ids.get("libera"), Some(&7));
    assert_eq!(
        state.networks.own_nicks.get("libera"),
        Some(&"sythos".to_string())
    );
}

#[test]
fn authoritative_refresh_removes_deleted_network_windows_and_listeners() {
    let mut state = WorkerState::new();
    state.conn.identifier = Some("sythos".to_string());
    state.networks.network_ids.insert("deleted".to_string(), 9);
    state.transcript.query_windows.push(QueryWindow {
        network: "deleted".to_string(),
        target_nick: "alice".to_string(),
        opened_at: "now".to_string(),
        dm_conversation_id: None,
    });
    let obsolete_topic = channel_topic("sythos", "deleted", "alice");
    state.conn.joined_topics.insert(obsolete_topic.clone());
    let obsolete_server_topic = channel_topic("sythos", "deleted", SERVER_WINDOW_NAME);
    state
        .conn
        .joined_topics
        .insert(obsolete_server_topic.clone());
    let server_row = serde_json::json!({
        "id": 21, "server_time": 100, "kind": "notice",
        "sender": "NickServ", "body": "Welcome"
    });
    merge_query_history(
        &mut state,
        &("deleted".to_string(), SERVER_WINDOW_NAME.to_string()),
        std::slice::from_ref(&server_row),
    );
    merge_query_history(
        &mut state,
        &("libera".to_string(), SERVER_WINDOW_NAME.to_string()),
        std::slice::from_ref(&server_row),
    );
    state
        .transcript
        .query_ready
        .insert(("deleted".to_string(), "alice".to_string()));
    let boot = BootResponse {
        networks: vec![serde_json::json!({"id": 7, "slug": "libera", "nick": "sythos"})],
        channels: HashMap::from([(
            "deleted".to_string(),
            vec![serde_json::json!({"name": "#stale", "joined": true})],
        )]),
        heads: HashMap::new(),
    };
    let me = MeResponse {
        read_cursors: serde_json::json!({}),
        unread_counts: serde_json::json!({}),
        badge_count: serde_json::json!(0),
        is_admin: false,
        kind: None,
        id: None,
        name: None,
        registered: None,
        home_data: None,
    };
    let actions = apply_network_rest_refresh(&mut state, "sythos", &boot, &me);
    assert_eq!(actions.len(), 4);
    assert!(actions.contains(&ChannelTopicAction::Leave(obsolete_topic)));
    assert!(actions.contains(&ChannelTopicAction::Leave(obsolete_server_topic)));
    assert!(actions.contains(&ChannelTopicAction::Join(channel_topic(
        "sythos", "libera", "sythos"
    ))));
    assert!(actions.contains(&ChannelTopicAction::Join(channel_topic(
        "sythos",
        "libera",
        SERVER_WINDOW_NAME
    ))));
    assert!(!state.networks.network_ids.contains_key("deleted"));
    assert!(!state
        .transcript
        .messages
        .contains_key(&("deleted".to_string(), SERVER_WINDOW_NAME.to_string())));
    assert_eq!(
        state
            .transcript
            .messages
            .get(&("libera".to_string(), SERVER_WINDOW_NAME.to_string()))
            .map(Vec::len),
        Some(1)
    );
    assert!(state.windows.channel_entries.is_empty());
    assert!(state.transcript.query_windows.is_empty());
    assert!(state.transcript.query_ready.is_empty());
    assert_eq!(
        state.conn.joined_topics,
        std::collections::HashSet::from([
            channel_topic("sythos", "libera", "sythos"),
            channel_topic("sythos", "libera", SERVER_WINDOW_NAME),
        ])
    );
    let groups = network_groups_data(
        &state.windows.channel_entries,
        &state.transcript.query_windows,
        &state.windows.expanded_networks,
        &state.networks.network_connection_states,
        &state.networks.network_ids,
    );
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].0, "libera");
}

#[test]
fn read_cursor_write_back_is_forward_only() {
    let mut state = WorkerState::new();
    let key = ("libera".to_string(), "#Rust".to_string());
    let line = |id| RenderedMessage {
        timestamp: "10:00".to_string(),
        nick: Some("foo".to_string()),
        text: "hi".to_string(),
        italic: false,
        message_id: Some(id),
        server_time: Some(id),
        presence_noise: false,
    };
    assert_eq!(read_cursor_to_write(&mut state), None);
    state.windows.current_channel = Some(key.clone());
    state
        .transcript
        .messages
        .insert(key.clone(), vec![line(7), line(9)]);
    assert_eq!(
        read_cursor_to_write(&mut state),
        Some(("libera".to_string(), "#Rust".to_string(), 9))
    );
    assert_eq!(
        state
            .windows
            .read_cursors
            .get(&window_state_key("libera", "#Rust")),
        Some(&9)
    );
    assert_eq!(read_cursor_to_write(&mut state), None);
    state
        .transcript
        .messages
        .get_mut(&key)
        .unwrap()
        .push(line(12));
    assert_eq!(
        read_cursor_to_write(&mut state),
        Some(("libera".to_string(), "#Rust".to_string(), 12))
    );
}

#[test]
fn catch_up_plan_pages_up_to_one_page_and_reloads_beyond_it() {
    assert_eq!(catch_up_plan(0), CatchUpPlan::Nothing);
    assert_eq!(catch_up_plan(1), CatchUpPlan::PageForward);
    assert_eq!(catch_up_plan(200), CatchUpPlan::PageForward);
    assert_eq!(catch_up_plan(201), CatchUpPlan::ReloadTail);
    assert_eq!(catch_up_plan(CATCH_UP_PROBE_CAP), CatchUpPlan::ReloadTail);
}

#[test]
fn catch_up_anchors_cover_joined_channels_and_keep_the_first_one() {
    let line = |id| RenderedMessage {
        timestamp: "10:00".to_string(),
        nick: Some("foo".to_string()),
        text: "hi".to_string(),
        italic: false,
        message_id: Some(id),
        server_time: Some(id),
        presence_noise: false,
    };
    let mut state = WorkerState::new();
    let joined = ("libera".to_string(), "#rust".to_string());
    let kicked = ("libera".to_string(), "#old".to_string());
    let empty = ("libera".to_string(), "#new".to_string());
    for key in [&joined, &kicked, &empty] {
        state
            .windows
            .channel_entries
            .push((key.0.clone(), key.1.clone(), key.1.clone()));
        state
            .windows
            .window_states
            .insert(window_state_key(&key.0, &key.1), ChannelWindowState::Joined);
    }
    state.windows.window_states.insert(
        window_state_key(&kicked.0, &kicked.1),
        ChannelWindowState::Kicked,
    );
    state
        .transcript
        .messages
        .insert(joined.clone(), vec![line(5), line(9), line(7)]);
    state
        .transcript
        .messages
        .insert(kicked.clone(), vec![line(3)]);

    note_catch_up_anchors(&mut state);
    assert_eq!(
        state.transcript.catch_up_anchors.iter().collect::<Vec<_>>(),
        vec![(&joined, &9)]
    );

    // A second drop before the catch-up ran keeps the older anchor.
    state
        .transcript
        .messages
        .get_mut(&joined)
        .unwrap()
        .push(line(12));
    note_catch_up_anchors(&mut state);
    assert_eq!(state.transcript.catch_up_anchors.get(&joined), Some(&9));
}

#[test]
fn history_tail_replaces_old_rows_keeps_live_ones_and_marks_the_hole() {
    let line = |id| RenderedMessage {
        timestamp: "10:00".to_string(),
        nick: Some("foo".to_string()),
        text: format!("row {id}"),
        italic: false,
        message_id: Some(id),
        server_time: Some(id),
        presence_noise: false,
    };
    let mut messages = vec![line(1), line(2), line(900)];
    // The tail arrives newest first, like the default page.
    replace_with_history_tail(&mut messages, vec![line(800), line(799), line(798)]);

    let ids: Vec<Option<i64>> = messages.iter().map(|m| m.message_id).collect();
    assert_eq!(ids, vec![None, Some(798), Some(799), Some(800), Some(900)]);
    assert!(messages[0].italic && messages[0].nick.is_none());
    assert_eq!(messages[0].server_time, Some(798));
}

#[test]
fn history_tail_without_rows_leaves_the_window_alone() {
    let mut messages = vec![RenderedMessage {
        timestamp: "10:00".to_string(),
        nick: Some("foo".to_string()),
        text: "hi".to_string(),
        italic: false,
        message_id: Some(4),
        server_time: Some(4),
        presence_noise: false,
    }];
    replace_with_history_tail(&mut messages, Vec::new());
    assert_eq!(messages.len(), 1);
}

#[test]
fn read_cursor_set_is_scoped_to_its_channel_shaped_topic_and_clamps_badge() {
    let channel = channel_topic("sythos", "libera", "#Cordiale");
    let payload = serde_json::json!({
        "kind": "read_cursor_set",
        "last_read_message_id": 202,
        "badge_count": 120,
        "future_field": "ignored"
    });

    assert_eq!(
        parse_read_cursor_set_event("sythos", &channel, &payload),
        Some((window_state_key("libera", "#cordiale"), 202, 99))
    );

    // Cicchetto uses the same channel-shaped topic for a DM or own-nick
    // listener, so those windows use the same per-network keying rule.
    let query = query_topic("sythos", "libera", "FrIeNd");
    let query_payload = serde_json::json!({
        "kind": "read_cursor_set",
        "last_read_message_id": 303,
        "badge_count": 7
    });
    assert_eq!(
        parse_read_cursor_set_event("sythos", &query, &query_payload),
        Some((window_state_key("libera", "friend"), 303, 7))
    );
}

#[test]
fn read_cursor_set_is_last_write_wins_even_when_cursor_moves_backward() {
    let topic = channel_topic("sythos", "libera", "#rust");
    let mut state = WorkerState::new();
    state.conn.identifier = Some("sythos".to_string());

    let newer = serde_json::json!({
        "kind": "read_cursor_set",
        "last_read_message_id": 202,
        "badge_count": 4
    });
    let older = serde_json::json!({
        "kind": "read_cursor_set",
        "last_read_message_id": 101,
        "badge_count": 5
    });

    assert!(apply_read_cursor_set(&mut state, "sythos", &topic, &newer));
    assert!(!apply_read_cursor_set(&mut state, "sythos", &topic, &newer));
    assert!(apply_read_cursor_set(&mut state, "sythos", &topic, &older));
    assert_eq!(
        state
            .windows
            .read_cursors
            .get(&window_state_key("libera", "#rust")),
        Some(&101)
    );
    assert_eq!(state.windows.badge_count, 5);
}

#[test]
fn read_cursors_are_seeded_from_me_without_fabricating_invalid_entries() {
    let payload = serde_json::json!({
        "libera": {
            "#Rust": 101,
            "Alice": 202,
            "#null": null,
            "#text": "203",
            "#fraction": 1.5
        },
        "invalid-network": 3,
        "empty-network": {}
    });
    let cursors = read_cursors_from_me(&payload);

    assert_eq!(cursors.len(), 2);
    assert_eq!(
        cursors.get(&window_state_key("libera", "#rust")),
        Some(&101)
    );
    assert_eq!(
        cursors.get(&window_state_key("libera", "alice")),
        Some(&202)
    );
    assert!(read_cursors_from_me(&Value::Null).is_empty());
}

#[test]
fn malformed_or_foreign_read_cursor_events_leave_state_unchanged() {
    let topic = channel_topic("sythos", "libera", "#rust");
    let mut state = WorkerState::new();
    state.conn.identifier = Some("sythos".to_string());
    state
        .windows
        .read_cursors
        .insert(window_state_key("libera", "#rust"), 101);
    state.windows.badge_count = 6;
    let before_cursors = state.windows.read_cursors.clone();
    let before_badge = state.windows.badge_count;

    for (identifier, event) in [
        (
            "someone-else",
            serde_json::json!({
                "kind": "read_cursor_set",
                "last_read_message_id": 202,
                "badge_count": 1
            }),
        ),
        (
            "sythos",
            serde_json::json!({
                "kind": "read_cursor_set",
                "last_read_message_id": "202",
                "badge_count": 1
            }),
        ),
        (
            "sythos",
            serde_json::json!({
                "kind": "window_counts",
                "last_read_message_id": 202,
                "badge_count": 1
            }),
        ),
    ] {
        assert!(!apply_read_cursor_set(
            &mut state, identifier, &topic, &event
        ));
    }
    assert!(!apply_read_cursor_set(
        &mut state,
        "sythos",
        "grappa:user:sythos",
        &serde_json::json!({
            "kind": "read_cursor_set",
            "last_read_message_id": 202,
            "badge_count": 1
        })
    ));

    assert_eq!(state.windows.read_cursors, before_cursors);
    assert_eq!(state.windows.badge_count, before_badge);
}

#[test]
fn read_cursor_badge_normalizes_values_like_cicchetto() {
    let cases = [
        (serde_json::json!(0), 0),
        (serde_json::json!(99), 99),
        (serde_json::json!(100), 99),
        (serde_json::json!(u64::MAX), 99),
        (serde_json::json!(-1), 0),
        (serde_json::json!(4.9), 4),
        (serde_json::json!(null), 0),
        (serde_json::json!("bad"), 0),
    ];

    for (value, expected) in cases {
        assert_eq!(normalize_badge_count(Some(&value)), expected);
    }
    assert_eq!(normalize_badge_count(None), 0);
}

#[test]
fn normalize_server_url_leaves_a_clean_url_untouched() {
    assert_eq!(
        normalize_server_url("https://irc.sindro.me"),
        "https://irc.sindro.me"
    );
}

#[test]
fn normalize_server_url_adds_a_missing_https_scheme() {
    assert_eq!(
        normalize_server_url("irc.sythos.dev"),
        "https://irc.sythos.dev"
    );
}

#[test]
fn normalize_server_url_leaves_an_explicit_http_scheme_alone() {
    assert_eq!(
        normalize_server_url("http://irc.sythos.dev"),
        "http://irc.sythos.dev"
    );
}

#[test]
fn to_ws_url_upgrades_https_to_wss() {
    assert_eq!(
        to_ws_url("https://irc.sindro.me"),
        format!(
            "wss://irc.sindro.me/socket/websocket?vsn=2.0.0&client_proto={CLIENT_PROTOCOL_VERSION}"
        )
    );
}

#[test]
fn recovery_input_trims_the_name_and_strips_whitespace_from_the_code() {
    assert_eq!(
        recovery_input("  vjt ", " abcd efgh\tijkl\n"),
        Some(("vjt".to_string(), "abcdefghijkl".to_string()))
    );
    assert_eq!(recovery_input("vjt", "  "), None);
    assert_eq!(recovery_input("  ", "abcd"), None);
    assert_eq!(recovery_input("", ""), None);
}

#[test]
fn recovery_refusals_tell_a_bad_code_from_a_throttle_and_a_busy_server() {
    let rejected = |status: u16, code: Option<&str>| GrappaClientError::Rejected {
        status: cordiale_core::client::StatusCode::from_u16(status).expect("status"),
        code: code.map(str::to_string),
        retry_after: None,
    };
    assert_eq!(
        recovery_error_key(&rejected(401, Some("invalid_two_factor"))),
        "recovery-invalid"
    );
    assert_eq!(
        recovery_error_key(&rejected(429, Some("too_many_attempts"))),
        "totp-throttled"
    );
    assert_eq!(
        recovery_error_key(&rejected(503, Some("db_unavailable"))),
        "recovery-busy"
    );
    assert_eq!(
        recovery_error_key(&rejected(400, Some("bad_request"))),
        "recovery-failed"
    );
    assert_eq!(recovery_error_key(&rejected(500, None)), "recovery-failed");
}

#[test]
fn share_token_refusals_name_what_the_user_can_do() {
    let rejected = |status: u16, code: Option<&str>| GrappaClientError::Rejected {
        status: cordiale_core::client::StatusCode::from_u16(status).expect("status"),
        code: code.map(str::to_string),
        retry_after: None,
    };
    assert_eq!(
        share_consume_error_key(&rejected(410, Some("share_token_expired"))),
        "share-expired"
    );
    assert_eq!(
        share_consume_error_key(&rejected(410, Some("share_token_consumed"))),
        "share-consumed"
    );
    assert_eq!(
        share_consume_error_key(&rejected(404, Some("not_found"))),
        "share-gone"
    );
    assert_eq!(
        share_consume_error_key(&rejected(429, Some("too_many_attempts"))),
        "too-many-attempts"
    );
    assert_eq!(
        share_consume_error_key(&rejected(401, Some("unauthorized"))),
        "share-invalid"
    );
    assert_eq!(
        share_consume_error_key(&rejected(400, Some("bad_request"))),
        "share-invalid"
    );
    assert_eq!(
        share_consume_error_key(&rejected(503, None)),
        "share-failed"
    );

    assert_eq!(
        share_mint_error_key(&rejected(403, Some("client_token_scope"))),
        "client-token"
    );
    assert_eq!(
        share_mint_error_key(&rejected(403, Some("forbidden"))),
        "incognito"
    );
    assert_eq!(share_mint_error_key(&rejected(429, None)), "throttled");
    assert_eq!(share_mint_error_key(&rejected(500, None)), "failed");
}

#[test]
fn a_shared_account_is_remembered_and_a_shared_guest_is_not() {
    let me = |value: serde_json::Value| -> MeResponse {
        serde_json::from_value(value).expect("a /me body")
    };
    let user = serde_json::json!({"kind": "user", "id": "u-1", "name": "vjt"});
    assert_eq!(
        shared_identity(Some(&user), &me(serde_json::json!({}))),
        ("vjt".to_string(), false)
    );
    let visitor = serde_json::json!({"kind": "visitor", "id": "v-1", "registered": false});
    assert_eq!(
        shared_identity(Some(&visitor), &me(serde_json::json!({"kind": "visitor"}))),
        (String::new(), true)
    );
    // Without a usable subject, `/me` says who signed in.
    assert_eq!(
        shared_identity(
            None,
            &me(serde_json::json!({"kind": "user", "name": "ada"}))
        ),
        ("ada".to_string(), false)
    );
    assert_eq!(
        shared_identity(None, &me(serde_json::json!({}))),
        (String::new(), true)
    );
}

#[test]
fn totp_sign_in_refusals_keep_the_step_or_restart_it() {
    let rejected = |status: u16, code: Option<&str>| GrappaClientError::Rejected {
        status: cordiale_core::client::StatusCode::from_u16(status).expect("status"),
        code: code.map(str::to_string),
        retry_after: None,
    };
    assert_eq!(
        totp_error_key(&rejected(401, Some("invalid_two_factor"))),
        "totp-invalid"
    );
    assert_eq!(
        totp_error_key(&rejected(401, Some("two_factor_challenge_expired"))),
        "totp-expired"
    );
    assert_eq!(
        totp_error_key(&rejected(429, Some("too_many_attempts"))),
        "totp-throttled"
    );
    assert_eq!(totp_error_key(&rejected(401, None)), "totp-invalid");
    assert_eq!(totp_error_key(&rejected(503, None)), "totp-failed");
}

#[test]
fn to_ws_url_upgrades_http_to_ws() {
    assert_eq!(
        to_ws_url("http://localhost:4000"),
        format!(
            "ws://localhost:4000/socket/websocket?vsn=2.0.0&client_proto={CLIENT_PROTOCOL_VERSION}"
        )
    );
}

fn nick_list(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| name.to_string()).collect()
}

#[test]
fn complete_nick_matches_prefix_case_insensitively_with_real_capitalisation() {
    let candidates = nick_list(&["Sythos", "sythe", "Somebody"]);
    let (text, _) = complete_nick("syt", &candidates, true, None).unwrap();
    assert_eq!(text, "Sythos: ");
}

#[test]
fn complete_nick_breaks_ties_by_member_list_order_not_alphabetical() {
    // "sythe" sorts after "Sythos" alphabetically but comes first in
    // the member list here — the list order must win.
    let candidates = nick_list(&["sythe", "Sythos"]);
    let (text, _) = complete_nick("syt", &candidates, true, None).unwrap();
    assert_eq!(text, "sythe: ");
}

#[test]
fn complete_nick_appends_colon_space_only_at_the_start_of_the_line() {
    let candidates = nick_list(&["Sythos"]);
    let (start_of_line, _) = complete_nick("syt", &candidates, true, None).unwrap();
    assert_eq!(start_of_line, "Sythos: ");

    let (mid_sentence, _) = complete_nick("hello syt", &candidates, true, None).unwrap();
    assert_eq!(mid_sentence, "hello Sythos ");
}

#[test]
fn complete_nick_cycles_forward_then_restores_the_original_then_wraps() {
    let candidates = nick_list(&["Sythos", "sythe"]);

    let (first, cycle1) = complete_nick("syt", &candidates, true, None).unwrap();
    assert_eq!(first, "Sythos: ");

    let (second, cycle2) = complete_nick(&first, &candidates, true, Some(&cycle1)).unwrap();
    assert_eq!(second, "sythe: ");

    let (third, cycle3) = complete_nick(&second, &candidates, true, Some(&cycle2)).unwrap();
    assert_eq!(
        third, "syt",
        "the last step in the cycle restores the typed text"
    );

    let (fourth, _) = complete_nick(&third, &candidates, true, Some(&cycle3)).unwrap();
    assert_eq!(
        fourth, "Sythos: ",
        "one more Tab wraps back to the first match"
    );
}

#[test]
fn complete_nick_shift_tab_cycles_backward() {
    let candidates = nick_list(&["Sythos", "sythe"]);
    let (first, cycle1) = complete_nick("syt", &candidates, true, None).unwrap();
    assert_eq!(first, "Sythos: ");

    // Backward from the first match skips straight to the original
    // text, the step immediately behind it in the cycle.
    let (back, _) = complete_nick(&first, &candidates, false, Some(&cycle1)).unwrap();
    assert_eq!(back, "syt");
}

#[test]
fn complete_nick_returns_none_when_nothing_matches() {
    let candidates = nick_list(&["Alice", "Bob"]);
    assert_eq!(complete_nick("zzz", &candidates, true, None), None);
}

#[test]
fn complete_nick_returns_none_for_an_empty_trailing_word() {
    let candidates = nick_list(&["Alice"]);
    assert_eq!(complete_nick("hello ", &candidates, true, None), None);
    assert_eq!(complete_nick("", &candidates, true, None), None);
}

#[test]
fn complete_nick_ignores_a_stale_cycle_after_a_manual_edit() {
    let candidates = nick_list(&["Sythos", "sythe"]);
    let (first, cycle1) = complete_nick("syt", &candidates, true, None).unwrap();
    assert_eq!(first, "Sythos: ");

    // The user kept typing instead of pressing Tab again: the compose
    // text no longer matches what the cycle last produced, so this is
    // treated as a brand-new completion request (starting over at the
    // first match) rather than a cycle step.
    let edited = "hi syt";
    let (restarted, _) = complete_nick(edited, &candidates, true, Some(&cycle1)).unwrap();
    assert_eq!(restarted, "hi Sythos ");
}

#[test]
fn complete_nick_keeps_a_multi_byte_prefix_intact_and_does_not_panic() {
    let candidates = nick_list(&["Test"]);
    let (text, _) = complete_nick("café tes", &candidates, true, None).unwrap();
    assert_eq!(text, "café Test ");
}

#[test]
fn prepend_anchor_keeps_the_top_line_and_its_offset() {
    // 200 rows averaging 20px, scrolled 105px down: row 5, 5px into it.
    let anchor = prepend_scroll_anchor(-105.0, 4000.0, 200, 100).unwrap();
    assert_eq!(anchor.row, 105);
    assert!((anchor.offset - 5.0).abs() < 1e-3);
    assert!((anchor.row_height - 20.0).abs() < 1e-3);

    // Flush with the top of row 0.
    let anchor = prepend_scroll_anchor(0.0, 4000.0, 200, 30).unwrap();
    assert_eq!((anchor.row, anchor.offset), (30, 0.0));

    // Exactly on a row boundary despite float rounding.
    let anchor = prepend_scroll_anchor(-60.0 + 1e-4, 4000.0, 200, 10).unwrap();
    assert_eq!(anchor.row, 13);
}

#[test]
fn resume_anchor_keeps_the_line_a_scrolled_up_reader_was_on() {
    // 200 rows averaging 20px, scrolled 105px down: row 5, 5px into it.
    let anchor = resume_scroll_anchor(false, -105.0, 4000.0, 200, 200).unwrap();
    assert_eq!(anchor.row, 5);
    assert!((anchor.offset - 5.0).abs() < 1e-3);
    assert!((anchor.row_height - 20.0).abs() < 1e-3);

    // Flush with the top of the first line.
    let anchor = resume_scroll_anchor(false, 0.0, 4000.0, 200, 200).unwrap();
    assert_eq!((anchor.row, anchor.offset), (0, 0.0));
}

#[test]
fn resume_anchor_ignores_lines_that_arrived_meanwhile() {
    // 30 lines came in at the tail while the reader was away.
    let anchor = resume_scroll_anchor(false, -105.0, 4000.0, 200, 230).unwrap();
    assert_eq!(anchor.row, 5);
    assert!((anchor.offset - 5.0).abs() < 1e-3);
    assert!((anchor.row_height - 20.0).abs() < 1e-3);
}

#[test]
fn resume_anchor_leaves_a_pane_at_the_tail_alone() {
    assert_eq!(resume_scroll_anchor(true, -3900.0, 4000.0, 200, 200), None);
    assert_eq!(resume_scroll_anchor(true, 0.0, 0.0, 0, 0), None);
}

#[test]
fn resume_anchor_needs_something_saved() {
    assert_eq!(resume_scroll_anchor(false, -50.0, 0.0, 200, 200), None);
    assert_eq!(resume_scroll_anchor(false, -50.0, 4000.0, 0, 200), None);
    assert_eq!(resume_scroll_anchor(false, -50.0, 4000.0, 200, 0), None);
}

#[test]
fn resume_anchor_clamps_to_the_lines_there_are() {
    // The saved position is past the end of a shorter window.
    let anchor = resume_scroll_anchor(false, -3000.0, 4000.0, 200, 10).unwrap();
    assert_eq!((anchor.row, anchor.offset), (9, 0.0));
}

#[test]
fn prepend_anchor_needs_something_to_anchor() {
    assert_eq!(prepend_scroll_anchor(-50.0, 4000.0, 200, 0), None);
    assert_eq!(prepend_scroll_anchor(0.0, 0.0, 0, 100), None);
    // Past the end (a stale position) clamps to the last row.
    let anchor = prepend_scroll_anchor(-9000.0, 4000.0, 200, 100).unwrap();
    assert_eq!(anchor.row, 299);
}

fn history_row(id: Option<i64>, server_time: Option<i64>) -> RenderedMessage {
    RenderedMessage {
        timestamp: String::new(),
        nick: None,
        text: format!("row {id:?}"),
        italic: false,
        message_id: id,
        server_time,
        presence_noise: false,
    }
}

fn row_ids(messages: &[RenderedMessage]) -> Vec<Option<i64>> {
    messages.iter().map(|message| message.message_id).collect()
}

#[test]
fn nothing_is_trimmed_until_the_window_is_past_the_slack() {
    assert_eq!(history_excess(0, 10, 3), 0);
    assert_eq!(history_excess(10, 10, 3), 0);
    assert_eq!(history_excess(13, 10, 3), 0);
    assert_eq!(history_excess(14, 10, 3), 4);
    assert_eq!(history_excess(100, 10, 3), 90);
    assert_eq!(history_excess(usize::MAX, usize::MAX, 3), 0);
}

#[test]
fn trimming_drops_the_oldest_rows_and_keeps_the_newest() {
    let mut messages: Vec<_> = (1..=14).map(|id| history_row(Some(id), Some(id))).collect();
    assert_eq!(trim_oldest_rows(&mut messages, 10, 3), 4);
    assert_eq!(messages.len(), 10);
    assert_eq!(messages.first().and_then(|m| m.message_id), Some(5));
    assert_eq!(messages.last().and_then(|m| m.message_id), Some(14));
}

#[test]
fn a_window_within_the_cap_is_left_alone() {
    let mut messages: Vec<_> = (1..=13).map(|id| history_row(Some(id), Some(id))).collect();
    assert_eq!(trim_oldest_rows(&mut messages, 10, 3), 0);
    assert_eq!(messages.len(), 13);
    let mut empty: Vec<RenderedMessage> = Vec::new();
    assert_eq!(trim_oldest_rows(&mut empty, 10, 3), 0);
}

#[test]
fn rows_are_kept_when_none_left_could_page_the_dropped_ones_back() {
    // Without a Grappa id left there is no `?before=` cursor.
    let mut messages: Vec<_> = (1..=14)
        .map(|id| history_row((id <= 4).then_some(id), Some(id)))
        .collect();
    assert_eq!(trim_oldest_rows(&mut messages, 10, 3), 0);
    assert_eq!(messages.len(), 14);
}

#[test]
fn trimming_a_window_resets_its_paging_state_only() {
    let key = ("libera".to_string(), "#busy".to_string());
    let other = ("libera".to_string(), "#quiet".to_string());
    let mut state = WorkerState::new();
    let total = (CHAT_HISTORY_CAP + CHAT_HISTORY_TRIM_SLACK + 1) as i64;
    state.transcript.messages.insert(
        key.clone(),
        (1..=total)
            .map(|id| history_row(Some(id), Some(id)))
            .collect(),
    );
    state
        .transcript
        .messages
        .insert(other.clone(), vec![history_row(Some(1), Some(1))]);
    state.transcript.history_start_reached.insert(key.clone());
    state.transcript.history_start_reached.insert(other.clone());
    state
        .transcript
        .history_cursors_fetched
        .insert((key.clone(), 1));
    state
        .transcript
        .history_cursors_fetched
        .insert((other.clone(), 1));

    assert!(trim_window_history(&mut state, &key));
    assert_eq!(state.transcript.messages[&key].len(), CHAT_HISTORY_CAP);
    assert_eq!(
        state.transcript.messages[&key]
            .last()
            .and_then(|m| m.message_id),
        Some(total)
    );
    assert!(!state.transcript.history_start_reached.contains(&key));
    assert!(!state
        .transcript
        .history_cursors_fetched
        .contains(&(key.clone(), 1)));
    // The oldest id left is the cursor older rows are paged from.
    assert_eq!(
        state.transcript.messages[&key]
            .iter()
            .filter_map(|m| m.message_id)
            .min(),
        Some(total - CHAT_HISTORY_CAP as i64 + 1)
    );
    assert!(state.transcript.history_start_reached.contains(&other));
    assert!(state
        .transcript
        .history_cursors_fetched
        .contains(&(other.clone(), 1)));

    // Already within the cap: nothing more to drop, nothing reset.
    state.transcript.history_start_reached.insert(key.clone());
    assert!(!trim_window_history(&mut state, &key));
    assert!(state.transcript.history_start_reached.contains(&key));
    let unknown = ("libera".to_string(), "#none".to_string());
    assert!(!trim_window_history(&mut state, &unknown));
}

#[test]
fn held_rows_count_every_window_and_the_largest() {
    let mut messages: MessagesByChannel = HashMap::new();
    assert_eq!(held_rows(&messages), (0, 0));
    messages.insert(
        ("n".to_string(), "#a".to_string()),
        vec![history_row(Some(1), None); 3],
    );
    messages.insert(
        ("n".to_string(), "#b".to_string()),
        vec![history_row(Some(2), None); 5],
    );
    assert_eq!(held_rows(&messages), (8, 5));
}

#[test]
fn a_live_line_that_sorts_last_is_appended() {
    let mut messages = vec![
        history_row(Some(1), Some(100)),
        history_row(Some(2), Some(200)),
    ];
    assert_eq!(
        insert_live_message(&mut messages, history_row(Some(3), Some(300))),
        LiveInsert::Appended
    );
    assert_eq!(row_ids(&messages), vec![Some(1), Some(2), Some(3)]);

    let mut empty = Vec::new();
    assert_eq!(
        insert_live_message(&mut empty, history_row(Some(1), Some(1))),
        LiveInsert::Appended
    );
    assert_eq!(empty.len(), 1);
}

#[test]
fn a_live_line_with_the_same_time_follows_by_id() {
    let mut messages = vec![history_row(Some(5), Some(200))];
    assert_eq!(
        insert_live_message(&mut messages, history_row(Some(6), Some(200))),
        LiveInsert::Appended
    );
    // A lower id at the same time sorts before the last row.
    assert_eq!(
        insert_live_message(&mut messages, history_row(Some(4), Some(200))),
        LiveInsert::Reordered
    );
    assert_eq!(row_ids(&messages), vec![Some(4), Some(5), Some(6)]);
}

#[test]
fn equal_keys_stay_in_arrival_order() {
    let mut messages = vec![history_row(None, Some(200))];
    let mut second = history_row(None, Some(200));
    second.text = "second".to_string();
    assert_eq!(
        insert_live_message(&mut messages, second),
        LiveInsert::Appended
    );
    assert_eq!(messages[1].text, "second");
}

#[test]
fn an_out_of_order_live_line_is_put_back_in_place() {
    let mut messages = vec![
        history_row(Some(1), Some(100)),
        history_row(Some(3), Some(300)),
    ];
    assert_eq!(
        insert_live_message(&mut messages, history_row(Some(2), Some(200))),
        LiveInsert::Reordered
    );
    assert_eq!(row_ids(&messages), vec![Some(1), Some(2), Some(3)]);
}

#[test]
fn rows_that_were_not_in_order_are_sorted_by_the_next_live_line() {
    // Newest first, as a history page arrives: appending would leave
    // the pane's rows out of order.
    let mut messages = vec![
        history_row(Some(3), Some(300)),
        history_row(Some(1), Some(100)),
    ];
    assert_eq!(
        insert_live_message(&mut messages, history_row(Some(4), Some(400))),
        LiveInsert::Reordered
    );
    assert_eq!(row_ids(&messages), vec![Some(1), Some(3), Some(4)]);
}

#[test]
fn a_duplicate_dm_line_is_not_stored_twice() {
    let key = ("libera".to_string(), "peer".to_string());
    let mut state = WorkerState::new();
    let payload = serde_json::json!({
        "id": 7,
        "server_time": 100,
        "kind": "privmsg",
        "sender": "peer",
        "body": "hello"
    });
    assert_eq!(
        append_query_live_message(&mut state, &key, &payload, None),
        Some(LiveInsert::Appended)
    );
    assert_eq!(
        append_query_live_message(&mut state, &key, &payload, None),
        None
    );
    let earlier = serde_json::json!({
        "id": 6,
        "server_time": 50,
        "kind": "privmsg",
        "sender": "peer",
        "body": "earlier"
    });
    assert_eq!(
        append_query_live_message(&mut state, &key, &earlier, None),
        Some(LiveInsert::Reordered)
    );
    assert_eq!(state.transcript.messages[&key].len(), 2);
}
