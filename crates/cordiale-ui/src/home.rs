// MIT License
//
// Copyright (c) 2026 Sythos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! The home page: Cicchetto's `HomePane` in native clothes. A welcome with
//! the honest session-lifetime line for the subject, one row per attached
//! network (connected rows jump to their `$server` window and can be
//! disconnected; parked or failed ones can be reconnected or removed from
//! the session), the operator's featured channels, and the networks the
//! subject can attach with one tap.
//!
//! This module holds the data only; `main.rs` owns the REST calls and the
//! Slint models. The rows themselves come from the same live snapshots the
//! sidebar uses, so the two never disagree about a network's state.

use std::collections::{HashMap, HashSet};

use cordiale_core::rest::{FeaturedChannel, MeResponse};

/// Who is signed in, as `GET /me` says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SubjectKind {
    #[default]
    Unknown,
    User,
    Visitor,
}

/// What the home page knows beyond the sidebar's own snapshots.
#[derive(Debug, Default)]
pub(crate) struct HomeState {
    pub(crate) subject: SubjectKind,
    /// A visitor's services registration (identity-wide).
    pub(crate) registered: bool,
    /// `home_data.available_networks`, in server order.
    pub(crate) available: Vec<String>,
    /// Networks whose credential carries a NickServ secret.
    pub(crate) recoverable: HashSet<String>,
    /// Row nicks from `home_data`, for a network whose live nick hasn't
    /// arrived yet.
    pub(crate) nicks: HashMap<String, String>,
    /// Last failed action per network row, as a status key.
    pub(crate) row_errors: HashMap<String, &'static str>,
    /// Rows with a reconnect in flight.
    pub(crate) reconnecting: HashSet<String>,
    /// The available network being attached, if any.
    pub(crate) connecting: Option<String>,
    /// The available network whose attach failed, with its status key.
    pub(crate) available_error: Option<(String, &'static str)>,
    /// Featured channels per network, fetched once per attached network.
    pub(crate) featured: HashMap<String, Vec<FeaturedChannel>>,
    /// The featured channel that couldn't be joined, per network.
    pub(crate) featured_errors: HashMap<String, String>,
}

impl HomeState {
    /// Takes the subject and `home_data` of a fresh `GET /me`. Anything
    /// the refresh no longer lists stops being offered.
    pub(crate) fn apply_me(&mut self, me: &MeResponse) {
        self.subject = match me.kind.as_deref() {
            Some("user") => SubjectKind::User,
            Some("visitor") => SubjectKind::Visitor,
            _ => SubjectKind::Unknown,
        };
        self.registered = me.registered == Some(true);
        let home = me.home_data.clone().unwrap_or_default();
        self.available = home
            .available_networks
            .into_iter()
            .map(|row| row.slug)
            .collect();
        self.recoverable = home
            .networks
            .iter()
            .filter(|row| row.recoverable)
            .map(|row| row.slug.clone())
            .collect();
        self.nicks = home
            .networks
            .into_iter()
            .filter(|row| !row.nick.is_empty())
            .map(|row| (row.slug, row.nick))
            .collect();
        if self
            .connecting
            .as_ref()
            .is_some_and(|slug| !self.available.contains(slug))
        {
            self.connecting = None;
        }
        if self
            .available_error
            .as_ref()
            .is_some_and(|(slug, _)| !self.available.contains(slug))
        {
            self.available_error = None;
        }
    }

    /// Drops per-row state of networks no longer attached.
    pub(crate) fn retain_networks(&mut self, attached: &HashSet<&str>) {
        self.row_errors
            .retain(|network, _| attached.contains(network.as_str()));
        self.reconnecting
            .retain(|network| attached.contains(network.as_str()));
        self.featured
            .retain(|network, _| attached.contains(network.as_str()));
        self.featured_errors
            .retain(|network, _| attached.contains(network.as_str()));
    }

    /// Key of the welcome's session-lifetime line.
    pub(crate) fn session_kind(&self) -> &'static str {
        match self.subject {
            SubjectKind::User => "user",
            SubjectKind::Visitor if self.registered => "visitor-registered",
            SubjectKind::Visitor => "visitor-guest",
            SubjectKind::Unknown => "",
        }
    }
}

/// Whether Settings > Security offers the account's second factors and
/// passkeys for this session kind (`HomeState::session_kind`). Those
/// belong to Grappa accounts: a guest or a registered visitor (whose
/// password is an IRC-network one) has none and Grappa refuses the routes.
/// An unknown kind keeps asking, as before.
pub(crate) fn account_security_available(session_kind: &str) -> bool {
    !matches!(session_kind, "visitor-guest" | "visitor-registered")
}

/// One attached network as the sidebar knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HomeRowInput {
    pub(crate) network: String,
    /// The live nick, when known.
    pub(crate) nick: Option<String>,
    /// `connected`, `failing`, `parked` or `failed`.
    pub(crate) state: &'static str,
    pub(crate) reason: Option<String>,
    /// The services verdict for this network.
    pub(crate) identified: bool,
}

/// One home row, ready for the Slint model.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct HomeRowView {
    pub(crate) network: String,
    pub(crate) nick: String,
    pub(crate) state: &'static str,
    pub(crate) connected: bool,
    pub(crate) reason: String,
    pub(crate) error: &'static str,
    pub(crate) reconnecting: bool,
    pub(crate) can_remove: bool,
    pub(crate) can_recover: bool,
    pub(crate) featured: Vec<FeaturedChannel>,
    pub(crate) featured_error: String,
}

/// Builds the rows in network-name order, like the sidebar. Only a
/// `connected` row is a live one; `failing`, `parked` and `failed` get the
/// reconnect row. Remove sits on that row alone (a network is stopped
/// before it is put away, as in Cicchetto) and never for a visitor, whose
/// identity lives on the credential: Grappa would answer 403.
pub(crate) fn home_rows(home: &HomeState, mut inputs: Vec<HomeRowInput>) -> Vec<HomeRowView> {
    inputs.sort_by(|left, right| left.network.cmp(&right.network));
    inputs
        .into_iter()
        .map(|input| {
            let connected = input.state == "connected";
            let nick = input
                .nick
                .filter(|nick| !nick.is_empty())
                .or_else(|| home.nicks.get(&input.network).cloned())
                .unwrap_or_default();
            HomeRowView {
                nick,
                state: input.state,
                connected,
                reason: if connected {
                    String::new()
                } else {
                    input.reason.unwrap_or_default()
                },
                error: home.row_errors.get(&input.network).copied().unwrap_or(""),
                reconnecting: home.reconnecting.contains(&input.network),
                can_remove: !connected && home.subject == SubjectKind::User,
                can_recover: connected
                    && home.subject == SubjectKind::Visitor
                    && home.recoverable.contains(&input.network)
                    && !input.identified,
                featured: home
                    .featured
                    .get(&input.network)
                    .cloned()
                    .unwrap_or_default(),
                featured_error: home
                    .featured_errors
                    .get(&input.network)
                    .cloned()
                    .unwrap_or_default(),
                network: input.network,
            }
        })
        .collect()
}

/// The `(nick, network)` a registered visitor's welcome may name: only
/// with exactly one network is that network certainly the registered one.
pub(crate) fn registered_naming(
    home: &HomeState,
    rows: &[HomeRowView],
) -> Option<(String, String)> {
    match (home.session_kind(), rows) {
        ("visitor-registered", [only]) if !only.nick.is_empty() => {
            Some((only.nick.clone(), only.network.clone()))
        }
        _ => None,
    }
}

/// Status key for a failed `DELETE /session/networks/:slug`: 403 is a
/// visitor, 404 a network this session no longer holds.
pub(crate) fn remove_error_key(status: Option<u16>) -> &'static str {
    match status {
        Some(403) => "remove-forbidden",
        Some(404) => "remove-not-found",
        _ => "remove-failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cordiale_core::rest::MeResponse;

    fn me(value: serde_json::Value) -> MeResponse {
        serde_json::from_value(value).expect("me")
    }

    fn input(network: &str, state: &'static str) -> HomeRowInput {
        HomeRowInput {
            network: network.into(),
            nick: Some("sythos".into()),
            state,
            reason: Some("user requested".into()),
            identified: false,
        }
    }

    #[test]
    fn apply_me_reads_subject_availability_and_recoverable_rows() {
        let mut home = HomeState::default();
        home.apply_me(&me(serde_json::json!({
            "kind": "visitor",
            "registered": true,
            "home_data": {
                "networks": [{"slug": "azzurra", "nick": "guest", "recoverable": true}],
                "available_networks": [{"slug": "libera"}]
            }
        })));
        assert_eq!(home.subject, SubjectKind::Visitor);
        assert_eq!(home.session_kind(), "visitor-registered");
        assert_eq!(home.available, vec!["libera".to_string()]);
        assert!(home.recoverable.contains("azzurra"));
        assert_eq!(home.nicks.get("azzurra").map(String::as_str), Some("guest"));
    }

    #[test]
    fn account_security_is_for_accounts_not_visitor_sessions() {
        assert!(account_security_available("user"));
        assert!(account_security_available(""));
        assert!(!account_security_available("visitor-guest"));
        assert!(!account_security_available("visitor-registered"));
    }

    #[test]
    fn apply_me_forgets_a_pending_connect_once_the_network_is_attached() {
        let mut home = HomeState {
            connecting: Some("libera".into()),
            available_error: Some(("oftc".into(), "connect-failed")),
            ..HomeState::default()
        };
        home.apply_me(&me(serde_json::json!({
            "kind": "user",
            "home_data": {"networks": [], "available_networks": [{"slug": "oftc"}]}
        })));
        assert_eq!(home.connecting, None);
        assert_eq!(
            home.available_error,
            Some(("oftc".into(), "connect-failed"))
        );
        assert_eq!(home.session_kind(), "user");
    }

    #[test]
    fn remove_is_offered_only_on_a_stopped_row_and_never_to_a_visitor() {
        let mut home = HomeState {
            subject: SubjectKind::User,
            ..HomeState::default()
        };
        let rows = home_rows(
            &home,
            vec![input("libera", "connected"), input("azzurra", "parked")],
        );
        assert_eq!(rows[0].network, "azzurra");
        assert!(rows[0].can_remove && !rows[0].connected);
        assert_eq!(rows[0].reason, "user requested");
        assert!(!rows[1].can_remove && rows[1].connected);
        assert_eq!(rows[1].reason, "");

        home.subject = SubjectKind::Visitor;
        let rows = home_rows(&home, vec![input("azzurra", "failed")]);
        assert!(!rows[0].can_remove);
    }

    #[test]
    fn failing_and_failed_rows_are_reconnect_rows() {
        let home = HomeState::default();
        for state in ["failing", "failed", "parked"] {
            let rows = home_rows(&home, vec![input("libera", state)]);
            assert!(!rows[0].connected, "{state}");
        }
    }

    #[test]
    fn recover_is_offered_to_an_unidentified_visitor_with_a_secret() {
        let mut home = HomeState {
            subject: SubjectKind::Visitor,
            ..HomeState::default()
        };
        home.recoverable.insert("azzurra".into());
        let mut row = input("azzurra", "connected");
        assert!(home_rows(&home, vec![row.clone()])[0].can_recover);
        row.identified = true;
        assert!(!home_rows(&home, vec![row.clone()])[0].can_recover);
        row.identified = false;
        home.subject = SubjectKind::User;
        assert!(!home_rows(&home, vec![row])[0].can_recover);
    }

    #[test]
    fn a_row_without_a_live_nick_falls_back_to_home_data() {
        let mut home = HomeState::default();
        home.nicks.insert("libera".into(), "sythos".into());
        let mut row = input("libera", "parked");
        row.nick = None;
        assert_eq!(home_rows(&home, vec![row])[0].nick, "sythos");
    }

    #[test]
    fn row_errors_and_featured_follow_their_network() {
        let mut home = HomeState::default();
        home.row_errors.insert("libera".into(), "remove-failed");
        home.featured.insert(
            "libera".into(),
            vec![FeaturedChannel {
                name: "#grappa".into(),
                description: None,
            }],
        );
        home.featured_errors
            .insert("libera".into(), "#grappa".into());
        let rows = home_rows(
            &home,
            vec![input("libera", "parked"), input("oftc", "parked")],
        );
        assert_eq!(rows[0].error, "remove-failed");
        assert_eq!(rows[0].featured.len(), 1);
        assert_eq!(rows[0].featured_error, "#grappa");
        assert_eq!(rows[1].error, "");

        home.retain_networks(&HashSet::from(["oftc"]));
        assert!(home.row_errors.is_empty());
        assert!(home.featured.is_empty());
        assert!(home.featured_errors.is_empty());
    }

    #[test]
    fn only_a_single_network_registered_visitor_is_named() {
        let home = HomeState {
            subject: SubjectKind::Visitor,
            registered: true,
            ..HomeState::default()
        };
        let one = home_rows(&home, vec![input("azzurra", "connected")]);
        assert_eq!(
            registered_naming(&home, &one),
            Some(("sythos".into(), "azzurra".into()))
        );
        let two = home_rows(
            &home,
            vec![input("azzurra", "connected"), input("libera", "connected")],
        );
        assert_eq!(registered_naming(&home, &two), None);
    }

    #[test]
    fn remove_errors_name_the_visitor_and_the_unknown_network() {
        assert_eq!(remove_error_key(Some(403)), "remove-forbidden");
        assert_eq!(remove_error_key(Some(404)), "remove-not-found");
        assert_eq!(remove_error_key(Some(500)), "remove-failed");
        assert_eq!(remove_error_key(None), "remove-failed");
    }
}
