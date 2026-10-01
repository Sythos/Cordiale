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

//! Per-channel "Denoise": which transcript lines count as presence noise,
//! when a channel hides them, and how the per-channel choice is kept in
//! step with Grappa.
//!
//! Mirrors Cicchetto's `presenceFilter.ts` and the server twin
//! (`Grappa.PresenceFilter`): the events are always delivered and always
//! processed (member lists, unread counts); this only decides whether the
//! lines are shown. The choice lives in `display_prefs.presence_filter` as
//! a `{"<slug> <channel>": "show" | "hide"}` map, where a missing key (not a
//! third value) means "no choice yet, follow the channel size".

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A channel with this many members or more hides presence by default,
/// until the user pins a choice. Must match Grappa's
/// `@large_channel_threshold` and Cicchetto's `LARGE_CHANNEL_THRESHOLD`:
/// the server applies the same default to the history pages it serves.
pub const LARGE_CHANNEL_THRESHOLD: usize = 200;

/// The row kinds Denoise hides, in Grappa's order
/// (`Grappa.Scrollback.Message.suppressed_presence_kinds/0`). Topic, kick
/// and server events are not churn and always stay visible.
const SUPPRESSED_KINDS: [&str; 5] = ["join", "part", "quit", "nick_change", "mode"];

/// A user's explicit choice for one channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresencePref {
    Show,
    Hide,
}

impl PresencePref {
    /// The value as Grappa spells it on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            PresencePref::Show => "show",
            PresencePref::Hide => "hide",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "show" => Some(PresencePref::Show),
            "hide" => Some(PresencePref::Hide),
            _ => None,
        }
    }
}

/// Whether a row is presence noise: one of the suppressed kinds, unless
/// Grappa tagged it `meta.structural` (a `MODE` that changed the channel
/// itself, such as a ban, a key or a limit, rather than a member's status).
/// Those stay visible even in a denoised channel.
pub fn is_presence_noise(kind: Option<&str>, structural: bool) -> bool {
    !structural && kind.is_some_and(|kind| SUPPRESSED_KINDS.contains(&kind))
}

/// Whether a channel hides its presence rows: an explicit choice wins, and
/// without one a channel of `LARGE_CHANNEL_THRESHOLD` members or more
/// hides. An unknown member count never hides on a guess.
pub fn presence_hidden(pref: Option<PresencePref>, member_count: Option<usize>) -> bool {
    match pref {
        Some(PresencePref::Hide) => true,
        Some(PresencePref::Show) => false,
        None => member_count.is_some_and(|count| count >= LARGE_CHANNEL_THRESHOLD),
    }
}

/// The choice a click on the toggle pins, given what the channel does now.
pub fn toggled_pref(currently_hidden: bool) -> PresencePref {
    if currently_hidden {
        PresencePref::Show
    } else {
        PresencePref::Hide
    }
}

/// What `GET /me/settings/display-prefs` says about the pinned channels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresencePins {
    pub pins: BTreeMap<String, PresencePref>,
    /// Whether the account ever saved its display preferences. Grappa
    /// answers with the defaults otherwise, so an empty map alone can't tell
    /// "never written" from "written empty".
    pub persisted: bool,
}

impl PresencePins {
    /// Reads a `{"display_prefs": {...}, "persisted": bool}` body. Entries
    /// that are not `"show"` or `"hide"` are dropped one by one, so a value
    /// from a newer server never costs the other pins.
    pub fn from_response(body: &Value) -> Self {
        let pins = body
            .get("display_prefs")
            .and_then(|prefs| prefs.get("presence_filter"))
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(key, value)| {
                        let pref = PresencePref::parse(value.as_str()?)?;
                        Some((key.clone(), pref))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let persisted = body
            .get("persisted")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        PresencePins { pins, persisted }
    }
}

/// The outcome of reconciling the local choices with the server's at
/// sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciled {
    /// The choices to use from now on.
    pub pins: BTreeMap<String, PresencePref>,
    /// The ones the server doesn't have yet and must be sent.
    pub push: BTreeMap<String, PresencePref>,
}

/// Same rule as Cicchetto's display-prefs sync: the server wins, except
/// for a choice made here whose upload never got confirmed (`unsynced`),
/// and, when the account never saved anything, everything set here is sent
/// up once instead of being wiped.
pub fn reconcile(
    local: &BTreeMap<String, PresencePref>,
    unsynced: &BTreeSet<String>,
    server: &PresencePins,
) -> Reconciled {
    if !server.persisted {
        return Reconciled {
            pins: local.clone(),
            push: local.clone(),
        };
    }
    let mut pins = server.pins.clone();
    let mut push = BTreeMap::new();
    for key in unsynced {
        if let Some(pref) = local.get(key) {
            pins.insert(key.clone(), *pref);
            push.insert(key.clone(), *pref);
        }
    }
    Reconciled { pins, push }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, PresencePref)]) -> BTreeMap<String, PresencePref> {
        entries
            .iter()
            .map(|(key, pref)| ((*key).to_string(), *pref))
            .collect()
    }

    #[test]
    fn join_part_quit_nick_change_and_mode_are_noise() {
        for kind in ["join", "part", "quit", "nick_change", "mode"] {
            assert!(is_presence_noise(Some(kind), false), "{kind}");
        }
    }

    #[test]
    fn chat_and_other_events_are_never_noise() {
        for kind in [
            "privmsg",
            "notice",
            "action",
            "topic",
            "kick",
            "server_event",
        ] {
            assert!(!is_presence_noise(Some(kind), false), "{kind}");
        }
        assert!(!is_presence_noise(None, false));
    }

    #[test]
    fn a_structural_mode_row_stays_visible() {
        assert!(!is_presence_noise(Some("mode"), true));
        assert!(is_presence_noise(Some("mode"), false));
    }

    #[test]
    fn an_explicit_choice_wins_over_the_channel_size() {
        assert!(presence_hidden(Some(PresencePref::Hide), Some(3)));
        assert!(!presence_hidden(Some(PresencePref::Show), Some(5_000)));
        assert!(presence_hidden(Some(PresencePref::Hide), None));
    }

    #[test]
    fn without_a_choice_only_a_large_channel_hides() {
        assert!(!presence_hidden(None, Some(LARGE_CHANNEL_THRESHOLD - 1)));
        assert!(presence_hidden(None, Some(LARGE_CHANNEL_THRESHOLD)));
        assert!(!presence_hidden(None, None));
    }

    #[test]
    fn the_toggle_pins_the_opposite_of_what_is_shown() {
        assert_eq!(toggled_pref(true), PresencePref::Show);
        assert_eq!(toggled_pref(false), PresencePref::Hide);
    }

    #[test]
    fn prefs_use_grappas_spelling_in_both_directions() {
        assert_eq!(
            serde_json::to_value(PresencePref::Hide).expect("serialize"),
            serde_json::json!("hide")
        );
        let pref: PresencePref = serde_json::from_value(serde_json::json!("show")).expect("show");
        assert_eq!(pref, PresencePref::Show);
        assert_eq!(PresencePref::Hide.as_str(), "hide");
        assert_eq!(PresencePref::Show.as_str(), "show");
    }

    #[test]
    fn pins_are_read_from_the_response_and_odd_entries_dropped() {
        let body = serde_json::json!({
            "display_prefs": {"presence_filter": {
                "libera #rust": "hide",
                "libera #go": "show",
                "libera #odd": "maybe",
                "libera #bool": true
            }},
            "persisted": true
        });
        let read = PresencePins::from_response(&body);
        assert!(read.persisted);
        assert_eq!(
            read.pins,
            map(&[
                ("libera #rust", PresencePref::Hide),
                ("libera #go", PresencePref::Show)
            ])
        );
    }

    #[test]
    fn a_response_without_pins_or_persisted_reads_as_empty_and_unsaved() {
        for body in [
            serde_json::json!({}),
            serde_json::json!({"display_prefs": {"presence_filter": "all"}}),
        ] {
            assert_eq!(PresencePins::from_response(&body), PresencePins::default());
        }
    }

    #[test]
    fn an_account_that_never_saved_gets_the_local_choices_pushed() {
        let local = map(&[("libera #rust", PresencePref::Hide)]);
        let server = PresencePins::default();
        let reconciled = reconcile(&local, &BTreeSet::new(), &server);
        assert_eq!(reconciled.pins, local);
        assert_eq!(reconciled.push, local);
    }

    #[test]
    fn the_server_wins_over_choices_already_uploaded() {
        let local = map(&[
            ("libera #rust", PresencePref::Hide),
            ("libera #old", PresencePref::Hide),
        ]);
        let server = PresencePins {
            pins: map(&[("libera #rust", PresencePref::Show)]),
            persisted: true,
        };
        let reconciled = reconcile(&local, &BTreeSet::new(), &server);
        assert_eq!(
            reconciled.pins,
            map(&[("libera #rust", PresencePref::Show)])
        );
        assert!(reconciled.push.is_empty());
    }

    #[test]
    fn an_unconfirmed_local_choice_survives_and_is_sent_again() {
        let local = map(&[
            ("libera #rust", PresencePref::Hide),
            ("libera #go", PresencePref::Hide),
        ]);
        let unsynced: BTreeSet<String> = ["libera #rust".to_string()].into();
        let server = PresencePins {
            pins: map(&[
                ("libera #rust", PresencePref::Show),
                ("libera #go", PresencePref::Show),
            ]),
            persisted: true,
        };
        let reconciled = reconcile(&local, &unsynced, &server);
        assert_eq!(
            reconciled.pins,
            map(&[
                ("libera #rust", PresencePref::Hide),
                ("libera #go", PresencePref::Show)
            ])
        );
        assert_eq!(
            reconciled.push,
            map(&[("libera #rust", PresencePref::Hide)])
        );
    }
}
