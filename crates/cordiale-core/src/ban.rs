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

//! Ban masks for `/kb` and `/kickban`: which form the user prefers and how
//! each one is built from what is known about the target.
//!
//! The choice is an account setting kept by Grappa (`ban_mask_form`, see
//! `GrappaClient::fetch_ban_mask_form`). A mask is only ever built
//! in the exact form asked for; when a part it needs is missing there is
//! no mask, never a broader or different one.

use serde::{Deserialize, Serialize};

/// The default ban form for `/kb` and `/kickban`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BanType {
    /// `nick!*@*`
    Nick,
    /// `*!user@host`
    UserHost,
    /// `*!*@host`. Also what an unknown stored value reads as.
    #[default]
    #[serde(other)]
    Host,
}

/// Why a ban mask could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanMaskError {
    /// A part the chosen form needs is missing or not usable in a mask.
    MissingPart,
}

impl BanType {
    /// Whether the mask needs the target's `user@host` from the server.
    pub fn needs_userhost(self) -> bool {
        !matches!(self, BanType::Nick)
    }

    /// The value Grappa stores in `ban_mask_form`.
    pub fn wire_name(self) -> &'static str {
        match self {
            BanType::Nick => "nick",
            BanType::Host => "host",
            BanType::UserHost => "user_host",
        }
    }

    /// The form for a `ban_mask_form` value; `None` for anything else.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "nick" => Some(BanType::Nick),
            "host" => Some(BanType::Host),
            "user_host" => Some(BanType::UserHost),
            _ => None,
        }
    }

    /// The position in the Settings picker.
    pub fn index(self) -> i32 {
        match self {
            BanType::Nick => 0,
            BanType::Host => 1,
            BanType::UserHost => 2,
        }
    }

    /// The form at a Settings picker position; anything unknown is the
    /// default.
    pub fn from_index(index: i32) -> Self {
        match index {
            0 => BanType::Nick,
            2 => BanType::UserHost,
            _ => BanType::Host,
        }
    }

    /// The ban mask for `nick`, whose resolved identity is `user` and
    /// `host` (unused parts may be `None`). `Err` when a part this form
    /// needs is absent, empty or has characters that don't belong in a
    /// mask.
    pub fn mask(
        self,
        nick: &str,
        user: Option<&str>,
        host: Option<&str>,
    ) -> Result<String, BanMaskError> {
        match self {
            BanType::Nick => Ok(format!("{}!*@*", mask_part(Some(nick))?)),
            BanType::Host => Ok(format!("*!*@{}", mask_part(host)?)),
            BanType::UserHost => Ok(format!("*!{}@{}", mask_part(user)?, mask_part(host)?)),
        }
    }
}

fn mask_part(value: Option<&str>) -> Result<&str, BanMaskError> {
    value
        .filter(|value| mask_part_is_valid(value))
        .ok_or(BanMaskError::MissingPart)
}

fn mask_part_is_valid(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '!' | '@' | '*' | '?' | ',')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_round_trip() {
        for ban_type in [BanType::Nick, BanType::Host, BanType::UserHost] {
            assert_eq!(
                BanType::from_wire_name(ban_type.wire_name()),
                Some(ban_type)
            );
        }
        assert_eq!(BanType::from_wire_name("mask"), None);
    }

    #[test]
    fn builds_each_form() {
        assert_eq!(
            BanType::Nick.mask("troll", None, None),
            Ok("troll!*@*".to_string())
        );
        assert_eq!(
            BanType::Host.mask("troll", Some("~u"), Some("spam.example")),
            Ok("*!*@spam.example".to_string())
        );
        assert_eq!(
            BanType::UserHost.mask("troll", Some("~u"), Some("spam.example")),
            Ok("*!~u@spam.example".to_string())
        );
    }

    #[test]
    fn a_missing_part_gives_no_mask_and_no_other_form() {
        assert!(BanType::Host.mask("troll", Some("u"), None).is_err());
        assert!(BanType::Host.mask("troll", Some("u"), Some("")).is_err());
        assert!(BanType::UserHost.mask("troll", None, Some("h")).is_err());
        assert!(BanType::UserHost.mask("troll", Some("u"), None).is_err());
        assert!(BanType::Nick.mask("", None, None).is_err());
        assert!(BanType::Host.mask("troll", None, Some("a b")).is_err());
        assert!(BanType::Host.mask("troll", None, Some("*")).is_err());
        assert!(BanType::Nick.mask("a@b", None, None).is_err());
    }

    #[test]
    fn only_the_nick_form_skips_the_lookup() {
        assert!(!BanType::Nick.needs_userhost());
        assert!(BanType::Host.needs_userhost());
        assert!(BanType::UserHost.needs_userhost());
    }

    #[test]
    fn picker_index_round_trips_and_defaults_to_host() {
        for ban_type in [BanType::Nick, BanType::Host, BanType::UserHost] {
            assert_eq!(BanType::from_index(ban_type.index()), ban_type);
        }
        assert_eq!(BanType::from_index(9), BanType::Host);
        assert_eq!(BanType::default(), BanType::Host);
    }

    #[test]
    fn serializes_like_the_setting_names() {
        assert_eq!(
            serde_json::to_value(BanType::UserHost).expect("serialize"),
            serde_json::json!("user_host")
        );
        assert_eq!(
            serde_json::from_value::<BanType>(serde_json::json!("nick")).expect("parse"),
            BanType::Nick
        );
        assert_eq!(
            serde_json::from_value::<BanType>(serde_json::json!("whatever")).expect("parse"),
            BanType::Host
        );
    }
}
