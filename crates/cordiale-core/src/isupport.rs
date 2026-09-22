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

//! Typed validation for Grappa's per-network IRC ISUPPORT snapshot.

use std::collections::HashMap;

use serde_json::Value;

/// IRC case-folding advertised by the connected server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseMapping {
    Ascii,
    Rfc1459,
    Rfc1459Strict,
}

/// Complete server capability snapshot for one network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsupportState {
    pub chanmodes_a: Vec<String>,
    pub chanmodes_b: Vec<String>,
    pub chanmodes_c: Vec<String>,
    pub chanmodes_d: Vec<String>,
    pub list_modes_queryable: Vec<String>,
    pub prefix: HashMap<String, String>,
    pub prefix_order: Vec<String>,
    pub chantypes: Vec<String>,
    pub casemapping: CaseMapping,
    pub maxlist: HashMap<String, u64>,
    pub nicklen: Option<u64>,
    pub channellen: Option<u64>,
    pub topiclen: Option<u64>,
    pub frame_budget_base: u64,
}

/// A validated `isupport_changed` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsupportChanged {
    pub network_id: i64,
    pub state: IsupportState,
}

/// Parses a complete `isupport_changed` snapshot. Unknown additive fields are
/// intentionally ignored for forward compatibility.
pub fn parse_isupport_changed(payload: &Value) -> Option<IsupportChanged> {
    if payload.get("kind")?.as_str()? != "isupport_changed" {
        return None;
    }
    let network_id = payload.get("network_id")?.as_i64()?;
    if network_id <= 0 {
        return None;
    }

    let casemapping = match payload.get("casemapping")?.as_str()? {
        "ascii" => CaseMapping::Ascii,
        "rfc1459" => CaseMapping::Rfc1459,
        "rfc1459_strict" => CaseMapping::Rfc1459Strict,
        _ => return None,
    };
    let frame_budget_base = positive_integer(payload.get("frame_budget_base")?)?;

    Some(IsupportChanged {
        network_id,
        state: IsupportState {
            chanmodes_a: string_array(payload.get("chanmodes_a")?)?,
            chanmodes_b: string_array(payload.get("chanmodes_b")?)?,
            chanmodes_c: string_array(payload.get("chanmodes_c")?)?,
            chanmodes_d: string_array(payload.get("chanmodes_d")?)?,
            list_modes_queryable: string_array(payload.get("list_modes_queryable")?)?,
            prefix: string_map(payload.get("prefix")?)?,
            prefix_order: string_array(payload.get("prefix_order")?)?,
            chantypes: string_array(payload.get("chantypes")?)?,
            casemapping,
            maxlist: positive_integer_map(payload.get("maxlist")?)?,
            nicklen: nullable_positive_integer(payload.get("nicklen")?)?,
            channellen: nullable_positive_integer(payload.get("channellen")?)?,
            topiclen: nullable_positive_integer(payload.get("topiclen")?)?,
            frame_budget_base,
        },
    })
}

fn string_array(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect()
}

fn string_map(value: &Value) -> Option<HashMap<String, String>> {
    value
        .as_object()?
        .iter()
        .map(|(key, entry)| Some((key.clone(), entry.as_str()?.to_owned())))
        .collect()
}

fn positive_integer_map(value: &Value) -> Option<HashMap<String, u64>> {
    value
        .as_object()?
        .iter()
        .map(|(key, entry)| Some((key.clone(), positive_integer(entry)?)))
        .collect()
}

fn positive_integer(value: &Value) -> Option<u64> {
    value.as_u64().filter(|number| *number > 0)
}

fn nullable_positive_integer(value: &Value) -> Option<Option<u64>> {
    if value.is_null() {
        Some(None)
    } else {
        positive_integer(value).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_payload() -> Value {
        serde_json::json!({
            "kind": "isupport_changed",
            "network_id": 7,
            "chanmodes_a": ["b"],
            "chanmodes_b": ["k"],
            "chanmodes_c": ["l"],
            "chanmodes_d": ["i", "m"],
            "list_modes_queryable": ["b"],
            "prefix": {"o": "@", "v": "+"},
            "prefix_order": ["o", "v"],
            "chantypes": ["#", "&"],
            "casemapping": "rfc1459",
            "maxlist": {"b": 100},
            "nicklen": 30,
            "channellen": null,
            "topiclen": 390,
            "frame_budget_base": 4096,
            "future_field": {"is_ignored": true}
        })
    }

    #[test]
    fn parses_complete_snapshot_and_tolerates_additive_fields() {
        let parsed = parse_isupport_changed(&valid_payload()).expect("valid snapshot");

        assert_eq!(parsed.network_id, 7);
        assert_eq!(parsed.state.casemapping, CaseMapping::Rfc1459);
        assert_eq!(parsed.state.prefix.get("o").map(String::as_str), Some("@"));
        assert_eq!(parsed.state.prefix_order, ["o", "v"]);
        assert_eq!(parsed.state.channellen, None);
        assert_eq!(parsed.state.maxlist.get("b"), Some(&100));
    }

    #[test]
    fn accepts_all_casemapping_values_and_empty_maxlist() {
        for (wire, expected) in [
            ("ascii", CaseMapping::Ascii),
            ("rfc1459", CaseMapping::Rfc1459),
            ("rfc1459_strict", CaseMapping::Rfc1459Strict),
        ] {
            let mut payload = valid_payload();
            payload["casemapping"] = Value::String(wire.to_string());
            payload["maxlist"] = serde_json::json!({});
            payload["nicklen"] = Value::Null;
            payload["topiclen"] = Value::Null;

            let parsed = parse_isupport_changed(&payload).expect("valid enum value");
            assert_eq!(parsed.state.casemapping, expected);
            assert!(parsed.state.maxlist.is_empty());
            assert_eq!(parsed.state.nicklen, None);
            assert_eq!(parsed.state.topiclen, None);
        }
    }

    #[test]
    fn rejects_invalid_required_fields_and_non_positive_limits() {
        for (field, invalid) in [
            ("network_id", serde_json::json!(0)),
            ("network_id", serde_json::json!("7")),
            ("chanmodes_a", serde_json::json!(["b", 1])),
            ("prefix", serde_json::json!({"o": 1})),
            ("casemapping", serde_json::json!("unicode")),
            ("maxlist", serde_json::json!({"b": 0})),
            ("nicklen", serde_json::json!(0)),
            ("channellen", serde_json::json!(-1)),
            ("topiclen", serde_json::json!("390")),
            ("frame_budget_base", serde_json::json!(0)),
        ] {
            let mut payload = valid_payload();
            payload[field] = invalid;
            assert_eq!(parse_isupport_changed(&payload), None, "field {field}");
        }

        let mut missing = valid_payload();
        missing.as_object_mut().expect("object").remove("topiclen");
        assert_eq!(parse_isupport_changed(&missing), None);
    }
}
