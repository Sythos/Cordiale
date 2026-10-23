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

//! Checks the shared E2E v2 fixtures against `e2e_wire`.
//!
//! The fixture file is plain JSON, so another implementation can read the
//! same vectors. The signed texts and the list order stay candidates until
//! the final protocol 49 contract and the final MD-3 pin land.

use cordiale_core::e2e_wire::{
    device_certificate_signed_text, did_from_key_text, format_frame, is_did_shape,
    parse_device_certificate_signed_text, parse_frame, signed_list_signed_text, Frame,
};
use serde_json::Value;

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/e2e/wire_v2.json")).expect("fixture file is JSON")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_else(|| panic!("field {key}"))
}

fn number(value: &Value, key: &str) -> u32 {
    value[key]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or_else(|| panic!("field {key}"))
}

fn keys(value: &Value) -> Vec<String> {
    value["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|key| key.as_str().expect("key text").to_string())
        .collect()
}

fn error_name<T: std::fmt::Debug, E: std::fmt::Debug>(result: Result<T, E>) -> String {
    format!("{:?}", result.expect_err("input must be rejected"))
}

#[test]
fn fixture_did_vectors_match() {
    for case in fixtures()["did"].as_array().expect("did") {
        let did = text(case, "did");
        assert_eq!(did_from_key_text(text(case, "key")).unwrap(), did);
        assert!(is_did_shape(did), "{}", text(case, "case"));
    }
}

#[test]
fn fixture_certificates_match() {
    let all = fixtures();
    for case in all["certificate"]["valid"].as_array().expect("valid") {
        let bytes = device_certificate_signed_text(number(case, "version"), text(case, "key"))
            .expect(text(case, "case"));
        assert_eq!(bytes, text(case, "signed_text").as_bytes());
        assert_eq!(
            parse_device_certificate_signed_text(&bytes).unwrap(),
            (number(case, "version"), text(case, "key").to_string())
        );
    }
    for case in all["certificate"]["invalid"].as_array().expect("invalid") {
        let result = parse_device_certificate_signed_text(text(case, "signed_text").as_bytes());
        assert_eq!(
            error_name(result),
            text(case, "error"),
            "{}",
            text(case, "case")
        );
    }
}

#[test]
fn fixture_signed_lists_match() {
    let all = fixtures();
    for case in all["signed_list"]["valid"].as_array().expect("valid") {
        let bytes = signed_list_signed_text(number(case, "version"), &keys(case))
            .expect(text(case, "case"));
        assert_eq!(bytes, text(case, "signed_text").as_bytes());
    }
    for case in all["signed_list"]["invalid"].as_array().expect("invalid") {
        let result = signed_list_signed_text(number(case, "version"), &keys(case));
        assert_eq!(
            error_name(result),
            text(case, "error"),
            "{}",
            text(case, "case")
        );
    }
}

#[test]
fn fixture_frames_parse_and_format_back() {
    for case in fixtures()["frames"]["valid"].as_array().expect("valid") {
        let frame = parse_frame(text(case, "text")).expect(text(case, "case"));
        assert_eq!(frame.verb.as_str(), text(case, "verb"));
        assert_eq!(frame.msgid, text(case, "msgid"));
        assert_eq!(frame.index, number(case, "index"));
        assert_eq!(frame.total, number(case, "total"));
        assert_eq!(frame.from, text(case, "from"));
        assert_eq!(frame.to, text(case, "to"));
        assert_eq!(frame.chunk, text(case, "chunk"));
        let again: Frame = frame.clone();
        assert_eq!(format_frame(&again).unwrap(), text(case, "text"));
    }
}

#[test]
fn fixture_bad_frames_are_rejected() {
    for case in fixtures()["frames"]["invalid"].as_array().expect("invalid") {
        assert_eq!(
            error_name(parse_frame(text(case, "text"))),
            text(case, "error"),
            "{}",
            text(case, "case")
        );
    }
}
