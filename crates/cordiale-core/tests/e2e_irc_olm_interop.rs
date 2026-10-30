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

//! Checks the wire vectors of irc-olm PR 4 in both directions.
//!
//! The vectors in `fixtures/e2e/irc_olm_v2.json` have the shape that
//! `devices.py` and `engine.py` of irc-olm write and read. The signatures use
//! the signed texts of irc-olm. The test reads each vector with the code of
//! Cordiale (irc-olm to Cordiale). It also builds each signed text and each
//! payload with the code of Cordiale and compares the bytes with the vector
//! (Cordiale to irc-olm). The ciphertext bodies are opaque test bytes: no
//! irc-olm process runs here, so this is a check of the shared wire shape and
//! not a live exchange.

use cordiale_core::e2e_device::{verify_device_certificate_bytes, verify_signed_list};
use cordiale_core::e2e_device_routes::InboxVerb;
use cordiale_core::e2e_engine::{Inner, InnerKind, KeysPayload, MessagePayload};
use cordiale_core::e2e_peer::{
    verify_certified_device, verify_peer_device, CertifiedBundle, PeerBundle,
};
use cordiale_core::e2e_trust::PeerTrust;
use cordiale_core::e2e_wire::{
    bundle_key_signed_text, decode_key, decode_signature, device_certificate_signed_text,
    device_id_signed_text, recipient_binding, signed_list_signed_text,
};
use serde_json::Value;
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

const NET: &str = "net";
const NICK: &str = "bot";

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/e2e/irc_olm_v2.json"))
        .expect("fixture file is JSON")
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

fn strings(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .expect("list")
        .iter()
        .map(|item| item.as_str().expect("text").to_string())
        .collect()
}

fn error_name<T: std::fmt::Debug, E: std::fmt::Debug>(result: Result<T, E>) -> String {
    format!("{:?}", result.expect_err("input must be rejected"))
}

/// Checks an Ed25519 signature over `signed`, the way irc-olm does.
fn signature_holds(signer: &str, signature: &str, signed: &[u8]) -> bool {
    let signer = Ed25519PublicKey::from_slice(&decode_key(signer).expect("key")).expect("key");
    let signature = Ed25519Signature::from_slice(&decode_signature(signature).expect("signature"))
        .expect("signature");
    signer.verify(signed, &signature).is_ok()
}

#[test]
fn the_fixture_has_a_current_revision() {
    assert_eq!(fixtures()["fixture_revision"], 1);
}

#[test]
fn signed_texts_built_by_cordiale_equal_the_texts_of_irc_olm() {
    let all = fixtures();
    let signed = &all["signed_texts"];

    let list = &signed["list"];
    let bytes = signed_list_signed_text(number(list, "version"), &strings(list, "keys"))
        .expect("list text");
    assert_eq!(bytes, text(list, "text").as_bytes());
    assert!(signature_holds(
        text(list, "master"),
        text(list, "signature"),
        &bytes
    ));
    verify_signed_list(
        number(list, "version"),
        &strings(list, "keys"),
        text(list, "master"),
        text(list, "signature"),
    )
    .expect("list signature");

    let id = &signed["id"];
    let id_text = device_id_signed_text(text(id, "curve25519"), text(id, "master"));
    assert_eq!(id_text, text(id, "text"));
    assert!(signature_holds(
        text(id, "device"),
        text(id, "signature"),
        id_text.as_bytes()
    ));

    let cert = &signed["certificate"];
    let bytes = device_certificate_signed_text(number(cert, "version"), text(cert, "device"))
        .expect("certificate text");
    assert_eq!(bytes, text(cert, "text").as_bytes());
    let master = text(cert, "master").to_string();
    assert_eq!(
        verify_device_certificate_bytes(
            &bytes,
            &master,
            text(cert, "signature"),
            std::slice::from_ref(&master)
        )
        .expect("certificate signature"),
        (number(cert, "version"), text(cert, "device").to_string())
    );

    let otk = &signed["one_time_key"];
    let bytes = bundle_key_signed_text(text(otk, "key")).expect("key text");
    assert_eq!(bytes, text(otk, "text").as_bytes());
    assert!(signature_holds(
        text(otk, "device"),
        text(otk, "signature"),
        &bytes
    ));

    let binding = &all["recipient_binding"];
    assert_eq!(
        recipient_binding(text(binding, "sender"), text(binding, "recipient")),
        text(binding, "fb")
    );
}

#[test]
fn a_keys_payload_of_irc_olm_is_read_verified_and_written_back() {
    let all = fixtures();
    for name in ["keys", "keys_fallback"] {
        let vector = &all["from_irc_olm"][name];
        let payload = KeysPayload::parse(text(vector, "text")).expect(name);
        assert_eq!(payload.devices.len(), 1, "{name}");
        let entry = &payload.devices[0];
        assert_eq!(
            entry.otk.fallback,
            vector["fallback"].as_bool().expect("flag"),
            "{name}"
        );

        // The list, the id block and the certificate chain verify.
        let mut trust = PeerTrust::default();
        let device = verify_peer_device(
            &mut trust,
            NET,
            NICK,
            None,
            &PeerBundle {
                master: &payload.master.ed25519,
                list_version: payload.master.list.ver,
                list_keys: &payload.master.list.devices,
                list_signature: &payload.master.sig,
                device_ed25519: &entry.id.ed25519,
                curve25519: &entry.id.curve25519,
                id_signature: &entry.id.sig,
            },
        )
        .expect(name);
        assert_eq!(device.did(), text(&vector["device"], "did"), "{name}");
        assert_eq!(
            device.ed25519(),
            text(&vector["device"], "ed25519"),
            "{name}"
        );
        assert_eq!(
            device.curve25519(),
            text(&vector["device"], "curve25519"),
            "{name}"
        );

        // The one-time key or the fallback key is signed by the device.
        let key_text = bundle_key_signed_text(&entry.otk.key).expect("key text");
        assert!(
            signature_holds(&entry.id.ed25519, &entry.otk.sig, &key_text),
            "{name}"
        );

        // Cordiale writes the same bytes back.
        assert_eq!(
            serde_json::to_string(&payload).expect("json"),
            text(vector, "text"),
            "{name}"
        );
    }
}

#[test]
fn a_pkmsg_payload_of_irc_olm_certifies_the_sender_and_is_written_back() {
    let all = fixtures();
    let vector = &all["from_irc_olm"]["pkmsg"];
    let MessagePayload::PreKey(payload) =
        MessagePayload::parse(InboxVerb::PkMsg, text(vector, "text")).expect("pkmsg")
    else {
        panic!("a pkmsg verb gives a pre-key payload");
    };
    assert_eq!(number(vector, "certificate_version"), payload.master.ver);
    let dids: Vec<&str> = payload.bodies.keys().map(String::as_str).collect();
    assert_eq!(dids, [text(vector, "to_did")]);

    let mut trust = PeerTrust::default();
    let device = verify_certified_device(
        &mut trust,
        NET,
        NICK,
        &CertifiedBundle {
            master: &payload.master.ed25519,
            certificate_version: payload.master.ver,
            certificate_signature: &payload.master.cert,
            device_ed25519: &payload.id.ed25519,
            curve25519: &payload.id.curve25519,
            id_signature: &payload.id.sig,
        },
    )
    .expect("certified device");
    // The `from` of the frame is the did of the id block.
    assert_eq!(device.did(), text(vector, "from_did"));

    assert_eq!(
        serde_json::to_string(&payload).expect("json"),
        text(vector, "text")
    );
}

#[test]
fn msg_payloads_of_irc_olm_are_read_and_written_back() {
    let all = fixtures();
    let one = &all["from_irc_olm"]["msg"];
    let MessagePayload::Normal(payload) =
        MessagePayload::parse(InboxVerb::Msg, text(one, "text")).expect("msg")
    else {
        panic!("a msg verb gives a normal payload");
    };
    assert_eq!(payload.ck, text(&all["keys"]["bot_device"], "curve25519"));
    let dids: Vec<&str> = payload.bodies.keys().map(String::as_str).collect();
    assert_eq!(dids, [text(one, "to_did")]);
    assert_eq!(
        serde_json::to_string(&payload).expect("json"),
        text(one, "text")
    );

    let two = &all["from_irc_olm"]["msg_to_two_devices"];
    let parsed = MessagePayload::parse(InboxVerb::Msg, text(two, "text")).expect("msg");
    let dids: Vec<String> = parsed.bodies().keys().cloned().collect();
    assert_eq!(dids, strings(two, "dids"));
}

#[test]
fn payloads_that_irc_olm_would_drop_are_rejected_here_too() {
    let all = fixtures();
    for case in all["malformed_payloads"].as_array().expect("cases") {
        let verb = match text(case, "verb") {
            "pkmsg" => InboxVerb::PkMsg,
            "msg" => InboxVerb::Msg,
            other => panic!("verb {other}"),
        };
        assert_eq!(
            error_name(MessagePayload::parse(verb, text(case, "text"))),
            text(case, "error"),
            "{}",
            text(case, "case")
        );
    }
    for case in all["malformed_keys"].as_array().expect("cases") {
        assert_eq!(
            error_name(KeysPayload::parse(text(case, "text"))),
            text(case, "error"),
            "{}",
            text(case, "case")
        );
    }
}

#[test]
fn inner_messages_of_irc_olm_are_read() {
    let all = fixtures();
    for case in all["from_irc_olm"]["inner"].as_array().expect("cases") {
        let name = text(case, "case");
        let inner = Inner::parse(text(case, "plain").as_bytes()).expect(name);
        assert_eq!(inner.lv, Some(number(case, "lv")), "{name}");
        assert_eq!(inner.fb.as_deref(), case["fb"].as_str(), "{name}");
        match (text(case, "kind"), inner.kind) {
            ("text", InnerKind::Text { body }) => assert_eq!(body, text(case, "body"), "{name}"),
            ("listreq", InnerKind::ListReq) | ("other", InnerKind::Other) => {}
            ("list", InnerKind::List { master }) => {
                // The list inside Olm verifies like the list of a KEYS.
                verify_signed_list(
                    master.list.ver,
                    &master.list.devices,
                    &master.ed25519,
                    &master.sig,
                )
                .expect(name);
            }
            (kind, other) => panic!("{name}: kind {kind} read as {other:?}"),
        }
    }
}
