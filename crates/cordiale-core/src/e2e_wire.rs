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

//! Pure helpers for the per-device E2E wire v2 (phase 1).
//!
//! This module covers the parts of the agreed wire that do not depend on the
//! open protocol 49 schemas: frame text, fragment checks, device ids (`did`),
//! strict key and signature text, version numbers, the recipient binding and
//! the signed-list version rule. It holds no key material and does no crypto
//! beyond SHA-256. Signature checks, Olm sessions and the REST and event
//! types come in later phases.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::value::RawValue;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A signed device list holds 1 to 4 devices.
pub const MAX_LIST_DEVICES: usize = 4;

/// Highest accepted value for `ver` and `lv`: 2^31 - 1.
pub const MAX_VERSION: u32 = i32::MAX as u32;

/// Length of an unpadded standard base64 Ed25519 or Curve25519 key.
pub const KEY_TEXT_LEN: usize = 43;

/// Length of an unpadded standard base64 Ed25519 signature.
pub const SIGNATURE_TEXT_LEN: usize = 86;

/// Length of a `did`: 8 bytes in unpadded base64url.
pub const DID_LEN: usize = 11;

/// Lifetime of an X1 pairing rendezvous, in seconds.
pub const PAIRING_LIFETIME_SECS: u64 = 300;

/// Largest X1 pairing message, in bytes: 16 KiB.
pub const PAIRING_MESSAGE_MAX_BYTES: usize = 16 * 1024;

/// Largest total size of the messages in one X1 rendezvous: 64 KiB.
pub const PAIRING_TOTAL_MAX_BYTES: usize = 64 * 1024;

/// Largest number of messages in one X1 rendezvous.
pub const PAIRING_MAX_MESSAGES: usize = 64;

/// Storage limit of one device inbox for S1 copies: 4 MiB.
pub const INBOX_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Storage limit of one device inbox for one sender: 1 MiB.
pub const INBOX_SENDER_MAX_BYTES: usize = 1024 * 1024;

/// Lifetime of an S1 inbox copy, in seconds: seven days.
pub const INBOX_EXPIRY_SECS: u64 = 7 * 24 * 60 * 60;

/// Check whether the relay accepts one more X1 pairing message.
///
/// `count` and `total_bytes` describe the messages already stored.
pub fn pairing_message_fits(count: usize, total_bytes: usize, next_len: usize) -> bool {
    next_len <= PAIRING_MESSAGE_MAX_BYTES
        && count < PAIRING_MAX_MESSAGES
        && total_bytes
            .checked_add(next_len)
            .is_some_and(|sum| sum <= PAIRING_TOTAL_MAX_BYTES)
}

/// Address used when a frame is not for one device.
pub const WILDCARD: &str = "*";

const FRAME_PREFIX: &str = "\u{1}E2E ";
const FRAME_SUFFIX: char = '\u{1}';

/// Why a wire value is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    BadFrame,
    BadVerb,
    BadMsgid,
    BadFragment,
    BadDid,
    BadKey,
    BadSignature,
    BadVersion,
    BadAddress,
    BadJson,
    FragmentMismatch,
    DuplicateDevice,
    BadDeviceCount,
}

/// Frame verb of the wire v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    KeyReq,
    Keys,
    PkMsg,
    Msg,
    Nack,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::KeyReq => "KEYREQ",
            Verb::Keys => "KEYS",
            Verb::PkMsg => "PKMSG",
            Verb::Msg => "MSG",
            Verb::Nack => "NACK",
        }
    }

    fn parse(text: &str) -> Result<Self, WireError> {
        match text {
            "KEYREQ" => Ok(Verb::KeyReq),
            "KEYS" => Ok(Verb::Keys),
            "PKMSG" => Ok(Verb::PkMsg),
            "MSG" => Ok(Verb::Msg),
            "NACK" => Ok(Verb::Nack),
            _ => Err(WireError::BadVerb),
        }
    }
}

/// One fragment of a wire message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub verb: Verb,
    pub msgid: String,
    pub index: u32,
    pub total: u32,
    pub from: String,
    pub to: String,
    pub chunk: String,
}

fn is_std_b64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/'
}

fn is_url_b64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Decodes unpadded standard base64 and rejects any non-canonical text.
fn decode_canonical(text: &str, expected_len: usize) -> Option<Vec<u8>> {
    if text.len() != expected_len || !text.chars().all(is_std_b64_char) {
        return None;
    }
    let raw = STANDARD_NO_PAD.decode(text).ok()?;
    (STANDARD_NO_PAD.encode(&raw) == text).then_some(raw)
}

/// Decodes a 43-character Ed25519 or Curve25519 public key.
pub fn decode_key(text: &str) -> Result<[u8; 32], WireError> {
    decode_canonical(text, KEY_TEXT_LEN)
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .ok_or(WireError::BadKey)
}

/// Decodes an 86-character Ed25519 signature.
pub fn decode_signature(text: &str) -> Result<[u8; 64], WireError> {
    decode_canonical(text, SIGNATURE_TEXT_LEN)
        .and_then(|raw| <[u8; 64]>::try_from(raw).ok())
        .ok_or(WireError::BadSignature)
}

/// The `did` of a raw Ed25519 key: base64url of the first 8 bytes of its
/// SHA-256 hash.
pub fn did_from_raw_key(key: &[u8; 32]) -> String {
    let hash = Sha256::digest(key);
    URL_SAFE_NO_PAD.encode(&hash[..8])
}

/// The `did` of an Ed25519 key given as standard base64 text.
pub fn did_from_key_text(key: &str) -> Result<String, WireError> {
    decode_key(key).map(|raw| did_from_raw_key(&raw))
}

/// True when the text has the shape of a `did`. This does not prove that it
/// belongs to a key: derive it from the checked key for that.
pub fn is_did_shape(text: &str) -> bool {
    text.len() == DID_LEN
        && text.chars().all(is_url_b64_char)
        && URL_SAFE_NO_PAD
            .decode(text)
            .map(|raw| URL_SAFE_NO_PAD.encode(raw) == text)
            .unwrap_or(false)
}

/// Reads `ver` or `lv`: an integral number from 1 to 2^31 - 1. A number such
/// as `1.0` is accepted. Booleans, strings, null and fractions are not.
///
/// The field comes as raw JSON text (`RawValue`), so the exact number text
/// is kept for this field only. A `Value` would round it through `f64`.
pub fn parse_version(raw: &RawValue) -> Result<u32, WireError> {
    let version = integral_decimal(raw.get()).ok_or(WireError::BadVersion)?;
    u32::try_from(version)
        .ok()
        .filter(|v| (1..=MAX_VERSION).contains(v))
        .ok_or(WireError::BadVersion)
}

/// Reads the exact decimal text of a JSON number as a whole number. A number
/// such as `1.0` or `1e0` is whole. A fraction is not, however small it is.
/// The text is not rounded through `f64`.
fn integral_decimal(text: &str) -> Option<u64> {
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i64>().ok()?),
        None => (text, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = format!("{whole}{fraction}");
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some(0);
    }
    let shift = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
    let scaled = if shift >= 0 {
        if digits.len() as u64 + shift as u64 > 19 {
            return None;
        }
        format!("{digits}{}", "0".repeat(shift as usize))
    } else {
        let cut = usize::try_from(shift.unsigned_abs()).ok()?;
        let keep = digits.len().checked_sub(cut)?;
        if !digits[keep..].bytes().all(|b| b == b'0') {
            return None;
        }
        digits[..keep].to_string()
    };
    scaled.parse().ok()
}

/// Text the master key signs to certify a device id block.
pub fn device_id_signed_text(curve25519_key: &str, master_ed25519_key: &str) -> String {
    format!("irc-e2e:v2:id:{curve25519_key}:{master_ed25519_key}")
}

fn check_version(version: u32) -> Result<(), WireError> {
    if (1..=MAX_VERSION).contains(&version) {
        Ok(())
    } else {
        Err(WireError::BadVersion)
    }
}

/// Text the master key signs to certify one device: `irc-e2e:v2:dev:<N>:<E>`.
///
/// `first_list_version` is N, the first accepted list version that holds the
/// device. `device_ed25519_key` is E, the public device key. Candidate format:
/// the final contract is not approved yet. Returns the exact UTF-8 bytes for
/// signing, apart from any signature or `did` text.
pub fn device_certificate_signed_text(
    first_list_version: u32,
    device_ed25519_key: &str,
) -> Result<Vec<u8>, WireError> {
    check_version(first_list_version)?;
    decode_key(device_ed25519_key)?;
    Ok(format!("irc-e2e:v2:dev:{first_list_version}:{device_ed25519_key}").into_bytes())
}

/// Text the master key signs for one device list:
/// `irc-e2e:v2:list:<N>:<E1>,<E2>,...`.
///
/// The keys keep the order of the caller: this function does not sort them.
/// The caller applies the key order of the final contract. Candidate format:
/// the final contract is not approved yet.
pub fn signed_list_signed_text(
    list_version: u32,
    device_keys: &[String],
) -> Result<Vec<u8>, WireError> {
    check_version(list_version)?;
    check_list_devices(device_keys)?;
    Ok(format!("irc-e2e:v2:list:{list_version}:{}", device_keys.join(",")).into_bytes())
}

/// The `fb` binding: the first 16 bytes of SHA-256 over the sender and
/// recipient Ed25519 keys, as unpadded standard base64.
pub fn recipient_binding(sender_ed25519_key: &str, recipient_ed25519_key: &str) -> String {
    let text = format!("irc-e2e:v2:bind:{sender_ed25519_key}:{recipient_ed25519_key}");
    let hash = Sha256::digest(text.as_bytes());
    STANDARD_NO_PAD.encode(&hash[..16])
}

/// Checks the device keys of one signed list: 1 to 4 valid keys, no repeats,
/// no repeated `did`.
pub fn check_list_devices(keys: &[String]) -> Result<(), WireError> {
    if keys.is_empty() || keys.len() > MAX_LIST_DEVICES {
        return Err(WireError::BadDeviceCount);
    }
    let mut dids: Vec<String> = Vec::with_capacity(keys.len());
    for key in keys {
        let did = did_from_key_text(key)?;
        if dids.contains(&did) {
            return Err(WireError::DuplicateDevice);
        }
        dids.push(did);
    }
    Ok(())
}

/// What to do with a signed list that passed its signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListDecision {
    /// Higher version: replace the stored set.
    Replace,
    /// Equal version and same keys: nothing changes.
    NoOp,
    /// Lower version, or equal version with other keys: ignore it.
    Ignore,
}

/// Applies the version rule of the signed list. A first list is always
/// accepted.
pub fn decide_list(
    stored: Option<(u32, &[String])>,
    new_version: u32,
    new_keys: &[String],
) -> ListDecision {
    let Some((version, keys)) = stored else {
        return ListDecision::Replace;
    };
    if new_version > version {
        return ListDecision::Replace;
    }
    if new_version < version {
        return ListDecision::Ignore;
    }
    let mut old: Vec<&String> = keys.iter().collect();
    let mut new: Vec<&String> = new_keys.iter().collect();
    old.sort();
    new.sort();
    if old == new {
        ListDecision::NoOp
    } else {
        ListDecision::Ignore
    }
}

fn check_msgid(msgid: &str) -> Result<(), WireError> {
    if msgid.is_empty() || !msgid.chars().all(is_std_b64_char) {
        return Err(WireError::BadMsgid);
    }
    Ok(())
}

fn check_address(text: &str) -> Result<(), WireError> {
    if text == WILDCARD || is_did_shape(text) {
        Ok(())
    } else {
        Err(WireError::BadAddress)
    }
}

/// Checks the `from` and `to` pair that each verb allows.
pub fn check_addresses(verb: Verb, from: &str, to: &str) -> Result<(), WireError> {
    check_address(from)?;
    check_address(to)?;
    let from_any = from == WILDCARD;
    let to_any = to == WILDCARD;
    let ok = match verb {
        Verb::KeyReq => !from_any && to_any,
        Verb::Keys => from_any && !to_any,
        Verb::PkMsg | Verb::Msg => !from_any,
        Verb::Nack => !from_any && !to_any,
    };
    if ok {
        Ok(())
    } else {
        Err(WireError::BadAddress)
    }
}

fn parse_count(text: &str) -> Result<u32, WireError> {
    if text.is_empty() || text.len() > 9 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WireError::BadFragment);
    }
    text.parse().map_err(|_| WireError::BadFragment)
}

/// Parses one frame. The chunk must be non-empty ASCII text.
pub fn parse_frame(text: &str) -> Result<Frame, WireError> {
    let body = text
        .strip_prefix(FRAME_PREFIX)
        .and_then(|rest| rest.strip_suffix(FRAME_SUFFIX))
        .ok_or(WireError::BadFrame)?;
    if !body.is_ascii() || body.bytes().any(|b| b.is_ascii_control()) {
        return Err(WireError::BadFrame);
    }
    let mut parts = body.splitn(6, ' ');
    let verb = Verb::parse(parts.next().ok_or(WireError::BadFrame)?)?;
    let msgid = parts.next().ok_or(WireError::BadFrame)?;
    let fragment = parts.next().ok_or(WireError::BadFrame)?;
    let from = parts.next().ok_or(WireError::BadFrame)?;
    let to = parts.next().ok_or(WireError::BadFrame)?;
    let chunk = parts.next().ok_or(WireError::BadFrame)?;
    check_msgid(msgid)?;
    let (index, total) = fragment.split_once('/').ok_or(WireError::BadFragment)?;
    let (index, total) = (parse_count(index)?, parse_count(total)?);
    if index == 0 || index > total {
        return Err(WireError::BadFragment);
    }
    check_addresses(verb, from, to)?;
    if chunk.is_empty() || chunk.contains(FRAME_SUFFIX) {
        return Err(WireError::BadFrame);
    }
    Ok(Frame {
        verb,
        msgid: msgid.to_string(),
        index,
        total,
        from: from.to_string(),
        to: to.to_string(),
        chunk: chunk.to_string(),
    })
}

/// Formats one frame. It applies the same checks as `parse_frame`.
pub fn format_frame(frame: &Frame) -> Result<String, WireError> {
    let text = format!(
        "{FRAME_PREFIX}{} {} {}/{} {} {} {}{FRAME_SUFFIX}",
        frame.verb.as_str(),
        frame.msgid,
        frame.index,
        frame.total,
        frame.from,
        frame.to,
        frame.chunk
    );
    // A field with a space would shift the others on re-parse: the parsed
    // frame must equal the input.
    if parse_frame(&text)? != *frame {
        return Err(WireError::BadFrame);
    }
    Ok(text)
}

/// Joins the fragments of one message in index order. Any change of verb,
/// msgid, `from`, `to` or total, a missing index or a repeated index drops
/// the whole message.
pub fn assemble_fragments(frames: &[Frame]) -> Result<String, WireError> {
    let first = frames.first().ok_or(WireError::BadFragment)?;
    if frames.len() != first.total as usize {
        return Err(WireError::BadFragment);
    }
    let mut chunks: Vec<Option<&str>> = vec![None; frames.len()];
    for frame in frames {
        if frame.verb != first.verb
            || frame.msgid != first.msgid
            || frame.from != first.from
            || frame.to != first.to
            || frame.total != first.total
        {
            return Err(WireError::FragmentMismatch);
        }
        let slot = (frame.index as usize)
            .checked_sub(1)
            .and_then(|position| chunks.get_mut(position))
            .ok_or(WireError::BadFragment)?;
        if slot.replace(&frame.chunk).is_some() {
            return Err(WireError::BadFragment);
        }
    }
    Ok(chunks.into_iter().flatten().collect())
}

/// Parses a chunk or a joined payload as strict JSON text: ASCII only, no
/// control characters (compact JSON has no raw tab or line break).
/// `serde_json` already rejects `NaN` and `Infinity`.
pub fn parse_payload(text: &str) -> Result<Value, WireError> {
    if !text.is_ascii() || text.bytes().any(|b| b.is_ascii_control()) {
        return Err(WireError::BadJson);
    }
    serde_json::from_str(text).map_err(|_| WireError::BadJson)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_message_fits_checks_every_limit() {
        assert!(pairing_message_fits(0, 0, PAIRING_MESSAGE_MAX_BYTES));
        assert!(!pairing_message_fits(0, 0, PAIRING_MESSAGE_MAX_BYTES + 1));
        assert!(pairing_message_fits(PAIRING_MAX_MESSAGES - 1, 0, 1));
        assert!(!pairing_message_fits(PAIRING_MAX_MESSAGES, 0, 1));
        assert!(pairing_message_fits(1, PAIRING_TOTAL_MAX_BYTES - 10, 10));
        assert!(!pairing_message_fits(1, PAIRING_TOTAL_MAX_BYTES - 10, 11));
        assert!(!pairing_message_fits(1, usize::MAX, 1));
    }

    fn key_text(byte: u8) -> String {
        STANDARD_NO_PAD.encode([byte; 32])
    }

    fn frame(verb: Verb, from: &str, to: &str, index: u32, total: u32, chunk: &str) -> Frame {
        Frame {
            verb,
            msgid: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
            index,
            total,
            from: from.to_string(),
            to: to.to_string(),
            chunk: chunk.to_string(),
        }
    }

    #[test]
    fn did_has_eleven_url_safe_characters() {
        for byte in 0..=255u8 {
            let did = did_from_raw_key(&[byte; 32]);
            assert_eq!(did.len(), DID_LEN);
            assert!(is_did_shape(&did), "{did}");
            assert!(!did.contains('+') && !did.contains('/') && !did.contains('='));
        }
    }

    #[test]
    fn did_matches_the_hash_prefix() {
        let hash = Sha256::digest([7u8; 32]);
        assert_eq!(
            did_from_key_text(&key_text(7)).unwrap(),
            URL_SAFE_NO_PAD.encode(&hash[..8])
        );
    }

    fn raw_key(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        <[u8; 32]>::try_from(bytes).unwrap()
    }

    /// (raw key in hex, standard unpadded key text, expected did)
    const DID_VECTORS: [(&str, &str, &str); 2] = [
        // RFC 8032 test key.
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "If4x36FUomE",
        ),
        // Vector 70: the did holds both base64url characters.
        (
            "ee5d35c971a86ab62d114de7c07174d7f088a3cfebf14d25274d539d42d3f486",
            "7l01yXGoarYtEU3nwHF01/CIo8/r8U0lJ01TnULT9IY",
            "_Uw_z3-OAsk",
        ),
    ];

    #[test]
    fn did_matches_the_approved_vectors() {
        for (hex, text, did) in DID_VECTORS {
            let raw = raw_key(hex);
            assert_eq!(STANDARD_NO_PAD.encode(raw), text);
            assert_eq!(did_from_raw_key(&raw), did);
            assert_eq!(did_from_key_text(text).unwrap(), did);
            assert!(is_did_shape(did));
        }
    }

    #[test]
    fn did_hashes_the_raw_key_not_its_text() {
        let (_, text, did) = DID_VECTORS[0];
        let from_text = Sha256::digest(text.as_bytes());
        assert_ne!(URL_SAFE_NO_PAD.encode(&from_text[..8]), did);
    }

    #[test]
    fn did_vector_70_uses_hyphen_and_underscore() {
        let (hex, _, did) = DID_VECTORS[1];
        assert!(did.contains('-') && did.contains('_'));
        assert!(is_did_shape(did));
        assert_eq!(did_from_raw_key(&raw_key(hex)), did);
        // The standard-base64 form of the same bytes is not a did.
        assert!(!is_did_shape("/Uw/z3+OAsk"));
    }

    #[test]
    fn did_shape_rejects_standard_base64_and_wrong_length() {
        assert!(!is_did_shape("abc+defghij"));
        assert!(!is_did_shape("abc/defghij"));
        assert!(!is_did_shape("abcdefghij"));
        assert!(!is_did_shape("abcdefghijkl"));
        assert!(!is_did_shape("abcdefghij="));
        // The last character of an 11-character did carries only 4 bits.
        assert!(!is_did_shape("AAAAAAAAAAB"));
        assert!(is_did_shape("AAAAAAAAAAA"));
    }

    #[test]
    fn key_text_is_strict() {
        assert!(decode_key(&key_text(1)).is_ok());
        assert_eq!(
            decode_key(&format!("{}=", key_text(1))),
            Err(WireError::BadKey)
        );
        assert_eq!(decode_key(&key_text(1)[..42]), Err(WireError::BadKey));
        assert_eq!(decode_key("-".repeat(43).as_str()), Err(WireError::BadKey));
        // Non-canonical final character: trailing bits are not zero.
        let mut text = key_text(0);
        text.replace_range(42..43, "B");
        assert_eq!(decode_key(&text), Err(WireError::BadKey));
    }

    #[test]
    fn signature_text_is_strict() {
        let good = STANDARD_NO_PAD.encode([9u8; 64]);
        assert_eq!(good.len(), SIGNATURE_TEXT_LEN);
        assert!(decode_signature(&good).is_ok());
        assert_eq!(decode_signature(&good[..85]), Err(WireError::BadSignature));
        assert_eq!(decode_signature(&key_text(9)), Err(WireError::BadSignature));
    }

    #[test]
    fn version_accepts_integral_numbers_only() {
        let raw = |text: &str| RawValue::from_string(text.to_string()).unwrap();
        assert_eq!(parse_version(&raw("1")), Ok(1));
        assert_eq!(parse_version(&raw("1.0")), Ok(1));
        assert_eq!(parse_version(&raw("2147483647")), Ok(MAX_VERSION));
        assert_eq!(parse_version(&raw("1e0")), Ok(1));
        assert_eq!(parse_version(&raw("20E-1")), Ok(2));
        assert_eq!(parse_version(&raw("1.00")), Ok(1));
        assert_eq!(parse_version(&raw("0.5e1")), Ok(5));
        for bad in [
            "1.00000000000000001",
            "0.15e1",
            "1e-1",
            "0.0",
            "2147483648.0",
            "0",
            "-1",
            "1.5",
            "2147483648",
            "true",
            "\"1\"",
            "null",
            "[1]",
            "{\"a\":1}",
        ] {
            assert_eq!(
                parse_version(&raw(bad)),
                Err(WireError::BadVersion),
                "{bad}"
            );
        }
    }

    #[test]
    fn payload_numbers_are_plain_values() {
        let value = parse_payload(r#"{"$serde_json::private::Number":"1"}"#).unwrap();
        assert!(value.is_object());
        assert!(parse_payload(r#"{"ver":1}"#).unwrap()["ver"].is_number());
    }

    #[test]
    fn signed_texts_follow_the_agreed_shape() {
        assert_eq!(device_id_signed_text("CUR", "MAS"), "irc-e2e:v2:id:CUR:MAS");
        let binding = recipient_binding(&key_text(1), &key_text(2));
        assert_eq!(binding.len(), 22);
        assert_ne!(binding, recipient_binding(&key_text(2), &key_text(1)));
    }

    #[test]
    fn list_holds_one_to_four_distinct_devices() {
        assert_eq!(check_list_devices(&[]), Err(WireError::BadDeviceCount));
        let five: Vec<String> = (1..=5).map(key_text).collect();
        assert_eq!(check_list_devices(&five), Err(WireError::BadDeviceCount));
        assert!(check_list_devices(&five[..4]).is_ok());
        let repeat = vec![key_text(1), key_text(1)];
        assert_eq!(check_list_devices(&repeat), Err(WireError::DuplicateDevice));
        assert_eq!(
            check_list_devices(&["bad".to_string()]),
            Err(WireError::BadKey)
        );
    }

    #[test]
    fn list_version_rule() {
        let a = vec![key_text(1), key_text(2)];
        let b = vec![key_text(1), key_text(3)];
        assert_eq!(decide_list(None, 1, &a), ListDecision::Replace);
        assert_eq!(decide_list(Some((1, &a)), 2, &b), ListDecision::Replace);
        assert_eq!(decide_list(Some((2, &a)), 1, &b), ListDecision::Ignore);
        let reordered = vec![key_text(2), key_text(1)];
        assert_eq!(
            decide_list(Some((2, &a)), 2, &reordered),
            ListDecision::NoOp
        );
        assert_eq!(decide_list(Some((2, &a)), 2, &b), ListDecision::Ignore);
    }

    #[test]
    fn frame_round_trip() {
        let from = did_from_key_text(&key_text(1)).unwrap();
        let to = did_from_key_text(&key_text(2)).unwrap();
        let sent = frame(Verb::Nack, &from, &to, 1, 1, r#"{"ver":1}"#);
        let text = format_frame(&sent).unwrap();
        assert!(text.starts_with("\u{1}E2E NACK "));
        assert!(text.ends_with('\u{1}'));
        assert_eq!(parse_frame(&text).unwrap(), sent);
    }

    #[test]
    fn frame_address_pairs_per_verb() {
        let did = did_from_key_text(&key_text(1)).unwrap();
        let other = did_from_key_text(&key_text(2)).unwrap();
        assert!(check_addresses(Verb::KeyReq, &did, "*").is_ok());
        assert!(check_addresses(Verb::KeyReq, "*", &did).is_err());
        assert!(check_addresses(Verb::Keys, "*", &did).is_ok());
        assert!(check_addresses(Verb::Keys, &did, "*").is_err());
        assert!(check_addresses(Verb::Msg, &did, "*").is_ok());
        assert!(check_addresses(Verb::PkMsg, &did, &other).is_ok());
        assert!(check_addresses(Verb::Msg, "*", &did).is_err());
        assert!(check_addresses(Verb::Nack, &did, &other).is_ok());
        assert!(check_addresses(Verb::Nack, &did, "*").is_err());
        assert!(check_addresses(Verb::Msg, "abc+defghij", "*").is_err());
    }

    #[test]
    fn frame_parser_rejects_bad_input() {
        let did = did_from_key_text(&key_text(1)).unwrap();
        let ok = format!("\u{1}E2E KEYREQ AAAA 1/1 {did} * {{}}\u{1}");
        assert!(parse_frame(&ok).is_ok());
        for bad in [
            format!("E2E KEYREQ AAAA 1/1 {did} * {{}}"),
            format!("\u{1}E2E HELLO AAAA 1/1 {did} * {{}}\u{1}"),
            format!("\u{1}E2E KEYREQ AAAA 0/1 {did} * {{}}\u{1}"),
            format!("\u{1}E2E KEYREQ AAAA 2/1 {did} * {{}}\u{1}"),
            format!("\u{1}E2E KEYREQ AAAA 1-1 {did} * {{}}\u{1}"),
            format!("\u{1}E2E KEYREQ AA=A 1/1 {did} * {{}}\u{1}"),
            format!("\u{1}E2E KEYREQ AAAA 1/1 {did} *\u{1}"),
            format!("\u{1}E2E KEYREQ AAAA 1/1 {did} * caf\u{e9}\u{1}"),
        ] {
            assert!(parse_frame(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fragments_join_in_order_and_reject_changes() {
        let did = did_from_key_text(&key_text(1)).unwrap();
        let one = frame(Verb::Msg, &did, "*", 1, 2, "{\"a\":");
        let two = frame(Verb::Msg, &did, "*", 2, 2, "1}");
        assert_eq!(
            assemble_fragments(&[two.clone(), one.clone()]).unwrap(),
            "{\"a\":1}"
        );
        assert!(assemble_fragments(std::slice::from_ref(&one)).is_err());
        assert!(assemble_fragments(&[one.clone(), one.clone()]).is_err());
        let mut other = two.clone();
        other.msgid = "BBBB".to_string();
        assert_eq!(
            assemble_fragments(&[one.clone(), other]),
            Err(WireError::FragmentMismatch)
        );
        let mut moved = two;
        moved.to = did.clone();
        assert_eq!(
            assemble_fragments(&[one, moved]),
            Err(WireError::FragmentMismatch)
        );
        assert!(assemble_fragments(&[]).is_err());
    }

    #[test]
    fn fragment_index_zero_is_rejected() {
        let did = did_from_key_text(&key_text(1)).unwrap();
        let zero = frame(Verb::Msg, &did, "*", 0, 1, "{}");
        assert_eq!(assemble_fragments(&[zero]), Err(WireError::BadFragment));
    }

    #[test]
    fn payload_must_be_ascii_json() {
        assert!(parse_payload(r#"{"ver":1}"#).is_ok());
        assert_eq!(parse_payload("{\"a\":\"\u{e9}\"}"), Err(WireError::BadJson));
        assert_eq!(parse_payload("{\"a\":NaN}"), Err(WireError::BadJson));
        assert_eq!(parse_payload("{\"a\":Infinity}"), Err(WireError::BadJson));
        assert_eq!(parse_payload("{\"ver\":\n1}"), Err(WireError::BadJson));
        assert_eq!(parse_payload("{\"ver\":\t1}"), Err(WireError::BadJson));
    }

    #[test]
    fn frame_rejects_control_characters() {
        let did = did_from_key_text(&key_text(1)).unwrap();
        let text = format!("\u{1}E2E KEYREQ AAAA 1/1 {did} * {{\"ver\":\n1}}\u{1}");
        assert_eq!(parse_frame(&text), Err(WireError::BadFrame));
    }

    #[test]
    fn format_rejects_a_field_with_a_space() {
        let did = did_from_key_text(&key_text(1)).unwrap();
        let mut bad = frame(Verb::KeyReq, &did, "*", 1, 1, "{}");
        bad.msgid = format!("AAAA 1/1 {did} *");
        bad.index = 0;
        assert!(format_frame(&bad).is_err());
        bad.index = 1;
        assert!(format_frame(&bad).is_err());
    }

    const KEY_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const KEY_B: &str = "//////////////////////////////////////////8";

    #[test]
    fn device_certificate_text_is_exact() {
        assert_eq!(
            device_certificate_signed_text(3, KEY_A).unwrap(),
            b"irc-e2e:v2:dev:3:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec()
        );
        assert_eq!(
            device_certificate_signed_text(MAX_VERSION, KEY_B).unwrap(),
            b"irc-e2e:v2:dev:2147483647://////////////////////////////////////////8".to_vec()
        );
    }

    #[test]
    fn device_certificate_text_changes_with_each_field() {
        let base = device_certificate_signed_text(3, KEY_A).unwrap();
        assert_ne!(base, device_certificate_signed_text(4, KEY_A).unwrap());
        assert_ne!(base, device_certificate_signed_text(3, KEY_B).unwrap());
    }

    #[test]
    fn device_certificate_text_rejects_bad_input() {
        assert_eq!(
            device_certificate_signed_text(0, KEY_A),
            Err(WireError::BadVersion)
        );
        assert_eq!(
            device_certificate_signed_text(MAX_VERSION + 1, KEY_A),
            Err(WireError::BadVersion)
        );
        assert_eq!(
            device_certificate_signed_text(1, &KEY_A[..42]),
            Err(WireError::BadKey)
        );
        assert_eq!(
            device_certificate_signed_text(1, "A:A"),
            Err(WireError::BadKey)
        );
    }

    #[test]
    fn signed_list_text_is_exact() {
        let one = vec![KEY_A.to_string()];
        assert_eq!(
            signed_list_signed_text(1, &one).unwrap(),
            b"irc-e2e:v2:list:1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec()
        );
        let two = vec![KEY_A.to_string(), KEY_B.to_string()];
        assert_eq!(
            signed_list_signed_text(12, &two).unwrap(),
            b"irc-e2e:v2:list:12:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,//////////////////////////////////////////8"
                .to_vec()
        );
    }

    #[test]
    fn signed_list_text_follows_caller_order_and_version() {
        let ab = vec![KEY_A.to_string(), KEY_B.to_string()];
        let ba = vec![KEY_B.to_string(), KEY_A.to_string()];
        let base = signed_list_signed_text(2, &ab).unwrap();
        assert_ne!(base, signed_list_signed_text(2, &ba).unwrap());
        assert_ne!(base, signed_list_signed_text(3, &ab).unwrap());
        assert_ne!(base, signed_list_signed_text(2, &ab[..1]).unwrap());
    }

    #[test]
    fn signed_list_text_rejects_bad_lists() {
        let a = KEY_A.to_string();
        assert_eq!(
            signed_list_signed_text(0, std::slice::from_ref(&a)),
            Err(WireError::BadVersion)
        );
        assert_eq!(
            signed_list_signed_text(1, &[]),
            Err(WireError::BadDeviceCount)
        );
        assert_eq!(
            signed_list_signed_text(1, &[a.clone(), a.clone()]),
            Err(WireError::DuplicateDevice)
        );
        assert_eq!(
            signed_list_signed_text(1, &[a.clone(), format!("{KEY_A},{KEY_B}")]),
            Err(WireError::BadKey)
        );
        assert_eq!(
            signed_list_signed_text(1, &[a, String::new()]),
            Err(WireError::BadKey)
        );
        let five: Vec<String> = (0..5u8).map(key_text).collect();
        assert_eq!(
            signed_list_signed_text(1, &five),
            Err(WireError::BadDeviceCount)
        );
    }
}
