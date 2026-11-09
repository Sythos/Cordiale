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

//! Files of an encrypted query (Grappa protocol 58, issue 2517).
//!
//! The sender seals the file with AES-256-GCM under a new random key and
//! nonce, uploads the ciphertext with `POST /api/uploads/encrypted` and sends
//! the descriptor inside the Olm message as the inner message
//! `{"t":"file","url","key","iv","sha256","name","mime","size","category",
//! "expires_at"}`. `key`, `iv` and `sha256` are standard base64 without
//! padding. `sha256` is the hash of the ciphertext. `size` is the length of
//! the plain file: the ciphertext is 16 bytes longer.
//!
//! The server sees only the ciphertext. The name, the type and the real size
//! live in the descriptor, which only the peer devices can read.
//!
//! A descriptor from a peer is data that nobody vetted. [`FileDescriptor::validate`]
//! runs before any download: it accepts only the configured server, the path
//! `/uploads/<slug>` and well-formed key, nonce, hash, size and expiry. The
//! download then checks the hash before the decryption.
//!
//! Inside the history and the engine a file is a text row in the stored form
//! [`file_text`], like an action row. The row never leaves the program in
//! that form.

use aes_gcm::aead::{Aead, Generate, Key, KeyInit, Nonce, Payload};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::e2e_pairing::parse_utc_seconds;
use crate::upload::UploadCategory;

/// Start of the stored text of a file row.
pub const FILE_OPEN: &str = "\u{1}FILE ";
/// End of the stored text of a file row.
pub const FILE_CLOSE: char = '\u{1}';

/// Length of the AES-256 key.
pub const KEY_LEN: usize = 32;
/// Length of the GCM nonce, called `iv` on the wire.
pub const IV_LEN: usize = 12;
/// Length of the GCM tag that ends the ciphertext.
pub const TAG_LEN: usize = 16;
/// Length of a SHA-256 hash.
pub const HASH_LEN: usize = 32;

/// Longest display name, in bytes.
pub const NAME_MAX_BYTES: usize = 255;
/// Longest MIME type, in bytes.
const MIME_MAX_BYTES: usize = 100;
/// Longest slug in a file URL.
const SLUG_MAX_BYTES: usize = 128;
/// The largest plain size a descriptor may claim: 4 GiB.
pub const MAX_PLAIN_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Why a file was not sealed, opened or accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
    /// The descriptor is not an object with the right fields.
    Malformed,
    /// The URL is not on the configured server or not an upload path.
    BadUrl,
    /// The key is not 32 bytes of base64.
    BadKey,
    /// The nonce is not 12 bytes of base64.
    BadIv,
    /// The hash is not 32 bytes of base64.
    BadHash,
    /// The size, the name, the type or the category is not valid.
    BadField,
    /// The expiry is missing or not a time.
    BadExpiry,
    /// The expiry has passed.
    Expired,
    /// The downloaded bytes have not the length that the descriptor says.
    BadLength,
    /// The hash of the downloaded bytes is not the one of the descriptor.
    HashMismatch,
    /// The tag or the key is wrong.
    DecryptFailed,
    /// The file was not sealed.
    EncryptFailed,
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed file descriptor",
            Self::BadUrl => "file URL is not valid",
            Self::BadKey => "file key is not valid",
            Self::BadIv => "file nonce is not valid",
            Self::BadHash => "file hash is not valid",
            Self::BadField => "file details are not valid",
            Self::BadExpiry => "file expiry is not valid",
            Self::Expired => "file has expired",
            Self::BadLength => "file length does not match",
            Self::HashMismatch => "file hash does not match",
            Self::DecryptFailed => "file could not be decrypted",
            Self::EncryptFailed => "file could not be encrypted",
        })
    }
}

impl std::error::Error for FileError {}

/// A file sealed for upload. The key stays in memory only until it drops.
pub struct Sealed {
    /// The bytes to upload: the ciphertext and the 16-byte tag.
    pub ciphertext: Vec<u8>,
    pub key: Zeroizing<[u8; KEY_LEN]>,
    pub iv: [u8; IV_LEN],
    /// SHA-256 of `ciphertext`.
    pub sha256: [u8; HASH_LEN],
    /// The length of the plain file.
    pub plain_len: u64,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Seals `plain` with a new random key and nonce.
pub fn seal(plain: &[u8]) -> Result<Sealed, FileError> {
    let key = Key::<Aes256Gcm>::generate();
    let nonce = Nonce::<Aes256Gcm>::generate();
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plain,
                aad: &[],
            },
        )
        .map_err(|_| FileError::EncryptFailed)?;
    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
    key_bytes.copy_from_slice(key.as_slice());
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(nonce.as_slice());
    let sha256 = sha256_of(&ciphertext);
    Ok(Sealed {
        ciphertext,
        key: key_bytes,
        iv,
        sha256,
        plain_len: plain.len() as u64,
    })
}

/// A descriptor as it travels in the inner message. The fields are the wire
/// text: nothing here is trusted until [`FileDescriptor::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptor {
    pub url: String,
    pub key: String,
    pub iv: String,
    pub sha256: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub category: String,
    pub expires_at: String,
}

impl FileDescriptor {
    /// The descriptor of a sealed file that the server stored at `url`.
    pub fn for_sealed(
        sealed: &Sealed,
        url: &str,
        expires_at: &str,
        (name, mime, category): (&str, &str, UploadCategory),
    ) -> Self {
        Self {
            url: url.to_string(),
            key: STANDARD_NO_PAD.encode(sealed.key.as_slice()),
            iv: STANDARD_NO_PAD.encode(sealed.iv),
            sha256: STANDARD_NO_PAD.encode(sealed.sha256),
            name: clean_name(name),
            mime: mime.to_string(),
            size: sealed.plain_len,
            category: category.wire_name().to_string(),
            expires_at: expires_at.to_string(),
        }
    }

    /// Reads the fields of an inner message. Extra fields are ignored.
    /// `None` when a field is missing or has the wrong type.
    pub fn from_map(map: &Map<String, Value>) -> Option<Self> {
        let text = |name: &str| map.get(name)?.as_str().map(str::to_string);
        Some(Self {
            url: text("url")?,
            key: text("key")?,
            iv: text("iv")?,
            sha256: text("sha256")?,
            name: text("name")?,
            mime: text("mime")?,
            size: map.get("size")?.as_u64()?,
            category: text("category")?,
            expires_at: text("expires_at")?,
        })
    }

    /// The fields as a JSON object, without `t`.
    pub fn to_map(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("url".into(), Value::from(self.url.as_str()));
        map.insert("key".into(), Value::from(self.key.as_str()));
        map.insert("iv".into(), Value::from(self.iv.as_str()));
        map.insert("sha256".into(), Value::from(self.sha256.as_str()));
        map.insert("name".into(), Value::from(self.name.as_str()));
        map.insert("mime".into(), Value::from(self.mime.as_str()));
        map.insert("size".into(), Value::from(self.size));
        map.insert("category".into(), Value::from(self.category.as_str()));
        map.insert("expires_at".into(), Value::from(self.expires_at.as_str()));
        map
    }

    /// Checks everything that does not need the server or the clock: the key,
    /// the nonce and the hash decode to the right length, and the size, the
    /// name, the type, the category and the expiry are valid. Gives the
    /// decoded values.
    pub fn check_shape(&self) -> Result<Decoded, FileError> {
        let key = decode_fixed::<KEY_LEN>(&self.key).ok_or(FileError::BadKey)?;
        let iv = decode_fixed::<IV_LEN>(&self.iv).ok_or(FileError::BadIv)?;
        let sha256 = decode_fixed::<HASH_LEN>(&self.sha256).ok_or(FileError::BadHash)?;
        let category = UploadCategory::from_wire_name(&self.category).ok_or(FileError::BadField)?;
        if self.size > MAX_PLAIN_BYTES
            || !valid_mime(&self.mime)
            || clean_name(&self.name).is_empty()
        {
            return Err(FileError::BadField);
        }
        let expires_at = parse_utc_seconds(&self.expires_at).ok_or(FileError::BadExpiry)?;
        Ok(Decoded {
            key: Zeroizing::new(key),
            iv,
            sha256,
            category,
            expires_at,
        })
    }

    /// Checks a descriptor of a peer before any download. `server_base` is
    /// the configured server, `now` is the time in Unix seconds. The URL must
    /// be an upload of that server and nothing else.
    pub fn validate(&self, server_base: &str, now: i64) -> Result<ValidFile, FileError> {
        let decoded = self.check_shape()?;
        if decoded.expires_at <= now {
            return Err(FileError::Expired);
        }
        let url = upload_url(&self.url, server_base).ok_or(FileError::BadUrl)?;
        Ok(ValidFile {
            url,
            key: decoded.key,
            iv: decoded.iv,
            sha256: decoded.sha256,
            name: clean_name(&self.name),
            mime: self.mime.clone(),
            size: self.size,
            category: decoded.category,
            expires_at: decoded.expires_at,
        })
    }
}

/// The decoded binary fields of a descriptor.
pub struct Decoded {
    pub key: Zeroizing<[u8; KEY_LEN]>,
    pub iv: [u8; IV_LEN],
    pub sha256: [u8; HASH_LEN],
    pub category: UploadCategory,
    pub expires_at: i64,
}

/// A descriptor that passed [`FileDescriptor::validate`]. The only way to
/// make one is the check, so a download takes this and never a raw URL.
pub struct ValidFile {
    pub url: reqwest::Url,
    pub key: Zeroizing<[u8; KEY_LEN]>,
    pub iv: [u8; IV_LEN],
    pub sha256: [u8; HASH_LEN],
    /// The display name, already cleaned.
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub category: UploadCategory,
    pub expires_at: i64,
}

impl std::fmt::Debug for ValidFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidFile")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl ValidFile {
    /// The length of the ciphertext that the server must give.
    pub fn ciphertext_len(&self) -> u64 {
        self.size + TAG_LEN as u64
    }

    /// Checks the downloaded bytes against the descriptor, then decrypts.
    /// The hash is checked before the decryption starts.
    pub fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, FileError> {
        if ciphertext.len() as u64 != self.ciphertext_len() {
            return Err(FileError::BadLength);
        }
        let hash = sha256_of(ciphertext);
        if hash != self.sha256 {
            return Err(FileError::HashMismatch);
        }
        let key = Key::<Aes256Gcm>::from(*self.key);
        let nonce = Nonce::<Aes256Gcm>::from(self.iv);
        let plain = Aes256Gcm::new(&key)
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| FileError::DecryptFailed)?;
        if plain.len() as u64 != self.size {
            return Err(FileError::BadLength);
        }
        Ok(plain)
    }
}

/// SHA-256 of `bytes`.
fn sha256_of(bytes: &[u8]) -> [u8; HASH_LEN] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Decodes standard base64 without padding, with trailing `=` accepted, to
/// exactly `N` bytes.
fn decode_fixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    let raw = STANDARD_NO_PAD.decode(text.trim_end_matches('=')).ok()?;
    raw.try_into().ok()
}

/// A `type/subtype` made of token characters only.
fn valid_mime(mime: &str) -> bool {
    let Some((kind, subtype)) = mime.split_once('/') else {
        return false;
    };
    let token = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'))
    };
    mime.len() <= MIME_MAX_BYTES && token(kind) && token(subtype)
}

/// The upload URL on `server_base` as a parsed URL, or `None`.
///
/// The URL must have the scheme, the host and the port of the server and the
/// path `<server path>/uploads/<slug>`. A slug has letters, digits, `-` and
/// `_` only, so it has no extension. Credentials, a query and a fragment are
/// refused.
fn upload_url(text: &str, server_base: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(text).ok()?;
    let base = reqwest::Url::parse(server_base).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.origin() != base.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let prefix = base.path().trim_end_matches('/');
    let slug = url.path().strip_prefix(prefix)?.strip_prefix("/uploads/")?;
    let valid_slug = !slug.is_empty()
        && slug.len() <= SLUG_MAX_BYTES
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    valid_slug.then_some(url)
}

/// A display name without control characters, bidirectional overrides and
/// path separators, at most [`NAME_MAX_BYTES`] bytes. A name with nothing
/// left is empty.
pub fn clean_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '/' | '\\')
                && !matches!(*c as u32, 0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F)
        })
        .collect();
    let mut kept = kept.trim().to_string();
    while kept.len() > NAME_MAX_BYTES {
        kept.pop();
    }
    kept
}

/// The stored text of a file row.
pub fn file_text(descriptor: &FileDescriptor) -> String {
    let json = Value::Object(descriptor.to_map()).to_string();
    format!("{FILE_OPEN}{json}{FILE_CLOSE}")
}

/// True when `stored` is a file row. A text from a person never starts like
/// this: the engine refuses it on the way in and on the way out.
pub fn is_file_text(stored: &str) -> bool {
    stored.starts_with(FILE_OPEN)
}

/// The descriptor of a file row, or `None` when `stored` is not one or its
/// details are not well formed.
pub fn file_descriptor(stored: &str) -> Option<FileDescriptor> {
    let rest = stored.strip_prefix(FILE_OPEN)?;
    let json = rest.strip_suffix(FILE_CLOSE)?;
    let value: Value = serde_json::from_str(json).ok()?;
    let descriptor = FileDescriptor::from_map(value.as_object()?)?;
    descriptor.check_shape().ok()?;
    Some(descriptor)
}

/// True when both texts are the same URL after the normal URL clean-up. A
/// text that is no URL is never the same as another.
pub fn same_url(first: &str, second: &str) -> bool {
    match (reqwest::Url::parse(first), reqwest::Url::parse(second)) {
        (Ok(first), Ok(second)) => first == second,
        _ => false,
    }
}

/// A size as text: `512 B`, `1.5 KB`, `3.2 MB`.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// The row text of a file in the locked window: the name, the type, the size
/// and the link. The link opens the decrypting viewer, never a browser.
pub fn file_row_text(descriptor: &FileDescriptor) -> String {
    let category =
        UploadCategory::from_wire_name(&descriptor.category).map_or("📎", UploadCategory::emoji);
    format!(
        "{category} {} ({}, {}) {}",
        clean_name(&descriptor.name),
        descriptor.mime,
        human_size(descriptor.size),
        descriptor.url
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "https://irc.example";
    const NOW: i64 = 1_790_000_000;
    // 2027-01-15T08:00:00Z, later than NOW.
    const LATER: &str = "2027-01-15T08:00:00Z";

    fn descriptor_for(plain: &[u8]) -> (FileDescriptor, Sealed) {
        let sealed = seal(plain).expect("seal");
        let descriptor = FileDescriptor::for_sealed(
            &sealed,
            "https://irc.example/uploads/AbC_123-x",
            LATER,
            ("holiday.jpg", "image/jpeg", UploadCategory::Image),
        );
        (descriptor, sealed)
    }

    #[test]
    fn a_sealed_file_opens_with_its_descriptor() {
        let plain = b"private picture bytes".to_vec();
        let (descriptor, sealed) = descriptor_for(&plain);
        assert_eq!(sealed.ciphertext.len(), plain.len() + TAG_LEN);
        assert_ne!(&sealed.ciphertext[..plain.len()], plain.as_slice());
        let valid = descriptor.validate(SERVER, NOW).expect("valid");
        assert_eq!(valid.open(&sealed.ciphertext).expect("open"), plain);
        assert_eq!(valid.size, plain.len() as u64);
        assert_eq!(valid.name, "holiday.jpg");
    }

    #[test]
    fn each_file_gets_a_new_key_and_nonce() {
        let first = seal(b"same").expect("seal");
        let second = seal(b"same").expect("seal");
        assert_ne!(first.key.as_slice(), second.key.as_slice());
        assert_ne!(first.iv, second.iv);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn the_wire_fields_never_hold_the_plain_file() {
        let plain = b"super secret plain text";
        let (descriptor, sealed) = descriptor_for(plain);
        assert!(!sealed
            .ciphertext
            .windows(plain.len())
            .any(|window| window == plain));
        assert_eq!(
            decode_fixed::<KEY_LEN>(&descriptor.key).unwrap(),
            *sealed.key
        );
        assert_eq!(decode_fixed::<IV_LEN>(&descriptor.iv).unwrap(), sealed.iv);
    }

    #[test]
    fn a_changed_byte_fails_the_hash_before_the_decryption() {
        let (descriptor, sealed) = descriptor_for(b"hello world");
        let valid = descriptor.validate(SERVER, NOW).expect("valid");
        let mut bad = sealed.ciphertext.clone();
        bad[0] ^= 1;
        assert_eq!(valid.open(&bad), Err(FileError::HashMismatch));
    }

    #[test]
    fn a_wrong_length_is_refused() {
        let (descriptor, sealed) = descriptor_for(b"hello world");
        let valid = descriptor.validate(SERVER, NOW).expect("valid");
        let mut long = sealed.ciphertext.clone();
        long.push(0);
        assert_eq!(valid.open(&long), Err(FileError::BadLength));
        assert_eq!(valid.open(&long[..5]), Err(FileError::BadLength));
    }

    #[test]
    fn a_wrong_key_fails_the_decryption() {
        let (mut descriptor, sealed) = descriptor_for(b"hello world");
        descriptor.key = STANDARD_NO_PAD.encode([7u8; KEY_LEN]);
        let valid = descriptor.validate(SERVER, NOW).expect("valid");
        assert_eq!(
            valid.open(&sealed.ciphertext),
            Err(FileError::DecryptFailed)
        );
    }

    #[test]
    fn a_wrong_nonce_fails_the_decryption() {
        let (mut descriptor, sealed) = descriptor_for(b"hello world");
        descriptor.iv = STANDARD_NO_PAD.encode([7u8; IV_LEN]);
        let valid = descriptor.validate(SERVER, NOW).expect("valid");
        assert_eq!(
            valid.open(&sealed.ciphertext),
            Err(FileError::DecryptFailed)
        );
    }

    #[test]
    fn a_bad_url_is_refused() {
        let (good, _) = descriptor_for(b"x");
        let urls = [
            "https://evil.example/uploads/abc",
            "http://irc.example/uploads/abc",
            "https://irc.example:8443/uploads/abc",
            "https://irc.example/uploads/abc.png",
            "https://irc.example/uploads/abc?x=1",
            "https://irc.example/uploads/abc#frag",
            "https://user@irc.example/uploads/abc",
            "https://irc.example/other/abc",
            "https://irc.example/uploads/",
            "https://irc.example/uploads/a/b",
            "https://irc.example/uploads/../etc",
            "https://irc.example.evil.example/uploads/abc",
            "ftp://irc.example/uploads/abc",
            "file:///etc/passwd",
            "/uploads/abc",
            "javascript:alert(1)",
            "",
        ];
        for url in urls {
            let descriptor = FileDescriptor {
                url: url.to_string(),
                ..good.clone()
            };
            assert_eq!(
                descriptor.validate(SERVER, NOW).err(),
                Some(FileError::BadUrl),
                "{url}"
            );
        }
    }

    #[test]
    fn a_server_with_a_path_needs_that_path() {
        let (good, _) = descriptor_for(b"x");
        let descriptor = FileDescriptor {
            url: "https://irc.example/grappa/uploads/abc".to_string(),
            ..good
        };
        assert!(descriptor
            .validate("https://irc.example/grappa", NOW)
            .is_ok());
        assert_eq!(
            descriptor.validate(SERVER, NOW).err(),
            Some(FileError::BadUrl)
        );
    }

    #[test]
    fn bad_key_nonce_and_hash_are_refused() {
        let (good, _) = descriptor_for(b"x");
        let short = STANDARD_NO_PAD.encode([1u8; 31]);
        let long = STANDARD_NO_PAD.encode([1u8; 33]);
        for bad in [short.as_str(), long.as_str(), "", "not base64!!", "AAAA"] {
            let key = FileDescriptor {
                key: bad.to_string(),
                ..good.clone()
            };
            assert_eq!(key.validate(SERVER, NOW).err(), Some(FileError::BadKey));
            let iv = FileDescriptor {
                iv: bad.to_string(),
                ..good.clone()
            };
            assert_eq!(iv.validate(SERVER, NOW).err(), Some(FileError::BadIv));
            let hash = FileDescriptor {
                sha256: bad.to_string(),
                ..good.clone()
            };
            assert_eq!(hash.validate(SERVER, NOW).err(), Some(FileError::BadHash));
        }
    }

    #[test]
    fn an_expired_or_unreadable_expiry_is_refused() {
        let (good, _) = descriptor_for(b"x");
        let past = FileDescriptor {
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            ..good.clone()
        };
        assert_eq!(past.validate(SERVER, NOW).err(), Some(FileError::Expired));
        for text in ["", "tomorrow", "2027-13-01T00:00:00Z", "2027-01-15"] {
            let bad = FileDescriptor {
                expires_at: text.to_string(),
                ..good.clone()
            };
            assert_eq!(
                bad.validate(SERVER, NOW).err(),
                Some(FileError::BadExpiry),
                "{text}"
            );
        }
        // The exact second of expiry is expired.
        let at = parse_utc_seconds(LATER).expect("time");
        assert_eq!(good.validate(SERVER, at).err(), Some(FileError::Expired));
        assert!(good.validate(SERVER, at - 1).is_ok());
    }

    #[test]
    fn bad_details_are_refused() {
        let (good, _) = descriptor_for(b"x");
        let cases = [
            FileDescriptor {
                category: "program".to_string(),
                ..good.clone()
            },
            FileDescriptor {
                mime: "no-slash".to_string(),
                ..good.clone()
            },
            FileDescriptor {
                mime: "image/jpeg; charset=x".to_string(),
                ..good.clone()
            },
            FileDescriptor {
                name: " / \u{202E} ".to_string(),
                ..good.clone()
            },
            FileDescriptor {
                size: MAX_PLAIN_BYTES + 1,
                ..good.clone()
            },
        ];
        for case in cases {
            assert_eq!(case.validate(SERVER, NOW).err(), Some(FileError::BadField));
        }
    }

    #[test]
    fn a_malformed_descriptor_is_not_read() {
        let (good, _) = descriptor_for(b"x");
        let full = good.to_map();
        for field in full.keys() {
            let mut map = full.clone();
            map.remove(field);
            assert_eq!(FileDescriptor::from_map(&map), None, "{field}");
        }
        let mut wrong = full.clone();
        wrong.insert("size".into(), Value::from("12"));
        assert_eq!(FileDescriptor::from_map(&wrong), None);
        let mut negative = full;
        negative.insert("size".into(), Value::from(-1));
        assert_eq!(FileDescriptor::from_map(&negative), None);
    }

    #[test]
    fn the_stored_text_round_trips() {
        let (descriptor, _) = descriptor_for(b"x");
        let stored = file_text(&descriptor);
        assert!(is_file_text(&stored));
        assert_eq!(file_descriptor(&stored), Some(descriptor));
        assert_eq!(file_descriptor("plain text"), None);
        assert_eq!(
            file_descriptor(&format!("{FILE_OPEN}{{}}{FILE_CLOSE}")),
            None
        );
        assert_eq!(file_descriptor(&format!("{FILE_OPEN}not json")), None);
    }

    #[test]
    fn names_lose_separators_controls_and_direction_marks() {
        assert_eq!(clean_name("a/b\\c.txt"), "abc.txt");
        assert_eq!(clean_name("x\u{202E}gpj.exe\u{0}"), "xgpj.exe");
        assert_eq!(clean_name("  note.txt  "), "note.txt");
        assert_eq!(clean_name("\u{2066}\u{2069}"), "");
        let long = "é".repeat(300);
        let cut = clean_name(&long);
        assert!(cut.len() <= NAME_MAX_BYTES);
        assert!(cut.chars().all(|c| c == 'é'));
    }

    #[test]
    fn the_row_text_has_the_name_and_a_link() {
        let (descriptor, _) = descriptor_for(&[0u8; 2048]);
        let row = file_row_text(&descriptor);
        assert!(row.starts_with("📸 holiday.jpg (image/jpeg, 2.0 KB) https://"));
        assert!(row.ends_with("/uploads/AbC_123-x"));
        assert!(!row.contains(&descriptor.key));
        assert_eq!(human_size(10), "10 B");
        assert_eq!(human_size(3 * 1024 * 1024 + 200 * 1024), "3.2 MB");
    }

    #[test]
    fn padded_base64_is_accepted_for_the_binary_fields() {
        let (mut descriptor, _) = descriptor_for(b"x");
        descriptor.iv = format!("{}=", descriptor.iv.trim_end_matches('='));
        assert!(descriptor.validate(SERVER, NOW).is_ok());
    }
}
