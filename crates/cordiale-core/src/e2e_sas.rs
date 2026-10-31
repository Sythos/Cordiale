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

//! The SAS code of a pair of master keys.
//!
//! Both users compare the code through a trusted channel. The code is a
//! pure function of the two public master keys, so it needs no message on
//! the wire and no secret. The order of the two keys does not change it:
//! both devices show the same code for the same pair of masters.

use sha2::{Digest, Sha256};

use crate::e2e_device::E2eError;
use crate::e2e_wire::decode_key;

const DOMAIN: &[u8] = b"cordiale-sas-v1";
const GROUPS: usize = 3;
const GROUP_DIGITS: usize = 4;

/// The SAS code of two master keys (43-character public keys): three groups
/// of four digits. It fails when a key is not a valid public key.
pub fn sas_code(own_master: &str, peer_master: &str) -> Result<String, E2eError> {
    let own = decode_key(own_master)?;
    let peer = decode_key(peer_master)?;
    let (low, high) = if own <= peer {
        (own, peer)
    } else {
        (peer, own)
    };
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(low);
    hasher.update(high);
    let hash = hasher.finalize();
    let modulus = 10u64.pow(GROUP_DIGITS as u32);
    let groups: Vec<String> = (0..GROUPS)
        .map(|index| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&hash[index * 8..index * 8 + 8]);
            format!(
                "{:0width$}",
                u64::from_be_bytes(raw) % modulus,
                width = GROUP_DIGITS
            )
        })
        .collect();
    Ok(groups.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vodozemac::olm::Account;

    fn key() -> String {
        Account::new().identity_keys().ed25519.to_base64()
    }

    #[test]
    fn both_orders_give_the_same_code() {
        let (a, b) = (key(), key());
        let code = sas_code(&a, &b).unwrap();
        assert_eq!(code, sas_code(&b, &a).unwrap());
        assert_eq!(code.len(), 14);
        assert!(code.chars().all(|c| c.is_ascii_digit() || c == ' '));
    }

    #[test]
    fn another_master_gives_another_code() {
        let (a, b) = (key(), key());
        assert_ne!(sas_code(&a, &b).unwrap(), sas_code(&a, &key()).unwrap());
    }

    #[test]
    fn a_bad_key_is_refused() {
        assert!(sas_code("short", &key()).is_err());
    }
}
