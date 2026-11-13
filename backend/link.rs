// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use base64::Engine;
use sha2::{Digest, Sha256};

pub const CSQTT_CIPHER_KEY_SEED: &str = "csqtt-chiper-key";

pub fn decrypt_csqtt_link(raw_link: &str) -> Option<String> {
    let trimmed = raw_link.trim();
    let payload = if let Some(p) = trimmed.strip_prefix("csqtt://") {
        p.trim()
    } else {
        trimmed
    };
    let clean = payload.replace(['\n', '\r', ' '], "");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&clean)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&clean))
        .ok()?;

    if bytes.len() >= 28 {
        let key_hash = Sha256::digest(CSQTT_CIPHER_KEY_SEED.as_bytes());
        if let Ok(unbound) = UnboundKey::new(&AES_256_GCM, &key_hash) {
            let key = LessSafeKey::new(unbound);
            let mut iv = [0u8; 12];
            iv.copy_from_slice(&bytes[..12]);
            if let Ok(nonce) = Nonce::try_assume_unique_for_key(&iv) {
                let mut ciphertext = bytes[12..].to_vec();
                if let Ok(decrypted) = key.open_in_place(nonce, Aad::empty(), &mut ciphertext) {
                    if let Ok(s) = String::from_utf8(decrypted.to_vec()) {
                        return Some(s);
                    }
                }
            }
        }
    }

    None
}

pub fn encrypt_csqtt_link(payload: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};

    let key_hash = Sha256::digest(CSQTT_CIPHER_KEY_SEED.as_bytes());
    let unbound = match UnboundKey::new(&AES_256_GCM, &key_hash) {
        Ok(k) => k,
        Err(_) => {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
            return format!("csqtt://{b64}");
        }
    };
    let key = LessSafeKey::new(unbound);

    let mut iv = [0u8; 12];
    type HmacSha256 = Hmac<Sha256>;
    if let Ok(mut mac) = HmacSha256::new_from_slice(&key_hash) {
        mac.update(payload.as_bytes());
        let result = mac.finalize().into_bytes();
        iv.copy_from_slice(&result[..12]);
    } else {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut iv);
    }
    let nonce = match Nonce::try_assume_unique_for_key(&iv) {
        Ok(n) => n,
        Err(_) => {
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
            return format!("csqtt://{b64}");
        }
    };

    let mut in_out = payload.as_bytes().to_vec();
    if key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .is_err()
    {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        return format!("csqtt://{b64}");
    }

    let mut combined = Vec::with_capacity(12 + in_out.len());
    combined.extend_from_slice(&iv);
    combined.extend_from_slice(&in_out);

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined);
    format!("csqtt://{b64}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_user_link() {
        let link = "csqtt://HJMQJQonUmf0QCS8uPzepph6MXN_Zvzw2RWRoKDwwywIGMN-XQoG9LxIu4wXpq3TR5gIxyutXhS9fw_-2pKmmB4XThy_t8S_VLpQ89pjpyP2nHiYvd7BuPszJWn2BDUn0frQ2fyx120F3ZAtnSteQr74DfHdOZqXBz6zMLFCDIrq4lovUO-Dp6UQJNTpXpNna5FJ";
        let decrypted = decrypt_csqtt_link(link).expect("should decrypt user link");
        assert!(decrypted.contains("host=48.102.163.215"));
        assert!(decrypted.contains("peer=46000"));
        assert!(decrypted.contains("password=G5fydUXX2dcJqcww"));
        assert!(decrypted.contains("hashes=dzuhe3Ayri1GNFJ5XjAUnx74ZjGh5E6mh-hxNZOlXx0"));
    }

    #[test]
    fn test_roundtrip() {
        let original = "connect?v=2&host=1.2.3.4&peer=46000&password=testpass123";
        let encrypted = encrypt_csqtt_link(original);
        assert!(encrypted.starts_with("csqtt://"));
        let decrypted = decrypt_csqtt_link(&encrypted).expect("should decrypt");
        assert_eq!(decrypted, original);
    }
}
