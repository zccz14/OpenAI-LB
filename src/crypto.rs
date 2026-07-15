use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte AES key");
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("credential encryption failed"))?;
    let mut output = nonce.to_vec();
    output.extend(ciphertext);
    Ok(STANDARD.encode(output))
}

pub fn decrypt(key: &[u8; 32], encoded: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(encoded)
        .context("invalid encrypted credential")?;
    let (nonce, ciphertext) = bytes
        .split_at_checked(12)
        .context("invalid encrypted credential")?;
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte AES key");
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| anyhow::anyhow!("credential decryption failed"))?;
    String::from_utf8(plaintext).context("credential is not UTF-8")
}

pub fn api_key_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_round_trip_without_deterministic_ciphertext() {
        let key = [7_u8; 32];
        let first = encrypt(&key, "refresh-secret").unwrap();
        let second = encrypt(&key, "refresh-secret").unwrap();
        assert_ne!(first, second);
        assert_eq!(decrypt(&key, &first).unwrap(), "refresh-secret");
    }

    #[test]
    fn api_key_hash_is_stable_and_does_not_contain_secret() {
        let hash = api_key_hash("sk-secret");
        assert_eq!(hash, api_key_hash("sk-secret"));
        assert!(!hash.contains("secret"));
    }
}
