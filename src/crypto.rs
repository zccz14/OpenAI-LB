use sha2::{Digest, Sha256};

pub fn api_key_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_hash_is_stable_and_does_not_contain_secret() {
        let hash = api_key_hash("sk-secret");
        assert_eq!(hash, api_key_hash("sk-secret"));
        assert!(!hash.contains("secret"));
    }
}
