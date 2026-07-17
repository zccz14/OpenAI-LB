use sha2::{Digest, Sha256};

pub fn consumer_secret_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer_secret_hash_is_stable_and_does_not_contain_secret() {
        let hash = consumer_secret_hash("sk-secret");
        assert_eq!(hash, consumer_secret_hash("sk-secret"));
        assert!(!hash.contains("secret"));
    }
}
