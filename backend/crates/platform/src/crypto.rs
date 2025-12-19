//! Cryptographic Utilities

use base64::{Engine, engine::general_purpose};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

/// Generate cryptographically secure random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Encode bytes as base64
pub fn to_base64(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

/// Decode base64 to bytes
pub fn from_base64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(s)
}

/// Compute HMAC-SHA256
pub fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    // HMAC: H((K XOR opad) || H((K XOR ipad) || message))
    let mut o_key_pad = [0x5cu8; 64];
    let mut i_key_pad = [0x36u8; 64];

    for i in 0..32 {
        o_key_pad[i] ^= key[i];
        i_key_pad[i] ^= key[i];
    }

    let mut inner_hash = Sha256::new();
    inner_hash.update(i_key_pad);
    inner_hash.update(data);
    let inner_result = inner_hash.finalize();

    let mut outer_hash = Sha256::new();
    outer_hash.update(o_key_pad);
    outer_hash.update(inner_result);
    outer_hash.finalize().into()
}

/// Constant-time comparison to prevent timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_values() {
        // SHA-256 of empty string
        let hash = sha256(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(hash.to_vec(), expected);

        // SHA-256 of "hello"
        let hash = sha256(b"hello");
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap();
        assert_eq!(hash.to_vec(), expected);
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);
        // Should not be all zeros (statistically)
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"hello world";
        let encoded = to_base64(data);
        let decoded = from_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hmac_consistency() {
        let key = [42u8; 32];
        let data = b"test message";
        let mac1 = hmac_sha256(&key, data);
        let mac2 = hmac_sha256(&key, data);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
