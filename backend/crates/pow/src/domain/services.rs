//! Domain Services
//!
//! Pure domain logic for PoW verification.

use sha2::{Digest, Sha256};

/// Count leading zero bits in a SHA-256 hash
pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u8 {
    let mut count = 0u8;
    for &byte in hash {
        if byte == 0 {
            count = count.saturating_add(8);
        } else {
            count = count.saturating_add(byte.leading_zeros() as u8);
            break;
        }
    }
    count
}

/// Verify that a hash meets the difficulty requirement
pub fn verify_difficulty(hash: &[u8; 32], difficulty_bits: u8) -> bool {
    count_leading_zero_bits(hash) >= difficulty_bits
}

/// Compute SHA-256 of concatenated challenge bytes and nonce (big-endian)
pub fn compute_pow_hash(challenge_bytes: &[u8], nonce_u32: u32) -> [u8; 32] {
    let nonce_be = nonce_u32.to_be_bytes();
    let mut hasher = Sha256::new();
    hasher.update(challenge_bytes);
    hasher.update(nonce_be);
    hasher.finalize().into()
}

/// Verify a PoW solution
pub fn verify_pow(challenge_bytes: &[u8], nonce_u32: u32, difficulty_bits: u8) -> bool {
    let hash = compute_pow_hash(challenge_bytes, nonce_u32);
    verify_difficulty(&hash, difficulty_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zero_bits() {
        // All zeros wraps around in u8, use saturating_add
        let hash = [0u8; 32];
        assert_eq!(count_leading_zero_bits(&hash), 255); // saturating at 255

        let mut hash = [0u8; 32];
        hash[0] = 0x01;
        assert_eq!(count_leading_zero_bits(&hash), 7);

        hash[0] = 0x80;
        assert_eq!(count_leading_zero_bits(&hash), 0);

        hash[0] = 0x00;
        hash[1] = 0x01;
        assert_eq!(count_leading_zero_bits(&hash), 15);
    }

    #[test]
    fn test_verify_difficulty() {
        let mut hash = [0u8; 32];
        hash[2] = 0x01; // 23 zero bits (8 + 8 + 7)
        assert!(verify_difficulty(&hash, 23));
        assert!(!verify_difficulty(&hash, 24));
    }

    #[test]
    fn test_pow_hash_big_endian() {
        let challenge = vec![0u8; 32];
        let nonce: u32 = 0x01020304;
        let hash = compute_pow_hash(&challenge, nonce);

        // Verify it's using big-endian
        let mut data = vec![0u8; 32];
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(hash, expected);
    }
}
