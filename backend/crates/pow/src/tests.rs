//! Unit tests for PoW crate
//! Target: C0 coverage 100%, C1 coverage 80%

#[cfg(test)]
mod crypto_tests {
    use crate::domain::services::*;
    use platform::crypto::*;

    #[test]
    fn test_random_bytes_length() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);

        let bytes = random_bytes(0);
        assert_eq!(bytes.len(), 0);

        let bytes = random_bytes(64);
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn test_random_bytes_not_all_zeros() {
        let bytes = random_bytes(32);
        assert!(
            bytes.iter().any(|&b| b != 0),
            "Random bytes should not be all zeros"
        );
    }

    #[test]
    fn test_sha256_known_value() {
        let hash = sha256(b"");
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(hash.to_vec(), expected);

        let hash = sha256(b"hello");
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap();
        assert_eq!(hash.to_vec(), expected);
    }

    #[test]
    fn test_compute_pow_hash_big_endian() {
        let challenge = vec![0u8; 32];
        let nonce: u32 = 0x01020304;

        let hash = compute_pow_hash(&challenge, nonce);

        let mut data = vec![0u8; 32];
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let expected = sha256(&data);

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_count_leading_zero_bits() {
        let hash = [0u8; 32];
        let _ = count_leading_zero_bits(&hash); // saturates at 255

        let mut hash = [0u8; 32];
        hash[0] = 0x80;
        assert_eq!(count_leading_zero_bits(&hash), 0);

        hash[0] = 0x40;
        assert_eq!(count_leading_zero_bits(&hash), 1);

        hash[0] = 0x01;
        assert_eq!(count_leading_zero_bits(&hash), 7);

        hash[0] = 0x00;
        hash[1] = 0x80;
        assert_eq!(count_leading_zero_bits(&hash), 8);

        hash[0] = 0x00;
        hash[1] = 0x00;
        hash[2] = 0x01;
        assert_eq!(count_leading_zero_bits(&hash), 23);
    }

    #[test]
    fn test_verify_difficulty() {
        let mut hash = [0u8; 32];
        hash[0] = 0xFF;
        assert!(verify_difficulty(&hash, 0));
        assert!(!verify_difficulty(&hash, 1));

        hash[0] = 0x00;
        hash[1] = 0xFF;
        assert!(verify_difficulty(&hash, 8));
        assert!(!verify_difficulty(&hash, 9));

        hash[0] = 0x00;
        hash[1] = 0x00;
        hash[2] = 0x3F;
        assert!(verify_difficulty(&hash, 18));
        assert!(!verify_difficulty(&hash, 19));
    }

    #[test]
    fn test_verify_pow_valid() {
        let challenge = random_bytes(32);
        let difficulty = 8;

        let mut nonce = 0u32;
        loop {
            if verify_pow(&challenge, nonce, difficulty) {
                break;
            }
            nonce += 1;
            if nonce > 1_000_000 {
                panic!("Could not find valid nonce within 1M attempts");
            }
        }

        assert!(verify_pow(&challenge, nonce, difficulty));
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"hello world";
        let encoded = to_base64(data);
        let decoded = from_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hmac_sha256_consistency() {
        let key = [42u8; 32];
        let data = b"test message";

        let mac1 = hmac_sha256(&key, data);
        let mac2 = hmac_sha256(&key, data);
        assert_eq!(mac1, mac2);

        let key2 = [43u8; 32];
        let mac3 = hmac_sha256(&key2, data);
        assert_ne!(mac1, mac3);

        let mac4 = hmac_sha256(&key, b"different message");
        assert_ne!(mac1, mac4);
    }
}

#[cfg(test)]
mod config_tests {
    use crate::application::config::*;
    use std::time::Duration;

    #[test]
    fn test_default_config() {
        let config = PowConfig::default();

        assert_eq!(config.challenge_bytes_len, 32);
        assert_eq!(config.difficulty_bits, 18);
        assert_eq!(config.challenge_ttl, Duration::from_secs(120));
        assert_eq!(config.session_ttl, Duration::from_secs(3600));
        assert_eq!(config.rate_limit_max_requests, 10);
        assert_eq!(config.rate_limit_window, Duration::from_secs(60));
        assert_eq!(config.session_cookie_name, "pow_session");
        assert!(config.cookie_secure);
        assert_eq!(config.cookie_same_site, SameSite::Lax);
    }

    #[test]
    fn test_with_random_secret() {
        let config1 = PowConfig::with_random_secret();
        let config2 = PowConfig::with_random_secret();

        assert_ne!(config1.session_secret, config2.session_secret);
        assert!(config1.session_secret.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_development_config() {
        let config = PowConfig::development();

        assert!(!config.cookie_secure);
        assert!(config.session_secret.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_cookie_same_site_variants() {
        let strict = SameSite::Strict;
        let lax = SameSite::Lax;
        let none = SameSite::None;

        assert_ne!(strict, lax);
        assert_ne!(lax, none);
        assert_ne!(strict, none);
    }
}

#[cfg(test)]
mod models_tests {
    use crate::presentation::dto::*;

    #[test]
    fn test_challenge_response_serialization() {
        let response = ChallengeResponse {
            pow_challenge_id: uuid::Uuid::nil(),
            pow_challenge_b64: "YWJjZA==".to_string(),
            pow_difficulty_bits: 18,
            pow_expires_at_ms: 1234567890000,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("powChallengeId"));
        assert!(json.contains("powChallengeB64"));
        assert!(json.contains("powDifficultyBits"));
        assert!(json.contains("powExpiresAtMs"));
    }

    #[test]
    fn test_submit_request_deserialization() {
        let json = r#"{"challengeId":"00000000-0000-0000-0000-000000000000","nonceU32":12345}"#;
        let request: SubmitRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.challenge_id, uuid::Uuid::nil());
        assert_eq!(request.nonce_u32, 12345);
        assert!(request.elapsed_ms.is_none());
        assert!(request.total_hashes.is_none());
    }

    #[test]
    fn test_submit_request_with_telemetry() {
        let json = r#"{"challengeId":"00000000-0000-0000-0000-000000000000","nonceU32":12345,"elapsedMs":5000,"totalHashes":1000000}"#;
        let request: SubmitRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.challenge_id, uuid::Uuid::nil());
        assert_eq!(request.nonce_u32, 12345);
        assert_eq!(request.elapsed_ms, Some(5000));
        assert_eq!(request.total_hashes, Some(1000000));
    }

    #[test]
    fn test_status_response_serialization() {
        let response = StatusResponse { passed: true };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""passed":true"#));

        let response = StatusResponse { passed: false };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""passed":false"#));
    }
}

#[cfg(test)]
mod domain_tests {
    use crate::domain::entities::*;
    use crate::domain::value_objects::*;

    #[test]
    fn test_challenge_creation() {
        let challenge = Challenge::new(vec![0u8; 32], 18, 120_000, vec![0u8; 32], None);

        assert_eq!(challenge.challenge_bytes.len(), 32);
        assert_eq!(challenge.difficulty_bits, 18);
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_session_creation() {
        let challenge = Challenge::new(vec![0u8; 32], 18, 120_000, vec![0u8; 32], None);

        let session = PowSession::new(&challenge, 3600_000);

        assert_eq!(session.challenge_id, challenge.id);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_difficulty_validation() {
        assert!(Difficulty::new(1).is_some());
        assert!(Difficulty::new(18).is_some());
        assert!(Difficulty::new(32).is_some());
        assert!(Difficulty::new(0).is_none());
        assert!(Difficulty::new(33).is_none());
    }

    #[test]
    fn test_client_fingerprint() {
        let fp = ClientFingerprint::new([0u8; 32], None);
        assert_eq!(fp.hash_vec().len(), 32);
    }
}

#[cfg(test)]
mod error_tests {
    use crate::error::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn test_error_into_response_status_codes() {
        let test_cases: Vec<(PowError, StatusCode)> = vec![
            (PowError::InvalidNonce, StatusCode::CONFLICT),
            (PowError::ChallengeExpired, StatusCode::GONE),
            (PowError::ChallengeNotFound, StatusCode::GONE),
            (PowError::RateLimitExceeded, StatusCode::TOO_MANY_REQUESTS),
            (PowError::SessionInvalid, StatusCode::UNAUTHORIZED),
            (
                PowError::SessionFingerprintMismatch,
                StatusCode::UNAUTHORIZED,
            ),
            (
                PowError::MissingHeader("User-Agent".into()),
                StatusCode::BAD_REQUEST,
            ),
            (
                PowError::Internal("test".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];

        for (error, expected_status) in test_cases {
            let response = error.into_response();
            assert_eq!(
                response.status(),
                expected_status,
                "Error should return correct status code"
            );
        }
    }

    #[test]
    fn test_error_display() {
        assert!(PowError::InvalidNonce.to_string().contains("nonce"));
        assert!(PowError::ChallengeExpired.to_string().contains("expired"));
        assert!(
            PowError::RateLimitExceeded
                .to_string()
                .contains("Rate limit")
        );
    }
}
