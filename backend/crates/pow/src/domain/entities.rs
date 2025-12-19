//! Domain Entities
//!
//! Core business entities for the PoW domain.

use chrono::{DateTime, Utc};
use std::net::IpAddr;
use uuid::Uuid;

/// Challenge entity - represents a PoW challenge issued to a client
#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_bytes: Vec<u8>,
    pub difficulty_bits: u8,
    pub expires_at_ms: i64,
    pub created_at: DateTime<Utc>,
    pub client_fingerprint_hash: Vec<u8>,
    pub client_ip: Option<IpAddr>,
}

impl Challenge {
    /// Create a new challenge
    pub fn new(
        challenge_bytes: Vec<u8>,
        difficulty_bits: u8,
        ttl_ms: i64,
        fingerprint_hash: Vec<u8>,
        client_ip: Option<IpAddr>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            challenge_bytes,
            difficulty_bits,
            expires_at_ms: now.timestamp_millis() + ttl_ms,
            created_at: now,
            client_fingerprint_hash: fingerprint_hash,
            client_ip,
        }
    }

    /// Check if the challenge has expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp_millis() > self.expires_at_ms
    }
}

/// PowSession entity - represents a valid PoW session
#[derive(Debug, Clone)]
pub struct PowSession {
    pub id: Uuid,
    pub expires_at_ms: i64,
    pub created_at: DateTime<Utc>,
    pub client_fingerprint_hash: Vec<u8>,
    pub challenge_id: Uuid,
}

impl PowSession {
    /// Create a new pow session from a solved challenge
    pub fn new(challenge: &Challenge, session_ttl_ms: i64) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            expires_at_ms: now.timestamp_millis() + session_ttl_ms,
            created_at: now,
            client_fingerprint_hash: challenge.client_fingerprint_hash.clone(),
            challenge_id: challenge.id,
        }
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp_millis() > self.expires_at_ms
    }
}
