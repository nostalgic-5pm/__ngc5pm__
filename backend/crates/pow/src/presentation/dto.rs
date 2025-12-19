//! API DTOs (Data Transfer Objects)

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Response for GET /api/pow/challenge
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub pow_challenge_id: Uuid,
    pub pow_challenge_b64: String,
    pub pow_difficulty_bits: u8,
    pub pow_expires_at_ms: i64,
}

/// Request for POST /api/pow/submit
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitRequest {
    pub challenge_id: Uuid,
    pub nonce_u32: u32,
    #[serde(default)]
    pub elapsed_ms: Option<i64>,
    #[serde(default)]
    pub total_hashes: Option<i64>,
}

/// Response for GET /api/pow/status
#[derive(Debug, Clone, Serialize)]
pub struct StatusResponse {
    pub passed: bool,
}
