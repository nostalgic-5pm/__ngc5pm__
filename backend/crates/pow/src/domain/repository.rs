//! Repository Traits
//!
//! Interfaces for data persistence. Implementation is in infrastructure layer.

use crate::domain::entities::{Challenge, PowSession};
use crate::domain::value_objects::ClientFingerprint;
use crate::error::PowResult;
use uuid::Uuid;

/// Challenge repository trait
#[trait_variant::make(ChallengeRepository: Send)]
pub trait LocalChallengeRepository {
    /// Create a new challenge
    async fn create(&self, challenge: &Challenge) -> PowResult<()>;

    /// Consume a challenge atomically (delete and return if valid)
    async fn consume(&self, challenge_id: Uuid) -> PowResult<Option<Challenge>>;
}

/// PowSession repository trait
#[trait_variant::make(PowSessionRepository: Send)]
pub trait LocalPowSessionRepository {
    /// Create a new pow session
    async fn create(&self, pow_session: &PowSession) -> PowResult<()>;

    /// Get pow session by ID and verify fingerprint
    async fn get(
        &self,
        pow_session_id: Uuid,
        fingerprint: &ClientFingerprint,
    ) -> PowResult<Option<PowSession>>;

    /// Delete a pow session
    async fn delete(&self, pow_session_id: Uuid) -> PowResult<()>;
}

/// Rate limit repository trait
#[trait_variant::make(RateLimitRepository: Send)]
pub trait LocalRateLimitRepository {
    /// Check rate limit for a fingerprint
    /// Returns true if request is allowed
    async fn check(
        &self,
        fingerprint: &ClientFingerprint,
        max_requests: u32,
        window_ms: i64,
    ) -> PowResult<bool>;
}
