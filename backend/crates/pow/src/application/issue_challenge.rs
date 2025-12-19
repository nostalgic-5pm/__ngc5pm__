//! Issue Challenge Use Case

use crate::application::config::PowConfig;
use crate::domain::entities::Challenge;
use crate::domain::repository::{ChallengeRepository, RateLimitRepository};
use crate::domain::value_objects::ClientFingerprint;
use crate::error::{PowError, PowResult};
use platform::crypto::random_bytes;
use std::sync::Arc;

/// Output DTO for issue challenge
#[derive(Debug, Clone)]
pub struct IssueChallengeOutput {
    pub challenge_id: uuid::Uuid,
    pub challenge_b64: String,
    pub difficulty_bits: u8,
    pub expires_at_ms: i64,
}

/// Issue Challenge Use Case
pub struct IssueChallengeUseCase<C, R>
where
    C: ChallengeRepository,
    R: RateLimitRepository,
{
    challenge_repo: Arc<C>,
    rate_limit_repo: Arc<R>,
    config: Arc<PowConfig>,
}

impl<C, R> IssueChallengeUseCase<C, R>
where
    C: ChallengeRepository,
    R: RateLimitRepository,
{
    pub fn new(challenge_repo: Arc<C>, rate_limit_repo: Arc<R>, config: Arc<PowConfig>) -> Self {
        Self {
            challenge_repo,
            rate_limit_repo,
            config,
        }
    }

    pub async fn execute(&self, fingerprint: ClientFingerprint) -> PowResult<IssueChallengeOutput> {
        // Check rate limit
        let allowed = self
            .rate_limit_repo
            .check(
                &fingerprint,
                self.config.rate_limit_max_requests,
                self.config.rate_limit_window_ms(),
            )
            .await?;

        if !allowed {
            return Err(PowError::RateLimitExceeded);
        }

        // Generate challenge
        let challenge_bytes = random_bytes(self.config.challenge_bytes_len);
        let challenge = Challenge::new(
            challenge_bytes.clone(),
            self.config.difficulty_bits,
            self.config.challenge_ttl_ms(),
            fingerprint.hash_vec(),
            fingerprint.ip,
        );

        self.challenge_repo.create(&challenge).await?;

        tracing::info!(
            challenge_id = %challenge.id,
            difficulty = self.config.difficulty_bits,
            "Issued challenge"
        );

        Ok(IssueChallengeOutput {
            challenge_id: challenge.id,
            challenge_b64: platform::crypto::to_base64(&challenge_bytes),
            difficulty_bits: self.config.difficulty_bits,
            expires_at_ms: challenge.expires_at_ms,
        })
    }
}
