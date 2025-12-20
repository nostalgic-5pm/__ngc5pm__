//! Submit Solution Use Case

use crate::application::config::PowConfig;
use crate::domain::entities::PowSession;
use crate::domain::repository::{ChallengeRepository, PowSessionRepository};
use crate::domain::services::verify_pow;
use crate::domain::value_objects::ClientFingerprint;
use crate::error::{PowError, PowResult};
use std::sync::Arc;
use uuid::Uuid;

/// Input DTO for submit solution
#[derive(Debug, Clone)]
pub struct SubmitSolutionInput {
    pub challenge_id: Uuid,
    pub nonce_u32: u32,
    /// Telemetry only - not trusted
    pub elapsed_ms: Option<i64>,
    /// Telemetry only - not trusted
    pub total_hashes: Option<i64>,
}

/// Output DTO for submit solution
#[derive(Debug, Clone)]
pub struct SubmitSolutionOutput {
    pub session_id: Uuid,
    pub session_token: String,
    pub expires_at_ms: i64,
}

/// Submit Solution Use Case
pub struct SubmitSolutionUseCase<C, S>
where
    C: ChallengeRepository,
    S: PowSessionRepository,
{
    challenge_repo: Arc<C>,
    pow_session_repo: Arc<S>,
    config: Arc<PowConfig>,
}

impl<C, S> SubmitSolutionUseCase<C, S>
where
    C: ChallengeRepository,
    S: PowSessionRepository,
{
    pub fn new(challenge_repo: Arc<C>, pow_session_repo: Arc<S>, config: Arc<PowConfig>) -> Self {
        Self {
            challenge_repo,
            pow_session_repo,
            config,
        }
    }

    pub async fn execute(
        &self,
        input: SubmitSolutionInput,
        fingerprint: ClientFingerprint,
    ) -> PowResult<SubmitSolutionOutput> {
        // Log telemetry (not used for verification)
        if let (Some(elapsed), Some(hashes)) = (input.elapsed_ms, input.total_hashes) {
            tracing::info!(
                challenge_id = %input.challenge_id,
                elapsed_ms = elapsed,
                total_hashes = hashes,
                "Submit telemetry (not verified)"
            );
        }

        // Atomically consume the challenge
        let challenge = self
            .challenge_repo
            .consume(input.challenge_id, &fingerprint)
            .await?
            .ok_or(PowError::ChallengeNotFound)?;

        // Verify the solution
        if !verify_pow(
            &challenge.challenge_bytes,
            input.nonce_u32,
            challenge.difficulty_bits,
        ) {
            tracing::warn!(
                challenge_id = %input.challenge_id,
                nonce = input.nonce_u32,
                "Invalid nonce"
            );
            return Err(PowError::InvalidNonce);
        }

        // Create pow session
        let pow_session = PowSession::new(&challenge, self.config.session_ttl_ms());
        self.pow_session_repo.create(&pow_session).await?;

        // Create signed pow session token
        let token = create_pow_session_token(&pow_session.id, &self.config.session_secret);

        tracing::info!(
            challenge_id = %input.challenge_id,
            pow_session_id = %pow_session.id,
            "PoW verification successful"
        );

        Ok(SubmitSolutionOutput {
            session_id: pow_session.id,
            session_token: token,
            expires_at_ms: pow_session.expires_at_ms,
        })
    }
}

/// Create a signed pow session token
fn create_pow_session_token(pow_session_id: &Uuid, pow_session_secret: &[u8; 32]) -> String {
    let id_bytes = pow_session_id.as_bytes();
    let signature = platform::crypto::hmac_sha256(pow_session_secret, id_bytes);
    let mut token_data = Vec::with_capacity(16 + 32);
    token_data.extend_from_slice(id_bytes);
    token_data.extend_from_slice(&signature);
    platform::crypto::to_base64(&token_data)
}
