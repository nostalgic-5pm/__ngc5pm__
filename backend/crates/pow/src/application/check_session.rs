//! Check Session Use Case

use crate::application::config::PowConfig;
use crate::domain::repository::PowSessionRepository;
use crate::domain::value_objects::ClientFingerprint;
use crate::error::PowResult;
use std::sync::Arc;
use uuid::Uuid;

/// Check Pow Session Use Case
pub struct CheckPowSessionUseCase<S>
where
    S: PowSessionRepository,
{
    pow_session_repo: Arc<S>,
    config: Arc<PowConfig>,
}

impl<S> CheckPowSessionUseCase<S>
where
    S: PowSessionRepository,
{
    pub fn new(pow_session_repo: Arc<S>, config: Arc<PowConfig>) -> Self {
        Self {
            pow_session_repo,
            config,
        }
    }

    /// Check if a pow session token is valid
    pub async fn check(&self, token: &str, fingerprint: &ClientFingerprint) -> PowResult<bool> {
        // Verify token signature and get pow session ID
        let pow_session_id = match verify_pow_session_token(token, &self.config.session_secret) {
            Some(id) => id,
            None => return Ok(false),
        };

        // Check pow session in database
        Ok(self
            .pow_session_repo
            .get(pow_session_id, fingerprint)
            .await?
            .is_some())
    }

    /// Delete a pow session
    pub async fn logout(&self, token: &str) -> PowResult<()> {
        if let Some(pow_session_id) = verify_pow_session_token(token, &self.config.session_secret) {
            self.pow_session_repo.delete(pow_session_id).await?;
        }
        Ok(())
    }
}

/// Verify and extract pow session ID from signed token
fn verify_pow_session_token(token: &str, secret: &[u8; 32]) -> Option<Uuid> {
    let token_data = platform::crypto::from_base64(token).ok()?;
    if token_data.len() != 48 {
        // 16 (UUID) + 32 (HMAC)
        return None;
    }

    let id_bytes: [u8; 16] = token_data[0..16].try_into().ok()?;
    let provided_signature: &[u8] = &token_data[16..48];

    let expected_signature = platform::crypto::hmac_sha256(secret, &id_bytes);

    // Constant-time comparison
    if !platform::crypto::constant_time_eq(provided_signature, &expected_signature) {
        return None;
    }

    Some(Uuid::from_bytes(id_bytes))
}
