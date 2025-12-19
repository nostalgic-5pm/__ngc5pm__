//! Sign Out Use Case
//!
//! Invalidates a user session.

use std::sync::Arc;

use crate::application::config::AuthConfig;
use crate::domain::repository::AuthSessionRepository;
use crate::error::{AuthError, AuthResult};
use uuid::Uuid;

/// Sign out use case
pub struct SignOutUseCase<S>
where
    S: AuthSessionRepository,
{
    session_repo: Arc<S>,
    config: Arc<AuthConfig>,
}

impl<S> SignOutUseCase<S>
where
    S: AuthSessionRepository,
{
    pub fn new(session_repo: Arc<S>, config: Arc<AuthConfig>) -> Self {
        Self {
            session_repo,
            config,
        }
    }

    /// Sign out from current session
    pub async fn execute(&self, session_token: &str) -> AuthResult<()> {
        let session_id = self.parse_session_token(session_token)?;
        self.session_repo.delete(session_id).await?;

        tracing::info!(session_id = %session_id, "User signed out");
        Ok(())
    }

    /// Sign out from all sessions (except current)
    pub async fn execute_all(
        &self,
        session_token: &str,
        fingerprint_hash: &[u8],
    ) -> AuthResult<u64> {
        let session_id = self.parse_session_token(session_token)?;

        // Get current session to find user_id
        let session = self
            .session_repo
            .find_by_id(session_id, fingerprint_hash)
            .await?
            .ok_or(AuthError::SessionInvalid)?;

        let deleted = self
            .session_repo
            .delete_all_for_user(&session.user_id, Some(session_id))
            .await?;

        tracing::info!(
            user_id = %session.user_id,
            deleted = deleted,
            "User signed out from all other sessions"
        );

        Ok(deleted)
    }

    /// Parse and verify session token
    fn parse_session_token(&self, token: &str) -> AuthResult<Uuid> {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err(AuthError::SessionInvalid);
        }

        let session_id_str = parts[0];
        let signature_b64 = parts[1];

        // Verify signature
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.config.session_secret)
            .expect("HMAC can take key of any size");
        mac.update(session_id_str.as_bytes());

        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| AuthError::SessionInvalid)?;

        mac.verify_slice(&signature)
            .map_err(|_| AuthError::SessionInvalid)?;

        // Parse UUID
        session_id_str
            .parse()
            .map_err(|_| AuthError::SessionInvalid)
    }
}
