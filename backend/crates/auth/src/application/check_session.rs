//! Check Session Use Case
//!
//! Verifies and retrieves session information.

use std::sync::Arc;

use crate::application::config::AuthConfig;
use crate::domain::entity::auth_session::AuthSession;
use crate::domain::repository::AuthSessionRepository;
use crate::error::{AuthError, AuthResult};
use uuid::Uuid;

/// Session info output
pub struct SessionInfoOutput {
    pub public_id: String,
    pub user_role: String,
    pub expires_at_ms: i64,
}

/// Check session use case
pub struct CheckSessionUseCase<S>
where
    S: AuthSessionRepository + Clone + Send + Sync + 'static,
{
    session_repo: Arc<S>,
    config: Arc<AuthConfig>,
}

impl<S> CheckSessionUseCase<S>
where
    S: AuthSessionRepository + Clone + Send + Sync + 'static,
{
    pub fn new(session_repo: Arc<S>, config: Arc<AuthConfig>) -> Self {
        Self {
            session_repo,
            config,
        }
    }

    /// Check if session is valid and return session info
    pub async fn execute(
        &self,
        session_token: &str,
        fingerprint_hash: &[u8],
    ) -> AuthResult<SessionInfoOutput> {
        let session = self.get_session(session_token, fingerprint_hash).await?;

        Ok(SessionInfoOutput {
            public_id: session.public_id.to_string(),
            user_role: session.user_role.code().to_string(),
            expires_at_ms: session.expires_at_ms,
        })
    }

    /// Just check if session is valid (returns bool)
    pub async fn is_valid(&self, session_token: &str, fingerprint_hash: &[u8]) -> bool {
        self.get_session(session_token, fingerprint_hash)
            .await
            .is_ok()
    }

    /// Get session and update last activity
    pub async fn get_session(
        &self,
        session_token: &str,
        fingerprint_hash: &[u8],
    ) -> AuthResult<AuthSession> {
        let session_id = self.parse_session_token(session_token)?;

        let session = self
            .session_repo
            .find_by_id(session_id, fingerprint_hash)
            .await?
            .ok_or(AuthError::SessionInvalid)?;

        if session.is_expired() {
            self.session_repo.delete(session_id).await?;
            return Err(AuthError::SessionInvalid);
        }

        // Update last activity (fire and forget)
        let mut session = session;
        session.touch();

        // Extend remember-me sessions based on config
        let ttl_long = chrono::Duration::from_std(self.config.session_ttl_long)
            .map_err(|e| AuthError::Internal(format!("Invalid session TTL: {e}")))?;
        session.extend_if_needed(ttl_long);

        // Update in background
        let session_clone = session.clone();
        let repo = self.session_repo.clone();
        tokio::spawn(async move {
            if let Err(e) = repo.update(&session_clone).await {
                tracing::warn!(error = %e, "Failed to update session activity");
            }
        });

        Ok(session)
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
