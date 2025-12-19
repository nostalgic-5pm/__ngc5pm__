//! TOTP Setup Use Case
//!
//! Set up and verify TOTP for two-factor authentication.

use std::sync::Arc;

use crate::application::config::AuthConfig;
use crate::domain::repository::{AuthRepository, UserRepository};
use crate::domain::value_object::user_id::UserId;
use crate::error::{AuthError, AuthResult};

/// TOTP setup output
pub struct TotpSetupOutput {
    /// QR code as base64-encoded PNG
    pub qr_code_base64: String,
    /// Secret for manual entry
    pub secret: String,
    /// otpauth:// URL
    pub otpauth_url: String,
}

/// TOTP setup use case
pub struct TotpSetupUseCase<U, A>
where
    U: UserRepository,
    A: AuthRepository,
{
    user_repo: Arc<U>,
    auth_repo: Arc<A>,
    #[allow(dead_code)]
    config: Arc<AuthConfig>,
}

impl<U, A> TotpSetupUseCase<U, A>
where
    U: UserRepository,
    A: AuthRepository,
{
    pub fn new(user_repo: Arc<U>, auth_repo: Arc<A>, config: Arc<AuthConfig>) -> Self {
        Self {
            user_repo,
            auth_repo,
            config,
        }
    }

    /// Start TOTP setup - generates new secret
    pub async fn setup(&self, user_id: &UserId) -> AuthResult<TotpSetupOutput> {
        // Get user for account name
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Get auth credentials
        let mut auth = self
            .auth_repo
            .find_by_user_id(user_id)
            .await?
            .ok_or(AuthError::Internal("Auth not found".to_string()))?;

        // Generate new TOTP secret
        let secret = auth.setup_totp();

        // Save the secret (not enabled yet)
        self.auth_repo.update(&auth).await?;

        let account_name = user.user_name.as_str();

        let qr_code = secret
            .generate_qr_code(account_name)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let otpauth_url = secret
            .get_otpauth_url(account_name)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        tracing::info!(
            user_id = %user_id,
            "TOTP setup initiated"
        );

        Ok(TotpSetupOutput {
            qr_code_base64: qr_code,
            secret: secret.as_base32().to_string(),
            otpauth_url,
        })
    }

    /// Verify TOTP code and enable 2FA
    pub async fn verify(&self, user_id: &UserId, code: &str) -> AuthResult<()> {
        // Get user for account name
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Get auth credentials
        let mut auth = self
            .auth_repo
            .find_by_user_id(user_id)
            .await?
            .ok_or(AuthError::Internal("Auth not found".to_string()))?;

        // Check if TOTP is set up
        let secret = auth.totp_secret.as_ref().ok_or(AuthError::TwoFactorNotSetup)?;

        // Verify the code
        let account_name = user.user_name.as_str();
        let valid = secret
            .verify(code, account_name)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        if !valid {
            return Err(AuthError::InvalidTwoFactorCode);
        }

        // Enable TOTP
        auth.enable_totp();
        self.auth_repo.update(&auth).await?;

        tracing::info!(
            user_id = %user_id,
            "TOTP enabled"
        );

        Ok(())
    }

    /// Disable TOTP
    pub async fn disable(&self, user_id: &UserId, code: &str) -> AuthResult<()> {
        // Get user for account name
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Get auth credentials
        let mut auth = self
            .auth_repo
            .find_by_user_id(user_id)
            .await?
            .ok_or(AuthError::Internal("Auth not found".to_string()))?;

        // Check if user is allowed to disable TOTP
        // Moderator+ cannot disable TOTP
        if user.requires_2fa() {
            return Err(AuthError::Internal(
                "Users with elevated privileges cannot disable 2FA".to_string(),
            ));
        }

        // Verify current TOTP code before disabling
        if let Some(secret) = &auth.totp_secret {
            let account_name = user.user_name.as_str();
            let valid = secret
                .verify(code, account_name)
                .map_err(|e| AuthError::Internal(e.to_string()))?;

            if !valid {
                return Err(AuthError::InvalidTwoFactorCode);
            }
        }

        // Disable TOTP
        auth.disable_totp();
        self.auth_repo.update(&auth).await?;

        tracing::info!(
            user_id = %user_id,
            "TOTP disabled"
        );

        Ok(())
    }
}
