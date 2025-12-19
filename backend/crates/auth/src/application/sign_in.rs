//! Sign In Use Case
//!
//! Authenticates a user and creates a session.

use std::sync::Arc;

use crate::application::config::AuthConfig;
use crate::domain::entity::auth_session::AuthSession;
use crate::domain::repository::{AuthRepository, AuthSessionRepository, UserRepository};
use crate::domain::value_object::{
    email::Email, user_name::UserName, user_password::RawPassword,
};
use crate::error::{AuthError, AuthResult};

/// Sign in input
pub struct SignInInput {
    /// User name or email
    pub identifier: String,
    /// Password
    pub password: String,
    /// Remember me flag
    pub remember_me: bool,
    /// TOTP code (if 2FA is enabled)
    pub totp_code: Option<String>,
}

/// Sign in output
pub struct SignInOutput {
    /// Session token for cookie
    pub session_token: String,
    /// Whether 2FA is required
    pub requires_2fa: bool,
    /// Public ID
    pub public_id: String,
}

/// Re-export ClientFingerprint from platform
pub use platform::client::ClientFingerprint;

/// Sign in use case
pub struct SignInUseCase<U, A, S>
where
    U: UserRepository,
    A: AuthRepository,
    S: AuthSessionRepository,
{
    user_repo: Arc<U>,
    auth_repo: Arc<A>,
    session_repo: Arc<S>,
    config: Arc<AuthConfig>,
}

impl<U, A, S> SignInUseCase<U, A, S>
where
    U: UserRepository,
    A: AuthRepository,
    S: AuthSessionRepository,
{
    pub fn new(
        user_repo: Arc<U>,
        auth_repo: Arc<A>,
        session_repo: Arc<S>,
        config: Arc<AuthConfig>,
    ) -> Self {
        Self {
            user_repo,
            auth_repo,
            session_repo,
            config,
        }
    }

    pub async fn execute(
        &self,
        input: SignInInput,
        fingerprint: ClientFingerprint,
    ) -> AuthResult<SignInOutput> {
        // Try to find user by user_name or email
        let user = if input.identifier.contains('@') {
            // Looks like email
            let email = Email::new(&input.identifier)
                .map_err(|_| AuthError::InvalidCredentials)?;
            self.find_user_by_email(&email).await?
        } else {
            // Treat as user name
            let user_name = UserName::new(&input.identifier, None)
                .map_err(|_| AuthError::InvalidCredentials)?;
            self.user_repo.find_by_user_name(&user_name).await?
        };

        let user = user.ok_or(AuthError::InvalidCredentials)?;

        // Check if user can login
        if !user.can_login() {
            return Err(AuthError::AccountDisabled);
        }

        // Get auth credentials
        let mut auth = self
            .auth_repo
            .find_by_user_id(&user.user_id)
            .await?
            .ok_or(AuthError::Internal("Auth not found".to_string()))?;

        // Check if account is locked
        if auth.is_locked() {
            return Err(AuthError::AccountLocked);
        }

        // Verify password
        let raw_password = RawPassword::new(input.password)
            .map_err(|_| AuthError::InvalidCredentials)?;

        let password_valid = auth
            .password_hash
            .verify(&raw_password, self.config.pepper())
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        if !password_valid {
            auth.record_failure();
            self.auth_repo.update(&auth).await?;
            return Err(AuthError::InvalidCredentials);
        }

        // Check if 2FA is required
        if user.requires_2fa() || auth.requires_2fa() {
            if !auth.totp_enabled {
                // User needs to set up 2FA first
                return Err(AuthError::TwoFactorNotSetup);
            }

            match &input.totp_code {
                None => {
                    // 2FA required but not provided
                    return Ok(SignInOutput {
                        session_token: String::new(),
                        requires_2fa: true,
                        public_id: user.public_id.to_string(),
                    });
                }
                Some(code) => {
                    // Verify TOTP
                    let totp_secret = auth
                        .totp_secret
                        .as_ref()
                        .ok_or(AuthError::TwoFactorNotSetup)?;

                    let account_name = user.user_name.as_str();
                    let valid = totp_secret
                        .verify(code, account_name)
                        .map_err(|e| AuthError::Internal(e.to_string()))?;

                    if !valid {
                        return Err(AuthError::InvalidTwoFactorCode);
                    }
                }
            }
        }

        // Reset failure count and update last login
        auth.reset_failures();
        self.auth_repo.update(&auth).await?;

        // Update user's last login
        let mut user = user;
        user.record_login();
        self.user_repo.update(&user).await?;

        // Create session
        let session = AuthSession::new(
            user.user_id.clone(),
            user.public_id.clone(),
            user.user_role,
            input.remember_me,
            fingerprint.hash_vec(),
            fingerprint.ip_string(),
            fingerprint.user_agent.clone(),
        );

        self.session_repo.create(&session).await?;

        // Generate session token
        let session_token = self.generate_session_token(&session);

        tracing::info!(
            public_id = %user.public_id,
            session_id = %session.session_id,
            remember_me = input.remember_me,
            "User signed in"
        );

        Ok(SignInOutput {
            session_token,
            requires_2fa: false,
            public_id: user.public_id.to_string(),
        })
    }

    /// Find user by email (requires joining with auth table)
    async fn find_user_by_email(&self, _email: &Email) -> AuthResult<Option<crate::domain::entity::user::User>> {
        // TODO: Implement email lookup
        // For now, email login is not supported
        Ok(None)
    }

    /// Generate signed session token
    fn generate_session_token(&self, session: &AuthSession) -> String {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let session_id = session.session_id.to_string();
        
        // Create HMAC signature
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.config.session_secret)
            .expect("HMAC can take key of any size");
        mac.update(session_id.as_bytes());
        let signature = mac.finalize().into_bytes();

        // Combine session_id + signature
        let combined = format!(
            "{}.{}",
            session_id,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature)
        );

        combined
    }
}
