//! Sign Up Use Case
//!
//! Creates a new user account.

use std::sync::Arc;

use crate::application::config::AuthConfig;
use crate::domain::entity::{auth::Auth, user::User};
use crate::domain::repository::{AuthRepository, UserRepository};
use crate::domain::value_object::{
    user_name::UserName, user_password::{RawPassword, UserPassword},
};
use crate::error::{AuthError, AuthResult};

/// Sign up input
pub struct SignUpInput {
    pub user_name: String,
    pub password: String,
}

/// Sign up output
pub struct SignUpOutput {
    pub public_id: String,
}

/// Sign up use case
pub struct SignUpUseCase<U, A>
where
    U: UserRepository,
    A: AuthRepository,
{
    user_repo: Arc<U>,
    auth_repo: Arc<A>,
    config: Arc<AuthConfig>,
}

impl<U, A> SignUpUseCase<U, A>
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

    pub async fn execute(&self, input: SignUpInput) -> AuthResult<SignUpOutput> {
        // Validate user name
        let user_name = UserName::new(input.user_name, None)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        // Check if user name is taken
        if self.user_repo.exists_by_user_name(&user_name).await? {
            return Err(AuthError::UserNameTaken);
        }

        // Validate and hash password
        let raw_password = RawPassword::new(input.password)
            .map_err(|e| AuthError::PasswordValidation(e.to_string()))?;
        let password_hash = UserPassword::from_raw(&raw_password, self.config.pepper())
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        // Create user
        let user = User::new(user_name);

        // Create auth credentials
        let auth = Auth::new(user.user_id.clone(), password_hash);

        // Persist
        self.user_repo.create(&user).await?;
        self.auth_repo.create(&auth).await?;

        tracing::info!(
            public_id = %user.public_id,
            user_name = %user.user_name,
            "User signed up"
        );

        Ok(SignUpOutput {
            public_id: user.public_id.to_string(),
        })
    }
}
