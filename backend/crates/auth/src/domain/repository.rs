//! Repository Traits
//!
//! Interfaces for data persistence. Implementation is in infrastructure layer.

use crate::domain::entity::{
    auth::Auth, auth_session::AuthSession, user::User, user_details::UserDetails,
};
use crate::domain::value_object::{public_id::PublicId, user_id::UserId, user_name::UserName};
use crate::error::AuthResult;
use uuid::Uuid;

/// User repository trait
#[trait_variant::make(UserRepository: Send)]
pub trait LocalUserRepository {
    /// Create a new user
    async fn create(&self, user: &User) -> AuthResult<()>;

    /// Find user by ID
    async fn find_by_id(&self, user_id: &UserId) -> AuthResult<Option<User>>;

    /// Find user by public ID
    async fn find_by_public_id(&self, public_id: &PublicId) -> AuthResult<Option<User>>;

    /// Find user by user name
    async fn find_by_user_name(&self, user_name: &UserName) -> AuthResult<Option<User>>;

    /// Check if user name exists
    async fn exists_by_user_name(&self, user_name: &UserName) -> AuthResult<bool>;

    /// Update user
    async fn update(&self, user: &User) -> AuthResult<()>;
}

/// User details repository trait
#[trait_variant::make(UserDetailsRepository: Send)]
pub trait LocalUserDetailsRepository {
    /// Create user details
    async fn create(&self, details: &UserDetails) -> AuthResult<()>;

    /// Find details by user ID
    async fn find_by_user_id(&self, user_id: &UserId) -> AuthResult<Option<UserDetails>>;

    /// Update user details
    async fn update(&self, details: &UserDetails) -> AuthResult<()>;

    /// Check if email exists
    async fn exists_by_email(&self, email: &str) -> AuthResult<bool>;
}

/// Auth credentials repository trait
#[trait_variant::make(AuthRepository: Send)]
pub trait LocalAuthRepository {
    /// Create auth credentials
    async fn create(&self, auth: &Auth) -> AuthResult<()>;

    /// Find auth by user ID
    async fn find_by_user_id(&self, user_id: &UserId) -> AuthResult<Option<Auth>>;

    /// Update auth credentials
    async fn update(&self, auth: &Auth) -> AuthResult<()>;
}

/// Auth session repository trait
#[trait_variant::make(AuthSessionRepository: Send)]
pub trait LocalAuthSessionRepository {
    /// Create a new session
    async fn create(&self, session: &AuthSession) -> AuthResult<()>;

    /// Find session by ID and verify fingerprint
    async fn find_by_id(
        &self,
        session_id: Uuid,
        fingerprint_hash: &[u8],
    ) -> AuthResult<Option<AuthSession>>;

    /// Find all sessions for a user
    async fn find_by_user_id(&self, user_id: &UserId) -> AuthResult<Vec<AuthSession>>;

    /// Update session (e.g., last activity)
    async fn update(&self, session: &AuthSession) -> AuthResult<()>;

    /// Delete a session

    async fn delete(&self, session_id: Uuid) -> AuthResult<()>;

    /// Delete all sessions for a user (except current)
    async fn delete_all_for_user(&self, user_id: &UserId, except: Option<Uuid>) -> AuthResult<u64>;

    /// Clean up expired sessions
    async fn cleanup_expired(&self) -> AuthResult<u64>;
}

/// Combined repository for transactions
#[trait_variant::make(AuthUnitOfWork: Send)]
pub trait LocalAuthUnitOfWork: UserRepository + AuthRepository + AuthSessionRepository {
    /// Execute operations in a transaction
    async fn transaction<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E> + Send,
        T: Send,
        E: Send;
}
