//! PostgreSQL Repository Implementations

use chrono::{DateTime, Utc};
use nid::Nanoid;
use sqlx::PgPool;
use std::str::FromStr;
use uuid::Uuid;

use crate::domain::entity::{auth::Auth, auth_session::AuthSession, user::User, user_details::UserDetails};
use crate::domain::repository::{AuthRepository, AuthSessionRepository, UserRepository, UserDetailsRepository};
use crate::domain::value_object::{
    email::Email, public_id::PublicId, totp_secret::TotpSecret,
    user_id::UserId, user_name::UserName, user_password::UserPassword, user_role::UserRole,
    user_status::UserStatus,
};
use crate::error::{AuthError, AuthResult};

/// PostgreSQL-backed auth repository
#[derive(Clone)]
pub struct PgAuthRepository {
    pool: PgPool,
}

impl PgAuthRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) -> AuthResult<u64> {
        let now_ms = Utc::now().timestamp_millis();

        let deleted = sqlx::query("DELETE FROM auth_sessions WHERE expires_at_ms < $1")
            .bind(now_ms)
            .execute(&self.pool)
            .await?
            .rows_affected();

        tracing::info!(sessions_deleted = deleted, "Cleaned up expired auth sessions");

        Ok(deleted)
    }
}

// ============================================================================
// User Repository Implementation
// ============================================================================

impl UserRepository for PgAuthRepository {
    async fn create(&self, user: &User) -> AuthResult<()> {
        sqlx::query(
            r#"
            INSERT INTO users (
                user_id,
                public_id,
                user_name,
                user_name_canonical,
                user_role,
                user_status,
                last_login_at,
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(user.user_id.as_uuid())
        .bind(user.public_id.as_str())
        .bind(user.user_name.original())
        .bind(user.user_name.canonical())
        .bind(user.user_role.id())
        .bind(user.user_status.id())
        .bind(user.last_login_at)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn find_by_id(&self, user_id: &UserId) -> AuthResult<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT
                user_id,
                public_id,
                user_name,
                user_name_canonical,
                user_role,
                user_status,
                last_login_at,
                created_at,
                updated_at
            FROM users
            WHERE user_id = $1
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.into_user()).transpose()
    }

    async fn find_by_public_id(&self, public_id: &PublicId) -> AuthResult<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT
                user_id,
                public_id,
                user_name,
                user_name_canonical,
                user_role,
                user_status,
                last_login_at,
                created_at,
                updated_at
            FROM users
            WHERE public_id = $1
            "#,
        )
        .bind(public_id.as_str())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.into_user()).transpose()
    }

    async fn find_by_user_name(&self, user_name: &UserName) -> AuthResult<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT
                user_id,
                public_id,
                user_name,
                user_name_canonical,
                user_role,
                user_status,
                last_login_at,
                created_at,
                updated_at
            FROM users
            WHERE user_name_canonical = $1
            "#,
        )
        .bind(user_name.canonical())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.into_user()).transpose()
    }

    async fn exists_by_user_name(&self, user_name: &UserName) -> AuthResult<bool> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE user_name_canonical = $1)",
        )
        .bind(user_name.canonical())
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    async fn update(&self, user: &User) -> AuthResult<()> {
        sqlx::query(
            r#"
            UPDATE users SET
                user_name = $2,
                user_name_canonical = $3,
                user_role = $4,
                user_status = $5,
                last_login_at = $6,
                updated_at = $7
            WHERE user_id = $1
            "#,
        )
        .bind(user.user_id.as_uuid())
        .bind(user.user_name.original())
        .bind(user.user_name.canonical())
        .bind(user.user_role.id())
        .bind(user.user_status.id())
        .bind(user.last_login_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ============================================================================
// Auth Repository Implementation
// ============================================================================

impl AuthRepository for PgAuthRepository {
    async fn create(&self, auth: &Auth) -> AuthResult<()> {
        sqlx::query(
            r#"
            INSERT INTO auth_credentials (
                user_id,
                password_hash,
                totp_secret,
                totp_enabled,
                login_failed_count,
                last_failed_at,
                locked_until,
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(auth.user_id.as_uuid())
        .bind(auth.password_hash.as_str())
        .bind(auth.totp_secret.as_ref().map(|s| s.as_base32()))
        .bind(auth.totp_enabled)
        .bind(auth.login_failed_count as i16)
        .bind(auth.last_failed_at)
        .bind(auth.locked_until)
        .bind(auth.created_at)
        .bind(auth.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn find_by_user_id(&self, user_id: &UserId) -> AuthResult<Option<Auth>> {
        let row = sqlx::query_as::<_, AuthRow>(
            r#"
            SELECT
                user_id,
                password_hash,
                totp_secret,
                totp_enabled,
                login_failed_count,
                last_failed_at,
                locked_until,
                created_at,
                updated_at
            FROM auth_credentials
            WHERE user_id = $1
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.into_auth()).transpose()
    }

    async fn update(&self, auth: &Auth) -> AuthResult<()> {
        sqlx::query(
            r#"
            UPDATE auth_credentials SET
                password_hash = $2,
                totp_secret = $3,
                totp_enabled = $4,
                login_failed_count = $5,
                last_failed_at = $6,
                locked_until = $7,
                updated_at = $8
            WHERE user_id = $1
            "#,
        )
        .bind(auth.user_id.as_uuid())
        .bind(auth.password_hash.as_str())
        .bind(auth.totp_secret.as_ref().map(|s| s.as_base32()))
        .bind(auth.totp_enabled)
        .bind(auth.login_failed_count as i16)
        .bind(auth.last_failed_at)
        .bind(auth.locked_until)
        .bind(auth.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ============================================================================
// User Details Repository Implementation
// ============================================================================

impl UserDetailsRepository for PgAuthRepository {
    async fn create(&self, details: &UserDetails) -> AuthResult<()> {
        sqlx::query(
            r#"
            INSERT INTO user_details (
                user_id,
                email,
                email_verified,
                display_name,
                first_name,
                last_name,
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(details.user_id.as_uuid())
        .bind(details.email.as_ref().map(|e| e.as_str()))
        .bind(details.email_verified)
        .bind(&details.display_name)
        .bind(&details.first_name)
        .bind(&details.last_name)
        .bind(details.created_at)
        .bind(details.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn find_by_user_id(&self, user_id: &UserId) -> AuthResult<Option<UserDetails>> {
        let row = sqlx::query_as::<_, UserDetailsRow>(
            r#"
            SELECT
                user_id,
                email,
                email_verified,
                display_name,
                first_name,
                last_name,
                created_at,
                updated_at
            FROM user_details
            WHERE user_id = $1
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_details()))
    }

    async fn update(&self, details: &UserDetails) -> AuthResult<()> {
        sqlx::query(
            r#"
            UPDATE user_details SET
                email = $2,
                email_verified = $3,
                display_name = $4,
                first_name = $5,
                last_name = $6,
                updated_at = $7
            WHERE user_id = $1
            "#,
        )
        .bind(details.user_id.as_uuid())
        .bind(details.email.as_ref().map(|e| e.as_str()))
        .bind(details.email_verified)
        .bind(&details.display_name)
        .bind(&details.first_name)
        .bind(&details.last_name)
        .bind(details.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn exists_by_email(&self, email: &str) -> AuthResult<bool> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM user_details WHERE email = $1)",
        )
        .bind(email)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }
}

// ============================================================================
// Auth Session Repository Implementation
// ============================================================================

impl AuthSessionRepository for PgAuthRepository {
    async fn create(&self, session: &AuthSession) -> AuthResult<()> {
        sqlx::query(
            r#"
            INSERT INTO auth_sessions (
                session_id,
                user_id,
                public_id,
                user_role,
                expires_at_ms,
                remember_me,
                client_fingerprint_hash,
                client_ip,
                user_agent,
                created_at,
                last_activity_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(session.session_id)
        .bind(session.user_id.as_uuid())
        .bind(session.public_id.as_str())
        .bind(session.user_role.id())
        .bind(session.expires_at_ms)
        .bind(session.remember_me)
        .bind(&session.client_fingerprint_hash)
        .bind(&session.client_ip)
        .bind(&session.user_agent)
        .bind(session.created_at)
        .bind(session.last_activity_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn find_by_id(
        &self,
        session_id: Uuid,
        fingerprint_hash: &[u8],
    ) -> AuthResult<Option<AuthSession>> {
        let now_ms = Utc::now().timestamp_millis();

        let row = sqlx::query_as::<_, AuthSessionRow>(
            r#"
            SELECT
                session_id,
                user_id,
                public_id,
                user_role,
                expires_at_ms,
                remember_me,
                client_fingerprint_hash,
                client_ip,
                user_agent,
                created_at,
                last_activity_at
            FROM auth_sessions
            WHERE session_id = $1 AND expires_at_ms > $2
            "#,
        )
        .bind(session_id)
        .bind(now_ms)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                // Verify fingerprint
                if r.client_fingerprint_hash != fingerprint_hash {
                    tracing::warn!(
                        session_id = %session_id,
                        "Auth session fingerprint mismatch"
                    );
                    return Err(AuthError::SessionFingerprintMismatch);
                }
                Ok(Some(r.into_session()?))
            }
            None => Ok(None),
        }
    }

    async fn find_by_user_id(&self, user_id: &UserId) -> AuthResult<Vec<AuthSession>> {
        let now_ms = Utc::now().timestamp_millis();

        let rows = sqlx::query_as::<_, AuthSessionRow>(
            r#"
            SELECT
                session_id,
                user_id,
                public_id,
                user_role,
                expires_at_ms,
                remember_me,
                client_fingerprint_hash,
                client_ip,
                user_agent,
                created_at,
                last_activity_at
            FROM auth_sessions
            WHERE user_id = $1 AND expires_at_ms > $2
            ORDER BY last_activity_at DESC
            "#,
        )
        .bind(user_id.as_uuid())
        .bind(now_ms)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_session()).collect()
    }

    async fn update(&self, session: &AuthSession) -> AuthResult<()> {
        sqlx::query(
            r#"
            UPDATE auth_sessions SET
                expires_at_ms = $2,
                last_activity_at = $3
            WHERE session_id = $1
            "#,
        )
        .bind(session.session_id)
        .bind(session.expires_at_ms)
        .bind(session.last_activity_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, session_id: Uuid) -> AuthResult<()> {
        sqlx::query("DELETE FROM auth_sessions WHERE session_id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: &UserId, except: Option<Uuid>) -> AuthResult<u64> {
        let deleted = match except {
            Some(except_id) => {
                sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1 AND session_id != $2")
                    .bind(user_id.as_uuid())
                    .bind(except_id)
                    .execute(&self.pool)
                    .await?
                    .rows_affected()
            }
            None => {
                sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1")
                    .bind(user_id.as_uuid())
                    .execute(&self.pool)
                    .await?
                    .rows_affected()
            }
        };

        Ok(deleted)
    }

    async fn cleanup_expired(&self) -> AuthResult<u64> {
        self.cleanup_expired().await
    }
}

// ============================================================================
// Row Types for sqlx mapping
// ============================================================================

#[derive(sqlx::FromRow)]
struct UserRow {
    user_id: Uuid,
    public_id: String,
    user_name: String,
    #[allow(dead_code)]
    user_name_canonical: String,
    user_role: i16,
    user_status: i16,
    last_login_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserRow {
    fn into_user(self) -> AuthResult<User> {
        let public_id = PublicId::from_nanoid(
            Nanoid::from_str(&self.public_id)
                .map_err(|e| AuthError::Internal(format!("Invalid public_id: {}", e)))?,
        );

        let user_name = UserName::from_db(&self.user_name)
            .map_err(|e| AuthError::Internal(format!("Invalid user_name: {}", e)))?;

        Ok(User {
            user_id: UserId::from_uuid(self.user_id),
            public_id,
            user_name,
            user_role: UserRole::from_id(self.user_role),
            user_status: UserStatus::from_id(self.user_status).unwrap_or_default(),
            last_login_at: self.last_login_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct AuthRow {
    user_id: Uuid,
    password_hash: String,
    totp_secret: Option<String>,
    totp_enabled: bool,
    login_failed_count: i16,
    last_failed_at: Option<DateTime<Utc>>,
    locked_until: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl AuthRow {
    fn into_auth(self) -> AuthResult<Auth> {
        let totp_secret = self
            .totp_secret
            .map(TotpSecret::from_base32)
            .transpose()
            .map_err(|e| AuthError::Internal(format!("Invalid TOTP secret: {}", e)))?;

        Ok(Auth {
            user_id: UserId::from_uuid(self.user_id),
            password_hash: UserPassword::from_db(self.password_hash),
            totp_secret,
            totp_enabled: self.totp_enabled,
            login_failed_count: self.login_failed_count as u16,
            last_failed_at: self.last_failed_at,
            locked_until: self.locked_until,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct AuthSessionRow {
    session_id: Uuid,
    user_id: Uuid,
    public_id: String,
    user_role: i16,
    expires_at_ms: i64,
    remember_me: bool,
    client_fingerprint_hash: Vec<u8>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    created_at: DateTime<Utc>,
    last_activity_at: DateTime<Utc>,
}

impl AuthSessionRow {
    fn into_session(self) -> AuthResult<AuthSession> {
        let public_id = PublicId::from_nanoid(
            Nanoid::from_str(&self.public_id)
                .map_err(|e| AuthError::Internal(format!("Invalid public_id: {}", e)))?,
        );

        Ok(AuthSession {
            session_id: self.session_id,
            user_id: UserId::from_uuid(self.user_id),
            public_id,
            user_role: UserRole::from_id(self.user_role),
            expires_at_ms: self.expires_at_ms,
            remember_me: self.remember_me,
            client_fingerprint_hash: self.client_fingerprint_hash,
            client_ip: self.client_ip,
            user_agent: self.user_agent,
            created_at: self.created_at,
            last_activity_at: self.last_activity_at,
        })
    }
}
#[derive(sqlx::FromRow)]
struct UserDetailsRow {
    user_id: Uuid,
    email: Option<String>,
    email_verified: bool,
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserDetailsRow {
    fn into_details(self) -> UserDetails {
        UserDetails {
            user_id: UserId::from_uuid(self.user_id),
            email: self.email.map(Email::from_db),
            email_verified: self.email_verified,
            display_name: self.display_name,
            first_name: self.first_name,
            last_name: self.last_name,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}