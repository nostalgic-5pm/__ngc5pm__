//! Auth Error Types
//!
//! This module provides auth-specific error variants that integrate
//! with the unified `kernel::error::AppError` system.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kernel::error::{app_error::AppError, kind::ErrorKind};
use thiserror::Error;

/// Auth-specific result type alias
pub type AuthResult<T> = Result<T, AuthError>;

/// Auth-specific error variants
#[derive(Debug, Error)]
pub enum AuthError {
    /// User not found
    #[error("User not found")]
    UserNotFound,

    /// User name already exists
    #[error("User name already exists")]
    UserNameTaken,

    /// Invalid credentials (wrong password)
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// Account is locked (too many failed attempts)
    #[error("Account is temporarily locked")]
    AccountLocked,

    /// Account is disabled
    #[error("Account is disabled")]
    AccountDisabled,

    /// Session not found or expired
    #[error("Session not found or expired")]
    SessionInvalid,

    /// Session fingerprint mismatch
    #[error("Session fingerprint mismatch")]
    SessionFingerprintMismatch,

    /// 2FA required
    #[error("Two-factor authentication required")]
    TwoFactorRequired,

    /// Invalid 2FA code
    #[error("Invalid two-factor authentication code")]
    InvalidTwoFactorCode,

    /// 2FA not set up
    #[error("Two-factor authentication not set up")]
    TwoFactorNotSetup,

    /// Email required (for moderator+ roles)
    #[error("Email is required for this role")]
    EmailRequired,

    /// Missing required header
    #[error("Missing required header: {0}")]
    MissingHeader(String),

    /// Password validation error
    #[error("Password validation failed: {0}")]
    PasswordValidation(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AuthError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            AuthError::UserNotFound => StatusCode::NOT_FOUND,
            AuthError::UserNameTaken => StatusCode::CONFLICT,
            AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AuthError::AccountLocked => StatusCode::LOCKED,
            AuthError::AccountDisabled => StatusCode::FORBIDDEN,
            AuthError::SessionInvalid | AuthError::SessionFingerprintMismatch => {
                StatusCode::UNAUTHORIZED
            }
            AuthError::TwoFactorRequired => StatusCode::from_u16(428).unwrap(), // Precondition Required
            AuthError::InvalidTwoFactorCode => StatusCode::UNAUTHORIZED,
            AuthError::TwoFactorNotSetup => StatusCode::PRECONDITION_FAILED,
            AuthError::EmailRequired => StatusCode::PRECONDITION_FAILED,
            AuthError::MissingHeader(_) | AuthError::PasswordValidation(_) => {
                StatusCode::BAD_REQUEST
            }
            AuthError::Database(_) | AuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the ErrorKind for this error
    pub fn kind(&self) -> ErrorKind {
        match self {
            AuthError::UserNotFound => ErrorKind::NotFound,
            AuthError::UserNameTaken => ErrorKind::Conflict,
            AuthError::InvalidCredentials
            | AuthError::SessionInvalid
            | AuthError::SessionFingerprintMismatch
            | AuthError::InvalidTwoFactorCode => ErrorKind::Unauthorized,
            AuthError::AccountLocked => ErrorKind::Forbidden,
            AuthError::AccountDisabled => ErrorKind::Forbidden,
            AuthError::TwoFactorRequired
            | AuthError::TwoFactorNotSetup
            | AuthError::EmailRequired => ErrorKind::UnprocessableEntity,
            AuthError::MissingHeader(_) | AuthError::PasswordValidation(_) => ErrorKind::BadRequest,
            AuthError::Database(_) | AuthError::Internal(_) => ErrorKind::InternalServerError,
        }
    }

    /// Convert to AppError
    pub fn to_app_error(&self) -> AppError {
        AppError::new(self.kind(), self.to_string())
    }

    /// Log the error with appropriate level
    fn log(&self) {
        match self {
            AuthError::Database(e) => {
                tracing::error!(error = %e, "Auth database error");
            }
            AuthError::Internal(msg) => {
                tracing::error!(message = %msg, "Auth internal error");
            }
            AuthError::InvalidCredentials => {
                tracing::warn!("Invalid login attempt");
            }
            AuthError::AccountLocked => {
                tracing::warn!("Login attempt on locked account");
            }
            AuthError::SessionFingerprintMismatch => {
                tracing::warn!("Session fingerprint mismatch detected");
            }
            _ => {
                tracing::debug!(error = %self, "Auth error");
            }
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        self.log();
        self.to_app_error().into_response()
    }
}

impl From<AppError> for AuthError {
    fn from(err: AppError) -> Self {
        AuthError::Internal(err.to_string())
    }
}

impl From<platform::client::FingerprintError> for AuthError {
    fn from(err: platform::client::FingerprintError) -> Self {
        match err {
            platform::client::FingerprintError::MissingHeader(header) => {
                AuthError::MissingHeader(header)
            }
        }
    }
}
