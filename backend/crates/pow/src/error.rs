//! PoW Error Types
//!
//! This module provides PoW-specific error variants that integrate
//! with the unified `kernel::error::AppError` system.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kernel::error::{app_error::AppError, kind::ErrorKind};
use thiserror::Error;

/// PoW-specific result type alias
pub type PowResult<T> = Result<T, PowError>;

/// PoW-specific error variants
///
/// These are domain-specific errors that map to appropriate HTTP status codes
/// and can be converted to `AppError` for unified error handling.
#[derive(Debug, Error)]
pub enum PowError {
    /// Challenge not found or already consumed
    #[error("Challenge not found or expired")]
    ChallengeNotFound,

    /// Challenge has expired (TTL exceeded)
    #[error("Challenge expired")]
    ChallengeExpired,

    /// Invalid nonce (hash does not meet difficulty)
    #[error("Invalid nonce: hash does not meet difficulty requirement")]
    InvalidNonce,

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Session not found or invalid
    #[error("Session not found or invalid")]
    SessionInvalid,

    /// Session fingerprint mismatch
    #[error("Session fingerprint mismatch")]
    SessionFingerprintMismatch,

    /// Missing required header (e.g., User-Agent)
    #[error("Missing required header: {0}")]
    MissingHeader(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl PowError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            PowError::ChallengeNotFound | PowError::ChallengeExpired => StatusCode::GONE,
            PowError::InvalidNonce => StatusCode::CONFLICT,
            PowError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            PowError::SessionInvalid | PowError::SessionFingerprintMismatch => {
                StatusCode::UNAUTHORIZED
            }
            PowError::MissingHeader(_) => StatusCode::BAD_REQUEST,
            PowError::Database(_) | PowError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the ErrorKind for this error
    pub fn kind(&self) -> ErrorKind {
        match self {
            PowError::ChallengeNotFound | PowError::ChallengeExpired => ErrorKind::Gone,
            PowError::InvalidNonce => ErrorKind::Conflict,
            PowError::RateLimitExceeded => ErrorKind::TooManyRequests,
            PowError::SessionInvalid | PowError::SessionFingerprintMismatch => {
                ErrorKind::Unauthorized
            }
            PowError::MissingHeader(_) => ErrorKind::BadRequest,
            PowError::Database(_) | PowError::Internal(_) => ErrorKind::InternalServerError,
        }
    }

    /// Log the error with appropriate level
    fn log(&self) {
        match self {
            PowError::Database(e) => {
                tracing::error!(error = %e, "PoW database error");
            }
            PowError::Internal(msg) => {
                tracing::error!(message = %msg, "PoW internal error");
            }
            PowError::InvalidNonce => {
                tracing::warn!("PoW invalid nonce attempt");
            }
            PowError::RateLimitExceeded => {
                tracing::warn!("PoW rate limit exceeded");
            }
            _ => {
                tracing::debug!(error = %self, "PoW error");
            }
        }
    }
}

impl From<PowError> for AppError {
    fn from(err: PowError) -> Self {
        let kind = err.kind();
        let message = err.to_string();
        AppError::new(kind, message)
    }
}

impl IntoResponse for PowError {
    fn into_response(self) -> Response {
        self.log();
        let status = self.status_code();
        // Return empty body for security (don't leak details)
        (status, ()).into_response()
    }
}

impl From<platform::client::FingerprintError> for PowError {
    fn from(err: platform::client::FingerprintError) -> Self {
        match err {
            platform::client::FingerprintError::MissingHeader(header) => {
                PowError::MissingHeader(header)
            }
        }
    }
}
