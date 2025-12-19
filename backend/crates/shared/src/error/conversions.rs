//! Error conversions - From implementations for common error types
//!
//! Provides automatic conversion from common error types to [`AppError`].

use super::app_error::AppError;
use super::kind::ErrorKind;

// ============================================================================
// Standard library conversions
// ============================================================================

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        let kind = match err.kind() {
            std::io::ErrorKind::NotFound => ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => ErrorKind::Forbidden,
            std::io::ErrorKind::TimedOut => ErrorKind::RequestTimeout,
            _ => ErrorKind::InternalServerError,
        };
        AppError::new(kind, "I/O operation failed").with_source(err)
    }
}

impl From<std::fmt::Error> for AppError {
    fn from(err: std::fmt::Error) -> Self {
        AppError::internal("Formatting error").with_source(err)
    }
}

impl From<std::string::FromUtf8Error> for AppError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        AppError::bad_request("Invalid UTF-8 string").with_source(err)
    }
}

impl From<std::num::ParseIntError> for AppError {
    fn from(err: std::num::ParseIntError) -> Self {
        AppError::bad_request("Invalid integer format").with_source(err)
    }
}

impl From<std::num::ParseFloatError> for AppError {
    fn from(err: std::num::ParseFloatError) -> Self {
        AppError::bad_request("Invalid float format").with_source(err)
    }
}

// ============================================================================
// serde_json conversions
// ============================================================================

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        if err.is_syntax() || err.is_data() {
            AppError::bad_request(format!("JSON parse error: {}", err)).with_source(err)
        } else {
            AppError::internal("JSON serialization error").with_source(err)
        }
    }
}

// ============================================================================
// SQLx conversions (feature-gated)
// ============================================================================

#[cfg(feature = "sqlx")]
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => AppError::not_found("Record not found").with_source(err),
            sqlx::Error::PoolTimedOut => {
                AppError::service_unavailable("Database connection pool exhausted").with_source(err)
            }
            sqlx::Error::Database(db_err) => {
                // PostgreSQL specific error codes
                // https://www.postgresql.org/docs/current/errcodes-appendix.html
                let app_err = if let Some(code) = db_err.code() {
                    match code.as_ref() {
                        // Class 23 — Integrity Constraint Violation
                        "23000" => AppError::conflict("Integrity constraint violation"),
                        "23001" => AppError::conflict("Restrict violation"),
                        "23502" => AppError::bad_request("Required field is null"),
                        "23503" => AppError::conflict("Foreign key violation"),
                        "23505" => AppError::conflict("Duplicate key value"),
                        "23514" => AppError::bad_request("Check constraint violation"),
                        // Class 42 — Syntax Error or Access Rule Violation
                        "42501" => AppError::forbidden("Insufficient privilege"),
                        // Class 53 — Insufficient Resources
                        "53000" | "53100" | "53200" | "53300" => {
                            AppError::service_unavailable("Database resource exhausted")
                        }
                        // Class 57 — Operator Intervention
                        "57000" | "57014" | "57P01" | "57P02" | "57P03" => {
                            AppError::service_unavailable("Database unavailable")
                        }
                        _ => AppError::internal("Database error"),
                    }
                } else {
                    AppError::internal("Database error")
                };
                app_err.with_source(err)
            }
            sqlx::Error::Io(_) => {
                AppError::service_unavailable("Database connection error").with_source(err)
            }
            sqlx::Error::Protocol(_) => {
                AppError::internal("Database protocol error").with_source(err)
            }
            sqlx::Error::Tls(_) => AppError::internal("Database TLS error").with_source(err),
            _ => AppError::internal("Database error").with_source(err),
        }
    }
}

// ============================================================================
// Axum conversions (feature-gated)
// ============================================================================

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use axum::Json;
        use axum::http::StatusCode;

        let status =
            StatusCode::from_u16(self.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        // RFC 7807 Problem Details for HTTP APIs
        let body = serde_json::json!({
            "type": format!("https://httpstatuses.io/{}", self.status_code()),
            "title": self.kind().as_str(),
            "status": self.status_code(),
            "detail": self.message(),
            "action": self.action(),
        });

        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let app_err: AppError = io_err.into();
        assert_eq!(app_err.kind(), ErrorKind::NotFound);

        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let app_err: AppError = io_err.into();
        assert_eq!(app_err.kind(), ErrorKind::Forbidden);
    }

    #[test]
    fn test_parse_int_error_conversion() {
        let parse_err: Result<i32, _> = "abc".parse();
        let app_err: AppError = parse_err.unwrap_err().into();
        assert_eq!(app_err.kind(), ErrorKind::BadRequest);
    }

    #[test]
    fn test_json_error_conversion() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let app_err: AppError = json_err.into();
        assert_eq!(app_err.kind(), ErrorKind::BadRequest);
    }
}
