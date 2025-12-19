//! Email Value Object
//!
//! Represents a validated email address.
//! Basic validation only - actual verification is done via email confirmation.

use kernel::error::app_error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Maximum email length (per RFC 5321)
const EMAIL_MAX_LENGTH: usize = 254;

/// Email address value object
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Email(String);

impl Email {
    /// Create a new email with validation
    pub fn new(email: impl Into<String>) -> AppResult<Self> {
        let email = email.into().trim().to_lowercase();

        if email.is_empty() {
            return Err(AppError::bad_request("Email cannot be empty"));
        }

        if email.len() > EMAIL_MAX_LENGTH {
            return Err(AppError::bad_request(format!(
                "Email must be at most {} characters",
                EMAIL_MAX_LENGTH
            )));
        }

        // Basic email format validation
        if !Self::is_valid_format(&email) {
            return Err(AppError::bad_request("Invalid email format"));
        }

        Ok(Self(email))
    }

    /// Basic email format validation
    fn is_valid_format(email: &str) -> bool {
        // Must contain exactly one @
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return false;
        }

        let local = parts[0];
        let domain = parts[1];

        // Local part checks
        if local.is_empty() || local.len() > 64 {
            return false;
        }

        // Domain checks
        if domain.is_empty() || !domain.contains('.') {
            return false;
        }

        // Check domain has valid characters
        if !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return false;
        }

        // Domain shouldn't start or end with dot or hyphen
        if domain.starts_with('.') || domain.ends_with('.') {
            return false;
        }
        if domain.starts_with('-') || domain.ends_with('-') {
            return false;
        }

        true
    }

    /// Create from database value (assumed already validated)
    pub fn from_db(email: impl Into<String>) -> Self {
        Self(email.into())
    }

    /// Get the email as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert to string for database storage
    pub fn into_db(self) -> String {
        self.0
    }

    /// Get the domain part of the email
    pub fn domain(&self) -> &str {
        self.0.split('@').nth(1).unwrap_or("")
    }

    /// Get the local part of the email
    pub fn local_part(&self) -> &str {
        self.0.split('@').next().unwrap_or("")
    }
}

impl FromStr for Email {
    type Err = AppError;

    fn from_str(s: &str) -> AppResult<Self> {
        Email::new(s)
    }
}

impl std::fmt::Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_valid() {
        assert!(Email::new("user@example.com").is_ok());
        assert!(Email::new("User@Example.COM").is_ok()); // Should lowercase
        assert!(Email::new("user.name@example.co.jp").is_ok());
        assert!(Email::new("user+tag@example.com").is_ok());
    }

    #[test]
    fn test_email_invalid() {
        assert!(Email::new("").is_err());
        assert!(Email::new("userexample.com").is_err());
        assert!(Email::new("user@").is_err());
        assert!(Email::new("@example.com").is_err());
        assert!(Email::new("user@@example.com").is_err());
        assert!(Email::new("user@example").is_err());
    }

    #[test]
    fn test_email_domain() {
        let email = Email::new("user@example.com").unwrap();
        assert_eq!(email.domain(), "example.com");
        assert_eq!(email.local_part(), "user");
    }

    #[test]
    fn test_email_case_normalization() {
        let email = Email::new("User@Example.COM").unwrap();
        assert_eq!(email.as_str(), "user@example.com");
    }
}
