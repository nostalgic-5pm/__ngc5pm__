//! User Password Value Object
//!
//! Domain value object for user passwords with NIST SP 800-63B compliance.
//! Delegates to `platform::password` for cryptographic operations.
//!
//! ## Security Features
//! - Argon2id hashing (memory-hard)
//! - Automatic memory zeroization
//! - Constant-time comparison
//! - Unicode NFKC normalization
//! - Optional breach checking via HIBP API
//!
//! ## Usage
//! ```rust
//! use auth::domain::value_object::user_password::{UserPassword, RawPassword};
//!
//! // Create from user input
//! let raw = RawPassword::new("MySecurePass123!".to_string())?;
//!
//! // Hash for storage
//! let hashed = UserPassword::from_raw(&raw, None)?;
//!
//! // Verify later
//! assert!(hashed.verify(&raw, None));
//! ```

use kernel::error::{
    app_error::{AppError, AppResult},
    kind::ErrorKind,
};
use platform::password::{
    ClearTextPassword, HashedPassword, PasswordHashError, PasswordPolicyError,
};
use std::fmt;

// ============================================================================
// Raw Password (User Input)
// ============================================================================

/// Raw password from user input
///
/// Wrapper around `ClearTextPassword` with domain-specific error handling.
/// Memory is automatically zeroized when dropped.
pub struct RawPassword(ClearTextPassword);

impl RawPassword {
    /// Create a new raw password with validation
    ///
    /// ## Validation Rules (NIST SP 800-63B)
    /// - Minimum 8 characters
    /// - Maximum 128 characters
    /// - No control characters
    /// - No common patterns (sequential, keyboard, dictionary)
    /// - Unicode NFKC normalized
    ///
    /// ## Errors
    /// Returns `AppError` with appropriate user-facing messages
    pub fn new(raw: String) -> AppResult<Self> {
        let clear_text = ClearTextPassword::new(raw).map_err(|e| match e {
            PasswordPolicyError::TooShort { min, actual } => AppError::bad_request(format!(
                "Password must be at least {} characters (got {})",
                min, actual
            ))
            .with_action("Please choose a longer password"),

            PasswordPolicyError::TooLong { max, actual } => AppError::bad_request(format!(
                "Password must be at most {} characters (got {})",
                max, actual
            ))
            .with_action("Please choose a shorter password"),

            PasswordPolicyError::Compromised => {
                AppError::bad_request("This password has been found in a data breach")
                    .with_action("Please choose a different password that hasn't been compromised")
            }

            PasswordPolicyError::EmptyOrWhitespace => {
                AppError::bad_request("Password cannot be empty")
                    .with_action("Please enter a password")
            }

            PasswordPolicyError::InvalidCharacter => {
                AppError::bad_request("Password contains invalid characters")
                    .with_action("Please remove any special control characters")
            }

            PasswordPolicyError::CommonPattern => {
                AppError::bad_request("Password is too common or follows a predictable pattern")
                    .with_action("Please choose a more unique password")
            }
        })?;

        Ok(Self(clear_text))
    }

    /// Check if password has been compromised (via HIBP API)
    ///
    /// Uses k-Anonymity model - only SHA-1 prefix is sent to API.
    ///
    /// ## Returns
    /// - `Ok(true)` if compromised
    /// - `Ok(false)` if not found in breaches
    /// - `Err(_)` if check failed (treat as non-blocking)
    pub async fn is_compromised(&self) -> AppResult<bool> {
        self.0
            .check_breach()
            .await
            .map_err(|e| AppError::service_unavailable(e.to_string()))
    }

    /// Access the inner ClearTextPassword
    pub(crate) fn inner(&self) -> &ClearTextPassword {
        &self.0
    }
}

impl fmt::Debug for RawPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RawPassword").field(&"[REDACTED]").finish()
    }
}

// ============================================================================
// User Password (Hashed, for storage)
// ============================================================================

/// Hashed user password for database storage
///
/// Stores password in Argon2id PHC string format.
/// Safe to store in database and logs.
#[derive(Clone, PartialEq, Eq)]
pub struct UserPassword(HashedPassword);

impl UserPassword {
    /// Create from raw password by hashing
    ///
    /// ## Arguments
    /// * `raw` - The validated raw password
    /// * `pepper` - Optional application-wide secret
    ///
    /// ## Returns
    /// Hashed password ready for storage
    pub fn from_raw(raw: &RawPassword, pepper: Option<&[u8]>) -> AppResult<Self> {
        let hashed = raw.inner().hash(pepper).map_err(|e| match e {
            PasswordHashError::HashingFailed(msg) => {
                AppError::internal(format!("Password hashing failed: {}", msg))
            }
            _ => AppError::internal("Unexpected error during password hashing"),
        })?;

        Ok(Self(hashed))
    }

    /// Create from PHC string (from database)
    ///
    /// ## Arguments
    /// * `phc_string` - PHC-formatted hash string from database
    pub fn from_phc_string(phc_string: impl Into<String>) -> AppResult<Self> {
        let hashed = HashedPassword::from_phc_string(phc_string).map_err(|_| {
            AppError::new(
                ErrorKind::InternalServerError,
                "Invalid password hash in database",
            )
        })?;

        Ok(Self(hashed))
    }

    /// Get PHC string for database storage
    pub fn as_phc_string(&self) -> &str {
        self.0.as_phc_string()
    }

    /// Verify a raw password against this hash
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// ## Arguments
    /// * `raw` - The raw password to verify
    /// * `pepper` - Must match the pepper used during hashing
    pub fn verify(&self, raw: &RawPassword, pepper: Option<&[u8]>) -> bool {
        self.0.verify(raw.inner(), pepper)
    }

    /// Check if password hash needs to be updated
    ///
    /// Returns true if using outdated algorithm/parameters
    pub fn needs_rehash(&self) -> bool {
        self.0.needs_rehash()
    }
}

impl fmt::Debug for UserPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserPassword")
            .field("hash", &"[HASH]")
            .finish()
    }
}

impl fmt::Display for UserPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[HASHED_PASSWORD]")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_password_validation() {
        // Valid password
        assert!(RawPassword::new("ValidPass123!".to_string()).is_ok());

        // Too short
        use platform::password::MIN_PASSWORD_LENGTH;
        let short_pass = "a".repeat(MIN_PASSWORD_LENGTH - 1);
        assert!(RawPassword::new(short_pass).is_err());

        // Too long
        use platform::password::MAX_PASSWORD_LENGTH;
        let long_pass = "a".repeat(MAX_PASSWORD_LENGTH);
        assert!(RawPassword::new(long_pass).is_err());

        // Common pattern
        assert!(RawPassword::new("password123".to_string()).is_err());

        // Empty
        assert!(RawPassword::new("".to_string()).is_err());
    }

    #[test]
    fn test_hash_and_verify() {
        let raw = RawPassword::new("TestPassword123!".to_string()).unwrap();
        let hashed = UserPassword::from_raw(&raw, None).unwrap();

        // Correct password should verify
        assert!(hashed.verify(&raw, None));

        // Wrong password should not verify
        let wrong = RawPassword::new("WrongPassword123!".to_string()).unwrap();
        assert!(!hashed.verify(&wrong, None));
    }

    #[test]
    fn test_hash_with_pepper() {
        let raw = RawPassword::new("TestPassword123!".to_string()).unwrap();
        let pepper = b"app_secret_pepper";
        let hashed = UserPassword::from_raw(&raw, Some(pepper)).unwrap();

        // With correct pepper
        assert!(hashed.verify(&raw, Some(pepper)));

        // Without pepper
        assert!(!hashed.verify(&raw, None));

        // With wrong pepper
        assert!(!hashed.verify(&raw, Some(b"wrong")));
    }

    #[test]
    fn test_phc_string_roundtrip() {
        let raw = RawPassword::new("TestPassword123!".to_string()).unwrap();
        let hashed = UserPassword::from_raw(&raw, None).unwrap();

        let phc = hashed.as_phc_string().to_string();
        let restored = UserPassword::from_phc_string(phc).unwrap();

        assert!(restored.verify(&raw, None));
    }

    #[test]
    fn test_debug_redaction() {
        let raw = RawPassword::new("SecretPassword123!".to_string()).unwrap();
        let debug = format!("{:?}", raw);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("Secret"));

        let hashed = UserPassword::from_raw(&raw, None).unwrap();
        let debug = format!("{:?}", hashed);
        assert!(debug.contains("HASH"));
    }

    #[test]
    fn test_unicode_password() {
        // Unicode passwords should work
        let raw = RawPassword::new("最も！！安全なパスワード".to_string()).unwrap();
        let hashed = UserPassword::from_raw(&raw, None).unwrap();
        assert!(hashed.verify(&raw, None));
    }

    #[test]
    fn test_long_password() {
        // Long passwords within limit should work
        let long_pass = format!("A1!{}", "a".repeat(100));
        let raw = RawPassword::new(long_pass).unwrap();
        let hashed = UserPassword::from_raw(&raw, None).unwrap();
        assert!(hashed.verify(&raw, None));
    }
}
