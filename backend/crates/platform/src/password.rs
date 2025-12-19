//! Password Hashing and Verification
//!
//! NIST SP 800-63B compliant password handling with:
//! - Argon2id hashing (memory-hard, recommended by OWASP)
//! - Zeroization of sensitive data
//! - Constant-time comparison
//! - Optional HIBP (Have I Been Pwned) breach checking
//!
//! ## Security Features
//! - Memory-hard hashing prevents GPU/ASIC attacks
//! - Zeroization prevents memory inspection attacks
//! - Pepper support for additional security layer
//! - k-Anonymity model for breach checking (only SHA-1 prefix sent)

use std::fmt;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::rngs::OsRng;
use sha1::{Digest, Sha1};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// Constants (NIST SP 800-63B compliant)
// ============================================================================

/// Minimum password length (NIST: SHALL be at least 8)
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Maximum password length (NIST: SHOULD permit at least 64)
pub const MAX_PASSWORD_LENGTH: usize = 128;

/// HIBP API endpoint (k-Anonymity model)
const HIBP_API_URL: &str = "https://api.pwnedpasswords.com/range/";

// ============================================================================
// Error Types
// ============================================================================

/// Password policy violation errors
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PasswordPolicyError {
    /// Password is too short
    #[error("Password must be at least {min} characters (got {actual})")]
    TooShort { min: usize, actual: usize },

    /// Password is too long
    #[error("Password must be at most {max} characters (got {actual})")]
    TooLong { max: usize, actual: usize },

    /// Password has been compromised in a data breach
    #[error("This password has been compromised in a data breach")]
    Compromised,

    /// Password contains only whitespace
    #[error("Password cannot be empty or contain only whitespace")]
    EmptyOrWhitespace,

    /// Password contains invalid characters (control characters)
    #[error("Password contains invalid control characters")]
    InvalidCharacter,

    /// Password matches common patterns (sequential, repeated)
    #[error("Password is too common or follows a predictable pattern")]
    CommonPattern,
}

/// Password hashing/verification errors
#[derive(Debug, Error)]
pub enum PasswordHashError {
    /// Hashing operation failed
    #[error("Password hashing failed: {0}")]
    HashingFailed(String),

    /// Invalid hash format
    #[error("Invalid password hash format")]
    InvalidHashFormat,

    /// HIBP API check failed (non-fatal, logged)
    #[error("Breach check failed: {0}")]
    BreachCheckFailed(String),
}

// ============================================================================
// Clear Text Password (Zeroized on drop)
// ============================================================================

/// Clear text password with automatic memory zeroization
///
/// This type ensures that password data is securely erased from memory
/// when the value is dropped, preventing memory inspection attacks.
///
/// ## Security
/// - Implements `Zeroize` and `ZeroizeOnDrop`
/// - Does not implement `Clone` to prevent accidental copies
/// - Debug output is redacted
///
/// ## Examples
/// ```rust
/// use platform::password::ClearTextPassword;
///
/// let password = ClearTextPassword::new("my_secure_password".to_string())?;
/// // Password is automatically zeroized when dropped
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClearTextPassword(String);

impl ClearTextPassword {
    /// Create a new clear text password with validation
    ///
    /// Validates against NIST SP 800-63B requirements:
    /// - Minimum 8 characters
    /// - Maximum 128 characters
    /// - No control characters
    /// - Not empty/whitespace only
    ///
    /// Unicode is normalized using NFKC before validation.
    pub fn new(raw: String) -> Result<Self, PasswordPolicyError> {
        // NIST: Unicode NFKC normalization before processing
        let normalized: String = raw.nfkc().collect();

        // Check for empty or whitespace-only
        let trimmed = normalized.trim();
        if trimmed.is_empty() {
            return Err(PasswordPolicyError::EmptyOrWhitespace);
        }

        // NIST: Count Unicode code points (not bytes)
        let char_count = normalized.chars().count();

        // NIST: SHALL be at least [`MIN_PASSWORD_LENGTH`] characters
        if char_count < MIN_PASSWORD_LENGTH {
            return Err(PasswordPolicyError::TooShort {
                min: MIN_PASSWORD_LENGTH,
                actual: char_count,
            });
        }

        // NIST: SHOULD permit at least [`MAX_PASSWORD_LENGTH`]  characters
        if char_count > MAX_PASSWORD_LENGTH {
            return Err(PasswordPolicyError::TooLong {
                max: MAX_PASSWORD_LENGTH,
                actual: char_count,
            });
        }

        // Check for control characters (except space, tab, newline)
        for ch in normalized.chars() {
            if ch.is_control() && ch != ' ' && ch != '\t' && ch != '\n' {
                return Err(PasswordPolicyError::InvalidCharacter);
            }
        }

        // Check for common weak patterns
        if is_common_pattern(&normalized) {
            return Err(PasswordPolicyError::CommonPattern);
        }

        Ok(Self(normalized))
    }

    /// Create without validation (for testing or trusted input)
    ///
    /// ## Safety
    /// Only use this for testing or when password has already been validated
    #[cfg(test)]
    pub fn new_unchecked(raw: String) -> Self {
        Self(raw)
    }

    /// Get the password as bytes for hashing
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Hash the password using Argon2id
    ///
    /// ## Arguments
    /// * `pepper` - Optional application-wide secret for additional security
    ///
    /// ## Returns
    /// PHC-formatted hash string wrapped in `HashedPassword`
    pub fn hash(&self, pepper: Option<&[u8]>) -> Result<HashedPassword, PasswordHashError> {
        // Combine password with pepper if provided
        let password_bytes = match pepper {
            Some(p) => {
                let mut combined = self.as_bytes().to_vec();
                combined.extend_from_slice(p);
                combined
            }
            None => self.as_bytes().to_vec(),
        };

        // Generate random salt (128 bits = 16 bytes)
        let salt = SaltString::generate(OsRng);

        // OWASP recommended Argon2id parameters:
        // m=19456 (19 MiB), t=2, p=1
        let argon2 = Argon2::default();

        let hash = argon2
            .hash_password(&password_bytes, &salt)
            .map_err(|e| PasswordHashError::HashingFailed(e.to_string()))?;

        Ok(HashedPassword {
            hash: hash.to_string(),
        })
    }

    /// Check if password has been compromised using HIBP API
    ///
    /// Uses k-Anonymity model:
    /// 1. Hash password with SHA-1
    /// 2. Send only first 5 characters of hash
    /// 3. Check if full hash appears in response
    ///
    /// ## Returns
    /// - `Ok(true)` if password is compromised
    /// - `Ok(false)` if password is not found in breaches
    /// - `Err(_)` if API check failed (should be treated as non-blocking)
    pub async fn check_breach(&self) -> Result<bool, PasswordHashError> {
        // SHA-1 hash of password (uppercase hex)
        let mut hasher = Sha1::new();
        hasher.update(self.as_bytes());
        let hash = hasher.finalize();
        let hash_hex = hex_encode_upper(&hash);

        // k-Anonymity: send only first 5 chars
        let prefix = &hash_hex[..5];
        let suffix = &hash_hex[5..];

        // Query HIBP API
        let url = format!("{}{}", HIBP_API_URL, prefix);
        let response = reqwest::get(&url)
            .await
            .map_err(|e| PasswordHashError::BreachCheckFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(PasswordHashError::BreachCheckFailed(format!(
                "API returned status: {}",
                response.status()
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| PasswordHashError::BreachCheckFailed(e.to_string()))?;

        // Check if our hash suffix appears in response
        // Format: SUFFIX:COUNT\r\n
        for line in body.lines() {
            if let Some((hash_suffix, _count)) = line.split_once(':') {
                if hash_suffix.eq_ignore_ascii_case(suffix) {
                    return Ok(true); // Password is compromised
                }
            }
        }

        Ok(false) // Password not found in breaches
    }
}

impl fmt::Debug for ClearTextPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClearTextPassword")
            .field(&"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Hashed Password (Safe to store)
// ============================================================================

/// Hashed password in PHC string format
///
/// This type stores the Argon2id hash in PHC format, which includes:
/// - Algorithm identifier
/// - Version
/// - Parameters (memory, iterations, parallelism)
/// - Salt
/// - Hash
///
/// ## Examples
/// ```rust
/// use platform::password::{ClearTextPassword, HashedPassword};
///
/// let password = ClearTextPassword::new("my_secure_password".to_string())?;
/// let hashed = password.hash(None)?;
///
/// // Later, verify
/// assert!(hashed.verify(&password, None));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct HashedPassword {
    hash: String,
}

impl HashedPassword {
    /// Create from PHC string (e.g., from database)
    pub fn from_phc_string(s: impl Into<String>) -> Result<Self, PasswordHashError> {
        let hash = s.into();

        // Validate it's a valid PHC string
        PasswordHash::new(&hash).map_err(|_| PasswordHashError::InvalidHashFormat)?;

        Ok(Self { hash })
    }

    /// Get the PHC string for storage
    pub fn as_phc_string(&self) -> &str {
        &self.hash
    }

    /// Verify a password against this hash
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// ## Arguments
    /// * `password` - The clear text password to verify
    /// * `pepper` - Optional pepper (must match the one used during hashing)
    pub fn verify(&self, password: &ClearTextPassword, pepper: Option<&[u8]>) -> bool {
        let password_bytes = match pepper {
            Some(p) => {
                let mut combined = password.as_bytes().to_vec();
                combined.extend_from_slice(p);
                combined
            }
            None => password.as_bytes().to_vec(),
        };

        let parsed_hash = match PasswordHash::new(&self.hash) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let argon2 = Argon2::default();

        // Argon2 uses constant-time comparison internally
        argon2
            .verify_password(&password_bytes, &parsed_hash)
            .is_ok()
    }

    /// Check if the hash needs to be rehashed (e.g., parameters changed)
    ///
    /// Returns true if the hash uses outdated parameters
    pub fn needs_rehash(&self) -> bool {
        let parsed_hash = match PasswordHash::new(&self.hash) {
            Ok(h) => h,
            Err(_) => return true,
        };

        // Check if algorithm is Argon2id
        if parsed_hash.algorithm != argon2::Algorithm::Argon2id.ident() {
            return true;
        }

        // Could add parameter version checking here
        false
    }
}

impl fmt::Debug for HashedPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashedPassword")
            .field("hash", &"[HASH]")
            .finish()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check for common weak patterns
fn is_common_pattern(password: &str) -> bool {
    let lower = password.to_lowercase();

    // Check for all same character (e.g., "aaaaaaaa")
    let chars: Vec<char> = lower.chars().collect();
    if chars.len() >= 3 && chars.windows(3).all(|w| w[0] == w[1] && w[1] == w[2]) {
        if chars.iter().all(|&c| c == chars[0]) {
            return true;
        }
    }

    // Check for sequential numbers (e.g., "12345678")
    if is_sequential_numbers(&lower) {
        return true;
    }

    // Check for keyboard patterns
    const KEYBOARD_PATTERNS: &[&str] = &[
        "qwerty",
        "qwertyuiop",
        "asdfgh",
        "asdfghjkl",
        "zxcvbn",
        "qazwsx",
        "1qaz2wsx",
    ];

    for pattern in KEYBOARD_PATTERNS {
        if lower.contains(pattern) {
            return true;
        }
    }

    // Check for extremely common passwords
    const COMMON_PASSWORDS: &[&str] = &[
        "password",
        "password1",
        "password123",
        "12345678",
        "123456789",
        "1234567890",
        "abcdefgh",
        "letmein",
        "welcome",
        "admin123",
        "iloveyou",
        "sunshine",
        "princess",
        "football",
        "monkey",
        "shadow",
        "master",
        "dragon",
        "baseball",
        "michael",
        "trustno1",
    ];

    COMMON_PASSWORDS.contains(&lower.as_str())
}

/// Check if string is sequential numbers
fn is_sequential_numbers(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();

    if digits.len() < 4 {
        return false;
    }

    // Check ascending
    let is_ascending = digits
        .windows(2)
        .all(|w| w[1] == w[0] + 1 || (w[0] == 9 && w[1] == 0));

    // Check descending
    let is_descending = digits
        .windows(2)
        .all(|w| w[0] == w[1] + 1 || (w[0] == 0 && w[1] == 9));

    is_ascending || is_descending
}

/// Encode bytes as uppercase hex string
fn hex_encode_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_too_short() {
        let result = ClearTextPassword::new("short".to_string());
        assert!(matches!(result, Err(PasswordPolicyError::TooShort { .. })));
    }

    #[test]
    fn test_password_too_long() {
        let long_password = "a".repeat(MAX_PASSWORD_LENGTH + 1);
        let result = ClearTextPassword::new(long_password);
        assert!(matches!(result, Err(PasswordPolicyError::TooLong { .. })));
    }

    #[test]
    fn test_password_empty() {
        let result = ClearTextPassword::new("".to_string());
        assert!(matches!(
            result,
            Err(PasswordPolicyError::EmptyOrWhitespace)
        ));
    }

    #[test]
    fn test_password_whitespace_only() {
        let result = ClearTextPassword::new("        ".to_string());
        assert!(matches!(
            result,
            Err(PasswordPolicyError::EmptyOrWhitespace)
        ));
    }

    #[test]
    fn test_password_common_pattern() {
        let result = ClearTextPassword::new("password123".to_string());
        assert!(matches!(result, Err(PasswordPolicyError::CommonPattern)));

        let result = ClearTextPassword::new("qwertyuiop".to_string());
        assert!(matches!(result, Err(PasswordPolicyError::CommonPattern)));

        let result = ClearTextPassword::new("12345678".to_string());
        assert!(matches!(result, Err(PasswordPolicyError::CommonPattern)));
    }

    #[test]
    fn test_valid_password() {
        let result = ClearTextPassword::new("MySecure#Pass2024!".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_unicode_password() {
        // Unicode passwords should work
        let result = ClearTextPassword::new("パスワード安全です!".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_and_verify() {
        let password = ClearTextPassword::new_unchecked("TestPassword123!".to_string());
        let hashed = password.hash(None).unwrap();

        // Correct password should verify
        assert!(hashed.verify(&password, None));

        // Wrong password should not verify
        let wrong_password = ClearTextPassword::new_unchecked("WrongPassword123!".to_string());
        assert!(!hashed.verify(&wrong_password, None));
    }

    #[test]
    fn test_hash_with_pepper() {
        let password = ClearTextPassword::new_unchecked("TestPassword123!".to_string());
        let pepper = b"my_secret_pepper";
        let hashed = password.hash(Some(pepper)).unwrap();

        // Correct password with correct pepper
        assert!(hashed.verify(&password, Some(pepper)));

        // Correct password without pepper should fail
        assert!(!hashed.verify(&password, None));

        // Correct password with wrong pepper should fail
        assert!(!hashed.verify(&password, Some(b"wrong_pepper")));
    }

    #[test]
    fn test_phc_string_roundtrip() {
        let password = ClearTextPassword::new_unchecked("TestPassword123!".to_string());
        let hashed = password.hash(None).unwrap();

        let phc_string = hashed.as_phc_string().to_string();
        let restored = HashedPassword::from_phc_string(phc_string).unwrap();

        assert!(restored.verify(&password, None));
    }

    #[test]
    fn test_invalid_phc_string() {
        let result = HashedPassword::from_phc_string("not_a_valid_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_redaction() {
        let password = ClearTextPassword::new_unchecked("secret".to_string());
        let debug_output = format!("{:?}", password);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains("secret"));
    }

    #[test]
    fn test_hex_encode_upper() {
        let bytes = [0xab, 0xcd, 0xef];
        assert_eq!(hex_encode_upper(&bytes), "ABCDEF");
    }
}
