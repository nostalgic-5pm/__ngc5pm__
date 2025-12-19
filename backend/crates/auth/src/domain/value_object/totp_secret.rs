//! TOTP Secret Value Object
//!
//! Wraps a TOTP secret for two-factor authentication.
//! Uses Google Authenticator compatible settings.

use kernel::error::app_error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

/// TOTP configuration constants
const TOTP_DIGITS: usize = 6;
const TOTP_STEP: u64 = 30;
const TOTP_ISSUER: &str = "__ngc5pm__";

/// TOTP Secret for two-factor authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    /// Base32-encoded secret
    secret_base32: String,
}

impl TotpSecret {
    /// Generate a new random TOTP secret
    pub fn generate() -> Self {
        let secret = Secret::generate_secret();
        Self {
            secret_base32: secret.to_encoded().to_string(),
        }
    }

    /// Create from a base32-encoded string (from database)
    pub fn from_base32(secret: impl Into<String>) -> AppResult<Self> {
        let secret_str = secret.into();
        // Validate by trying to decode
        Secret::Encoded(secret_str.clone())
            .to_bytes()
            .map_err(|e| AppError::internal(format!("Invalid TOTP secret: {}", e)))?;

        Ok(Self {
            secret_base32: secret_str,
        })
    }

    /// Get the base32-encoded secret for storage
    pub fn as_base32(&self) -> &str {
        &self.secret_base32
    }

    /// Create a TOTP instance for this secret
    fn to_totp(&self, account_name: &str) -> AppResult<TOTP> {
        let secret = Secret::Encoded(self.secret_base32.clone());

        TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            1, // skew (allow 1 step before/after)
            TOTP_STEP,
            secret
                .to_bytes()
                .map_err(|e| AppError::internal(format!("Invalid TOTP secret: {}", e)))?,
            Some(TOTP_ISSUER.to_string()),
            account_name.to_string(),
        )
        .map_err(|e| AppError::internal(format!("Failed to create TOTP: {}", e)))
    }

    /// Verify a TOTP code
    pub fn verify(&self, code: &str, account_name: &str) -> AppResult<bool> {
        let totp = self.to_totp(account_name)?;
        Ok(totp.check_current(code).unwrap_or(false))
    }

    /// Generate current TOTP code (for testing)
    #[cfg(test)]
    pub fn generate_current(&self, account_name: &str) -> AppResult<String> {
        let totp = self.to_totp(account_name)?;
        totp.generate_current()
            .map_err(|e| AppError::internal(format!("Failed to generate TOTP: {}", e)))
    }

    /// Generate QR code as base64-encoded PNG
    pub fn generate_qr_code(&self, account_name: &str) -> AppResult<String> {
        let totp = self.to_totp(account_name)?;
        totp.get_qr_base64()
            .map_err(|e| AppError::internal(format!("Failed to generate QR code: {}", e)))
    }

    /// Get the otpauth:// URL for manual entry
    pub fn get_otpauth_url(&self, account_name: &str) -> AppResult<String> {
        let totp = self.to_totp(account_name)?;
        Ok(totp.get_url())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_secret_generate() {
        let secret = TotpSecret::generate();
        assert!(!secret.as_base32().is_empty());
    }

    #[test]
    fn test_totp_secret_verify() {
        let secret = TotpSecret::generate();
        let account = "test@example.com";

        // Generate current code and verify
        let code = secret.generate_current(account).unwrap();
        assert!(secret.verify(&code, account).unwrap());

        // Wrong code should fail
        assert!(!secret.verify("000000", account).unwrap());
    }

    #[test]
    fn test_totp_secret_from_base32() {
        let secret = TotpSecret::generate();
        let base32 = secret.as_base32().to_string();

        let restored = TotpSecret::from_base32(base32).unwrap();
        assert_eq!(secret.as_base32(), restored.as_base32());
    }

    #[test]
    fn test_totp_qr_code() {
        let secret = TotpSecret::generate();
        let qr = secret.generate_qr_code("test@example.com").unwrap();
        // QR code should be a valid base64 string\
        assert!(!qr.is_empty());
    }
}
