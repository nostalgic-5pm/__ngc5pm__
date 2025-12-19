//! Application Configuration
//!
//! Configuration for the Auth application layer.

use std::time::Duration;

/// Re-export SameSite from platform
pub use platform::cookie::SameSite;

/// Auth application configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Session cookie name
    pub session_cookie_name: String,
    /// Session secret key for HMAC signing (32 bytes)
    pub session_secret: [u8; 32],
    /// Session TTL without "Remember Me" (12 hours)
    pub session_ttl_short: Duration,
    /// Session TTL with "Remember Me" (1 week)
    pub session_ttl_long: Duration,
    /// Whether to require Secure cookie
    pub cookie_secure: bool,
    /// SameSite policy
    pub cookie_same_site: SameSite,
    /// Password pepper (optional, application-wide secret)
    pub password_pepper: Option<Vec<u8>>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_cookie_name: "auth_session".to_string(),
            session_secret: [0u8; 32],
            session_ttl_short: Duration::from_secs(12 * 3600), // 12 hours
            session_ttl_long: Duration::from_secs(7 * 24 * 3600), // 1 week
            cookie_secure: true,
            cookie_same_site: SameSite::Lax,
            password_pepper: None,
        }
    }
}

impl AuthConfig {
    /// Create config with a random session secret (for development)
    pub fn with_random_secret() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        Self {
            session_secret: secret,
            ..Default::default()
        }
    }

    /// Create config for development (insecure cookie)
    pub fn development() -> Self {
        Self {
            cookie_secure: false,
            ..Self::with_random_secret()
        }
    }

    /// Get session TTL in milliseconds
    pub fn session_ttl_short_ms(&self) -> i64 {
        self.session_ttl_short.as_millis() as i64
    }

    /// Get session TTL with Remember Me in milliseconds
    pub fn session_ttl_long_ms(&self) -> i64 {
        self.session_ttl_long.as_millis() as i64
    }

    /// Get password pepper as slice
    pub fn pepper(&self) -> Option<&[u8]> {
        self.password_pepper.as_deref()
    }
}
