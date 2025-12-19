//! Application Configuration
//!
//! Configuration for the PoW application layer.

use std::time::Duration;

/// Re-export SameSite from platform
pub use platform::cookie::SameSite;

/// PoW application configuration
#[derive(Debug, Clone)]
pub struct PowConfig {
    /// Challenge bytes length
    pub challenge_bytes_len: usize,
    /// Difficulty in leading zero bits
    pub difficulty_bits: u8,
    /// Challenge TTL
    pub challenge_ttl: Duration,
    /// Session TTL
    pub session_ttl: Duration,
    /// Rate limit: max requests per window
    pub rate_limit_max_requests: u32,
    /// Rate limit window
    pub rate_limit_window: Duration,
    /// Cookie name for session
    pub session_cookie_name: String,
    /// Session secret key for HMAC signing (32 bytes)
    pub session_secret: [u8; 32],
    /// Whether to require Secure cookie
    pub cookie_secure: bool,
    /// SameSite policy
    pub cookie_same_site: SameSite,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            challenge_bytes_len: 32,
            difficulty_bits: 23,
            challenge_ttl: Duration::from_secs(120),
            session_ttl: Duration::from_secs(3600),
            rate_limit_max_requests: 10,
            rate_limit_window: Duration::from_secs(60),
            session_cookie_name: "pow_session".to_string(),
            session_secret: [0u8; 32],
            cookie_secure: true,
            cookie_same_site: SameSite::Lax,
        }
    }
}

impl PowConfig {
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

    pub fn challenge_ttl_ms(&self) -> i64 {
        self.challenge_ttl.as_millis() as i64
    }

    pub fn session_ttl_ms(&self) -> i64 {
        self.session_ttl.as_millis() as i64
    }

    pub fn rate_limit_window_ms(&self) -> i64 {
        self.rate_limit_window.as_millis() as i64
    }
}
