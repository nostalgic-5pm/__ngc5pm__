//! Rate Limiting Infrastructure
//!
//! Common rate limiting abstractions and implementations.

use std::time::Duration;

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window
    pub max_requests: u32,
    /// Time window duration
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 10,
            window: Duration::from_secs(60),
        }
    }
}

impl RateLimitConfig {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    pub fn window_ms(&self) -> i64 {
        self.window.as_millis() as i64
    }
}

/// Rate limit check result
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub reset_at_ms: i64,
}

/// Trait for rate limit storage backends
#[trait_variant::make(RateLimitStore: Send)]
pub trait LocalRateLimitStore {
    /// Check and increment rate limit counter
    /// Returns (allowed, remaining_requests)
    async fn check_and_increment(
        &self,
        key: &str,
        config: &RateLimitConfig,
    ) -> Result<RateLimitResult, Box<dyn std::error::Error + Send + Sync>>;
}
