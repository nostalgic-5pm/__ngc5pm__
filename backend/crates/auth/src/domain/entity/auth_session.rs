//! Auth Session Entity
//!
//! Represents an authenticated user session.
//! Stored in database with cookie-based token reference.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::domain::value_object::{public_id::PublicId, user_id::UserId, user_role::UserRole};

/// Auth session entity
#[derive(Debug, Clone)]
pub struct AuthSession {
    /// Session ID (UUID v4)
    pub session_id: Uuid,
    /// Reference to User
    pub user_id: UserId,
    /// Public ID for API responses
    pub public_id: PublicId,
    /// User role at session creation
    pub user_role: UserRole,
    /// Session expiration (Unix timestamp ms)
    pub expires_at_ms: i64,
    /// Whether "Remember Me" was checked
    pub remember_me: bool,
    /// Client fingerprint hash (User-Agent based)
    pub client_fingerprint_hash: Vec<u8>,
    /// Client IP (optional, for logging)
    pub client_ip: Option<String>,
    /// User agent string (for session management display)
    pub user_agent: Option<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity_at: DateTime<Utc>,
}

impl AuthSession {
    /// Create a new auth session
    ///
    /// TTL is provided by the application layer (config), not hard-coded here.
    pub fn new(
        user_id: UserId,
        public_id: PublicId,
        user_role: UserRole,
        remember_me: bool,
        fingerprint_hash: Vec<u8>,
        client_ip: Option<String>,
        user_agent: Option<String>,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();

        Self {
            session_id: Uuid::new_v4(),
            user_id,
            public_id,
            user_role,
            expires_at_ms: (now + ttl).timestamp_millis(),
            remember_me,
            client_fingerprint_hash: fingerprint_hash,
            client_ip,
            user_agent,
            created_at: now,
            last_activity_at: now,
        }
    }

    /// Check if session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp_millis() > self.expires_at_ms
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity_at = Utc::now();
    }

    /// Get remaining time until expiration
    pub fn remaining_ms(&self) -> i64 {
        let now_ms = Utc::now().timestamp_millis();
        (self.expires_at_ms - now_ms).max(0)
    }

    /// Extend session if "Remember Me" is enabled
    ///
    /// The extension policy is intentionally simple:
    /// - only applies to remember_me sessions
    /// - extend to (now + ttl_long) when remaining time falls below half of ttl_long
    pub fn extend_if_needed(&mut self, ttl_long: Duration) {
        if !self.remember_me {
            return;
        }

        let now = Utc::now();
        let new_expires = (now + ttl_long).timestamp_millis();

        // Only extend if less than half the TTL remains
        if self.expires_at_ms < (now + (ttl_long / 2)).timestamp_millis() {
            self.expires_at_ms = new_expires;
        }
    }
}

/// Session info for API responses (non-sensitive)
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: Uuid,
    pub user_agent: Option<String>,
    pub client_ip: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub is_current: bool,
}

impl From<&AuthSession> for SessionInfo {
    fn from(session: &AuthSession) -> Self {
        Self {
            session_id: session.session_id,
            user_agent: session.user_agent.clone(),
            client_ip: session.client_ip.clone(),
            created_at: session.created_at,
            last_activity_at: session.last_activity_at,
            is_current: false, // Set by caller
        }
    }
}
