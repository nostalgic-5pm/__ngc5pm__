//! Auth Entity
//!
//! Authentication credentials for a user.
//! Separated from User entity to isolate sensitive data.

use chrono::{DateTime, Utc};

use crate::domain::value_object::{
    totp_secret::TotpSecret, user_id::UserId, user_password::UserPassword,
};

/// Auth credentials entity
///
/// Contains sensitive authentication data:
/// - Password hash
/// - TOTP secret (for 2FA)
/// - Login failure tracking
#[derive(Debug, Clone)]
pub struct Auth {
    /// Reference to User
    pub user_id: UserId,
    /// Hashed password
    pub password_hash: UserPassword,
    /// TOTP secret for 2FA
    pub totp_secret: Option<TotpSecret>,
    /// Whether TOTP 2FA is enabled and verified
    pub totp_enabled: bool,
    /// Consecutive login failure count
    pub login_failed_count: u16,
    /// Last login failure time
    pub last_failed_at: Option<DateTime<Utc>>,
    /// Account locked until (temporary lockout after failures)
    pub locked_until: Option<DateTime<Utc>>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl Auth {
    /// Maximum login failures before temporary lockout
    pub const MAX_LOGIN_FAILURES: u16 = 5;
    /// Lockout duration in minutes
    pub const LOCKOUT_MINUTES: i64 = 15;

    /// Create new auth credentials
    pub fn new(user_id: UserId, password_hash: UserPassword) -> Self {
        let now = Utc::now();
        Self {
            user_id,
            password_hash,
            totp_secret: None,
            totp_enabled: false,
            login_failed_count: 0,
            last_failed_at: None,
            locked_until: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if account is currently locked
    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            Utc::now() < locked_until
        } else {
            false
        }
    }

    /// Record a failed login attempt
    pub fn record_failure(&mut self) {
        let now = Utc::now();
        self.login_failed_count += 1;
        self.last_failed_at = Some(now);
        self.updated_at = now;

        // Lock account after too many failures
        if self.login_failed_count >= Self::MAX_LOGIN_FAILURES {
            self.locked_until = Some(now + chrono::Duration::minutes(Self::LOCKOUT_MINUTES));
        }
    }

    /// Reset login failure count on successful login
    pub fn reset_failures(&mut self) {
        self.login_failed_count = 0;
        self.last_failed_at = None;
        self.locked_until = None;
        self.updated_at = Utc::now();
    }

    /// Set up TOTP (generates new secret)
    pub fn setup_totp(&mut self) -> TotpSecret {
        let secret = TotpSecret::generate();
        self.totp_secret = Some(secret.clone());
        self.totp_enabled = false; // Not enabled until verified
        self.updated_at = Utc::now();
        secret
    }

    /// Enable TOTP after verification
    pub fn enable_totp(&mut self) {
        if self.totp_secret.is_some() {
            self.totp_enabled = true;
            self.updated_at = Utc::now();
        }
    }

    /// Disable TOTP
    pub fn disable_totp(&mut self) {
        self.totp_secret = None;
        self.totp_enabled = false;
        self.updated_at = Utc::now();
    }

    /// Check if 2FA is required (TOTP is set up and enabled)
    pub fn requires_2fa(&self) -> bool {
        self.totp_enabled && self.totp_secret.is_some()
    }

    /// Update password
    pub fn update_password(&mut self, new_password: UserPassword) {
        self.password_hash = new_password;
        self.updated_at = Utc::now();
    }
}
