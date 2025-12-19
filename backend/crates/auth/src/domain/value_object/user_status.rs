//! User Status Value Objects
//!
//! Simplified user status management for individual development.
//!
//! ## Design Decisions
//! - **3 statuses only**: Active, Disabled, Memorial
//! - **No soft delete**: Deleted/Archived are anti-patterns that complicate queries
//! - **DisabledReason**: Separate enum to track why a user is disabled
//! - **DisabledUntil**: Optional timestamp for temporary suspensions
//!
//! ## Migration from complex statuses
//! - Locked, Deactivated, Suspended → Disabled (with appropriate reason)
//! - Deleted → Physical delete or archive to separate table
//! - Archived → Physical delete or archive to separate table

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// UserStatus - Core status enum (simplified)
// ============================================================================

/// User account status
///
/// Intentionally kept simple with only 3 states:
/// - **Active**: Normal, fully functional account
/// - **Disabled**: Account is disabled (see DisabledReason for details)
/// - **Memorial**: Memorialized account (deceased user, preserved permanently)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(i16)]
pub enum UserStatus {
    /// Normal active account - can login and use all features
    #[default]
    Active = 0,

    /// Disabled account - cannot login, check DisabledReason for details
    Disabled = 1,

    /// Memorial account - preserved for deceased users, cannot be modified
    Memorial = 2,
}

impl UserStatus {
    /// Get numeric ID for database storage
    #[inline]
    pub const fn id(&self) -> i16 {
        *self as i16
    }

    /// Get string code for serialization/API
    #[inline]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Memorial => "memorial",
        }
    }

    /// Check if login is allowed
    #[inline]
    pub const fn can_login(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if account can be modified
    #[inline]
    pub const fn can_modify(&self) -> bool {
        matches!(self, Self::Active | Self::Disabled)
    }

    /// Check if this is a terminal state (cannot transition out)
    #[inline]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Memorial)
    }

    /// Create from numeric ID
    #[inline]
    pub fn from_id(id: i16) -> Option<Self> {
        match id {
            0 => Some(Self::Active),
            1 => Some(Self::Disabled),
            2 => Some(Self::Memorial),
            _ => None,
        }
    }

    /// Create from string code
    #[inline]
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            "memorial" => Some(Self::Memorial),
            _ => None,
        }
    }
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

// ============================================================================
// DisabledReason - Why the account is disabled
// ============================================================================

/// Reason for account being disabled
///
/// Stored separately from UserStatus to provide context for disabled accounts.
/// Only relevant when `UserStatus == Disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i16)]
pub enum DisabledReason {
    /// User voluntarily deactivated their account
    UserRequested = 0,

    /// Account locked due to security concerns (e.g., suspicious activity)
    SecurityLock = 1,

    /// Temporarily suspended by admin (e.g., policy violation)
    AdminSuspension = 2,

    /// Too many failed login attempts
    TooManyFailedAttempts = 3,

    /// Email not verified within required timeframe
    EmailNotVerified = 4,

    /// Other administrative reason
    AdminOther = 99,
}

impl DisabledReason {
    /// Get numeric ID for database storage
    #[inline]
    pub const fn id(&self) -> i16 {
        *self as i16
    }

    /// Get string code for serialization/API
    #[inline]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UserRequested => "user_requested",
            Self::SecurityLock => "security_lock",
            Self::AdminSuspension => "admin_suspension",
            Self::TooManyFailedAttempts => "too_many_failed_attempts",
            Self::EmailNotVerified => "email_not_verified",
            Self::AdminOther => "admin_other",
        }
    }

    /// Check if this is a user-initiated disable
    #[inline]
    pub const fn is_user_initiated(&self) -> bool {
        matches!(self, Self::UserRequested)
    }

    /// Check if this is automatically recoverable (e.g., by verifying email)
    #[inline]
    pub const fn is_auto_recoverable(&self) -> bool {
        matches!(self, Self::TooManyFailedAttempts | Self::EmailNotVerified)
    }

    /// Check if admin intervention is required to recover
    #[inline]
    pub const fn requires_admin_review(&self) -> bool {
        matches!(
            self,
            Self::SecurityLock | Self::AdminSuspension | Self::AdminOther
        )
    }

    /// Get user-facing message for this reason
    #[inline]
    pub const fn user_message(&self) -> &'static str {
        match self {
            Self::UserRequested => "Your account has been deactivated at your request.",
            Self::SecurityLock => {
                "Your account has been locked for security reasons. Please contact support."
            }
            Self::AdminSuspension => {
                "Your account has been suspended. Please contact support for details."
            }
            Self::TooManyFailedAttempts => {
                "Your account has been temporarily locked due to too many failed login attempts."
            }
            Self::EmailNotVerified => "Please verify your email address to activate your account.",
            Self::AdminOther => "Your account has been disabled. Please contact support.",
        }
    }

    /// Create from numeric ID
    #[inline]
    pub fn from_id(id: i16) -> Option<Self> {
        match id {
            0 => Some(Self::UserRequested),
            1 => Some(Self::SecurityLock),
            2 => Some(Self::AdminSuspension),
            3 => Some(Self::TooManyFailedAttempts),
            4 => Some(Self::EmailNotVerified),
            99 => Some(Self::AdminOther),
            _ => None,
        }
    }

    /// Create from string code
    #[inline]
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "user_requested" => Some(Self::UserRequested),
            "security_lock" => Some(Self::SecurityLock),
            "admin_suspension" => Some(Self::AdminSuspension),
            "too_many_failed_attempts" => Some(Self::TooManyFailedAttempts),
            "email_not_verified" => Some(Self::EmailNotVerified),
            "admin_other" => Some(Self::AdminOther),
            _ => None,
        }
    }
}

impl fmt::Display for DisabledReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // UserStatus tests
    mod user_status {
        use super::*;

        #[test]
        fn test_from_id() {
            assert_eq!(UserStatus::from_id(0), Some(UserStatus::Active));
            assert_eq!(UserStatus::from_id(1), Some(UserStatus::Disabled));
            assert_eq!(UserStatus::from_id(2), Some(UserStatus::Memorial));
            assert_eq!(UserStatus::from_id(99), None);
        }

        #[test]
        fn test_from_code() {
            assert_eq!(UserStatus::from_code("active"), Some(UserStatus::Active));
            assert_eq!(
                UserStatus::from_code("disabled"),
                Some(UserStatus::Disabled)
            );
            assert_eq!(
                UserStatus::from_code("memorial"),
                Some(UserStatus::Memorial)
            );
            assert_eq!(UserStatus::from_code("invalid"), None);
        }

        #[test]
        fn test_display() {
            assert_eq!(UserStatus::Active.to_string(), "active");
            assert_eq!(UserStatus::Disabled.to_string(), "disabled");
            assert_eq!(UserStatus::Memorial.to_string(), "memorial");
        }

        #[test]
        fn test_can_login() {
            assert!(UserStatus::Active.can_login());
            assert!(!UserStatus::Disabled.can_login());
            assert!(!UserStatus::Memorial.can_login());
        }

        #[test]
        fn test_can_modify() {
            assert!(UserStatus::Active.can_modify());
            assert!(UserStatus::Disabled.can_modify());
            assert!(!UserStatus::Memorial.can_modify());
        }

        #[test]
        fn test_is_terminal() {
            assert!(!UserStatus::Active.is_terminal());
            assert!(!UserStatus::Disabled.is_terminal());
            assert!(UserStatus::Memorial.is_terminal());
        }

        #[test]
        fn test_default() {
            assert_eq!(UserStatus::default(), UserStatus::Active);
        }
    }

    // DisabledReason tests
    mod disabled_reason {
        use super::*;

        #[test]
        fn test_from_id() {
            assert_eq!(
                DisabledReason::from_id(0),
                Some(DisabledReason::UserRequested)
            );
            assert_eq!(
                DisabledReason::from_id(1),
                Some(DisabledReason::SecurityLock)
            );
            assert_eq!(
                DisabledReason::from_id(2),
                Some(DisabledReason::AdminSuspension)
            );
            assert_eq!(
                DisabledReason::from_id(3),
                Some(DisabledReason::TooManyFailedAttempts)
            );
            assert_eq!(
                DisabledReason::from_id(4),
                Some(DisabledReason::EmailNotVerified)
            );
            assert_eq!(
                DisabledReason::from_id(99),
                Some(DisabledReason::AdminOther)
            );
            assert_eq!(DisabledReason::from_id(50), None);
        }

        #[test]
        fn test_from_code() {
            assert_eq!(
                DisabledReason::from_code("user_requested"),
                Some(DisabledReason::UserRequested)
            );
            assert_eq!(
                DisabledReason::from_code("security_lock"),
                Some(DisabledReason::SecurityLock)
            );
            assert_eq!(DisabledReason::from_code("invalid"), None);
        }

        #[test]
        fn test_display() {
            assert_eq!(DisabledReason::UserRequested.to_string(), "user_requested");
            assert_eq!(DisabledReason::SecurityLock.to_string(), "security_lock");
        }

        #[test]
        fn test_is_user_initiated() {
            assert!(DisabledReason::UserRequested.is_user_initiated());
            assert!(!DisabledReason::SecurityLock.is_user_initiated());
            assert!(!DisabledReason::AdminSuspension.is_user_initiated());
        }

        #[test]
        fn test_is_auto_recoverable() {
            assert!(!DisabledReason::UserRequested.is_auto_recoverable());
            assert!(!DisabledReason::SecurityLock.is_auto_recoverable());
            assert!(DisabledReason::TooManyFailedAttempts.is_auto_recoverable());
            assert!(DisabledReason::EmailNotVerified.is_auto_recoverable());
        }

        #[test]
        fn test_requires_admin_review() {
            assert!(!DisabledReason::UserRequested.requires_admin_review());
            assert!(DisabledReason::SecurityLock.requires_admin_review());
            assert!(DisabledReason::AdminSuspension.requires_admin_review());
            assert!(DisabledReason::AdminOther.requires_admin_review());
        }

        #[test]
        fn test_user_message_not_empty() {
            assert!(!DisabledReason::UserRequested.user_message().is_empty());
            assert!(!DisabledReason::SecurityLock.user_message().is_empty());
            assert!(!DisabledReason::AdminSuspension.user_message().is_empty());
            assert!(
                !DisabledReason::TooManyFailedAttempts
                    .user_message()
                    .is_empty()
            );
            assert!(!DisabledReason::EmailNotVerified.user_message().is_empty());
            assert!(!DisabledReason::AdminOther.user_message().is_empty());
        }
    }
}
