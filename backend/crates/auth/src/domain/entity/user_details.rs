//! User Details Entity
//!
//! Extended profile and contact information for users.
//! Separated from core User entity for:
//! - Keeping auth queries fast (no extra columns)
//! - Easy extension with new profile fields
//! - GDPR compliance (easy to delete profile data)

use chrono::{DateTime, Utc};

use crate::domain::value_object::{email::Email, user_id::UserId};

/// User details entity
///
/// Contains optional profile and contact information:
/// - Email (for contact/recovery)
/// - Display name
/// - Personal info (future)
#[derive(Debug, Clone)]
pub struct UserDetails {
    /// Reference to User
    pub user_id: UserId,
    /// Contact email (optional for regular users, required for moderators+)
    pub email: Option<Email>,
    /// Whether email has been verified
    pub email_verified: bool,
    /// Display name (separate from user_name handle)
    pub display_name: Option<String>,
    /// First name (future use)
    pub first_name: Option<String>,
    /// Last name (future use)
    pub last_name: Option<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl UserDetails {
    /// Create new empty user details
    pub fn new(user_id: UserId) -> Self {
        let now = Utc::now();
        Self {
            user_id,
            email: None,
            email_verified: false,
            display_name: None,
            first_name: None,
            last_name: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set email address
    pub fn set_email(&mut self, email: Email) {
        self.email = Some(email);
        self.email_verified = false; // Reset verification on change
        self.updated_at = Utc::now();
    }

    /// Clear email address
    pub fn clear_email(&mut self) {
        self.email = None;
        self.email_verified = false;
        self.updated_at = Utc::now();
    }

    /// Mark email as verified
    pub fn verify_email(&mut self) {
        if self.email.is_some() {
            self.email_verified = true;
            self.updated_at = Utc::now();
        }
    }

    /// Set display name
    pub fn set_display_name(&mut self, name: Option<String>) {
        self.display_name = name;
        self.updated_at = Utc::now();
    }

    /// Set personal info
    pub fn set_name(&mut self, first: Option<String>, last: Option<String>) {
        self.first_name = first;
        self.last_name = last;
        self.updated_at = Utc::now();
    }

    /// Check if user has verified email
    pub fn has_verified_email(&self) -> bool {
        self.email.is_some() && self.email_verified
    }
}
