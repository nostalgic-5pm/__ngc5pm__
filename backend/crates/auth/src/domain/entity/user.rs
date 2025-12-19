//! User Entity
//!
//! Core user profile entity containing non-sensitive user data.

use chrono::{DateTime, Utc};

use crate::domain::value_object::{
    public_id::PublicId, user_id::UserId, user_name::UserName, user_role::UserRole,
    user_status::UserStatus,
};

/// User entity
///
/// Contains public user profile information.
/// Sensitive auth data is in the Auth entity.
#[derive(Debug, Clone)]
pub struct User {
    /// Internal UUID identifier
    pub user_id: UserId,
    /// Public-facing nanoid identifier (URL-safe)
    pub public_id: PublicId,
    /// User name (unique, for login and display)
    pub user_name: UserName,
    /// Role (User, Moderator, Admin, SuperAdmin)
    pub user_role: UserRole,
    /// Status (Active, Disabled, Memorial)
    pub user_status: UserStatus,
    /// Last successful login time
    pub last_login_at: Option<DateTime<Utc>>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Create a new user
    pub fn new(user_name: UserName) -> Self {
        let now = Utc::now();
        let public_id = PublicId::new();

        Self {
            user_id: UserId::new(),
            public_id,
            user_name,
            user_role: UserRole::default(),
            user_status: UserStatus::default(),
            last_login_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Record successful login
    pub fn record_login(&mut self) {
        let now = Utc::now();
        self.last_login_at = Some(now);
        self.updated_at = now;
    }

    /// Check if user can login
    pub fn can_login(&self) -> bool {
        self.user_status.can_login()
    }

    /// Check if user requires 2FA (Moderator or higher)
    pub fn requires_2fa(&self) -> bool {
        self.user_role.is_moderator_or_higher()
    }

    /// Update user role
    pub fn set_role(&mut self, role: UserRole) {
        self.user_role = role;
        self.updated_at = Utc::now();
    }

    /// Update user status
    pub fn set_status(&mut self, status: UserStatus) {
        self.user_status = status;
        self.updated_at = Utc::now();
    }

    /// Update user name
    pub fn set_user_name(&mut self, user_name: UserName) {
        self.user_name = user_name;
        self.updated_at = Utc::now();
    }
}
