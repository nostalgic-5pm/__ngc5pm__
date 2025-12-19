use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(i16)]
pub enum UserRole {
    #[default]
    User = 0,
    Moderator = 1,
    Admin = 2,
    SuperAdmin = 3,
    // Guest: A conceptual UserRole representing an unauthenticated user.
}

impl UserRole {
    #[inline]
    pub const fn id(&self) -> i16 {
        *self as i16
    }

    #[inline]
    pub const fn code(&self) -> &'static str {
        use UserRole::*;
        match self {
            User => "user",
            Moderator => "moderator",
            Admin => "admin",
            SuperAdmin => "super_admin",
        }
    }

    #[inline]
    pub const fn is_moderator_or_higher(&self) -> bool {
        use UserRole::*;
        matches!(self, Moderator | Admin | SuperAdmin)
    }

    #[inline]
    pub const fn is_admin_or_higher(&self) -> bool {
        use UserRole::*;
        matches!(self, Admin | SuperAdmin)
    }

    #[inline]
    pub const fn is_super_admin(&self) -> bool {
        matches!(self, UserRole::SuperAdmin)
    }

    #[inline]
    pub fn from_id(id: i16) -> Self {
        use UserRole::*;
        match id {
            0 => User,
            1 => Moderator,
            2 => Admin,
            3 => SuperAdmin,
            _ => {
                tracing::error!("Invalid UserRole id: {}", id);
                unreachable!("Invalid UserRole id: {}", id)
            }
        }
    }

    #[inline]
    pub fn from_code(code: &str) -> Self {
        use UserRole::*;
        match code {
            "user" => User,
            "moderator" => Moderator,
            "admin" => Admin,
            "super_admin" => SuperAdmin,
            _ => {
                tracing::error!("Invalid UserRole code: {}", code);
                unreachable!("Invalid UserRole code: {}", code)
            }
        }
    }
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_from_id() {
        assert_eq!(UserRole::from_id(0), UserRole::User);
        assert_eq!(UserRole::from_id(1), UserRole::Moderator);
        assert_eq!(UserRole::from_id(2), UserRole::Admin);
        assert_eq!(UserRole::from_id(3), UserRole::SuperAdmin);
    }

    #[test]
    fn test_user_role_from_code() {
        assert_eq!(UserRole::from_code("user"), UserRole::User);
        assert_eq!(UserRole::from_code("moderator"), UserRole::Moderator);
        assert_eq!(UserRole::from_code("admin"), UserRole::Admin);
        assert_eq!(UserRole::from_code("super_admin"), UserRole::SuperAdmin);
    }

    #[test]
    fn test_user_role_display() {
        assert_eq!(UserRole::User.to_string(), "user");
        assert_eq!(UserRole::Moderator.to_string(), "moderator");
        assert_eq!(UserRole::Admin.to_string(), "admin");
        assert_eq!(UserRole::SuperAdmin.to_string(), "super_admin");
    }

    #[test]
    fn test_user_role_checks() {
        assert!(!UserRole::User.is_moderator_or_higher());
        assert!(UserRole::Moderator.is_moderator_or_higher());
        assert!(UserRole::Admin.is_moderator_or_higher());
        assert!(UserRole::SuperAdmin.is_moderator_or_higher());
        assert!(!UserRole::User.is_admin_or_higher());
        assert!(!UserRole::Moderator.is_admin_or_higher());
        assert!(UserRole::Admin.is_admin_or_higher());
        assert!(UserRole::SuperAdmin.is_admin_or_higher());
        assert!(!UserRole::User.is_super_admin());
        assert!(!UserRole::Moderator.is_super_admin());
        assert!(!UserRole::Admin.is_super_admin());
        assert!(UserRole::SuperAdmin.is_super_admin());
    }
}
