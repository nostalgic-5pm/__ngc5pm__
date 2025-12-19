//! PublicId Value Object
//! THis object is used for public identifiers in the auth domain.
//! It wraps a Nanoid for compact, URL-safe IDs.
//!
//! ## Usage
//! ```rust
//! use auth::domain::value_object::public_id::PublicId;
//!
//! // Create new PublicId
//! let public_id = PublicId::new();
//!
//! // PublicId length is 21 characters
//! assert_eq!(public_id.as_str().len(), 21);
//! ```
use std::str::FromStr;

use kernel::error::app_error::{AppError, AppResult};
use nid::Nanoid;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicId(pub Nanoid);

impl PublicId {
    #[inline]
    pub fn new() -> Self {
        Self(Nanoid::new())
    }

    #[inline]
    pub fn from_nanoid(s: Nanoid) -> Self {
        Self(s)
    }

    #[inline]
    pub fn parse_str(s: &str) -> AppResult<Self> {
        Nanoid::from_str(s)
            .map(PublicId)
            .map_err(|e| AppError::bad_request(format!("Invalid PublicId: {}", e)))
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[inline]
    pub fn into_inner(self) -> Nanoid {
        self.0
    }
}

impl FromStr for PublicId {
    type Err = AppError;

    fn from_str(s: &str) -> AppResult<Self> {
        PublicId::parse_str(s)
    }
}

impl Default for PublicId {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<Nanoid> for PublicId {
    fn as_ref(&self) -> &Nanoid {
        &self.0
    }
}

impl std::fmt::Display for PublicId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_id_new() {
        let public_id = PublicId::new();
        assert_eq!(public_id.as_str().len(), 21); // Default Nanoid length
    }

    #[test]
    fn test_public_id_parse_str() {
        let id_str = "0123456789abcdefghi01"; // 21-char valid Nanoid
        let public_id = PublicId::parse_str(id_str).unwrap();
        assert_eq!(public_id.as_str(), id_str);
    }

    #[test]
    fn test_public_id_parse_str_invalid() {
        let id_str = "invalid_id!@#"; // Invalid Nanoid
        let result = PublicId::parse_str(id_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_id_from_str_trait() {
        let id_str = "0123456789abcdefghi01"; // 21-char valid Nanoid
        let public_id: PublicId = id_str.parse().unwrap();
        assert_eq!(public_id.as_str(), id_str);
    }
}
