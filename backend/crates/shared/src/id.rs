//! Common ID Types
//!
//! Type-safe ID wrappers for domain entities.

use std::fmt;
use std::marker::PhantomData;
use uuid::Uuid;

/// Generic typed ID wrapper
///
/// Usage:
/// ```
/// use kernel::id::{Id, markers};
/// type UserId = Id<markers::User>;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id<T> {
    value: uuid::Uuid,
    _marker: PhantomData<T>,
}

impl<T> Id<T> {
    /// Create a new random ID (UUID v4)
    pub fn new() -> Self {
        Self {
            value: Uuid::new_v4(),
            _marker: PhantomData,
        }
    }

    /// Create from an existing UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self {
            value: uuid,
            _marker: PhantomData,
        }
    }

    /// Get the underlying UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.value
    }

    /// Convert to UUID
    pub fn into_uuid(self) -> Uuid {
        self.value
    }
}

impl<T> Default for Id<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.value)
    }
}

impl<T> fmt::Display for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<T> From<Uuid> for Id<T> {
    fn from(uuid: Uuid) -> Self {
        Self::from_uuid(uuid)
    }
}

impl<T> From<Id<T>> for Uuid {
    fn from(id: Id<T>) -> Self {
        id.value
    }
}

/// Marker types for different entity IDs
pub mod markers {
    /// Marker for Challenge IDs
    pub struct Challenge;

    /// Marker for PowSession IDs
    pub struct PowSession;
}

/// Type aliases for common IDs
pub type ChallengeId = Id<markers::Challenge>;
pub type PowSessionId = Id<markers::PowSession>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_type_safety() {
        let challenge_id: ChallengeId = Id::new();
        let session_id: PowSessionId = Id::new();

        // These are different types, cannot be mixed
        let _c: Uuid = challenge_id.into_uuid();
        let _s: Uuid = session_id.into_uuid();
    }

    #[test]
    fn test_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let id: ChallengeId = Id::from_uuid(uuid);
        assert_eq!(id.as_uuid(), &uuid);
    }
}
