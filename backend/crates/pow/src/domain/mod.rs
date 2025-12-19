//! Domain Layer - Business logic and entities
//!
//! This layer contains:
//! - Domain entities (Challenge, PowSession)
//! - Domain value objects (ClientFingerprint, Difficulty)
//! - Domain services (PoW verification logic)
//! - Repository traits (interfaces)

pub mod entities;
pub mod services;
pub mod repository;
pub mod value_objects;
