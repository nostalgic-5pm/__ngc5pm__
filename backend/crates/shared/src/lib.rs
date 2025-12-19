//! Shared Kernel - Domain-crossing minimal core
//!
//! This crate contains the "smallest core" of domain vocabulary:
//! - Common error types and result aliases
//! - Common primitive value objects (ID types, etc.)
//! - Cross-cutting validation rules
//!
//! **Design Principle**: Only include things that are "hard to change"
//! and have consistent meaning across all domains.

pub mod error {
    pub mod app_error;
    pub mod conversions;
    pub mod kind;
}
pub mod id;
