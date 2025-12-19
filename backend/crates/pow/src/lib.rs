//! PoW (Proof of Work) Backend Module
//!
//! Clean Architecture structure:
//! - `domain/` - Business logic, entities, repository traits
//! - `application/` - Use cases
//! - `infrastructure/` - Database implementations
//! - `presentation/` - HTTP handlers
//!
//! ## Security Model
//! - Backend is the sole authority for challenge generation, difficulty, TTL, and verification
//! - Client-reported values (elapsedMs, totalHashes) are telemetry only, never trusted
//! - Sessions are HTTP-only cookies bound to User-Agent fingerprint
//! - Challenge consumption is atomic (no double-spend)

pub mod application;
pub mod domain;
pub mod error;
pub mod infra;
pub mod presentation;

// Re-exports for convenience
pub use application::config::PowConfig;
pub use error::{PowError, PowResult};
pub use infra::postgres::PgPowRepository;
pub use presentation::router::pow_router;

// Re-export kernel error types for unified error handling
pub use kernel::error::{
    app_error::{AppError, AppResult, OptionExt, ResultExt},
    kind::ErrorKind,
};

// Legacy compatibility - will be removed
pub mod config {
    pub use crate::application::config::*;
}

pub mod crypto {
    //! Re-export crypto utilities from platform crate
    pub use crate::domain::services::*;
    pub use platform::crypto::*;
}

pub mod models {
    pub use crate::domain::entities::*;
    pub use crate::domain::value_objects::*;
    pub use crate::presentation::dto::*;
}

pub mod handlers {
    pub use crate::presentation::handlers::*;
}

pub mod store {
    pub use crate::infra::postgres::PgPowRepository as PowStore;
}

pub mod router {
    pub use crate::presentation::router::*;
}

pub mod middleware {
    pub use crate::presentation::middleware::*;
}

#[cfg(test)]
mod tests;
