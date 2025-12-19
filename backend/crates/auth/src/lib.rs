//! Auth (Authentication) Backend Module
//!
//! Clean Architecture structure:
//! - `domain/` - Business logic, entities, repository traits
//! - `application/` - Use cases and application services
//! - `infra/` - Database implementations
//! - `presentation/` - HTTP handlers, DTOs, router
//!
//! ## Features
//! - User signup/signin with username + password
//! - TOTP-based 2FA (Google Authenticator compatible)
//! - Server-side sessions with cookie-based tokens
//! - Role-based access (User, Moderator, Admin, SuperAdmin)
//!
//! ## Security Model
//! - Passwords hashed with Argon2id (NIST SP 800-63B compliant)
//! - Sessions bound to client fingerprint (User-Agent)
//! - Automatic lockout after failed login attempts
//! - Moderator+ roles require 2FA

pub mod application;
pub mod domain;
pub mod error;
pub mod infra;
pub mod presentation;

// Re-exports for convenience
pub use application::config::AuthConfig;
pub use error::{AuthError, AuthResult};
pub use infra::postgres::PgAuthRepository;
pub use presentation::router::auth_router;

// Re-export kernel error types for unified error handling
pub use kernel::error::{
    app_error::{AppError, AppResult},
    kind::ErrorKind,
};

// Convenience re-exports
pub mod config {
    pub use crate::application::config::*;
}

pub mod models {
    pub use crate::domain::entity::*;
    pub use crate::domain::value_object::*;
    pub use crate::presentation::dto::*;
}

pub mod handlers {
    pub use crate::presentation::handlers::*;
}

pub mod store {
    pub use crate::infra::postgres::PgAuthRepository as AuthStore;
}

pub mod router {
    pub use crate::presentation::router::*;
}

pub mod middleware {
    pub use crate::presentation::middleware::*;
}

