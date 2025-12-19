//! Presentation Layer
//!
//! HTTP handlers, DTOs, router, and middleware.

pub mod dto;
pub mod handlers;
pub mod middleware;
pub mod router;

pub use handlers::AuthAppState;
pub use middleware::{AuthMiddlewareState, AuthStatus, check_auth_session, require_auth_session};
pub use router::{auth_router, auth_router_generic};
