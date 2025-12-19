//! Auth Router

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

use crate::application::config::AuthConfig;
use crate::domain::repository::{AuthRepository, AuthSessionRepository, UserRepository};
use crate::infra::postgres::PgAuthRepository;
use crate::presentation::handlers::{self, AuthAppState};

/// Create the Auth router with PostgreSQL repository
pub fn auth_router(repo: PgAuthRepository, config: AuthConfig) -> Router {
    let state = AuthAppState {
        repo: Arc::new(repo),
        config: Arc::new(config),
    };

    Router::new()
        .route("/signup", post(handlers::sign_up::<PgAuthRepository>))
        .route("/signin", post(handlers::sign_in::<PgAuthRepository>))
        .route("/signout", post(handlers::sign_out::<PgAuthRepository>))
        .route("/status", get(handlers::session_status::<PgAuthRepository>))
        .route("/totp/setup", post(handlers::totp_setup::<PgAuthRepository>))
        .route("/totp/verify", post(handlers::totp_verify::<PgAuthRepository>))
        .route("/totp/disable", post(handlers::totp_disable::<PgAuthRepository>))
        .with_state(state)
}

/// Create a generic Auth router for any repository implementation
pub fn auth_router_generic<R>(repo: R, config: AuthConfig) -> Router
where
    R: UserRepository + AuthRepository + AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let state = AuthAppState {
        repo: Arc::new(repo),
        config: Arc::new(config),
    };

    Router::new()
        .route("/signup", post(handlers::sign_up::<R>))
        .route("/signin", post(handlers::sign_in::<R>))
        .route("/signout", post(handlers::sign_out::<R>))
        .route("/status", get(handlers::session_status::<R>))
        .route("/totp/setup", post(handlers::totp_setup::<R>))
        .route("/totp/verify", post(handlers::totp_verify::<R>))
        .route("/totp/disable", post(handlers::totp_disable::<R>))
        .with_state(state)
}
