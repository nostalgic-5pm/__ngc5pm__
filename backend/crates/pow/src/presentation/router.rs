//! PoW Router

use crate::application::config::PowConfig;
use crate::domain::repository::{ChallengeRepository, PowSessionRepository, RateLimitRepository};
use crate::infra::postgres::PgPowRepository;
use crate::presentation::handlers::{self, PowAppState};
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

/// Create the PoW router with PostgreSQL repository
pub fn pow_router(repo: PgPowRepository, config: PowConfig) -> Router {
    let state = PowAppState {
        repo: Arc::new(repo),
        config: Arc::new(config),
    };

    Router::new()
        .route(
            "/challenge",
            get(handlers::issue_challenge::<PgPowRepository>),
        )
        .route(
            "/submit",
            post(handlers::submit_solution::<PgPowRepository>),
        )
        .route("/status", get(handlers::check_status::<PgPowRepository>))
        .route("/logout", post(handlers::logout::<PgPowRepository>))
        .with_state(state)
}

/// Create a generic PoW router for any repository implementation
pub fn pow_router_generic<R>(repo: R, config: PowConfig) -> Router
where
    R: ChallengeRepository
        + PowSessionRepository
        + RateLimitRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let state = PowAppState {
        repo: Arc::new(repo),
        config: Arc::new(config),
    };

    Router::new()
        .route("/challenge", get(handlers::issue_challenge::<R>))
        .route("/submit", post(handlers::submit_solution::<R>))
        .route("/status", get(handlers::check_status::<R>))
        .route("/logout", post(handlers::logout::<R>))
        .with_state(state)
}
