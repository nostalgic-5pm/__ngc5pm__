//! Auth Middleware
//!
//! Middleware for requiring authentication on protected routes.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use platform::client::{extract_client_ip, extract_fingerprint};
use std::sync::Arc;

use crate::application::config::AuthConfig;
use crate::application::CheckSessionUseCase;
use crate::domain::repository::AuthSessionRepository;
use crate::error::AuthError;

/// Middleware state
#[derive(Clone)]
pub struct AuthMiddlewareState<R>
where
    R: AuthSessionRepository + Clone + Send + Sync + 'static,
{
    pub repo: Arc<R>,
    pub config: Arc<AuthConfig>,
}

/// Middleware that requires a valid auth session
pub async fn require_auth_session<R>(
    state: AuthMiddlewareState<R>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response>
where
    R: AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let headers = req.headers();

    let client_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip());

    let client_ip = extract_client_ip(headers, client_ip);

    let fingerprint = match extract_fingerprint(headers, client_ip) {
        Ok(fp) => fp,
        Err(e) => return Err(AuthError::from(e).into_response()),
    };

    let token = platform::cookie::extract_cookie(headers, &state.config.session_cookie_name);

    let use_case = CheckSessionUseCase::new(state.repo.clone(), state.config.clone());

    let session_valid = if let Some(token) = token {
        use_case.is_valid(&token, &fingerprint.hash).await
    } else {
        false
    };

    if !session_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            [("X-Auth-Required", "true")],
        )
            .into_response());
    }

    Ok(next.run(req).await)
}

/// Middleware that checks auth session but doesn't require it
/// Sets X-Authenticated header for downstream handlers
pub async fn check_auth_session<R>(
    state: AuthMiddlewareState<R>,
    mut req: Request<Body>,
    next: Next,
) -> Response
where
    R: AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let headers = req.headers();

    let client_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip());

    let client_ip = extract_client_ip(headers, client_ip);

    let fingerprint = extract_fingerprint(headers, client_ip).ok();

    let token = platform::cookie::extract_cookie(headers, &state.config.session_cookie_name);

    let is_authenticated = if let (Some(token), Some(fp)) = (token, fingerprint) {
        let use_case = CheckSessionUseCase::new(state.repo.clone(), state.config.clone());
        use_case.is_valid(&token, &fp.hash).await
    } else {
        false
    };

    // Store authentication status in request extensions
    req.extensions_mut().insert(AuthStatus { is_authenticated });

    next.run(req).await
}

/// Authentication status stored in request extensions
#[derive(Clone, Copy)]
pub struct AuthStatus {
    pub is_authenticated: bool,
}
