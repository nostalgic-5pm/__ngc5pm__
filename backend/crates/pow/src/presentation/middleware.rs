//! PoW Middleware

use crate::application::check_session::CheckPowSessionUseCase;
use crate::application::config::PowConfig;
use crate::domain::repository::{ChallengeRepository, RateLimitRepository, PowSessionRepository};
use crate::presentation::handlers::{extract_client_ip, extract_fingerprint};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// Middleware state
#[derive(Clone)]
pub struct PowMiddlewareState<R>
where
    R: PowSessionRepository + Clone + Send + Sync + 'static,
{
    pub repo: Arc<R>,
    pub config: Arc<PowConfig>,
}

/// Middleware that requires a valid PoW session
pub async fn require_pow_session<R>(
    state: PowMiddlewareState<R>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response>
where
    R: ChallengeRepository + PowSessionRepository + RateLimitRepository + Clone + Send + Sync + 'static,
{
    let headers = req.headers();

    let client_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip());

    let client_ip = extract_client_ip(headers, client_ip);

    let fingerprint = match extract_fingerprint(headers, client_ip) {
        Ok(fp) => fp,
        Err(e) => return Err(e.into_response()),
    };

    let token = platform::cookie::extract_cookie(headers, &state.config.session_cookie_name);

    let use_case = CheckPowSessionUseCase::new(state.repo.clone(), state.config.clone());

    let session_valid = if let Some(token) = token {
        match use_case.check(&token, &fingerprint).await {
            Ok(valid) => valid,
            Err(e) => {
                tracing::error!(error = %e, "Error checking PoW session");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, ()).into_response());
            }
        }
    } else {
        tracing::debug!("No PoW session cookie");
        false
    };

    if !session_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            [("X-PoW-Required", "true")],
        )
            .into_response());
    }

    Ok(next.run(req).await)
}
