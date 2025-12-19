//! HTTP Handlers

use crate::application::check_session::CheckPowSessionUseCase;
use crate::application::config::{PowConfig, SameSite};
use crate::application::issue_challenge::IssueChallengeUseCase;
use crate::application::submit_solution::{SubmitSolutionInput, SubmitSolutionUseCase};
use crate::domain::repository::{ChallengeRepository, PowSessionRepository, RateLimitRepository};
use crate::error::PowResult;
use crate::presentation::dto::{ChallengeResponse, StatusResponse, SubmitRequest};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use platform::client::{extract_client_ip, extract_fingerprint};
use std::sync::Arc;

/// Shared state for PoW handlers
#[derive(Clone)]
pub struct PowAppState<R>
where
    R: ChallengeRepository
        + PowSessionRepository
        + RateLimitRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub repo: Arc<R>,
    pub config: Arc<PowConfig>,
}

/// GET /api/pow/challenge
pub async fn issue_challenge<R>(
    State(state): State<PowAppState<R>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> PowResult<Json<ChallengeResponse>>
where
    R: ChallengeRepository
        + PowSessionRepository
        + RateLimitRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let client_ip = extract_client_ip(&headers, Some(addr.ip()));
    let fingerprint = extract_fingerprint(&headers, client_ip)?;

    let use_case =
        IssueChallengeUseCase::new(state.repo.clone(), state.repo.clone(), state.config.clone());

    let output = use_case.execute(fingerprint).await?;

    Ok(Json(ChallengeResponse {
        pow_challenge_id: output.challenge_id,
        pow_challenge_b64: output.challenge_b64,
        pow_difficulty_bits: output.difficulty_bits,
        pow_expires_at_ms: output.expires_at_ms,
    }))
}

/// POST /api/pow/submit
pub async fn submit_solution<R>(
    State(state): State<PowAppState<R>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<SubmitRequest>,
) -> PowResult<impl IntoResponse>
where
    R: ChallengeRepository
        + PowSessionRepository
        + RateLimitRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let client_ip = extract_client_ip(&headers, Some(addr.ip()));
    let fingerprint = extract_fingerprint(&headers, client_ip)?;

    let use_case =
        SubmitSolutionUseCase::new(state.repo.clone(), state.repo.clone(), state.config.clone());

    let input = SubmitSolutionInput {
        challenge_id: req.challenge_id,
        nonce_u32: req.nonce_u32,
        elapsed_ms: req.elapsed_ms,
        total_hashes: req.total_hashes,
    };

    let output = use_case.execute(input, fingerprint).await?;

    let cookie = build_session_cookie(&state.config, &output.session_token);

    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]))
}

/// GET /api/pow/status
pub async fn check_status<R>(
    State(state): State<PowAppState<R>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> PowResult<Json<StatusResponse>>
where
    R: ChallengeRepository
        + PowSessionRepository
        + RateLimitRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let client_ip = extract_client_ip(&headers, Some(addr.ip()));
    let fingerprint = extract_fingerprint(&headers, client_ip)?;

    let token = extract_session_cookie(&headers, &state.config.session_cookie_name);

    let use_case = CheckPowSessionUseCase::new(state.repo.clone(), state.config.clone());

    let passed = if let Some(token) = token {
        use_case.check(&token, &fingerprint).await?
    } else {
        false
    };

    Ok(Json(StatusResponse { passed }))
}

/// POST /api/pow/logout
pub async fn logout<R>(
    State(state): State<PowAppState<R>>,
    headers: HeaderMap,
) -> PowResult<impl IntoResponse>
where
    R: ChallengeRepository
        + PowSessionRepository
        + RateLimitRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let token = extract_session_cookie(&headers, &state.config.session_cookie_name);

    let use_case = CheckPowSessionUseCase::new(state.repo.clone(), state.config.clone());

    if let Some(token) = token {
        use_case.logout(&token).await?;
    }

    let cookie = build_clear_cookie(&state.config);

    tracing::info!("PoW session logged out");

    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]))
}

fn build_session_cookie(config: &PowConfig, token: &str) -> String {
    let mut parts = vec![
        format!("{}={}", config.session_cookie_name, token),
        "HttpOnly".to_string(),
        "Path=/".to_string(),
        format!("Max-Age={}", config.session_ttl.as_secs()),
    ];

    if config.cookie_secure {
        parts.push("Secure".to_string());
    }

    match config.cookie_same_site {
        SameSite::Strict => parts.push("SameSite=Strict".to_string()),
        SameSite::Lax => parts.push("SameSite=Lax".to_string()),
        SameSite::None => parts.push("SameSite=None".to_string()),
    }

    parts.join("; ")
}

fn build_clear_cookie(config: &PowConfig) -> String {
    format!(
        "{}=; HttpOnly; Path=/; Max-Age=0",
        config.session_cookie_name
    )
}

fn extract_session_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    platform::cookie::extract_cookie(headers, cookie_name)
}
