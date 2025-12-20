//! HTTP Handlers

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use std::sync::Arc;

use platform::client::{extract_client_ip, extract_fingerprint};

use crate::application::config::{AuthConfig, SameSite};
use crate::application::{
    CheckSessionUseCase, SignInInput, SignInUseCase, SignOutUseCase, SignUpInput, SignUpUseCase,
    TotpSetupUseCase,
};
use crate::domain::repository::{AuthRepository, AuthSessionRepository, UserRepository};
use crate::error::{AuthError, AuthResult};
use crate::presentation::dto::{
    SessionStatusResponse, SignInRequest, SignInResponse, SignUpRequest, SignUpResponse,
    TotpDisableRequest, TotpSetupResponse, TotpVerifyRequest,
};

/// Shared state for auth handlers
#[derive(Clone)]
pub struct AuthAppState<R>
where
    R: UserRepository + AuthRepository + AuthSessionRepository + Clone + Send + Sync + 'static,
{
    pub repo: Arc<R>,
    pub config: Arc<AuthConfig>,
}

// ============================================================================
// Sign Up
// ============================================================================

/// POST /api/auth/signup
pub async fn sign_up<R>(
    State(state): State<AuthAppState<R>>,
    Json(req): Json<SignUpRequest>,
) -> AuthResult<Json<SignUpResponse>>
where
    R: UserRepository + AuthRepository + AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let use_case = SignUpUseCase::new(state.repo.clone(), state.repo.clone(), state.config.clone());

    let input = SignUpInput {
        user_name: req.user_name,
        password: req.password,
    };

    let output = use_case.execute(input).await?;

    Ok(Json(SignUpResponse {
        public_id: output.public_id,
    }))
}

// ============================================================================
// Sign In
// ============================================================================

/// POST /api/auth/signin
pub async fn sign_in<R>(
    State(state): State<AuthAppState<R>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<SignInRequest>,
) -> AuthResult<impl IntoResponse>
where
    R: UserRepository + AuthRepository + AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let client_ip = extract_client_ip(&headers, Some(addr.ip()));
    let fingerprint = extract_fingerprint(&headers, client_ip)?;

    let use_case = SignInUseCase::new(
        state.repo.clone(),
        state.repo.clone(),
        state.repo.clone(),
        state.config.clone(),
    );

    // req のムーブ後も使えるように remember_me を退避
    let remember_me = req.remember_me;

    let input = SignInInput {
        identifier: req.identifier,
        password: req.password,
        remember_me,
        totp_code: req.totp_code,
    };

    let output = use_case.execute(input, fingerprint).await?;

    if output.requires_2fa {
        // 2FA required - return response without session cookie
        return Ok((
            StatusCode::OK,
            Json(SignInResponse {
                public_id: output.public_id,
                requires_2fa: true,
            }),
        )
            .into_response());
    }

    // Success - set session cookie (Max-Age must match remember_me)
    let cookie = build_session_cookie(&state.config, &output.session_token, remember_me);

    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(SignInResponse {
            public_id: output.public_id,
            requires_2fa: false,
        }),
    )
        .into_response())
}

// ============================================================================
// Sign Out
// ============================================================================

/// POST /api/auth/signout
pub async fn sign_out<R>(
    State(state): State<AuthAppState<R>>,
    headers: HeaderMap,
) -> AuthResult<impl IntoResponse>
where
    R: UserRepository + AuthRepository + AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let token = extract_session_cookie(&headers, &state.config.session_cookie_name);

    if let Some(token) = token {
        let use_case = SignOutUseCase::new(state.repo.clone(), state.config.clone());
        // Ignore errors - just clear the cookie
        let _ = use_case.execute(&token).await;
    }

    let cookie = build_clear_cookie(&state.config);

    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]))
}

// ============================================================================
// Session Status
// ============================================================================

/// GET /api/auth/status
pub async fn session_status<R>(
    State(state): State<AuthAppState<R>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> AuthResult<Json<SessionStatusResponse>>
where
    R: UserRepository + AuthRepository + AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let client_ip = extract_client_ip(&headers, Some(addr.ip()));
    let fingerprint = extract_fingerprint(&headers, client_ip)?;

    let token = extract_session_cookie(&headers, &state.config.session_cookie_name);

    let use_case = CheckSessionUseCase::new(state.repo.clone(), state.config.clone());

    let session_info = if let Some(token) = token {
        use_case.execute(&token, &fingerprint.hash).await.ok()
    } else {
        None
    };

    match session_info {
        Some(info) => Ok(Json(SessionStatusResponse {
            authenticated: true,
            public_id: Some(info.public_id),
            user_role: Some(info.user_role),
            expires_at_ms: Some(info.expires_at_ms),
        })),
        None => Ok(Json(SessionStatusResponse {
            authenticated: false,
            public_id: None,
            user_role: None,
            expires_at_ms: None,
        })),
    }
}

// ============================================================================
// TOTP Setup (requires authentication)
// ============================================================================

/// POST /api/auth/totp/setup
pub async fn totp_setup<R>(
    State(state): State<AuthAppState<R>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> AuthResult<Json<TotpSetupResponse>>
where
    R: UserRepository + AuthRepository + AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let client_ip = extract_client_ip(&headers, Some(addr.ip()));
    let fingerprint = extract_fingerprint(&headers, client_ip)?;

    // Get current session
    let token = extract_session_cookie(&headers, &state.config.session_cookie_name)
        .ok_or(AuthError::SessionInvalid)?;

    let check_use_case = CheckSessionUseCase::new(state.repo.clone(), state.config.clone());
    let session = check_use_case
        .get_session(&token, &fingerprint.hash)
        .await?;

    // Setup TOTP
    let use_case =
        TotpSetupUseCase::new(state.repo.clone(), state.repo.clone(), state.config.clone());

    let output = use_case.setup(&session.user_id).await?;

    Ok(Json(TotpSetupResponse {
        qr_code: output.qr_code_base64,
        secret: output.secret,
        otpauth_url: output.otpauth_url,
    }))
}

/// POST /api/auth/totp/verify
pub async fn totp_verify<R>(
    State(state): State<AuthAppState<R>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<TotpVerifyRequest>,
) -> AuthResult<StatusCode>
where
    R: UserRepository + AuthRepository + AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let client_ip = extract_client_ip(&headers, Some(addr.ip()));
    let fingerprint = extract_fingerprint(&headers, client_ip)?;

    // Get current session
    let token = extract_session_cookie(&headers, &state.config.session_cookie_name)
        .ok_or(AuthError::SessionInvalid)?;

    let check_use_case = CheckSessionUseCase::new(state.repo.clone(), state.config.clone());
    let session = check_use_case
        .get_session(&token, &fingerprint.hash)
        .await?;

    // Verify TOTP
    let use_case =
        TotpSetupUseCase::new(state.repo.clone(), state.repo.clone(), state.config.clone());

    use_case.verify(&session.user_id, &req.code).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/auth/totp/disable
pub async fn totp_disable<R>(
    State(state): State<AuthAppState<R>>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<TotpDisableRequest>,
) -> AuthResult<StatusCode>
where
    R: UserRepository + AuthRepository + AuthSessionRepository + Clone + Send + Sync + 'static,
{
    let client_ip = extract_client_ip(&headers, Some(addr.ip()));
    let fingerprint = extract_fingerprint(&headers, client_ip)?;

    // Get current session
    let token = extract_session_cookie(&headers, &state.config.session_cookie_name)
        .ok_or(AuthError::SessionInvalid)?;

    let check_use_case = CheckSessionUseCase::new(state.repo.clone(), state.config.clone());
    let session = check_use_case
        .get_session(&token, &fingerprint.hash)
        .await?;

    // Disable TOTP
    let use_case =
        TotpSetupUseCase::new(state.repo.clone(), state.repo.clone(), state.config.clone());

    use_case.disable(&session.user_id, &req.code).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Helper Functions
// ============================================================================

fn extract_session_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    platform::cookie::extract_cookie(headers, name)
}

fn build_session_cookie(config: &AuthConfig, token: &str, remember_me: bool) -> String {
    let max_age = if remember_me {
        config.session_ttl_long.as_secs()
    } else {
        config.session_ttl_short.as_secs()
    };

    let mut parts = vec![
        format!("{}={}", config.session_cookie_name, token),
        "HttpOnly".to_string(),
        "Path=/".to_string(),
        format!("Max-Age={}", max_age),
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

fn build_clear_cookie(config: &AuthConfig) -> String {
    let mut parts = vec![
        format!("{}=", config.session_cookie_name),
        "HttpOnly".to_string(),
        "Path=/".to_string(),
        "Max-Age=0".to_string(),
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
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
