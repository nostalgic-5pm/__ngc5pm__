//! API DTOs (Data Transfer Objects)

use serde::{Deserialize, Serialize};

// ============================================================================
// Sign Up
// ============================================================================

/// Sign up request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequest {
    pub user_name: String,
    pub password: String,
}

/// Sign up response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpResponse {
    pub public_id: String,
}

// ============================================================================
// Sign In
// ============================================================================

/// Sign in request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInRequest {
    /// User name or email
    pub identifier: String,
    pub password: String,
    #[serde(default)]
    pub remember_me: bool,
    /// TOTP code if 2FA is enabled
    pub totp_code: Option<String>,
}

/// Sign in response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInResponse {
    pub public_id: String,
    /// True if 2FA is required (need to submit totp_code)
    pub requires_2fa: bool,
}

// ============================================================================
// Session Status
// ============================================================================

/// Session status response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatusResponse {
    pub authenticated: bool,
    pub public_id: Option<String>,
    pub user_role: Option<String>,
    pub expires_at_ms: Option<i64>,
}

// ============================================================================
// TOTP Setup
// ============================================================================

/// TOTP setup response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetupResponse {
    /// QR code as base64-encoded PNG (data:image/png;base64,...)
    pub qr_code: String,
    /// Secret for manual entry
    pub secret: String,
    /// otpauth:// URL
    pub otpauth_url: String,
}

/// TOTP verify request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpVerifyRequest {
    pub code: String,
}

/// TOTP disable request
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpDisableRequest {
    /// Current TOTP code to confirm disable
    pub code: String,
}

// ============================================================================
// User Info (for authenticated users)
// ============================================================================

/// Current user info response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfoResponse {
    pub public_id: String,
    pub user_name: String,
    pub user_role: String,
    pub totp_enabled: bool,
    pub last_login_at: Option<i64>,
}

