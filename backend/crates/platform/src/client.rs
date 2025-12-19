//! Client identification utilities
//!
//! Common functions for identifying clients via HTTP headers.

use axum::http::{HeaderMap, header};
use std::net::IpAddr;

use crate::crypto::sha256;

/// Client fingerprint derived from request headers
///
/// Used to bind sessions to specific clients and detect session hijacking.
#[derive(Debug, Clone)]
pub struct ClientFingerprint {
    /// SHA-256 hash of the User-Agent header
    pub hash: [u8; 32],
    /// Client IP address (from X-Forwarded-For or direct connection)
    pub ip: Option<IpAddr>,
    /// Original User-Agent string (for logging/display)
    pub user_agent: Option<String>,
}

impl ClientFingerprint {
    /// Create a new fingerprint
    pub fn new(hash: [u8; 32], ip: Option<IpAddr>, user_agent: Option<String>) -> Self {
        Self { hash, ip, user_agent }
    }

    /// Get hash as Vec<u8> (for database storage)
    pub fn hash_vec(&self) -> Vec<u8> {
        self.hash.to_vec()
    }

    /// Get IP as string (for database storage)
    pub fn ip_string(&self) -> Option<String> {
        self.ip.map(|ip| ip.to_string())
    }
}

/// Error when extracting client fingerprint
#[derive(Debug, Clone, thiserror::Error)]
pub enum FingerprintError {
    #[error("Missing required header: {0}")]
    MissingHeader(String),
}

/// Extract client fingerprint from request headers
///
/// The fingerprint is a SHA-256 hash of the User-Agent header,
/// used to bind sessions to specific clients.
///
/// ## Arguments
/// * `headers` - HTTP request headers
/// * `client_ip` - Client IP address (from connection or X-Forwarded-For)
///
/// ## Returns
/// * `Ok(ClientFingerprint)` - Successfully extracted fingerprint
/// * `Err(FingerprintError)` - Missing User-Agent header
pub fn extract_fingerprint(
    headers: &HeaderMap,
    client_ip: Option<IpAddr>,
) -> Result<ClientFingerprint, FingerprintError> {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| FingerprintError::MissingHeader("User-Agent".to_string()))?;

    let hash = sha256(user_agent.as_bytes());

    Ok(ClientFingerprint::new(
        hash,
        client_ip,
        Some(user_agent.to_string()),
    ))
}

/// Extract client IP address from headers
///
/// Checks X-Forwarded-For header first (for reverse proxy setups),
/// then falls back to direct connection IP.
///
/// ## Arguments
/// * `headers` - HTTP request headers
/// * `direct_ip` - Direct connection IP address
///
/// ## Returns
/// The client IP address, or None if not determinable
pub fn extract_client_ip(headers: &HeaderMap, direct_ip: Option<IpAddr>) -> Option<IpAddr> {
    // Check X-Forwarded-For header (first IP in the list)
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first_ip) = xff.split(',').next() {
            if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    direct_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_extract_fingerprint() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 Test Browser"),
        );

        let fp = extract_fingerprint(&headers, None).unwrap();
        assert_eq!(fp.hash.len(), 32);
        assert_eq!(fp.user_agent, Some("Mozilla/5.0 Test Browser".to_string()));
    }

    #[test]
    fn test_extract_fingerprint_missing_ua() {
        let headers = HeaderMap::new();
        let result = extract_fingerprint(&headers, None);
        assert!(matches!(result, Err(FingerprintError::MissingHeader(_))));
    }

    #[test]
    fn test_extract_client_ip_xff() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.168.1.1, 10.0.0.1"),
        );

        let ip = extract_client_ip(&headers, None);
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_direct() {
        let headers = HeaderMap::new();
        let direct: IpAddr = "127.0.0.1".parse().unwrap();

        let ip = extract_client_ip(&headers, Some(direct));
        assert_eq!(ip, Some(direct));
    }
}
