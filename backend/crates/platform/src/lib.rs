//! Platform Crate - Technical Infrastructure
//!
//! This crate provides shared technical foundations:
//! - Cryptographic utilities (SHA-256, HMAC, Base64)
//! - Password hashing (Argon2id, NIST SP 800-63B compliant)
//! - Cookie management
//! - Client identification (fingerprinting, IP extraction)
//! - Rate limiting infrastructure
//! - Common middleware components

pub mod client;
pub mod config;
pub mod cookie;
pub mod crypto;
pub mod password;
pub mod rate_limit;
