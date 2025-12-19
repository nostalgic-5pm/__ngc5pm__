//! Domain Value Objects
//!
//! Immutable value types for the PoW domain.

use std::net::IpAddr;

/// Client fingerprint - derived from User-Agent header
#[derive(Debug, Clone)]
pub struct ClientFingerprint {
    pub hash: [u8; 32],
    pub ip: Option<IpAddr>,
}

impl ClientFingerprint {
    pub fn new(hash: [u8; 32], ip: Option<IpAddr>) -> Self {
        Self { hash, ip }
    }

    pub fn hash_vec(&self) -> Vec<u8> {
        self.hash.to_vec()
    }
}

/// Difficulty level for PoW
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Difficulty(u8);

impl Difficulty {
    pub const DEFAULT: Difficulty = Difficulty(18);
    pub const MIN: u8 = 1;
    pub const MAX: u8 = 32; // Max practical difficulty

    pub fn new(bits: u8) -> Option<Self> {
        if (Self::MIN..=Self::MAX).contains(&bits) {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub fn bits(&self) -> u8 {
        self.0
    }
}

impl Default for Difficulty {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl From<Difficulty> for u8 {
    fn from(d: Difficulty) -> Self {
        d.0
    }
}
