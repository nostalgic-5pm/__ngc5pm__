//! Infrastructure Layer
//!
//! Database implementations and external service integrations.

pub mod postgres;

pub use postgres::PgAuthRepository;
