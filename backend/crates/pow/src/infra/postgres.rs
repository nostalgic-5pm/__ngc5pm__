//! PostgreSQL Repository Implementations

use crate::domain::entities::{Challenge, PowSession};
use crate::domain::repository::{ChallengeRepository, PowSessionRepository, RateLimitRepository};
use crate::domain::value_objects::ClientFingerprint;
use crate::error::{PowError, PowResult};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

const OLD_WINDOW_MS: i64 = 3600_000; // 1 hour

/// PostgreSQL-backed repository
#[derive(Clone)]
pub struct PgPowRepository {
    pool: PgPool,
}

impl PgPowRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Clean up expired data
    pub async fn cleanup_expired(&self) -> PowResult<(u64, u64, u64)> {
        let now_ms = Utc::now().timestamp_millis();
        let old_window_ms = now_ms - OLD_WINDOW_MS;

        let challenges_deleted = sqlx::query("DELETE FROM pow_challenges WHERE expires_at_ms < $1")
            .bind(now_ms)
            .execute(&self.pool)
            .await?
            .rows_affected();

        let sessions_deleted = sqlx::query("DELETE FROM pow_sessions WHERE expires_at_ms < $1")
            .bind(now_ms)
            .execute(&self.pool)
            .await?
            .rows_affected();

        let rate_limits_deleted =
            sqlx::query("DELETE FROM pow_rate_limits WHERE window_start_ms < $1")
                .bind(old_window_ms)
                .execute(&self.pool)
                .await?
                .rows_affected();

        tracing::info!(
            challenges = challenges_deleted,
            sessions = sessions_deleted,
            rate_limits = rate_limits_deleted,
            "Cleaned up expired PoW data"
        );

        Ok((challenges_deleted, sessions_deleted, rate_limits_deleted))
    }
}

impl ChallengeRepository for PgPowRepository {
    async fn create(&self, challenge: &Challenge) -> PowResult<()> {
        sqlx::query(
            r#"
            INSERT INTO pow_challenges (
                pow_challenge_id,
                pow_challenge_bytes,
                pow_difficulty_bits,
                expires_at_ms,
                client_fingerprint_hash,
                client_ip
            ) VALUES ($1, $2, $3, $4, $5, $6::inet)
            "#,
        )
        .bind(challenge.id)
        .bind(&challenge.challenge_bytes)
        .bind(challenge.difficulty_bits as i16)
        .bind(challenge.expires_at_ms)
        .bind(&challenge.client_fingerprint_hash)
        .bind(challenge.client_ip.as_ref().map(|ip| ip.to_string()))
        .execute(&self.pool)
        .await?;

        tracing::info!(
            challenge_id = %challenge.id,
            difficulty = challenge.difficulty_bits,
            "Challenge created"
        );

        Ok(())
    }

    async fn consume(&self, challenge_id: Uuid) -> PowResult<Option<Challenge>> {
        let now_ms = Utc::now().timestamp_millis();

        let row = sqlx::query_as::<_, ChallengeRow>(
            r#"
                DELETE FROM pow_challenges
                WHERE pow_challenge_id = $1 AND expires_at_ms > $2
                RETURNING
                    pow_challenge_id,
                    pow_challenge_bytes,
                    pow_difficulty_bits,
                    expires_at_ms,
                    created_at,
                    client_fingerprint_hash,
                    client_ip::TEXT
            "#,
        )
        .bind(challenge_id)
        .bind(now_ms)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                tracing::info!(challenge_id = %challenge_id, "Challenge consumed");
                Ok(Some(r.into_challenge()?))
            }
            None => {
                // Check if it exists but expired
                let exists = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM pow_challenges WHERE pow_challenge_id = $1)",
                )
                .bind(challenge_id)
                .fetch_one(&self.pool)
                .await?;

                if exists {
                    tracing::warn!(challenge_id = %challenge_id, "Challenge expired");
                    Err(PowError::ChallengeExpired)
                } else {
                    tracing::warn!(challenge_id = %challenge_id, "Challenge not found");
                    Ok(None)
                }
            }
        }
    }
}

impl PowSessionRepository for PgPowRepository {
    async fn create(&self, pow_session: &PowSession) -> PowResult<()> {
        sqlx::query(
            r#"
            INSERT INTO pow_sessions (
                pow_session_id,
                expires_at_ms,
                client_fingerprint_hash,
                pow_challenge_id
            ) VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(pow_session.id)
        .bind(pow_session.expires_at_ms)
        .bind(&pow_session.client_fingerprint_hash)
        .bind(pow_session.challenge_id)
        .execute(&self.pool)
        .await?;

        tracing::info!(
            pow_session_id = %pow_session.id,
            challenge_id = %pow_session.challenge_id,
            "PoW session created"
        );

        Ok(())
    }

    async fn get(
        &self,
        pow_session_id: Uuid,
        fingerprint: &ClientFingerprint,
    ) -> PowResult<Option<PowSession>> {
        let now_ms = chrono::Utc::now().timestamp_millis();

        let row = sqlx::query_as::<_, PowSessionRow>(
            r#"
            SELECT
                pow_session_id,
                expires_at_ms,
                created_at,
                client_fingerprint_hash,
                pow_challenge_id
            FROM pow_sessions
            WHERE pow_session_id = $1 AND expires_at_ms > $2
            "#,
        )
        .bind(pow_session_id)
        .bind(now_ms)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                // Verify fingerprint matches
                if r.client_fingerprint_hash != fingerprint.hash.as_slice() {
                    tracing::warn!(
                        pow_session_id = %pow_session_id,
                        "PoW session fingerprint mismatch"
                    );
                    return Err(PowError::SessionFingerprintMismatch);
                }
                Ok(Some(r.into_pow_session()))
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, pow_session_id: Uuid) -> PowResult<()> {
        sqlx::query("DELETE FROM pow_sessions WHERE pow_session_id = $1")
            .bind(pow_session_id)
            .execute(&self.pool)
            .await?;

        tracing::info!(pow_session_id = %pow_session_id, "PoW session deleted");
        Ok(())
    }
}

impl RateLimitRepository for PgPowRepository {
    async fn check(
        &self,
        fingerprint: &ClientFingerprint,
        max_requests: u32,
        window_ms: i64,
    ) -> PowResult<bool> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let window_start = (now_ms / window_ms) * window_ms;

        let row = sqlx::query_as::<_, (i32,)>(
            r#"
            INSERT INTO pow_rate_limits (client_fingerprint_hash, window_start_ms, request_count)
            VALUES ($1, $2, 1)
            ON CONFLICT (client_fingerprint_hash, window_start_ms)
            DO UPDATE SET request_count = pow_rate_limits.request_count + 1
            RETURNING request_count
            "#,
        )
        .bind(fingerprint.hash.as_slice())
        .bind(window_start)
        .fetch_one(&self.pool)
        .await?;

        let count = row.0 as u32;
        let allowed = count <= max_requests;

        if !allowed {
            tracing::warn!(count = count, max = max_requests, "Rate limit exceeded");
        }

        Ok(allowed)
    }
}

// Internal row types for sqlx mapping
#[derive(sqlx::FromRow)]
struct ChallengeRow {
    pow_challenge_id: Uuid,
    pow_challenge_bytes: Vec<u8>,
    pow_difficulty_bits: i16,
    expires_at_ms: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    client_fingerprint_hash: Vec<u8>,
    client_ip: Option<String>,
}

impl ChallengeRow {
    fn into_challenge(self) -> PowResult<Challenge> {
        Ok(Challenge {
            id: self.pow_challenge_id,
            challenge_bytes: self.pow_challenge_bytes,
            difficulty_bits: self.pow_difficulty_bits as u8,
            expires_at_ms: self.expires_at_ms,
            created_at: self.created_at,
            client_fingerprint_hash: self.client_fingerprint_hash,
            client_ip: self.client_ip.and_then(|s| s.parse().ok()),
        })
    }
}

#[derive(sqlx::FromRow)]
struct PowSessionRow {
    pow_session_id: Uuid,
    expires_at_ms: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    client_fingerprint_hash: Vec<u8>,
    pow_challenge_id: Uuid,
}

impl PowSessionRow {
    fn into_pow_session(self) -> PowSession {
        PowSession {
            id: self.pow_session_id,
            expires_at_ms: self.expires_at_ms,
            created_at: self.created_at,
            client_fingerprint_hash: self.client_fingerprint_hash,
            challenge_id: self.pow_challenge_id,
        }
    }
}
