-- Auth Tables Migration
-- Users, Auth Credentials, and Auth Sessions
-- ============================================================================
-- Users Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS users(
    -- Internal UUID identifier
    user_id UUID PRIMARY KEY,
    -- Public-facing nanoid identifier (21 chars, URL-safe)
    public_id VARCHAR(21) NOT NULL UNIQUE,
    -- User name (original case)
    user_name VARCHAR(30) NOT NULL,
    -- User name (canonical, lowercase for uniqueness)
    user_name_canonical VARCHAR(30) NOT NULL UNIQUE,
    -- Role: 0=User, 1=Moderator, 2=Admin, 3=SuperAdmin
    user_role SMALLINT NOT NULL DEFAULT 0 CHECK (user_role >= 0 AND user_role <= 3),
    -- Status: 0=Active, 1=Disabled, 2=Memorial
    user_status SMALLINT NOT NULL DEFAULT 0 CHECK (user_status >= 0 AND user_status <= 2),
    -- Last successful login
    last_login_at TIMESTAMPTZ,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for users
CREATE INDEX IF NOT EXISTS idx_users_public_id ON users(public_id);

CREATE INDEX IF NOT EXISTS idx_users_user_name_canonical ON users(user_name_canonical);

CREATE INDEX IF NOT EXISTS idx_users_user_role ON users(user_role);

CREATE INDEX IF NOT EXISTS idx_users_user_status ON users(user_status);

COMMENT ON TABLE users IS 'User profile information (non-sensitive)';

COMMENT ON COLUMN users.public_id IS 'URL-safe nanoid for public identification';

COMMENT ON COLUMN users.user_name_canonical IS 'Lowercase user name for case-insensitive uniqueness';

-- ============================================================================
-- Auth Credentials Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth_credentials(
    -- Reference to user
    user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    -- Password hash (Argon2id PHC string format)
    password_hash VARCHAR(255) NOT NULL,
    -- Email (optional for regular users, required for moderator+)
    email VARCHAR(254) UNIQUE,
    -- TOTP secret (base32 encoded, for 2FA)
    totp_secret VARCHAR(64),
    -- Whether TOTP is enabled and verified
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    -- Login failure tracking
    login_failed_count SMALLINT NOT NULL DEFAULT 0,
    last_failed_at TIMESTAMPTZ,
    locked_until TIMESTAMPTZ,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for auth_credentials
CREATE INDEX IF NOT EXISTS idx_auth_credentials_email ON auth_credentials(email)
WHERE
    email IS NOT NULL;

COMMENT ON TABLE auth_credentials IS 'Sensitive authentication credentials (separated from users)';

COMMENT ON COLUMN auth_credentials.password_hash IS 'Argon2id hash in PHC string format';

COMMENT ON COLUMN auth_credentials.totp_secret IS 'Base32-encoded TOTP secret for Google Authenticator';

-- ============================================================================
-- Auth Sessions Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth_sessions(
    -- Session UUID
    session_id UUID PRIMARY KEY,
    -- Reference to user
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    -- Public ID (denormalized for quick access)
    public_id VARCHAR(21) NOT NULL,
    -- User role at session creation
    user_role SMALLINT NOT NULL,
    -- Expiration timestamp (ms)
    expires_at_ms BIGINT NOT NULL,
    -- Remember me flag
    remember_me BOOLEAN NOT NULL DEFAULT FALSE,
    -- Client fingerprint (SHA-256 of User-Agent)
    client_fingerprint_hash BYTEA NOT NULL CHECK (octet_length(client_fingerprint_hash) = 32),
    -- Client IP (for logging/display)
    client_ip VARCHAR(45),
    -- User agent (for session management display)
    user_agent TEXT,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for auth_sessions
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at_ms);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_fingerprint ON auth_sessions(client_fingerprint_hash);

COMMENT ON TABLE auth_sessions IS 'Server-side session storage for authenticated users';

COMMENT ON COLUMN auth_sessions.expires_at_ms IS 'Unix timestamp in milliseconds';

COMMENT ON COLUMN auth_sessions.client_fingerprint_hash IS 'SHA-256 hash of User-Agent for session binding';

-- ============================================================================
-- Cleanup Function
-- ============================================================================
CREATE OR REPLACE FUNCTION cleanup_expired_auth_data()
    RETURNS void
    AS $$
BEGIN
    -- Delete expired sessions
    DELETE FROM auth_sessions
    WHERE expires_at_ms <(extract(EPOCH FROM now()) * 1000)::BIGINT;
    -- Reset lockouts that have expired
    UPDATE
        auth_credentials
    SET
        locked_until = NULL,
        login_failed_count = 0
    WHERE
        locked_until IS NOT NULL
        AND locked_until < now();
END;
$$
LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_auth_data IS 'Cleanup expired auth sessions and reset expired lockouts';

