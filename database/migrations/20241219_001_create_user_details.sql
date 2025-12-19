-- User Details Migration
-- Separate profile/contact information from core auth
-- ============================================================================
-- User Details Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_details(
    -- Reference to user
    user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    -- Contact information
    email VARCHAR(254) UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    -- Display information
    display_name VARCHAR(50),
    -- Personal information (future use)
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_user_details_email ON user_details(email)
WHERE
    email IS NOT NULL;

COMMENT ON TABLE user_details IS 'Extended user profile and contact information';

COMMENT ON COLUMN user_details.email IS 'Contact email (also used for password recovery)';

COMMENT ON COLUMN user_details.display_name IS 'Display name (separate from user_name handle)';

-- ============================================================================
-- Migrate email from auth_credentials to user_details
-- ============================================================================
-- Copy existing emails to user_details
INSERT INTO user_details(user_id, email, created_at, updated_at)
SELECT
    user_id,
    email,
    created_at,
    updated_at
FROM
    auth_credentials
WHERE
    email IS NOT NULL
ON CONFLICT (user_id)
    DO UPDATE SET
        email = EXCLUDED.email,
        updated_at = EXCLUDED.updated_at;

-- Remove email column from auth_credentials
ALTER TABLE auth_credentials
    DROP COLUMN IF EXISTS email;

-- Drop old index if exists
DROP INDEX IF EXISTS idx_auth_credentials_email;

