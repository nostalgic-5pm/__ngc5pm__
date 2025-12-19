-- PoW Challenge Store
-- Challenge は発行後、検証成功時に原子的に消費（削除）される

CREATE TABLE IF NOT EXISTS pow_challenges (
    -- Challenge 識別子（UUID v4）
    pow_challenge_id UUID PRIMARY KEY,
    
    -- Challenge bytes（32 bytes、サーバ生成ランダム値）
    pow_challenge_bytes BYTEA NOT NULL CHECK (octet_length(pow_challenge_bytes) = 32),
    
    -- 難易度（先頭ゼロビット数）
    pow_difficulty_bits SMALLINT NOT NULL CHECK (pow_difficulty_bits >= 1 AND pow_difficulty_bits <= 32),
    
    -- 有効期限（UNIX timestamp ms）
    expires_at_ms BIGINT NOT NULL,
    
    -- 発行日時
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- クライアント fingerprint（User-Agent hash、rate limit 用）
    client_fingerprint_hash BYTEA NOT NULL CHECK (octet_length(client_fingerprint_hash) = 32),
    
    -- クライアント IP（参考情報、rate limit の弱い要素として）
    client_ip INET
);

-- 期限切れ challenge の定期削除用インデックス
CREATE INDEX IF NOT EXISTS idx_pow_challenges_expires_at 
    ON pow_challenges (expires_at_ms);

-- fingerprint による rate limit 用インデックス
CREATE INDEX IF NOT EXISTS idx_pow_challenges_fingerprint 
    ON pow_challenges (client_fingerprint_hash, created_at);

-- PoW Session Store（サーバサイドセッション）
CREATE TABLE IF NOT EXISTS pow_sessions (
    -- Session ID（署名なしの場合は UUID、署名ありなら token hash）
    pow_session_id UUID PRIMARY KEY,
    
    -- 有効期限
    expires_at_ms BIGINT NOT NULL,
    
    -- 発行日時
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- bind された fingerprint（検証時に一致確認）
    client_fingerprint_hash BYTEA NOT NULL CHECK (octet_length(client_fingerprint_hash) = 32),
    
    -- 元の challenge ID（監査用）
    pow_challenge_id UUID NOT NULL
);

-- 期限切れ session の定期削除用インデックス
CREATE INDEX IF NOT EXISTS idx_pow_sessions_expires_at 
    ON pow_sessions (expires_at_ms);

-- fingerprint による session 検索用インデックス
CREATE INDEX IF NOT EXISTS idx_pow_sessions_fingerprint 
    ON pow_sessions (client_fingerprint_hash);

-- Rate limit tracking（IP + fingerprint 単位）
CREATE TABLE IF NOT EXISTS pow_rate_limits (
    -- fingerprint hash
    client_fingerprint_hash BYTEA NOT NULL CHECK (octet_length(client_fingerprint_hash) = 32),
    
    -- 時間窓の開始（分単位で丸めた timestamp）
    window_start_ms BIGINT NOT NULL,
    
    -- この窓でのリクエスト数
    request_count INTEGER NOT NULL DEFAULT 1,
    
    PRIMARY KEY (client_fingerprint_hash, window_start_ms)
);

-- 古い rate limit レコード削除用インデックス
CREATE INDEX IF NOT EXISTS idx_pow_rate_limits_window 
    ON pow_rate_limits (window_start_ms);

-- 期限切れデータのクリーンアップ用関数
CREATE OR REPLACE FUNCTION cleanup_expired_pow_data() RETURNS void AS $$
BEGIN
    -- 期限切れ challenge を削除
    DELETE FROM pow_challenges WHERE expires_at_ms < (EXTRACT(EPOCH FROM now()) * 1000)::BIGINT;
    
    -- 期限切れ session を削除
    DELETE FROM pow_sessions WHERE expires_at_ms < (EXTRACT(EPOCH FROM now()) * 1000)::BIGINT;
    
    -- 1時間以上前の rate limit レコードを削除
    DELETE FROM pow_rate_limits 
    WHERE window_start_ms < ((EXTRACT(EPOCH FROM now()) - 3600) * 1000)::BIGINT;
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE pow_challenges IS 'PoW challenge store. Challenges are atomically consumed on successful verification.';
COMMENT ON TABLE pow_sessions IS 'PoW session store. Sessions prove that a client has passed PoW verification.';
COMMENT ON TABLE pow_rate_limits IS 'Rate limiting for PoW challenge issuance.';
