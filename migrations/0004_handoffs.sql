-- One-time credentials used to transfer an authenticated browser from
-- the Cloudflare/auth stage into the DMZ stage.
CREATE TABLE handoffs (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

CREATE INDEX idx_handoffs_token_hash
    ON handoffs(token_hash);

CREATE INDEX idx_handoffs_session_id
    ON handoffs(session_id);
