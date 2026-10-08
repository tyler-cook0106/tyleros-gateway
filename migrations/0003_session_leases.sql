ALTER TABLE sessions ADD COLUMN last_seen_at INTEGER;

UPDATE sessions
SET last_seen_at = created_at
WHERE last_seen_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_sessions_last_seen_at
  ON sessions(last_seen_at);
