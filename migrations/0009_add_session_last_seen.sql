ALTER TABLE user_sessions
ADD COLUMN last_seen_at TIMESTAMPTZ;

CREATE INDEX idx_sessions_last_seen ON user_sessions(last_seen_at);
