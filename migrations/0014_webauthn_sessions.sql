CREATE TABLE webauthn_sessions (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  user_id UUID,
  data JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_webauthn_sessions_type_user ON webauthn_sessions(type, user_id);
CREATE INDEX idx_webauthn_sessions_expires ON webauthn_sessions(expires_at);
