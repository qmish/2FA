CREATE TABLE lockouts (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  ip TEXT NOT NULL,
  reason TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_lockouts_user ON lockouts(user_id);
CREATE INDEX idx_lockouts_ip ON lockouts(ip);
CREATE INDEX idx_lockouts_expires ON lockouts(expires_at);
