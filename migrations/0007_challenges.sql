CREATE TABLE challenges (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  method TEXT NOT NULL CHECK (method IN ('push','otp','call')),
  status TEXT NOT NULL CHECK (status IN ('created','sent','pending','approved','denied','expired','failed')),
  code_hash TEXT,
  provider_id TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_challenges_user ON challenges(user_id);
CREATE INDEX idx_challenges_status ON challenges(status);
CREATE INDEX idx_challenges_expires ON challenges(expires_at);
