CREATE TABLE recovery_codes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_recovery_codes_user_hash ON recovery_codes(user_id, code_hash);
CREATE INDEX idx_recovery_codes_user_used ON recovery_codes(user_id, used_at);
