CREATE TABLE invites (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  token_hash TEXT NOT NULL UNIQUE,
  email TEXT,
  phone TEXT,
  role TEXT NOT NULL CHECK (role IN ('user','admin')),
  status TEXT NOT NULL CHECK (status IN ('pending','used','expired')),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  used_at TIMESTAMPTZ,
  used_by UUID REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_invites_status ON invites(status);
CREATE INDEX idx_invites_expires ON invites(expires_at);
