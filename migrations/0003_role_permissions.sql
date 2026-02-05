CREATE TABLE role_permissions (
  role TEXT NOT NULL CHECK (role IN ('user','admin')),
  permission TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (role, permission)
);

CREATE INDEX idx_role_permissions_role ON role_permissions(role);
