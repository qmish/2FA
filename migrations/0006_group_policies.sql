CREATE TABLE group_policies (
  group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id)
);

CREATE INDEX idx_group_policies_policy ON group_policies(policy_id);
