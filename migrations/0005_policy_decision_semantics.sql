ALTER TABLE policy.access_policies
    ADD COLUMN effect text NOT NULL DEFAULT 'allow'
        CHECK (effect IN ('allow', 'deny')),
    ADD COLUMN priority integer NOT NULL DEFAULT 0,
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    ADD COLUMN capabilities text[] NOT NULL DEFAULT ARRAY['ssh', 'wireguard'],
    ADD COLUMN revoked_at timestamptz,
    ADD CONSTRAINT access_policies_capabilities_not_empty
        CHECK (cardinality(capabilities) > 0);

CREATE INDEX access_policy_resolution_idx ON policy.access_policies
    (domain_id, subject_user_id, target_node_id, priority DESC, revision DESC)
    WHERE enabled AND revoked_at IS NULL;
