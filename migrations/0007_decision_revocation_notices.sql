CREATE SEQUENCE policy.revocation_notice_sequence AS bigint START WITH 1;

CREATE TABLE policy.revocation_notices (
    sequence bigint PRIMARY KEY DEFAULT nextval('policy.revocation_notice_sequence'),
    domain_id uuid NOT NULL,
    decision_id text NOT NULL,
    target_node_id uuid NOT NULL,
    reason text NOT NULL CHECK (reason <> ''),
    revoked_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    envelope jsonb NOT NULL,
    UNIQUE (domain_id, decision_id),
    CHECK (expires_at > revoked_at)
);

CREATE INDEX revocation_notices_target_sequence_idx
    ON policy.revocation_notices (domain_id, target_node_id, sequence);
