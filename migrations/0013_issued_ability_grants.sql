-- Issuance provenance only. A row does not assert target installation or liveness.
CREATE TABLE policy.issued_ability_grants (
    domain_id uuid NOT NULL,
    subject_user_id uuid NOT NULL,
    device_id uuid NOT NULL,
    target_node_id uuid NOT NULL,
    decision_id text NOT NULL CHECK (length(decision_id) BETWEEN 1 AND 128),
    ability_kind text NOT NULL CHECK (ability_kind IN (
        'mesh_membership', 'ssh_credential', 'mtls_credential', 'tcp_admission'
    )),
    ability jsonb NOT NULL CHECK (jsonb_typeof(ability) = 'object'),
    policy_refs jsonb NOT NULL CHECK (jsonb_typeof(policy_refs) = 'array' AND jsonb_array_length(policy_refs) > 0),
    not_before bigint NOT NULL CHECK (not_before >= 0),
    expires_at bigint NOT NULL CHECK (expires_at > not_before),
    revoked_at bigint CHECK (revoked_at >= 0),
    PRIMARY KEY (domain_id, target_node_id, decision_id, ability_kind),
    CHECK (COALESCE(
        ability #>> '{scope,kind}' = ability_kind
        AND (ability #>> '{binding,domain_id}')::uuid = domain_id
        AND (ability #>> '{binding,subject_user_id}')::uuid = subject_user_id
        AND (ability #>> '{binding,device_id}')::uuid = device_id
        AND (ability #>> '{binding,target_node_id}')::uuid = target_node_id
        AND (ability #>> '{validity,not_before}')::bigint = not_before
        AND (ability #>> '{validity,expires_at}')::bigint = expires_at,
        false
    ))
);
CREATE INDEX issued_ability_grants_subject_idx ON policy.issued_ability_grants
    (domain_id, subject_user_id, device_id, target_node_id, expires_at)
    WHERE revoked_at IS NULL;
