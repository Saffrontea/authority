ALTER TABLE identity.pending_challenges ADD COLUMN subject_user_id uuid;
UPDATE identity.pending_challenges SET subject_user_id = (payload->>'user_id')::uuid;
ALTER TABLE identity.pending_challenges ALTER COLUMN subject_user_id SET NOT NULL;
CREATE INDEX pending_challenge_subject_idx ON identity.pending_challenges(domain_id,kind,subject_user_id,expires_at);
CREATE TABLE identity.challenge_rate_limits (
    domain_id uuid NOT NULL,
    kind text NOT NULL CHECK(kind IN ('registration','authentication')),
    subject_user_id uuid NOT NULL,
    window_start timestamptz NOT NULL,
    attempts integer NOT NULL CHECK(attempts > 0),
    PRIMARY KEY(domain_id,kind,subject_user_id)
);
CREATE INDEX sessions_subject_expiry_idx ON identity.sessions(domain_id,user_id,expires_at,token_digest);
-- Include revoked rows: private reconciliation must find all of an owner's grants.
CREATE INDEX issued_grant_owner_idx ON policy.issued_ability_grants
    (domain_id,subject_user_id,device_id,target_node_id,decision_id);
