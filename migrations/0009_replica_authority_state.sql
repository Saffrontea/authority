-- Shared authority. Local memory is reserved for live sockets and immutable keys.
CREATE TABLE identity.auth_domains (domain_id uuid PRIMARY KEY);
CREATE TABLE identity.bootstrap_tokens (
    domain_id uuid NOT NULL, token_digest bytea NOT NULL CHECK (octet_length(token_digest)=32),
    consumed_at timestamptz, PRIMARY KEY(domain_id, token_digest)
);
CREATE TABLE identity.pending_challenges (
    domain_id uuid NOT NULL, id uuid NOT NULL, kind text NOT NULL CHECK(kind IN ('registration','authentication')),
    payload jsonb NOT NULL, expires_at timestamptz NOT NULL, PRIMARY KEY(domain_id,id)
);
CREATE INDEX pending_challenge_expiry ON identity.pending_challenges(expires_at);
CREATE TABLE identity.sessions (
    domain_id uuid NOT NULL, token_digest bytea PRIMARY KEY CHECK(octet_length(token_digest)=32),
    user_id uuid NOT NULL, device_id uuid NOT NULL, device_public_key bytea NOT NULL CHECK(octet_length(device_public_key)=32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX session_expiry ON identity.sessions(expires_at);
CREATE TABLE identity.session_nonces (
    token_digest bytea NOT NULL REFERENCES identity.sessions(token_digest) ON DELETE CASCADE,
    nonce text NOT NULL, PRIMARY KEY(token_digest,nonce)
);
CREATE SEQUENCE issuer.certificate_serial AS bigint START WITH 1;
CREATE TABLE issuer.ca_registry (
    ca_id text PRIMARY KEY, certificate_der bytea NOT NULL, public_key_der bytea NOT NULL
);
CREATE TABLE issuer.decision_state (
    domain_id text NOT NULL, target_node_id text NOT NULL, decision_id text NOT NULL,
    revoked_at bigint, expires_at bigint NOT NULL,
    PRIMARY KEY(domain_id,target_node_id,decision_id)
);
CREATE TABLE issuer.consumed_authorizations (
    issuer_id text NOT NULL, nonce text NOT NULL, expires_at bigint NOT NULL,
    PRIMARY KEY(issuer_id,nonce)
);
CREATE TABLE issuer.certificates (
    ca_id text NOT NULL REFERENCES issuer.ca_registry(ca_id), serial bigint NOT NULL,
    domain_id text NOT NULL, target_node_id text NOT NULL, decision_id text NOT NULL,
    authorization_nonce text NOT NULL, certificate_der bytea NOT NULL,
    not_before bigint NOT NULL, expires_at bigint NOT NULL, revoked_at bigint,
    PRIMARY KEY(ca_id,serial), UNIQUE(ca_id,authorization_nonce),
    FOREIGN KEY(domain_id,target_node_id,decision_id) REFERENCES issuer.decision_state
);
CREATE INDEX certificates_decision ON issuer.certificates(domain_id,target_node_id,decision_id);
CREATE TABLE policy.revocation_stream (id boolean PRIMARY KEY DEFAULT true CHECK(id));
INSERT INTO policy.revocation_stream VALUES(true);
CREATE TABLE policy.enforcement_instances (
    instance_id uuid PRIMARY KEY, domain_id uuid NOT NULL, target_node_id uuid NOT NULL,
    role text NOT NULL, last_sequence bigint NOT NULL DEFAULT 0, lease_until timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX enforcement_members ON policy.enforcement_instances(domain_id,target_node_id,lease_until);
CREATE TABLE policy.revocation_receipts (
    sequence bigint NOT NULL REFERENCES policy.revocation_notices(sequence),
    instance_id uuid NOT NULL REFERENCES policy.enforcement_instances(instance_id),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(sequence,instance_id)
);
CREATE TABLE policy.revocation_members (
    sequence bigint NOT NULL REFERENCES policy.revocation_notices(sequence),
    instance_id uuid NOT NULL REFERENCES policy.enforcement_instances(instance_id),
    lease_until timestamptz NOT NULL, PRIMARY KEY(sequence,instance_id)
);
CREATE TABLE issuer.crl_counters (ca_id text PRIMARY KEY REFERENCES issuer.ca_registry(ca_id), number bigint NOT NULL);
CREATE TABLE policy.adapter_deliveries (
    sequence bigint NOT NULL REFERENCES policy.revocation_notices(sequence),
    receiver_id text NOT NULL, origin text NOT NULL,
    lease_owner uuid, lease_until timestamptz, completed_at timestamptz,
    PRIMARY KEY(sequence,receiver_id)
);
