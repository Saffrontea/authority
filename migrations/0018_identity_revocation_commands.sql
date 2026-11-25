CREATE TABLE policy.identity_revocation_commands (
    domain_id uuid NOT NULL, nonce text NOT NULL, command jsonb NOT NULL,
    response jsonb NOT NULL DEFAULT '{}', occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(domain_id,nonce)
);
CREATE TABLE policy.scoped_revocation_notices (
    sequence bigint PRIMARY KEY,
    domain_id uuid NOT NULL, operation_nonce text NOT NULL, target_node_id uuid NOT NULL,
    envelope jsonb NOT NULL,
    completed_at timestamptz, lease_owner uuid, lease_until timestamptz,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY(domain_id,operation_nonce) REFERENCES policy.identity_revocation_commands(domain_id,nonce)
);
CREATE INDEX scoped_revocation_pending_idx ON policy.scoped_revocation_notices(sequence) WHERE completed_at IS NULL;
CREATE TABLE policy.identity_revocation_children (
    domain_id uuid NOT NULL, operation_nonce text NOT NULL, sequence bigint NOT NULL REFERENCES policy.revocation_notices(sequence),
    PRIMARY KEY(domain_id,operation_nonce,sequence),
    FOREIGN KEY(domain_id,operation_nonce) REFERENCES policy.identity_revocation_commands(domain_id,nonce)
);
ALTER TABLE device.nodes ADD COLUMN enforcement_origin text;
ALTER TABLE identity.sessions
    ADD COLUMN subject_generation bigint NOT NULL DEFAULT 1 CHECK(subject_generation>0),
    ADD COLUMN device_generation bigint NOT NULL DEFAULT 1 CHECK(device_generation>0);

CREATE FUNCTION identity.bind_session_generations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    SELECT generation INTO STRICT NEW.subject_generation FROM identity.users
        WHERE id=NEW.user_id AND domain_id=NEW.domain_id AND status='active' FOR SHARE;
    SELECT generation INTO STRICT NEW.device_generation FROM device.devices
        WHERE id=NEW.device_id AND domain_id=NEW.domain_id AND owner_user_id=NEW.user_id AND status='active' FOR SHARE;
    RETURN NEW;
END $$;
CREATE TRIGGER session_generation_binding BEFORE INSERT ON identity.sessions
    FOR EACH ROW EXECUTE FUNCTION identity.bind_session_generations();
