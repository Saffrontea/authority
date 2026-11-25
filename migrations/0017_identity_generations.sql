ALTER TABLE identity.users ADD COLUMN generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0);
ALTER TABLE device.devices ADD COLUMN generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0);
ALTER TABLE policy.issued_ability_grants
    ADD COLUMN subject_generation bigint NOT NULL DEFAULT 1 CHECK (subject_generation > 0),
    ADD COLUMN device_generation bigint NOT NULL DEFAULT 1 CHECK (device_generation > 0);
ALTER TABLE issuer.certificates
    ADD COLUMN subject_user_id text,
    ADD COLUMN device_id text,
    ADD COLUMN subject_generation bigint CHECK (subject_generation > 0),
    ADD COLUMN device_generation bigint CHECK (device_generation > 0);

-- Reassignment, disabling and key replacement must not recycle an old epoch.
CREATE FUNCTION identity.advance_user_generation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.generation < OLD.generation THEN RAISE EXCEPTION 'user generation rollback'; END IF;
    IF (NEW.status, NEW.domain_id) IS DISTINCT FROM (OLD.status, OLD.domain_id)
        AND NEW.generation = OLD.generation THEN NEW.generation := OLD.generation + 1; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER user_generation_guard BEFORE UPDATE ON identity.users
    FOR EACH ROW EXECUTE FUNCTION identity.advance_user_generation();

CREATE FUNCTION device.advance_device_generation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.generation < OLD.generation THEN RAISE EXCEPTION 'device generation rollback'; END IF;
    IF (NEW.status, NEW.domain_id, NEW.owner_user_id, NEW.device_public_key, NEW.wireguard_public_key)
       IS DISTINCT FROM (OLD.status, OLD.domain_id, OLD.owner_user_id, OLD.device_public_key, OLD.wireguard_public_key)
        AND NEW.generation = OLD.generation THEN NEW.generation := OLD.generation + 1; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER device_generation_guard BEFORE UPDATE ON device.devices
    FOR EACH ROW EXECUTE FUNCTION device.advance_device_generation();

-- The caller already holds the shared identity guards through issuance.
CREATE FUNCTION policy.bind_issued_generations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    SELECT generation INTO STRICT NEW.subject_generation FROM identity.users
        WHERE id=NEW.subject_user_id AND domain_id=NEW.domain_id AND status='active';
    SELECT generation INTO STRICT NEW.device_generation FROM device.devices
        WHERE id=NEW.device_id AND domain_id=NEW.domain_id AND owner_user_id=NEW.subject_user_id AND status='active';
    RETURN NEW;
END $$;
CREATE TRIGGER issued_generation_binding BEFORE INSERT ON policy.issued_ability_grants
    FOR EACH ROW EXECUTE FUNCTION policy.bind_issued_generations();

CREATE TABLE issuer.ssh_decision_state (
    domain_id text NOT NULL, target_node_id text NOT NULL, decision_id text NOT NULL,
    revoked_at bigint, expires_at bigint NOT NULL,
    PRIMARY KEY(domain_id,target_node_id,decision_id)
);
CREATE TABLE issuer.ssh_certificates (
    serial bigint PRIMARY KEY, domain_id text NOT NULL, target_node_id text NOT NULL,
    subject_user_id text NOT NULL, device_id text NOT NULL,
    subject_generation bigint NOT NULL CHECK(subject_generation>0),
    device_generation bigint NOT NULL CHECK(device_generation>0),
    decision_id text NOT NULL, certificate_openssh text NOT NULL,
    ca_fingerprint text NOT NULL, not_before bigint NOT NULL, expires_at bigint NOT NULL,
    revoked_at bigint
);
CREATE INDEX ssh_certificates_identity_idx ON issuer.ssh_certificates(domain_id,subject_user_id,device_id,expires_at);
