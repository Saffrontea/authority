-- Concrete policies replace capability groups in the live authorization path.
-- Existing access_policies rows are deliberately not converted.
CREATE TABLE policy.ability_policies (
    id uuid PRIMARY KEY,
    domain_id uuid NOT NULL,
    subject_user_id uuid NOT NULL,
    required_device_id uuid,
    target_node_id uuid NOT NULL,
    selector jsonb NOT NULL CHECK (jsonb_typeof(selector) = 'object'),
    effect text NOT NULL CHECK (effect IN ('allow', 'deny')),
    priority integer NOT NULL DEFAULT 0,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    enabled boolean NOT NULL DEFAULT true,
    revoked_at timestamptz,
    valid_from timestamptz,
    valid_until timestamptz,
    CHECK (valid_from IS NULL OR valid_from >= to_timestamp(0)),
    CHECK (valid_until IS NULL OR valid_until > COALESCE(valid_from, to_timestamp(0)))
);
CREATE INDEX ability_policy_lookup_idx ON policy.ability_policies
    (domain_id, subject_user_id, target_node_id);

-- Readers hold the shared transaction lock before reading under READ COMMITTED.
-- Every writer, including a direct SQL insertion of a deny, takes it exclusively.
-- No policy row locks are needed: MVCC plus this guard also prevents phantoms.
CREATE FUNCTION policy.ability_policy_lock_key(domain_id uuid, subject_user_id uuid, target_node_id uuid)
RETURNS bigint LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT hashtextextended(domain_id::text || ':' || subject_user_id::text || ':' || target_node_id::text, 0)
$$;
CREATE FUNCTION policy.lock_ability_policy_write() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_key bigint; new_key bigint;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        old_key := policy.ability_policy_lock_key(OLD.domain_id, OLD.subject_user_id, OLD.target_node_id);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_key := policy.ability_policy_lock_key(NEW.domain_id, NEW.subject_user_id, NEW.target_node_id);
    END IF;
    IF old_key IS NOT NULL AND new_key IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(LEAST(old_key, new_key));
        IF old_key <> new_key THEN
            PERFORM pg_advisory_xact_lock(GREATEST(old_key, new_key));
        END IF;
    ELSE
        PERFORM pg_advisory_xact_lock(COALESCE(old_key, new_key));
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER ability_policy_write_guard
    BEFORE INSERT OR UPDATE OR DELETE ON policy.ability_policies
    FOR EACH ROW EXECUTE FUNCTION policy.lock_ability_policy_write();
