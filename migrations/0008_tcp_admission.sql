ALTER TABLE policy.access_policies
    ADD COLUMN tcp_ports integer[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT tcp_ports_valid CHECK (
        cardinality(tcp_ports) <= 64 AND
        (cardinality(tcp_ports) = 0 OR (0 < ALL(tcp_ports) AND 65536 > ALL(tcp_ports)))
    );

ALTER TABLE policy.revocation_notices
    DROP CONSTRAINT revocation_notices_domain_id_decision_id_key,
    ADD COLUMN scope_key text NOT NULL DEFAULT '';

UPDATE policy.revocation_notices
SET scope_key = (
    SELECT string_agg(kind, ',' ORDER BY kind)
    FROM jsonb_array_elements_text(envelope->'notice'->'adapter_kinds') AS kinds(kind)
)
WHERE envelope->'notice' ? 'adapter_kinds';

ALTER TABLE policy.revocation_notices
    ADD CONSTRAINT revocation_notices_scope_unique UNIQUE (domain_id, decision_id, scope_key);
