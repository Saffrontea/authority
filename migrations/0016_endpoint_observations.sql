-- Only a freshly challenged, registered target key may publish environment evidence.
-- Writers and authorizers serialize through the target node row (UPDATE / SHARE).
CREATE TABLE device.endpoint_observations (
    node_id uuid PRIMARY KEY REFERENCES device.nodes(id),
    domain_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    requested_at bigint NOT NULL CHECK (requested_at >= 0),
    window_start bigint NOT NULL CHECK (window_start >= 0),
    attempts integer NOT NULL CHECK (attempts BETWEEN 1 AND 64),
    pending_challenge jsonb NOT NULL CHECK (jsonb_typeof(pending_challenge) = 'object'),
    consumed boolean NOT NULL DEFAULT false,
    envelope jsonb CHECK (envelope IS NULL OR jsonb_typeof(envelope) = 'object')
);
CREATE INDEX endpoint_observations_domain_idx ON device.endpoint_observations(domain_id, node_id);
