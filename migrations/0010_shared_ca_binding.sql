CREATE TABLE issuer.ca_bindings (
    slot text PRIMARY KEY, ca_id text NOT NULL REFERENCES issuer.ca_registry(ca_id)
);
