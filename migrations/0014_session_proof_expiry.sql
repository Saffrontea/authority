-- Existing nonces must survive the entire remaining proof acceptance window.
ALTER TABLE identity.session_nonces ADD COLUMN proof_expires_at bigint NOT NULL
    DEFAULT (CEIL(EXTRACT(EPOCH FROM clock_timestamp()))::bigint + 60);
CREATE INDEX session_nonce_expiry_idx ON identity.session_nonces(token_digest, proof_expires_at);
