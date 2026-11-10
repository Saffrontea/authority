ALTER TABLE identity.webauthn_credentials
    ADD COLUMN passkey jsonb;

ALTER TABLE identity.webauthn_credentials
    ALTER COLUMN public_key SET DEFAULT ''::bytea;
