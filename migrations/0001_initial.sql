CREATE SCHEMA identity AUTHORIZATION authority;
CREATE SCHEMA device AUTHORIZATION authority;
CREATE SCHEMA policy AUTHORIZATION authority;
CREATE SCHEMA issuer AUTHORIZATION authority;
CREATE SCHEMA audit AUTHORIZATION authority;
CREATE SCHEMA outbox AUTHORIZATION authority;

CREATE TABLE identity.users (
    id uuid PRIMARY KEY,
    domain_id uuid NOT NULL,
    display_name text NOT NULL CHECK (display_name <> ''),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX identity_users_domain_idx ON identity.users (domain_id, id);

CREATE TABLE identity.webauthn_credentials (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES identity.users (id),
    credential_id bytea NOT NULL UNIQUE,
    public_key bytea NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

CREATE TABLE device.devices (
    id uuid PRIMARY KEY,
    domain_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    device_public_key bytea NOT NULL,
    wireguard_public_key bytea NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'active', 'disabled')),
    enrolled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (domain_id, device_public_key),
    UNIQUE (domain_id, wireguard_public_key)
);

CREATE INDEX devices_owner_idx ON device.devices (domain_id, owner_user_id);

CREATE TABLE device.nodes (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES device.devices (id),
    hostname text NOT NULL CHECK (hostname <> ''),
    mesh_address inet NOT NULL,
    ssh_principals text[] NOT NULL DEFAULT '{}',
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (mesh_address)
);

CREATE TABLE policy.access_policies (
    id uuid PRIMARY KEY,
    domain_id uuid NOT NULL,
    subject_user_id uuid NOT NULL,
    required_device_id uuid,
    target_node_id uuid NOT NULL,
    ssh_principal text NOT NULL CHECK (ssh_principal <> ''),
    valid_from timestamptz,
    valid_until timestamptz,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
);

CREATE INDEX access_policy_lookup_idx ON policy.access_policies
    (domain_id, subject_user_id, target_node_id)
    WHERE enabled;

CREATE TABLE issuer.issued_credentials (
    id uuid PRIMARY KEY,
    domain_id uuid NOT NULL,
    subject_user_id uuid NOT NULL,
    device_id uuid NOT NULL,
    target_node_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    contract_version smallint NOT NULL CHECK (contract_version = 1),
    certificate_serial numeric(20, 0) NOT NULL UNIQUE,
    public_key_fingerprint text NOT NULL,
    certificate_fingerprint text NOT NULL UNIQUE,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > issued_at)
);

CREATE INDEX issued_credentials_subject_idx ON issuer.issued_credentials
    (domain_id, subject_user_id, issued_at DESC);

CREATE TABLE audit.events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id uuid NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    decision text CHECK (decision IN ('allow', 'deny')),
    reason text,
    payload jsonb NOT NULL DEFAULT '{}',
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_domain_time_idx ON audit.events
    (domain_id, occurred_at DESC);

CREATE TABLE outbox.events (
    id uuid PRIMARY KEY,
    owner_module text NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    event_type text NOT NULL,
    contract_version smallint NOT NULL,
    payload jsonb NOT NULL,
    occurred_at timestamptz NOT NULL,
    published_at timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);

CREATE INDEX outbox_unpublished_idx ON outbox.events (occurred_at)
    WHERE published_at IS NULL;
