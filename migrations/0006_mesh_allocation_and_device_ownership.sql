CREATE TABLE device.mesh_addresses (
    address inet PRIMARY KEY,
    owner_kind text NOT NULL CHECK (owner_kind IN ('device', 'node')),
    owner_id uuid NOT NULL,
    allocated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_kind, owner_id),
    CHECK (family(address) = 4)
);

INSERT INTO device.mesh_addresses (address, owner_kind, owner_id)
SELECT mesh_address, 'device', id
FROM device.devices
WHERE mesh_address IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO device.mesh_addresses (address, owner_kind, owner_id)
SELECT mesh_address, 'node', id
FROM device.nodes
ON CONFLICT DO NOTHING;

ALTER TABLE device.devices
    ADD COLUMN owner_kind text NOT NULL DEFAULT 'user'
        CHECK (owner_kind IN ('user', 'domain')),
    ADD COLUMN owner_domain_id uuid;

UPDATE device.devices
SET owner_domain_id = domain_id
WHERE owner_kind = 'domain';

ALTER TABLE device.devices
    ALTER COLUMN owner_user_id DROP NOT NULL,
    ADD CONSTRAINT devices_owner_shape CHECK (
        (owner_kind = 'user' AND owner_user_id IS NOT NULL AND owner_domain_id IS NULL)
        OR
        (owner_kind = 'domain' AND owner_user_id IS NULL AND owner_domain_id = domain_id)
    );
