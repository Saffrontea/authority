ALTER TABLE device.nodes ADD COLUMN endpoint_facts text[] NOT NULL DEFAULT '{}';
