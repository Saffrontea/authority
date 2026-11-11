ALTER TABLE device.devices
    ADD COLUMN mesh_address inet;

CREATE UNIQUE INDEX devices_mesh_address_idx
    ON device.devices (mesh_address)
    WHERE mesh_address IS NOT NULL;
