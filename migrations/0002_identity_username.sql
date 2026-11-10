ALTER TABLE identity.users
    ADD COLUMN username text NOT NULL CHECK (username ~ '^[A-Za-z0-9_.@-]{1,128}$');

CREATE UNIQUE INDEX identity_users_domain_username_idx
    ON identity.users (domain_id, username);
