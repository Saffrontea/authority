# Database migrations

Migrations are append-only and execute in filename order. The runner wraps
each file in a transaction, applies it as the `authority` database owner, and
records its SHA-256 digest in `platform.schema_migrations`.

Rules:

- never edit an applied migration;
- never use cross-schema foreign keys;
- modules refer to external entities by ID only;
- let the runner own transactions; destructive table/schema/column/index/type
  removal and `TRUNCATE` are rejected, while ordinary constraint changes are allowed;
- use expand/migrate/contract changes across separate migrations;
- update `manifest.json` only after reviewing the SQL diff.
