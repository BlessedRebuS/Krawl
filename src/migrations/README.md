# Database Migrations

`runner.py` is applied automatically at every startup by
`DatabaseManager.initialize()`. It only covers ALTER-level changes (new columns,
new indexes) that `Base.metadata.create_all()` cannot apply to existing tables;
new tables are handled by `create_all()`.

All steps are idempotent and dialect-agnostic (SQLite and PostgreSQL), so there
are no standalone scripts to run by hand.

## Adding a migration

Append to `COLUMNS` (table, column, SQL type) or `INDEXES` (name, table, column)
in `runner.py`. Nothing else is needed — existing entries are skipped when
already present, and a failing step is logged without aborting the rest.
