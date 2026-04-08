# Database Backups

Krawl includes an automatic backup job that periodically creates a database backup using native tools for each deployment mode.

## Configuration

### Via config.yaml

```yaml
backups:
  path: "backups"          # Directory where backups are saved
  cron: "*/30 * * * *"     # Cron schedule (default: every 30 minutes)
  enabled: true            # Enable or disable the backup job
```

### Via Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KRAWL_BACKUPS_PATH` | Directory where backup files are saved | `backups` |
| `KRAWL_BACKUPS_CRON` | Cron expression controlling backup frequency | `*/30 * * * *` |
| `KRAWL_BACKUPS_ENABLED` | Enable or disable the backup job | `true` |

## How It Works

The backup method depends on the deployment mode:

### Standalone Mode (SQLite)

Uses Python's `sqlite3.backup()` API to create an **atomic, consistent copy** of the database file.

- **Output**: `{backups_path}/krawl_backup.db` (a full SQLite database file)
- Writes to a temporary file first, then atomically renames it — a partial backup never replaces a good one
- Safe to run while Krawl is serving requests (SQLite WAL mode allows concurrent reads)

**Restoring:**
```bash
# Stop Krawl first
cp backups/krawl_backup.db data/krawl.db
```

### Scalable Mode (PostgreSQL)

Uses `pg_dump` to create a standard SQL dump of the PostgreSQL database.

- **Output**: `{backups_path}/db_dump.sql`
- Requires `pg_dump` to be available in the container (included in the Krawl Docker image)
- Uses `--no-owner --no-privileges` for portable dumps
- 5-minute timeout to prevent hung backups

**Restoring:**
```bash
psql -h localhost -U krawl -d krawl < backups/db_dump.sql
```

> **Note**: If `pg_dump` is not available, an error is logged. Install `postgresql-client` to enable PostgreSQL backups.

## Schedule

- The backup job runs on the configured cron schedule (default: every 30 minutes).
- Each backup **overwrites** the previous file.
- The job also runs once immediately on startup.

## Data Retention

Separately from backups, Krawl runs a **data retention job** daily at 3:00 AM that cleans up old records from the live database. This is controlled by `KRAWL_DATABASE_RETENTION_DAYS` (default: 30 days).

The retention job preserves:
- All credential capture attempts
- All suspicious access logs and honeypot triggers
- IPs with suspicious activity history

It removes:
- Non-suspicious access logs older than the retention period
- Stale IP entries with no suspicious history
- Orphaned attack detection records

## Verifying Backups

Check that the backup file exists and is recent:

```bash
ls -la backups/
```

Check the Krawl logs for backup task output:

```bash
# Docker
docker logs krawl-server | grep "dump-krawl-data"

# Kubernetes
kubectl logs -l app.kubernetes.io/name=krawl | grep "dump-krawl-data"
```
