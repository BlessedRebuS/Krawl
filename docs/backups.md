# Database Backups

Krawl includes an automatic database dump job that periodically exports the full database to a SQL file.

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

- The backup job runs on the configured cron schedule (default: every 30 minutes).
- It exports the **full database schema and data** to a single SQL dump file at `{backups_path}/db_dump.sql`.
- Each backup **overwrites** the previous dump file.
- The dump includes `CREATE TABLE` statements and `INSERT` statements for all tables.
- The job also runs once immediately on startup (`run_when_loaded: true`).

## Backup Format

The output is a standard SQL file that can be executed by any SQL-compatible tool:

```sql
-- Schema
CREATE TABLE IF NOT EXISTS access_logs (...);
CREATE TABLE IF NOT EXISTS ip_stats (...);
...

-- Data
INSERT INTO access_logs VALUES (...);
...
```

## Restoring from a Backup

There is no built-in restore command. To restore, use standard SQL tools:

**SQLite (standalone mode):**
```bash
sqlite3 data/krawl.db < backups/db_dump.sql
```

**PostgreSQL (scalable mode):**
```bash
psql -h localhost -U krawl -d krawl < backups/db_dump.sql
```

> **Note**: You should stop Krawl before restoring to avoid conflicts with the running database.

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
ls -la backups/db_dump.sql
```

Check the Krawl logs for backup task output:

```bash
# Docker
docker logs krawl-server | grep "dump-krawl-data"

# Kubernetes
kubectl logs -l app.kubernetes.io/name=krawl | grep "dump-krawl-data"
```
