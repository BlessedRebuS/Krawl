# Deployment Modes

Krawl supports two deployment modes: **standalone** and **scalable**. The mode is controlled by the `mode` setting in `config.yaml` or the `KRAWL_MODE` environment variable.

## Standalone Mode (default)

The original single-instance deployment using SQLite and an in-memory cache.

| Component | Technology |
|-----------|------------|
| Database | SQLite (WAL mode) |
| Cache | In-memory Python dict |
| Replicas | 1 (single instance only) |

**When to use**: single-node deployments, development, low-traffic honeypots, or when you want the simplest possible setup with no external dependencies.

### Configuration

No extra configuration needed — standalone is the default.

```yaml
# config.yaml
mode: standalone

database:
  path: "data/krawl.db"
```

Or via environment variable:

```bash
KRAWL_MODE=standalone
```

## Scalable Mode

Multi-instance deployment backed by PostgreSQL and Redis, allowing horizontal scaling.

| Component | Technology |
|-----------|------------|
| Database | PostgreSQL |
| Cache | Redis |
| Replicas | 1+ (horizontal scaling) |

**When to use**: production deployments that need high availability, multiple replicas behind a load balancer, or when you expect high request volumes.

### Configuration

```yaml
# config.yaml
mode: scalable

postgres:
  host: "localhost"
  port: 5432
  user: "krawl"
  password: "krawl"
  database: "krawl"

redis:
  host: "localhost"
  port: 6379
  db: 0
  password: null
  cache_ttl: 600    # Dashboard warmup data TTL (seconds)
  hot_ttl: 30       # Hot-path cache TTL (ban info, IP categories)
  table_ttl: 120    # Paginated dashboard table TTL
```

Or via environment variables:

```bash
KRAWL_MODE=scalable

KRAWL_POSTGRES_HOST=localhost
KRAWL_POSTGRES_PORT=5432
KRAWL_POSTGRES_USER=krawl
KRAWL_POSTGRES_PASSWORD=krawl
KRAWL_POSTGRES_DATABASE=krawl

KRAWL_REDIS_HOST=localhost
KRAWL_REDIS_PORT=6379
KRAWL_REDIS_DB=0
# KRAWL_REDIS_PASSWORD=  # omit or leave unset if Redis has no password
KRAWL_REDIS_CACHE_TTL=600
KRAWL_REDIS_HOT_TTL=30
KRAWL_REDIS_TABLE_TTL=120
```

### What changes between modes

| Concern | Standalone | Scalable |
|---------|-----------|----------|
| Data storage | SQLite file on disk | PostgreSQL server |
| Dashboard cache | Thread-locked Python dict | Redis with multi-tier TTL caching |
| Rate limiting / bans | SQLite queries | PostgreSQL + Redis hot-path cache (30s TTL) |
| Deployment strategy (K8s) | `Recreate` (SQLite file lock) | `RollingUpdate` (shared DB) |
| SQLite PVC (K8s) | Required | Not used |
| Multiple replicas | Not supported | Fully supported |
| External dependencies | None | PostgreSQL + Redis |

### Redis cache tiers (scalable mode)

In scalable mode, Redis is used across three cache tiers to reduce database load. All TTLs are configurable via `redis.cache_ttl`, `redis.hot_ttl`, and `redis.table_ttl` in `config.yaml` (or the corresponding `KRAWL_REDIS_*_TTL` environment variables).

| Tier | Default TTL | Config key | What it caches |
|------|-------------|------------|----------------|
| **Hot-path** | 30s | `redis.hot_ttl` | Ban info and IP stats/categories. Checked on every incoming request via middleware, avoiding a PostgreSQL round-trip per request. |
| **Table** | 2min | `redis.table_ttl` | Paginated dashboard tables (attackers, credentials, honeypot triggers, attacks, patterns, access logs, attack stats). Shared across all replicas so multiple dashboard users don't duplicate queries. Automatically invalidated on write operations (ban overrides, IP tracking changes). |
| **Warmup** | 10min | `redis.cache_ttl` | Pre-computed overview stats, top IPs/paths/user-agents, and map data. Refreshed by the dashboard warmup background task (if enabled). |

In standalone mode, only the warmup cache is used (in-memory dict). The hot-path and table caches are no-ops since there's only one process and the database is local.

> **Tip**: In scalable mode, you can disable `dashboard.cache_warmup` in your config. The table-tier cache already reduces DB load for dashboard requests without needing a background task. This avoids unnecessary periodic queries against PostgreSQL.

---

## Running Scalable Mode

### Docker Compose

A dedicated compose file is provided with PostgreSQL and Redis pre-configured:

```bash
docker compose -f docker-compose.scalable.yaml up -d
```

This starts three services:
- **krawl-postgres**: PostgreSQL 16 Alpine with a persistent volume
- **krawl-redis**: Redis 7 Alpine with a persistent volume
- **krawl-server**: Krawl in scalable mode, waits for healthy DB/cache before starting

To stop:

```bash
docker compose -f docker-compose.scalable.yaml down
```

The standalone compose file (`docker-compose.yaml`) remains unchanged for standalone mode.

### Kubernetes (Helm)

The Helm chart can either **bundle** PostgreSQL and Redis as StatefulSets or connect to **external** instances.

#### Bundled PostgreSQL and Redis

Deploy everything in one command — the chart creates StatefulSets with Services in the same namespace:

```bash
helm install krawl ./helm -n krawl-system --create-namespace \
  --set mode=scalable \
  --set postgres.enabled=true \
  --set postgres.password=krawl \
  --set redis.enabled=true \
  --set redis.password=redispass \
  --set replicaCount=2
```

Or in `values.yaml`:

```yaml
mode: scalable
replicaCount: 2

postgres:
  enabled: true
  host: "postgres"
  password: "krawl"

redis:
  enabled: true
  host: "redis"
  password: "redispass"
```

Both StatefulSets include persistence by default. See the [Helm README](../helm/README.md) for all available parameters (`image`, `persistence`, `resources`).

#### External PostgreSQL and Redis

Connect to existing instances (managed services, separately deployed charts, etc.):

```bash
helm install krawl ./helm -n krawl-system --create-namespace \
  --set mode=scalable \
  --set postgres.host=your-postgres-host \
  --set postgres.password=krawl \
  --set redis.host=your-redis-host \
  --set replicaCount=2
```

Leave `postgres.enabled` and `redis.enabled` as `false` (default) when using external databases.

When `mode=scalable`:
- The SQLite PVC is **not created**
- The deployment strategy switches to `RollingUpdate`
- PostgreSQL and Redis credentials are injected via Kubernetes Secrets
- `replicaCount` can be safely increased above 1

### Docker Run

```bash
docker run -d \
  -p 5000:5000 \
  -e KRAWL_MODE=scalable \
  -e KRAWL_POSTGRES_HOST=your-postgres-host \
  -e KRAWL_POSTGRES_PORT=5432 \
  -e KRAWL_POSTGRES_USER=krawl \
  -e KRAWL_POSTGRES_PASSWORD=krawl \
  -e KRAWL_POSTGRES_DATABASE=krawl \
  -e KRAWL_REDIS_HOST=your-redis-host \
  -e KRAWL_REDIS_PORT=6379 \
  --name krawl \
  ghcr.io/blessedrebus/krawl:latest
```

### Uvicorn (Python)

Set the environment variables before starting:

```bash
export KRAWL_MODE=scalable
export KRAWL_POSTGRES_HOST=localhost
export KRAWL_POSTGRES_PORT=5432
export KRAWL_POSTGRES_USER=krawl
export KRAWL_POSTGRES_PASSWORD=krawl
export KRAWL_POSTGRES_DATABASE=krawl
export KRAWL_REDIS_HOST=localhost
export KRAWL_REDIS_PORT=6379

pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5000 --app-dir src
```

---

## Migrating Data from Standalone to Scalable

When switching from standalone to scalable mode, you can transfer existing data from SQLite to PostgreSQL using the included migration script.

### Prerequisites

- PostgreSQL must be running and reachable
- The target database must exist (the script creates tables automatically)
- Krawl should be **stopped** during migration to avoid SQLite write locks

### Migration Script

The migration script is located at `scripts/migrate_sqlite_to_postgres.py`. It:
1. Reads all tables from the SQLite database
2. Creates the schema in PostgreSQL
3. Copies rows in configurable batches (default: 1000)
4. Falls back to row-by-row insert on batch errors
5. Prints a verification summary comparing source and destination row counts

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--sqlite-path` | (required) | Path to the SQLite database file |
| `--postgres-host` | `localhost` | PostgreSQL hostname |
| `--postgres-port` | `5432` | PostgreSQL port |
| `--postgres-user` | `krawl` | PostgreSQL username |
| `--postgres-password` | `krawl` | PostgreSQL password |
| `--postgres-database` | `krawl` | PostgreSQL database name |
| `--batch-size` | `1000` | Rows per INSERT batch |
| `--drop-existing` | `false` | Drop existing PostgreSQL tables before migrating |

### Local / Docker Host

```bash
# 1. Stop Krawl
docker compose down
# or: kill the uvicorn process

# 2. Start PostgreSQL (if not already running)
docker run -d --name krawl-postgres \
  -e POSTGRES_DB=krawl \
  -e POSTGRES_USER=krawl \
  -e POSTGRES_PASSWORD=krawl \
  -p 5432:5432 \
  postgres:16-alpine

# 3. Run the migration
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path data/krawl.db \
  --postgres-host localhost \
  --postgres-port 5432 \
  --postgres-user krawl \
  --postgres-password krawl \
  --postgres-database krawl

# 4. Start Krawl in scalable mode
docker compose -f docker-compose.scalable.yaml up -d
```

### Docker Compose

If you're already using the standalone `docker-compose.yaml`:

```bash
# 1. Stop the standalone stack
docker compose down

# 2. Start only PostgreSQL and Redis from the scalable stack
docker compose -f docker-compose.scalable.yaml up -d postgres redis

# 3. Run migration from the host (SQLite data is in ./data/)
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path data/krawl.db \
  --postgres-host localhost \
  --postgres-port 5432 \
  --postgres-user krawl \
  --postgres-password krawl \
  --postgres-database krawl

# 4. Start the full scalable stack
docker compose -f docker-compose.scalable.yaml up -d
```

Alternatively, run the migration inside a container with access to both volumes:

```bash
docker compose -f docker-compose.scalable.yaml run --rm \
  -v ./data:/app/data:ro \
  krawl python /app/scripts/migrate_sqlite_to_postgres.py \
    --sqlite-path /app/data/krawl.db \
    --postgres-host postgres \
    --postgres-user krawl \
    --postgres-password krawl \
    --postgres-database krawl
```

### Kubernetes (Helm)

In Kubernetes, the SQLite data lives on a PersistentVolumeClaim. The Helm chart includes a migration Job that mounts the existing PVC and writes to PostgreSQL.

#### With bundled PostgreSQL

If you're using the chart's built-in PostgreSQL StatefulSet, deploy it first, then run the migration:

```bash
# 1. Deploy bundled PostgreSQL, Redis, and the migration Job
#    Scale Krawl to 0 to release the SQLite PVC and avoid locks
helm upgrade <release> ./helm \
  --set replicaCount=0 \
  --set postgres.enabled=true \
  --set postgres.password=<postgres-password> \
  --set redis.enabled=true \
  --set redis.password=<redis-password> \
  --set migration.enabled=true

# 2. Wait for the migration Job to complete and verify
kubectl wait --for=condition=complete job/<release>-krawl-migrate --timeout=600s
kubectl logs job/<release>-krawl-migrate

# 3. Switch to scalable mode
helm upgrade <release> ./helm \
  --set mode=scalable \
  --set migration.enabled=false \
  --set postgres.enabled=true \
  --set postgres.password=<postgres-password> \
  --set redis.enabled=true \
  --set redis.password=<redis-password> \
  --set replicaCount=1
```

#### With external PostgreSQL

If PostgreSQL is already running outside the chart (managed service, separate Helm release, etc.):

```bash
# 1. Ensure PostgreSQL is reachable from the namespace

# 2. Run the migration Job — scale Krawl to 0 to release the SQLite PVC
helm upgrade <release> ./helm \
  --set replicaCount=0 \
  --set migration.enabled=true \
  --set postgres.host=<postgres-host> \
  --set postgres.password=<postgres-password>

# 3. Wait for the Job to complete and verify
kubectl wait --for=condition=complete job/<release>-krawl-migrate --timeout=600s
kubectl logs job/<release>-krawl-migrate

# 4. Switch to scalable mode
helm upgrade <release> ./helm \
  --set mode=scalable \
  --set migration.enabled=false \
  --set postgres.host=<postgres-host> \
  --set postgres.password=<postgres-password> \
  --set redis.host=<redis-host> \
  --set replicaCount=2
```

#### Helm migration values

| Value | Default | Description |
|-------|---------|-------------|
| `migration.enabled` | `false` | Create the migration Job |
| `migration.sqliteFilename` | `krawl.db` | SQLite filename inside the PVC |
| `migration.batchSize` | `1000` | Rows per INSERT batch |
| `migration.dropExisting` | `false` | Drop PostgreSQL tables before migrating |
| `migration.existingClaim` | auto | Override the source PVC name (defaults to `<release>-krawl-db`) |
| `migration.backoffLimit` | `3` | Job retry attempts |
| `migration.ttlSecondsAfterFinished` | `3600` | Auto-cleanup the completed Job after this many seconds |

> **Important**: After confirming the migration succeeded, you can safely delete the old SQLite PVC to reclaim storage. The PVC is not automatically deleted when switching to scalable mode.
