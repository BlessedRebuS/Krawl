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

Multi-instance deployment backed by MariaDB and Redis, allowing horizontal scaling.

| Component | Technology |
|-----------|------------|
| Database | MariaDB |
| Cache | Redis |
| Replicas | 1+ (horizontal scaling) |

**When to use**: production deployments that need high availability, multiple replicas behind a load balancer, or when you expect high request volumes.

### Configuration

```yaml
# config.yaml
mode: scalable

mariadb:
  host: "localhost"
  port: 3306
  user: "krawl"
  password: "krawl"
  database: "krawl"

redis:
  host: "localhost"
  port: 6379
  db: 0
  password: null
```

Or via environment variables:

```bash
KRAWL_MODE=scalable

KRAWL_MARIADB_HOST=localhost
KRAWL_MARIADB_PORT=3306
KRAWL_MARIADB_USER=krawl
KRAWL_MARIADB_PASSWORD=krawl
KRAWL_MARIADB_DATABASE=krawl

KRAWL_REDIS_HOST=localhost
KRAWL_REDIS_PORT=6379
KRAWL_REDIS_DB=0
# KRAWL_REDIS_PASSWORD=  # omit or leave unset if Redis has no password
```

### What changes between modes

| Concern | Standalone | Scalable |
|---------|-----------|----------|
| Data storage | SQLite file on disk | MariaDB server |
| Dashboard cache | Thread-locked Python dict | Redis with multi-tier TTL caching |
| Rate limiting / bans | SQLite queries | MariaDB + Redis hot-path cache (30s TTL) |
| Deployment strategy (K8s) | `Recreate` (SQLite file lock) | `RollingUpdate` (shared DB) |
| SQLite PVC (K8s) | Required | Not used |
| Multiple replicas | Not supported | Fully supported |
| External dependencies | None | MariaDB + Redis |

### Redis cache tiers (scalable mode)

In scalable mode, Redis is used across three cache tiers to reduce database load:

| Tier | TTL | What it caches |
|------|-----|----------------|
| **Hot-path** | 30s | Ban info and IP stats/categories. Checked on every incoming request via middleware, avoiding a MariaDB round-trip per request. |
| **Table** | 2min | Paginated dashboard tables (attackers, credentials, honeypot triggers, attacks, patterns, access logs, attack stats). Shared across all replicas so multiple dashboard users don't duplicate queries. Automatically invalidated on write operations (ban overrides, IP tracking changes). |
| **Warmup** | 10min | Pre-computed overview stats, top IPs/paths/user-agents, and map data. Refreshed by a background task every 5 minutes. |

In standalone mode, only the warmup cache is used (in-memory dict). The hot-path and table caches are no-ops since there's only one process and the database is local.

---

## Running Scalable Mode

### Docker Compose

A dedicated compose file is provided with MariaDB and Redis pre-configured:

```bash
docker compose -f docker-compose.scalable.yaml up -d
```

This starts three services:
- **krawl-mariadb**: MariaDB 11 with a persistent volume
- **krawl-redis**: Redis 7 Alpine with a persistent volume
- **krawl-server**: Krawl in scalable mode, waits for healthy DB/cache before starting

To stop:

```bash
docker compose -f docker-compose.scalable.yaml down
```

The standalone compose file (`docker-compose.yaml`) remains unchanged for standalone mode.

### Kubernetes (Helm)

The Helm chart can either **bundle** MariaDB and Redis as StatefulSets or connect to **external** instances.

#### Bundled MariaDB and Redis

Deploy everything in one command — the chart creates StatefulSets with Services in the same namespace:

```bash
helm install krawl ./helm -n krawl-system --create-namespace \
  --set mode=scalable \
  --set mariadb.enabled=true \
  --set mariadb.password=krawl \
  --set mariadb.rootPassword=rootpass \
  --set redis.enabled=true \
  --set redis.password=redispass \
  --set replicaCount=2
```

Or in `values.yaml`:

```yaml
mode: scalable
replicaCount: 2

mariadb:
  enabled: true
  host: "mariadb"
  password: "krawl"
  rootPassword: "rootpass"

redis:
  enabled: true
  host: "redis"
  password: "redispass"
```

Both StatefulSets include persistence by default. See the [Helm README](../helm/README.md) for all available parameters (`image`, `persistence`, `resources`).

#### External MariaDB and Redis

Connect to existing instances (managed services, separately deployed charts, etc.):

```bash
helm install krawl ./helm -n krawl-system --create-namespace \
  --set mode=scalable \
  --set mariadb.host=your-mariadb-host \
  --set mariadb.password=krawl \
  --set redis.host=your-redis-host \
  --set replicaCount=2
```

Leave `mariadb.enabled` and `redis.enabled` as `false` (default) when using external databases.

When `mode=scalable`:
- The SQLite PVC is **not created**
- The deployment strategy switches to `RollingUpdate`
- MariaDB and Redis credentials are injected via Kubernetes Secrets
- `replicaCount` can be safely increased above 1

### Docker Run

```bash
docker run -d \
  -p 5000:5000 \
  -e KRAWL_MODE=scalable \
  -e KRAWL_MARIADB_HOST=your-mariadb-host \
  -e KRAWL_MARIADB_PORT=3306 \
  -e KRAWL_MARIADB_USER=krawl \
  -e KRAWL_MARIADB_PASSWORD=krawl \
  -e KRAWL_MARIADB_DATABASE=krawl \
  -e KRAWL_REDIS_HOST=your-redis-host \
  -e KRAWL_REDIS_PORT=6379 \
  --name krawl \
  ghcr.io/blessedrebus/krawl:latest
```

### Uvicorn (Python)

Set the environment variables before starting:

```bash
export KRAWL_MODE=scalable
export KRAWL_MARIADB_HOST=localhost
export KRAWL_MARIADB_PORT=3306
export KRAWL_MARIADB_USER=krawl
export KRAWL_MARIADB_PASSWORD=krawl
export KRAWL_MARIADB_DATABASE=krawl
export KRAWL_REDIS_HOST=localhost
export KRAWL_REDIS_PORT=6379

pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5000 --app-dir src
```

---

## Migrating Data from Standalone to Scalable

When switching from standalone to scalable mode, you can transfer existing data from SQLite to MariaDB using the included migration script.

### Prerequisites

- MariaDB must be running and reachable
- The target database must exist (the script creates tables automatically)
- Krawl should be **stopped** during migration to avoid SQLite write locks

### Migration Script

The migration script is located at `scripts/migrate_sqlite_to_mariadb.py`. It:
1. Reads all tables from the SQLite database
2. Creates the schema in MariaDB
3. Copies rows in configurable batches (default: 1000)
4. Falls back to row-by-row insert on batch errors
5. Prints a verification summary comparing source and destination row counts

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--sqlite-path` | (required) | Path to the SQLite database file |
| `--mariadb-host` | `localhost` | MariaDB hostname |
| `--mariadb-port` | `3306` | MariaDB port |
| `--mariadb-user` | `krawl` | MariaDB username |
| `--mariadb-password` | `krawl` | MariaDB password |
| `--mariadb-database` | `krawl` | MariaDB database name |
| `--batch-size` | `1000` | Rows per INSERT batch |
| `--drop-existing` | `false` | Drop existing MariaDB tables before migrating |

### Local / Docker Host

```bash
# 1. Stop Krawl
docker compose down
# or: kill the uvicorn process

# 2. Start MariaDB (if not already running)
docker run -d --name krawl-mariadb \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=krawl \
  -e MYSQL_USER=krawl \
  -e MYSQL_PASSWORD=krawl \
  -p 3306:3306 \
  mariadb:11

# 3. Run the migration
python scripts/migrate_sqlite_to_mariadb.py \
  --sqlite-path data/krawl.db \
  --mariadb-host localhost \
  --mariadb-port 3306 \
  --mariadb-user krawl \
  --mariadb-password krawl \
  --mariadb-database krawl

# 4. Start Krawl in scalable mode
docker compose -f docker-compose.scalable.yaml up -d
```

### Docker Compose

If you're already using the standalone `docker-compose.yaml`:

```bash
# 1. Stop the standalone stack
docker compose down

# 2. Start only MariaDB and Redis from the scalable stack
docker compose -f docker-compose.scalable.yaml up -d mariadb redis

# 3. Run migration from the host (SQLite data is in ./data/)
python scripts/migrate_sqlite_to_mariadb.py \
  --sqlite-path data/krawl.db \
  --mariadb-host localhost \
  --mariadb-port 3306 \
  --mariadb-user krawl \
  --mariadb-password krawl \
  --mariadb-database krawl

# 4. Start the full scalable stack
docker compose -f docker-compose.scalable.yaml up -d
```

Alternatively, run the migration inside a container with access to both volumes:

```bash
docker compose -f docker-compose.scalable.yaml run --rm \
  -v ./data:/app/data:ro \
  krawl python /app/scripts/migrate_sqlite_to_mariadb.py \
    --sqlite-path /app/data/krawl.db \
    --mariadb-host mariadb \
    --mariadb-user krawl \
    --mariadb-password krawl \
    --mariadb-database krawl
```

### Kubernetes (Helm)

In Kubernetes, the SQLite data lives on a PersistentVolumeClaim. The Helm chart includes a migration Job that mounts the existing PVC and writes to MariaDB.

#### With bundled MariaDB

If you're using the chart's built-in MariaDB StatefulSet, deploy it first, then run the migration:

```bash
# 1. Scale down Krawl to release the SQLite PVC and avoid locks
kubectl scale deployment <release>-krawl --replicas=0

# 2. Deploy bundled MariaDB (and optionally Redis) — keep mode=standalone
#    so the existing SQLite PVC is not removed
helm upgrade <release> ./helm \
  --set mariadb.enabled=true \
  --set mariadb.password=<mariadb-password> \
  --set mariadb.rootPassword=<root-password> \
  --set redis.enabled=true \
  --set redis.password=<redis-password> \
  --set migration.enabled=true

# 3. Wait for the migration Job to complete and verify
kubectl wait --for=condition=complete job/<release>-krawl-migrate --timeout=600s
kubectl logs job/<release>-krawl-migrate

# 4. Switch to scalable mode
helm upgrade <release> ./helm \
  --set mode=scalable \
  --set migration.enabled=false \
  --set mariadb.enabled=true \
  --set mariadb.password=<mariadb-password> \
  --set mariadb.rootPassword=<root-password> \
  --set redis.enabled=true \
  --set redis.password=<redis-password> \
  --set replicaCount=2
```

#### With external MariaDB

If MariaDB is already running outside the chart (managed service, separate Helm release, etc.):

```bash
# 1. Scale down Krawl to release the SQLite PVC and avoid locks
kubectl scale deployment <release>-krawl --replicas=0

# 2. Ensure MariaDB is reachable from the namespace

# 3. Run the migration Job
helm upgrade <release> ./helm \
  --set migration.enabled=true \
  --set mariadb.host=<mariadb-host> \
  --set mariadb.password=<mariadb-password>

# 4. Wait for the Job to complete and verify
kubectl wait --for=condition=complete job/<release>-krawl-migrate --timeout=600s
kubectl logs job/<release>-krawl-migrate

# 5. Switch to scalable mode
helm upgrade <release> ./helm \
  --set mode=scalable \
  --set migration.enabled=false \
  --set mariadb.host=<mariadb-host> \
  --set mariadb.password=<mariadb-password> \
  --set redis.host=<redis-host> \
  --set replicaCount=2
```

#### Helm migration values

| Value | Default | Description |
|-------|---------|-------------|
| `migration.enabled` | `false` | Create the migration Job |
| `migration.sqliteFilename` | `krawl.db` | SQLite filename inside the PVC |
| `migration.batchSize` | `1000` | Rows per INSERT batch |
| `migration.dropExisting` | `false` | Drop MariaDB tables before migrating |
| `migration.existingClaim` | auto | Override the source PVC name (defaults to `<release>-krawl-db`) |
| `migration.backoffLimit` | `3` | Job retry attempts |
| `migration.ttlSecondsAfterFinished` | `3600` | Auto-cleanup the completed Job after this many seconds |

> **Important**: After confirming the migration succeeded, you can safely delete the old SQLite PVC to reclaim storage. The PVC is not automatically deleted when switching to scalable mode.
