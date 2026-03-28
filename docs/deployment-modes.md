# Deployment Modes

Krawl supports two deployment modes: **standalone** and **scalable**. The mode is controlled by the `mode` setting in `config.yaml` or the `KRAWL_MODE` environment variable.

## Table of Contents
- [At a Glance](#at-a-glance)
- [Standalone Mode](#standalone-mode)
- [Scalable Mode](#scalable-mode)
  - [Redis Cache Tiers](#redis-cache-tiers)
- [Running with Docker Compose](#running-with-docker-compose)
  - [Standalone](#standalone)
  - [Scalable](#scalable)
  - [Docker Run](#docker-run)
  - [Uvicorn (Python)](#uvicorn-python)
- [Running with Kubernetes (Helm)](#running-with-kubernetes-helm)
- [Migrating Data from Standalone to Scalable](#migrating-data-from-standalone-to-scalable)
  - [Pre-migration Checklist](#pre-migration-checklist)
  - [Migration Script](#migration-script)
  - [Step-by-step: Local / Docker Host](#step-by-step-local--docker-host)
  - [Step-by-step: Docker Compose](#step-by-step-docker-compose)
  - [Step-by-step: Kubernetes (Helm)](#step-by-step-kubernetes-helm)
  - [Post-migration](#post-migration)

---

## At a Glance

| | Standalone | Scalable |
|---|---|---|
| **Database** | SQLite (WAL mode) | PostgreSQL |
| **Cache** | In-memory Python dict | Redis (multi-tier TTL) |
| **Replicas** | 1 (single instance only) | 1+ (horizontal scaling) |
| **External deps** | None | PostgreSQL + Redis |
| **K8s strategy** | `Recreate` (SQLite file lock) | `RollingUpdate` (shared DB) |
| **Best for** | Dev, single-node, low-traffic | Production, HA, high-traffic |

---

## Standalone Mode

The original single-instance deployment using SQLite and an in-memory cache. **No extra configuration needed** — standalone is the default.

**When to use**: single-node deployments, development, low-traffic honeypots, or when you want the simplest possible setup with no external dependencies.

### Configuration

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

---

## Scalable Mode

Multi-instance deployment backed by PostgreSQL and Redis, allowing horizontal scaling.

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

### Redis Cache Tiers

In scalable mode, Redis is used across three cache tiers to reduce database load. All TTLs are configurable via `redis.cache_ttl`, `redis.hot_ttl`, and `redis.table_ttl` in `config.yaml` (or the corresponding `KRAWL_REDIS_*_TTL` environment variables).

| Tier | Default TTL | Config key | What it caches |
|------|-------------|------------|----------------|
| **Hot-path** | 30s | `redis.hot_ttl` | Ban info and IP stats/categories. Checked on every incoming request via middleware, avoiding a PostgreSQL round-trip per request. |
| **Table** | 2min | `redis.table_ttl` | Paginated dashboard tables (attackers, credentials, honeypot triggers, attacks, patterns, access logs, attack stats). Shared across all replicas so multiple dashboard users don't duplicate queries. Automatically invalidated on write operations (ban overrides, IP tracking changes). |
| **Warmup** | 10min | `redis.cache_ttl` | Pre-computed overview stats, top IPs/paths/user-agents, and map data. Refreshed by the dashboard warmup background task (if enabled). |

In standalone mode, only the warmup cache is used (in-memory dict). The hot-path and table caches are no-ops since there's only one process and the database is local.

> **Tip**: In scalable mode, you can disable `dashboard.cache_warmup` in your config. The table-tier cache already reduces DB load for dashboard requests without needing a background task.

---

## Running with Docker Compose

Production-ready compose files are available in the [`docker/`](../docker/) directory (using pre-built images). Development compose files at the project root use `build` + `watch` for hot-reload.

| File | Mode | Purpose |
|------|------|---------|
| `docker/docker-compose.standalone.yaml` | Standalone | Production — pre-built image |
| `docker/docker-compose.scalable.yaml` | Scalable | Production — pre-built image |
| `docker-compose.yaml` | Standalone | Development — builds from source, hot-reload |
| `docker-compose.scalable.yaml` | Scalable | Development — builds from source, hot-reload |

### Standalone

`docker/docker-compose.standalone.yaml`:

```yaml
services:
  krawl:
    image: ghcr.io/blessedrebus/krawl:latest
    container_name: krawl-server
    ports:
      - "5000:5000"
    environment:
      - CONFIG_LOCATION=config.yaml
      # Uncomment to set a custom dashboard password (auto-generated if not set)
      # - KRAWL_DASHBOARD_PASSWORD=your-secret-password
      # Set this to change timezone
      # - TZ=Europe/Rome
    volumes:
      - ./wordlists.json:/app/wordlists.json:ro
      - ./config.yaml:/app/config.yaml:ro
      - ./logs:/app/logs
      - ./exports:/app/exports
      - ./data:/app/data
      - ./backups:/app/backups
    restart: unless-stopped
```

```bash
docker compose -f docker/docker-compose.standalone.yaml up -d
```

### Scalable

> [!CAUTION]
> The compose file below uses **default passwords** (`krawl`/`krawl`) for PostgreSQL and Redis. **Change them before deploying to production.** Update `POSTGRES_PASSWORD`, `KRAWL_POSTGRES_PASSWORD`, and optionally add a Redis password.

`docker/docker-compose.scalable.yaml`:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    container_name: krawl-postgres
    environment:
      POSTGRES_DB: krawl
      POSTGRES_USER: krawl
      POSTGRES_PASSWORD: krawl
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U krawl -d krawl"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: krawl-redis
    volumes:
      - redis_data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  krawl:
    image: ghcr.io/blessedrebus/krawl:latest
    container_name: krawl-server
    ports:
      - "5000:5000"
    environment:
      - CONFIG_LOCATION=config.yaml
      - KRAWL_MODE=scalable
      - KRAWL_POSTGRES_HOST=postgres
      - KRAWL_POSTGRES_PORT=5432
      - KRAWL_POSTGRES_USER=krawl
      - KRAWL_POSTGRES_PASSWORD=krawl
      - KRAWL_POSTGRES_DATABASE=krawl
      - KRAWL_REDIS_HOST=redis
      - KRAWL_REDIS_PORT=6379
      # Uncomment to set a custom dashboard password (auto-generated if not set)
      # - KRAWL_DASHBOARD_PASSWORD=your-secret-password
      # Set this to change timezone
      # - TZ=Europe/Rome
    volumes:
      - ./wordlists.json:/app/wordlists.json:ro
      - ./config.yaml:/app/config.yaml:ro
      - ./logs:/app/logs
      - ./exports:/app/exports
      - ./backups:/app/backups
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

volumes:
  postgres_data:
  redis_data:
```

```bash
docker compose -f docker/docker-compose.scalable.yaml up -d
```

This starts three services:
- **krawl-postgres**: PostgreSQL 16 Alpine with a persistent volume
- **krawl-redis**: Redis 7 Alpine with a persistent volume
- **krawl-server**: Krawl in scalable mode, waits for healthy DB/cache before starting

### Docker Run

You can also run Krawl directly with `docker run`:

```bash
# Standalone
docker run -d \
  -p 5000:5000 \
  -v krawl-data:/app/data \
  --name krawl \
  ghcr.io/blessedrebus/krawl:latest

# Scalable (provide your own PostgreSQL and Redis)
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

## Running with Kubernetes (Helm)

The Helm chart defaults to **scalable** mode with bundled PostgreSQL and Redis. See the [Helm README](../helm/README.md) for all available parameters.

### Scalable — Bundled PostgreSQL and Redis (default)

```bash
helm install krawl ./helm -n krawl-system --create-namespace \
  --set postgres.password=your-password \
  --set redis.password=your-redis-password \
  --set replicaCount=2
```

### Scalable — External PostgreSQL and Redis

```bash
helm install krawl ./helm -n krawl-system --create-namespace \
  --set postgres.enabled=false \
  --set postgres.host=your-postgres-host \
  --set postgres.password=your-password \
  --set redis.enabled=false \
  --set redis.host=your-redis-host \
  --set redis.password=your-redis-password \
  --set replicaCount=2
```

### Standalone

```bash
helm install krawl ./helm -n krawl-system --create-namespace \
  --set mode=standalone \
  --set postgres.enabled=false \
  --set redis.enabled=false
```

Minimal example values files are provided:
- [`values-minimal.yaml`](../helm/values-minimal.yaml) — Scalable mode (default)
- [`values-standalone.yaml`](../helm/values-standalone.yaml) — Standalone mode

---

## Migrating Data from Standalone to Scalable

> [!CAUTION]
> **BACK UP YOUR DATA BEFORE MIGRATING.**
> The migration script reads from SQLite and writes to PostgreSQL. While it does not modify the source SQLite file, you should **always create a backup** before proceeding. If anything goes wrong (network issues, disk full, interrupted migration), having a backup ensures you can recover.

> [!WARNING]
> **Krawl MUST be stopped during migration.** Running the migration while Krawl is active can cause SQLite write locks, incomplete reads, or data inconsistency. Make sure **no Krawl instance** is connected to the SQLite database before starting.

### Pre-migration Checklist

Before you begin, make sure:

- [ ] **You have a backup** of your SQLite database (`data/krawl.db`). Copy it somewhere safe:
  ```bash
  cp data/krawl.db data/krawl.db.backup
  ```
- [ ] **Krawl is fully stopped** — no running containers, processes, or pods connected to the SQLite file
- [ ] **PostgreSQL is running and reachable** from where you'll run the migration
- [ ] **The target database exists** (the migration script creates tables automatically, but the database itself must exist)
- [ ] **You have enough disk space** on the PostgreSQL host to hold all migrated data

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

### Step-by-step: Local / Docker Host

```bash
# 1. BACK UP your SQLite database
cp data/krawl.db data/krawl.db.backup

# 2. Stop Krawl completely
docker compose down
# or: kill the uvicorn process

# 3. Verify Krawl is stopped (no containers should be listed)
docker ps | grep krawl

# 4. Start PostgreSQL (if not already running)
docker run -d --name krawl-postgres \
  -e POSTGRES_DB=krawl \
  -e POSTGRES_USER=krawl \
  -e POSTGRES_PASSWORD=krawl \
  -p 5432:5432 \
  postgres:16-alpine

# 5. Wait for PostgreSQL to be ready
until docker exec krawl-postgres pg_isready -U krawl -d krawl; do sleep 1; done

# 6. Run the migration
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path data/krawl.db \
  --postgres-host localhost \
  --postgres-port 5432 \
  --postgres-user krawl \
  --postgres-password krawl \
  --postgres-database krawl

# 7. Verify the migration output — check that row counts match!

# 8. Start Krawl in scalable mode
docker compose -f docker/docker-compose.scalable.yaml up -d
```

### Step-by-step: Docker Compose

If you're already using the standalone `docker-compose.yaml`:

```bash
# 1. BACK UP your SQLite database
cp data/krawl.db data/krawl.db.backup

# 2. Stop the standalone stack completely
docker compose down

# 3. Verify Krawl is stopped
docker ps | grep krawl

# 4. Start only PostgreSQL and Redis from the scalable stack
docker compose -f docker-compose.scalable.yaml up -d postgres redis

# 5. Wait for PostgreSQL to be healthy
docker compose -f docker-compose.scalable.yaml exec postgres pg_isready -U krawl -d krawl

# 6. Run migration from the host (SQLite data is in ./data/)
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path data/krawl.db \
  --postgres-host localhost \
  --postgres-port 5432 \
  --postgres-user krawl \
  --postgres-password krawl \
  --postgres-database krawl

# 7. Verify the migration output — check that row counts match!

# 8. Start the full scalable stack
docker compose -f docker/docker-compose.scalable.yaml up -d
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

### Step-by-step: Kubernetes (Helm)

In Kubernetes, the SQLite data lives on a PersistentVolumeClaim. The Helm chart includes a migration Job that mounts the existing PVC and writes to PostgreSQL.

> [!IMPORTANT]
> You **must scale Krawl to 0 replicas** before running the migration. This releases the SQLite PVC and prevents file locks. The migration Job will fail if the PVC is still mounted by a running pod.

#### With bundled PostgreSQL

```bash
# 1. Scale Krawl to 0 and deploy PostgreSQL + Redis + migration Job
helm upgrade <release> ./helm \
  --set replicaCount=0 \
  --set postgres.enabled=true \
  --set postgres.password=<postgres-password> \
  --set redis.enabled=true \
  --set redis.password=<redis-password> \
  --set migration.enabled=true

# 2. Wait for the migration Job to complete
kubectl wait --for=condition=complete job/<release>-krawl-migrate --timeout=600s

# 3. Check migration logs — verify row counts match!
kubectl logs job/<release>-krawl-migrate

# 4. If migration succeeded, switch to scalable mode
helm upgrade <release> ./helm \
  --set mode=scalable \
  --set migration.enabled=false \
  --set postgres.enabled=true \
  --set postgres.password=<postgres-password> \
  --set redis.enabled=true \
  --set redis.password=<redis-password> \
  --set replicaCount=2

# 5. Verify pods are running
kubectl get pods -l app.kubernetes.io/name=krawl
```

#### With external PostgreSQL

```bash
# 1. Ensure PostgreSQL is reachable from the namespace

# 2. Scale Krawl to 0 and run the migration Job
helm upgrade <release> ./helm \
  --set replicaCount=0 \
  --set migration.enabled=true \
  --set postgres.host=<postgres-host> \
  --set postgres.password=<postgres-password>

# 3. Wait for the Job to complete
kubectl wait --for=condition=complete job/<release>-krawl-migrate --timeout=600s

# 4. Check migration logs — verify row counts match!
kubectl logs job/<release>-krawl-migrate

# 5. Switch to scalable mode
helm upgrade <release> ./helm \
  --set mode=scalable \
  --set migration.enabled=false \
  --set postgres.host=<postgres-host> \
  --set postgres.password=<postgres-password> \
  --set redis.host=<redis-host> \
  --set redis.password=<redis-password> \
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

### Post-migration

After confirming the migration succeeded:

1. **Verify your data** — log into the Krawl dashboard and check that your IPs, attack logs, and statistics look correct
2. **Keep the SQLite backup** for at least a few days until you're confident everything works
3. You can safely delete the old SQLite PVC (Kubernetes) or `data/krawl.db` file (Docker) to reclaim storage — the PVC is **not** automatically deleted when switching to scalable mode

> [!TIP]
> If the migration fails or produces incorrect data, you can always go back to standalone mode using your backup. Just restore `data/krawl.db.backup` to `data/krawl.db` and start Krawl in standalone mode again.
