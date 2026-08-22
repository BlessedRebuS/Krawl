# Krawl Helm Chart

A Helm chart for deploying the Krawl honeypot application on Kubernetes.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- Persistent Volume provisioner (for standalone mode database persistence)
- PostgreSQL and Redis (for scalable mode — bundled via the chart or external/managed)

## Installation

### From OCI Registry

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart \
  --version 2.3.1 \
  --namespace krawl-system \
  --create-namespace \
  -f values.yaml  # optional
```

### From local chart

```bash
helm install krawl ./helm -n krawl-system --create-namespace -f values.yaml
```

Minimal example values files are provided: [`values-minimal.yaml`](values-minimal.yaml) (scalable) and [`values-standalone.yaml`](values-standalone.yaml) (standalone).

Once installed, get your service IP:

```bash
kubectl get svc krawl -n krawl-system
```

Then access the deception server at `http://<EXTERNAL-IP>:5000`

## Deployment Modes

The chart supports two deployment modes controlled by the `mode` value:

- **`scalable`** (default): PostgreSQL + Redis backends. Supports multiple replicas. No SQLite PVC needed. Deployment strategy is `RollingUpdate`. PostgreSQL and Redis are bundled by default.
- **`standalone`**: SQLite database with in-memory cache. Single replica only. Requires a PVC for the database file. Deployment strategy is `Recreate`.

Minimal example values files are provided: [`values-minimal.yaml`](values-minimal.yaml) (scalable) and [`values-standalone.yaml`](values-standalone.yaml) (standalone).

### Scalable with bundled PostgreSQL and Redis (default)

```bash
helm install krawl ./helm -n krawl-system --create-namespace \
  --set postgres.password=your-password \
  --set redis.password=your-redis-password \
  --set replicaCount=2
```

This deploys PostgreSQL and Redis StatefulSets with Services in the same namespace. Persistence is enabled by default.

> [!CAUTION]
> The minimal values below use placeholder passwords. **Change `postgres.password` and `redis.password` before deploying to production.**

Minimal `values-minimal.yaml` for scalable mode:

> **Tip**: For production deployments, pin the image tag to a specific version (e.g., `tag: "2.3.1"`) instead of `latest` to ensure reproducible deployments.

```yaml
mode: scalable
replicaCount: 2

image:
  repository: ghcr.io/blessedrebus/krawl
  tag: "latest"
  pullPolicy: Always

ingress:
  enabled: true
  className: traefik
  hosts:
    - host: krawl.example.com
      paths:
        - path: /
          pathType: Prefix

postgres:
  enabled: true
  password: "change-me"

redis:
  enabled: true

config:
  dashboard:
    secret_path: null
  database:
    retention_days: 30
  server:
    port: 5000
    delay: 100
```

### Scalable with external PostgreSQL and Redis

Connect to existing PostgreSQL and Redis instances (e.g., managed services or separately deployed):

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

> **Note**: Set `postgres.enabled=false` and `redis.enabled=false` when using external databases to skip the bundled StatefulSets.

### Standalone

```bash
helm install krawl ./helm -n krawl-system --create-namespace -f values-standalone.yaml
```

Minimal `values-standalone.yaml`:

```yaml
mode: standalone
replicaCount: 1

image:
  repository: ghcr.io/blessedrebus/krawl
  tag: "latest"
  pullPolicy: Always

ingress:
  enabled: true
  className: traefik
  hosts:
    - host: krawl.example.com
      paths:
        - path: /
          pathType: Prefix

# PostgreSQL and Redis are not needed in standalone mode
postgres:
  enabled: false

redis:
  enabled: false

database:
  persistence:
    enabled: true
    size: 1Gi
    accessMode: ReadWriteOnce

config:
  dashboard:
    secret_path: null
  database:
    path: "data/krawl.db"
    retention_days: 30
  server:
    port: 5000
    delay: 100
```

For full details on modes, Redis cache tiers, and data migration, see the [Deployment Modes documentation](../docs/deployment-modes.md).

## Configuration

The following table lists the main configuration parameters of the Krawl chart and their default values.

### Global Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `mode` | Deployment mode (`standalone` or `scalable`) | `scalable` |
| `replicaCount` | Number of pod replicas (>1 only in scalable mode) | `1` |
| `image.repository` | Image repository | `ghcr.io/blessedrebus/krawl` |
| `image.tag` | Image tag | `2.3.1` |
| `image.pullPolicy` | Image pull policy | `Always` |

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `LoadBalancer` |
| `service.port` | Service port | `5000` |
| `service.externalTrafficPolicy` | External traffic policy | `Local` |

### Ingress Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `true` |
| `ingress.className` | Ingress class name | `traefik` |
| `ingress.hosts[0].host` | Ingress hostname | `krawl.example.com` |

### External Traefik / Reverse Proxy Setup

If you're using Traefik in a separate namespace (e.g., `cattle-system`) or running a reverse proxy like nginx in front of Traefik, you must configure both the Traefik service and deployment to preserve the real client IP. This ensures Krawl receives the actual attacker IP instead of the proxy's IP.

**Apply these patches to your Traefik deployment** (replace `cattle-system` with your Traefik namespace and `<IP>` with your actual IP if needed):

1. **Patch the Traefik Service** to use local traffic policy:

```bash
kubectl patch svc traefik -n cattle-system -p '{"spec":{"externalTrafficPolicy":"Local"}}'
```

2. **Patch the Traefik Deployment** to add trusted IPs to the entrypoints:

```bash
kubectl patch deployment traefik -n cattle-system --type=json -p='[
  {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--entrypoints.web.forwardedHeaders.trustedIPs=<IP>"},
  {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--entrypoints.websecure.forwardedHeaders.trustedIPs=<IP>"}
]'
```

> **Note**: These patches must be reapplied after any Traefik upgrade. Consider adding them to your cluster initialization automation or Traefik Helm values if using a Traefik Helm chart.

The Krawl service already includes `externalTrafficPolicy: Local` by default to preserve source IPs at the service level.

### Server Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.server.port` | Server port | `5000` |
| `config.server.delay` | Response delay in milliseconds | `100` |
| `config.server.timezone` | IANA timezone (e.g., "America/New_York") | `null` |

### Links Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.links.min_length` | Minimum link length | `5` |
| `config.links.max_length` | Maximum link length | `15` |
| `config.links.min_per_page` | Minimum links per page | `10` |
| `config.links.max_per_page` | Maximum links per page | `15` |
| `config.links.char_space` | Character space for link generation | `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789` |
| `config.links.max_counter` | Maximum counter value | `10` |

### Canary Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.canary.token_url` | Canary token URL | `null` |
| `config.canary.token_tries` | Number of canary token tries | `10` |

### Dashboard Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.dashboard.secret_path` | Secret dashboard path (auto-generated if null) | `null` |
| `dashboardPassword` | Password for protected panels (injected via Secret as `KRAWL_DASHBOARD_PASSWORD` env, auto-generated if empty) | `""` |
| `dashboardExistingSecret.name` | Externally-managed Secret holding the dashboard password (and optionally the path). When set, the chart-managed Secret is not created. | `""` |
| `dashboardExistingSecret.passwordKey` | Key holding the dashboard password | `dashboard-password` |
| `dashboardExistingSecret.pathKey` | Key holding the dashboard secret path. When set, `KRAWL_DASHBOARD_SECRET_PATH` is injected from the Secret and overrides `config.dashboard.secret_path`. | `""` |
| `aiExistingSecret.name` | Externally-managed Secret holding the AI/LLM API key. When set, the chart-managed AI Secret is not created. | `""` |
| `aiExistingSecret.key` | Key holding the API key | `ai-api-key` |
| `canaryTokenUrl` | Canary token URL. Stored in a chart-managed Secret and injected as `KRAWL_CANARY_TOKEN_URL`, keeping it out of the ConfigMap. | `""` |
| `canaryExistingSecret.name` | Externally-managed Secret holding the canary token URL | `""` |
| `canaryExistingSecret.key` | Key holding the URL | `canary-token-url` |
| `cloudflare.enabled` | Enable CloudFlare WAF/banlist sync (`KRAWL_CLOUDFLARE_ENABLED`) | `false` |
| `cloudflare.accountId` / `cloudflare.authToken` | CloudFlare credentials, stored in a chart-managed Secret. Injected as env, take precedence over `data/webhooks.json`, and are never written back to disk. | `""` |
| `cloudflare.existingSecret.name` | Externally-managed Secret holding the CloudFlare credentials | `""` |
| `cloudflare.existingSecret.accountIdKey` / `.authTokenKey` | Keys in that Secret | `cloudflare-account-id` / `cloudflare-auth-token` |
| `extraEnv` | Extra env vars for the Krawl container (list of `name`/`value` or `valueFrom` entries) | `[]` |
| `extraEnvFrom` | Extra `envFrom` sources (`secretRef` / `configMapRef`) — escape hatch for External Secrets Operator / Vault | `[]` |

### API Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.api.server_url` | API server URL | `null` |
| `config.api.server_port` | API server port | `8080` |
| `config.api.server_path` | API server path | `/api/v2/users` |

### Database Configuration (Standalone)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.database.path` | Database file path | `data/krawl.db` |
| `config.database.retention_days` | Data retention in days | `30` |
| `database.persistence.enabled` | Enable persistent volume (standalone only) | `true` |
| `database.persistence.size` | Persistent volume size | `1Gi` |
| `database.persistence.accessMode` | Access mode | `ReadWriteOnce` |
| `database.persistence.storageClassName` | Storage class name | `` (default) |
| `database.persistence.existingClaim` | Use an existing PVC | `` |

### PostgreSQL Configuration (Scalable)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgres.enabled` | Deploy a bundled PostgreSQL StatefulSet | `true` |
| `postgres.host` | PostgreSQL hostname (also used as Service name when bundled) | `postgres` |
| `postgres.port` | PostgreSQL port | `5432` |
| `postgres.user` | PostgreSQL username | `krawl` |
| `postgres.password` | PostgreSQL password | `krawl` |
| `postgres.database` | PostgreSQL database name | `krawl` |
| `postgres.existingSecret.name` | Externally-managed Secret for the PostgreSQL credentials (skips the chart-managed Secret; used by the Krawl Deployment, bundled StatefulSet and migration Job) | `""` |
| `postgres.existingSecret.passwordKey` | Key holding the password | `postgres-password` |
| `postgres.existingSecret.userKey` | Key holding the username (empty = use `postgres.user`) | `""` |
| `postgres.existingSecret.hostKey` | Key holding the host (empty = use `postgres.host`) | `""` |
| `postgres.existingSecret.portKey` | Key holding the port (empty = use `postgres.port`) | `""` |
| `postgres.existingSecret.databaseKey` | Key holding the database name (empty = use `postgres.database`) | `""` |
| `postgres.image.repository` | PostgreSQL image repository (bundled only) | `postgres` |

| `postgres.image.tag` | PostgreSQL image tag | `16-alpine` |
| `postgres.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `postgres.persistence.enabled` | Enable persistent storage for PostgreSQL | `true` |
| `postgres.persistence.size` | PVC size | `5Gi` |
| `postgres.persistence.accessMode` | PVC access mode | `ReadWriteOnce` |
| `postgres.persistence.storageClassName` | Storage class name | `` |
| `postgres.resources` | CPU/memory resource requests and limits | `{}` |

### Redis Configuration (Scalable)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `redis.enabled` | Deploy a bundled Redis StatefulSet | `true` |
| `redis.host` | Redis hostname (also used as Service name when bundled) | `redis` |
| `redis.port` | Redis port | `6379` |
| `redis.db` | Redis database number | `0` |
| `redis.password` | Redis password | `` |
| `redis.existingSecret.name` | Externally-managed Secret for the Redis credentials (skips the chart-managed Secret; used by the Krawl Deployment and bundled StatefulSet) | `""` |
| `redis.existingSecret.passwordKey` | Key holding the password | `redis-password` |
| `redis.existingSecret.hostKey` | Key holding the host (empty = use `redis.host`) | `""` |
| `redis.existingSecret.portKey` | Key holding the port (empty = use `redis.port`) | `""` |
| `redis.image.repository` | Redis image repository (bundled only) | `redis` |
| `redis.image.tag` | Redis image tag | `7-alpine` |
| `redis.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `redis.persistence.enabled` | Enable persistent storage for Redis | `true` |
| `redis.persistence.size` | PVC size | `1Gi` |
| `redis.persistence.accessMode` | PVC access mode | `ReadWriteOnce` |
| `redis.persistence.storageClassName` | Storage class name | `` |
| `redis.resources` | CPU/memory resource requests and limits | `{}` |

### Migration Job (SQLite to PostgreSQL)

A one-shot Kubernetes Job that copies data from an existing SQLite PVC into PostgreSQL. See [Deployment Modes](../docs/deployment-modes.md) for step-by-step instructions.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `migration.enabled` | Create the migration Job | `false` |
| `migration.sqliteFilename` | SQLite filename inside the PVC | `krawl.db` |
| `migration.batchSize` | Rows per INSERT batch | `1000` |
| `migration.dropExisting` | Drop existing PostgreSQL tables before migrating | `false` |
| `migration.existingClaim` | Override the source PVC name | `<release>-krawl-db` |
| `migration.backoffLimit` | Job retry attempts | `3` |
| `migration.ttlSecondsAfterFinished` | Auto-cleanup completed Job after (seconds) | `3600` |

### Behavior Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.behavior.probability_error_codes` | Error code probability (0-100) | `0` |

### Analyzer Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.analyzer.http_risky_methods_threshold` | HTTP risky methods threshold | `0.1` |
| `config.analyzer.violated_robots_threshold` | Violated robots.txt threshold | `0.1` |
| `config.analyzer.uneven_request_timing_threshold` | Uneven request timing threshold | `0.5` |
| `config.analyzer.uneven_request_timing_time_window_seconds` | Time window for request timing analysis | `300` |
| `config.analyzer.user_agents_used_threshold` | User agents threshold | `2` |
| `config.analyzer.attack_urls_threshold` | Attack URLs threshold | `1` |

### Crawl Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.crawl.infinite_pages_for_malicious` | Infinite pages for malicious crawlers | `true` |
| `config.crawl.max_pages_limit` | Maximum pages limit for legitimate crawlers | `250` |
| `config.crawl.ban_duration_seconds` | IP ban duration in seconds | `600` |

### Ignored IPs

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.ignored_ips` | List of IPs / CIDR ranges (IPv4/IPv6) never tracked, banned, exported, or persisted — and purged from the database on startup | loopback, RFC1918, link-local, CGNAT ranges |

### Banlist Federation

Publish this instance's banlist on an unauthenticated path and merge lists pulled from other Krawl instances (or any plain-text IP list).

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.banlist.export_path` | Public banlist download path, e.g. `/public_banlist.txt`. Supports the same `?categories=` / `?fwtype=` parameters as the main API. Empty = disabled | `""` |
| `config.banlist.sources` | Upstream banlist URLs to fetch and merge | `[]` |
| `config.banlist.refresh_interval` | Seconds between upstream fetches | `3600` |

### Tarpit

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.tarpit.enabled` | Trap AI agents with slow responses and random text | `false` |
| `config.tarpit.delay_seconds` | Extra delay added to each response when the tarpit is active | `5` |

### Deception Pages

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.deception.import_pages` | Auto-import HTML deception pages from `src/templates/deception/` at startup | `true` |
| `customTemplate.enabled` | Mount a custom honeypot page template at `/etc/krawl/templates/custom_page.html` | `false` |
| `customTemplate.content` | Inline HTML for that template | Example page |

### Metrics and Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.metrics.enabled` | Expose Prometheus metrics at `/<dashboard.secret_path>/metrics` | `true` |
| `config.logging.level` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) | `INFO` |
| `serviceMonitor.enabled` | Create a Prometheus Operator `ServiceMonitor`. Requires `config.metrics.enabled` and an explicitly set `config.dashboard.secret_path` (the metrics path is derived from it) | `false` |
| `serviceMonitor.interval` / `.scrapeTimeout` | Scrape interval and timeout | `30s` / `10s` |
| `serviceMonitor.labels` | Extra labels so your Prometheus `serviceMonitorSelector` matches (e.g. `release: kube-prometheus-stack`) | `{}` |
| `serviceMonitor.honorLabels` / `.relabelings` / `.metricRelabelings` | Passed through to the ServiceMonitor endpoint | `false` / `[]` / `[]` |
| `grafanaDashboard.enabled` | Ship the Krawl Grafana dashboard as a ConfigMap for the Grafana sidecar to discover | `false` |
| `grafanaDashboard.label` / `.labelValue` | Label the sidecar watches for | `grafana_dashboard` / `"1"` |
| `grafanaDashboard.namespace` | Namespace the sidecar watches, when not the release namespace (e.g. `cattle-monitoring-system`) | `""` |
| `grafanaDashboard.annotations` | Extra annotations on the dashboard ConfigMap | `{}` |

### Bundled Local LLM (optional)

Deploy Ollama and/or llama.cpp alongside Krawl for AI deception pages without an external provider. Point `config.ai.openai_base_url` at `http://<release-name>-ollama:8080/v1` or `http://<release-name>-llamacpp:8080/v1`.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `llm.ollama.enabled` | Deploy Ollama | `false` |
| `llm.ollama.model` / `.pullModel` | Model to serve and whether to pull it on startup | `qwen:1.8b` / `true` |
| `llm.ollama.persistence.enabled` / `.size` | Persistent volume for downloaded models | `true` / `5Gi` |
| `llm.llamaCpp.enabled` | Deploy llama.cpp | `false` |

### Resource Limits

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `64Mi` |

### Network Policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicy.enabled` | Enable network policy | `true` |

### Retrieving Dashboard Path

Check server startup logs or get the secret with 

```bash
kubectl get secret krawl-server -n krawl-system \
  -o jsonpath='{.data.dashboard-path}' | base64 -d && echo
```

## Usage Examples

### Scalable with bundled PostgreSQL and Redis (default)

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart --version 2.3.1 \
  --set replicaCount=3 \
  --set postgres.password=your-password \
  --set redis.password=your-redis-password \
  --set ingress.hosts[0].host=honeypot.example.com
```

### Scalable with external PostgreSQL and Redis

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart --version 2.3.1 \
  --set replicaCount=3 \
  --set postgres.enabled=false \
  --set postgres.host=your-postgres-host \
  --set postgres.password=your-password \
  --set redis.enabled=false \
  --set redis.host=your-redis-host \
  --set redis.password=your-redis-password \
  --set ingress.hosts[0].host=honeypot.example.com
```

### Standalone with custom settings

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart --version 2.3.1 \
  --set mode=standalone \
  --set postgres.enabled=false \
  --set redis.enabled=false \
  --set ingress.hosts[0].host=honeypot.example.com \
  --set config.canary.token_url=https://canarytokens.com/your-token
```

### Run migration from SQLite to PostgreSQL

See [Deployment Modes — Migration](../docs/deployment-modes.md#migrating-data-from-standalone-to-scalable) for detailed step-by-step instructions.

```bash
helm upgrade krawl ./helm \
  --set replicaCount=0 \
  --set migration.enabled=true \
  --set postgres.password=your-password
```

## Upgrading

```bash
helm upgrade krawl oci://ghcr.io/blessedrebus/krawl-chart --version 2.3.1 -f values.yaml
```

## Uninstalling

```bash
helm uninstall krawl -n krawl-system
```

## Troubleshooting

### Check chart syntax

```bash
helm lint ./helm
```

### Dry run to verify values

```bash
helm install krawl ./helm --dry-run --debug
```

### Check deployed configuration

```bash
kubectl get configmap krawl-config -o yaml
```

### View pod logs

```bash
kubectl logs -l app.kubernetes.io/name=krawl
```

## Chart Files

- `Chart.yaml` - Chart metadata
- `values.yaml` - Default configuration values
- `values-minimal.yaml` - Minimal scalable mode example
- `values-standalone.yaml` - Minimal standalone mode example
- `files/grafana-dashboard.json` - Grafana dashboard embedded by the dashboard ConfigMap
- `templates/` - Kubernetes resource templates
  - `deployment.yaml` - Krawl deployment (branches on `mode` for strategy, env vars, volumes)
  - `service.yaml` - Service configuration
  - `configmap.yaml` - Application configuration
  - `wordlists-configmap.yaml` - Wordlists configuration
  - `secret.yaml` - Dashboard password secret
  - `secret-scalable.yaml` - PostgreSQL and Redis password secrets (scalable mode only)
  - `secret-ai.yaml` - AI/LLM API key secret (`aiExistingSecret` skips it)
  - `secret-canary.yaml` - Canary token URL secret
  - `secret-cloudflare.yaml` - CloudFlare account ID and auth token secret
  - `postgres.yaml` - Bundled PostgreSQL StatefulSet, Service, and PVC (scalable mode, `postgres.enabled`)
  - `redis.yaml` - Bundled Redis StatefulSet, Service, and PVC (scalable mode, `redis.enabled`)
  - `pvc.yaml` - Persistent volume claim (standalone mode only)
  - `migration-job.yaml` - SQLite to PostgreSQL migration Job
  - `ingress.yaml` - Ingress configuration
  - `network-policy.yaml` - Network policies
  - `servicemonitor.yaml` - Prometheus Operator ServiceMonitor (`serviceMonitor.enabled`)
  - `grafana-dashboard.yaml` - Grafana dashboard ConfigMap (`grafanaDashboard.enabled`), rendering `files/grafana-dashboard.json`
  - `custom-template-configmap.yaml` - Custom honeypot page template (`customTemplate.enabled`)
  - `llm.yaml` - Bundled Ollama / llama.cpp workloads (`llm.*.enabled`)
  - `_helpers.tpl` - Shared template helpers

## Support

For issues and questions, please visit the [Krawl GitHub repository](https://github.com/BlessedRebuS/Krawl).
