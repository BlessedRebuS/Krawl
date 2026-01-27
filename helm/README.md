# Krawl Helm Chart

A Helm chart for deploying the Krawl honeypot application on Kubernetes.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- Persistent Volume provisioner (optional, for database persistence)

## Installation

### Add the repository (if applicable)

```bash
helm repo add krawl https://github.com/BlessedRebuS/Krawl
helm repo update
```

### Install from OCI Registry

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart --version 0.2.1
```

Or with a specific namespace:

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart --version 0.2.1 -n krawl --create-namespace
```

### Install the chart locally

```bash
helm install krawl ./helm
```

### Install with custom values

```bash
helm install krawl ./helm -f values.yaml
```

### Install in a specific namespace

```bash
helm install krawl ./helm -n krawl --create-namespace
```

## Configuration

The following table lists the main configuration parameters of the Krawl chart and their default values.

### Global Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of pod replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/blessedrebus/krawl` |
| `image.tag` | Image tag | `latest` |
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

### API Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.api.server_url` | API server URL | `null` |
| `config.api.server_port` | API server port | `8080` |
| `config.api.server_path` | API server path | `/api/v2/users` |

### Database Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.database.path` | Database file path | `data/krawl.db` |
| `config.database.retention_days` | Data retention in days | `30` |
| `database.persistence.enabled` | Enable persistent volume | `true` |
| `database.persistence.size` | Persistent volume size | `1Gi` |
| `database.persistence.accessMode` | Access mode | `ReadWriteOnce` |

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

### Resource Limits

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `64Mi` |

### Autoscaling

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable horizontal pod autoscaling | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `1` |
| `autoscaling.maxReplicas` | Maximum replicas | `1` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization | `70` |
| `autoscaling.targetMemoryUtilizationPercentage` | Target memory utilization | `80` |

### Network Policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicy.enabled` | Enable network policy | `true` |

## Usage Examples

### Basic Installation

```bash
helm install krawl ./helm
```

### Installation with Custom Domain

```bash
helm install krawl ./helm \
  --set ingress.hosts[0].host=honeypot.example.com
```

### Enable Canary Tokens

```bash
helm install krawl ./helm \
  --set config.canary.token_url=https://canarytokens.com/your-token
```

### Configure Custom API Endpoint

```bash
helm install krawl ./helm \
  --set config.api.server_url=https://api.example.com \
  --set config.api.server_port=443
```

### Create Values Override File

Create `custom-values.yaml`:

```yaml
config:
  server:
    port: 8080
    delay: 500
  canary:
    token_url: https://your-canary-token-url
  dashboard:
    secret_path: /super-secret-path
  crawl:
    max_pages_limit: 500
    ban_duration_seconds: 3600
```

Then install:

```bash
helm install krawl ./helm -f custom-values.yaml
```

## Upgrading

```bash
helm upgrade krawl ./helm
```

## Uninstalling

```bash
helm uninstall krawl
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
- `templates/` - Kubernetes resource templates
  - `deployment.yaml` - Krawl deployment
  - `service.yaml` - Service configuration
  - `configmap.yaml` - Application configuration
  - `pvc.yaml` - Persistent volume claim
  - `ingress.yaml` - Ingress configuration
  - `hpa.yaml` - Horizontal pod autoscaler
  - `network-policy.yaml` - Network policies

## Support

For issues and questions, please visit the [Krawl GitHub repository](https://github.com/BlessedRebuS/Krawl).
