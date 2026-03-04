# Krawl Helm Chart

A Helm chart for deploying the Krawl honeypot application on Kubernetes.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- Persistent Volume provisioner (optional, for database persistence)

## Installation

### From OCI Registry

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart \
  --version 1.1.3 \
  --namespace krawl-system \
  --create-namespace \
  -f values.yaml  # optional
```

### From local chart

```bash
helm install krawl ./helm -n krawl-system --create-namespace -f values.yaml
```

A minimal [values.yaml](values-minimal.yaml) example is provided in this directory.

Once installed, get your service IP:

```bash
kubectl get svc krawl -n krawl-system
```

Then access the deception server at `http://<EXTERNAL-IP>:5000`

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

You can override individual values with `--set` without a values file:

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart --version 1.1.3 \
  --set ingress.hosts[0].host=honeypot.example.com \
  --set config.canary.token_url=https://canarytokens.com/your-token
```

## Upgrading

```bash
helm upgrade krawl oci://ghcr.io/blessedrebus/krawl-chart --version 1.1.3 -f values.yaml
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
- `templates/` - Kubernetes resource templates
  - `deployment.yaml` - Krawl deployment
  - `service.yaml` - Service configuration
  - `configmap.yaml` - Application configuration
  - `pvc.yaml` - Persistent volume claim
  - `ingress.yaml` - Ingress configuration
  - `network-policy.yaml` - Network policies

## Support

For issues and questions, please visit the [Krawl GitHub repository](https://github.com/BlessedRebuS/Krawl).
