# Krawl

Krawl is a deception server that detects, delays and profiles attackers, web
crawlers and automated scanners. It serves realistic fake applications, such
as admin panels, exposed configuration files and leaked credentials, detects
attacks with YARA rules, answers each one with a convincing fake reply, and
classifies every client IP by its behaviour. A dashboard shows all of it, and
banlists export to your firewall.

![Krawl dashboard](img/geoip_dashboard.png)

Try the demo: [demo.krawlme.com](http://demo.krawlme.com), dashboard at
[/das_dashboard](http://demo.krawlme.com/das_dashboard).

## Quick start

```bash
docker run -d \
  -p 5000:5000 \
  -e KRAWL_DASHBOARD_SECRET_PATH="/my-secret-dashboard" \
  -e KRAWL_DASHBOARD_PASSWORD="my-secret-password" \
  -v krawl-data:/app/data \
  --name krawl \
  ghcr.io/blessedrebus/krawl:latest
```

The trap answers on `http://localhost:5000`, the dashboard on
`http://localhost:5000/my-secret-dashboard`. Docker Compose, Kubernetes and
Helm are covered in [Deployment modes](deployment-modes.md).

Upgrading from 2.4? Read [Upgrading from 2.4 to 3.0](upgrading.md) first.

## Documentation

### Set up

| Page | What it covers |
|------|----------------|
| [Configuration](configuration.md) | `config.yaml`, every `KRAWL_*` variable and its default |
| [Deployment modes](deployment-modes.md) | Standalone (SQLite) or scalable (PostgreSQL and Redis), Docker Compose, Helm, migration |
| [Reverse proxy](reverse-proxy.md) | Running behind NGINX or a CDN, and decoy subdomains |
| [Upgrading from 2.4 to 3.0](upgrading.md) | Breaking changes and what happens on first start |

### How it works

| Page | What it covers |
|------|----------------|
| [Honeypot](honeypot.md) | How requests are answered, the bait pages, and the `pages:` manifest |
| [Attack detection](detection.md) | The YARA rules, fake replies, and adding or uploading rules |
| [How IPs are evaluated](algorithms.md) | Categorising IPs, and pruning uninteresting requests |
| [Tarpit](tarpit.md) | Slowing down and poisoning AI crawlers |
| [AI generation](ai_generation.md) | AI-generated deception pages with OpenRouter, OpenAI, Ollama or llama.cpp |
| [Deception pages](deception_pages.md) | Managing, importing and exporting generated pages |
| [Canary token](canary-token.md) | Alerting through canarytokens.org |

### Use the data

| Page | What it covers |
|------|----------------|
| [Dashboard](dashboard.md) | Every tab, with screenshots |
| [Dashboard API](dashboard-api.md) | Krawl's JSON API and its OpenAPI docs |
| [Firewall exporters](firewall-exporters.md) | Banlists in raw, iptables or nftables format |
| [Cloudflare banlist](cloudflare_banlist.md) | Syncing bans to a Cloudflare IP list for WAF rules |
| [Monitoring](monitoring.md) | Prometheus metrics and the Grafana dashboard |

### Operate

| Page | What it covers |
|------|----------------|
| [Retention](retention.md) | How long each kind of data is kept |
| [Backups](backups.md) | The scheduled database dump |
| [External APIs](api.md) | Third-party services Krawl calls for IP data |

### Develop

| Page | What it covers |
|------|----------------|
| [Architecture](architecture.md) | Code layout, request pipeline, schema and background tasks |
| [Coding guidelines](coding-guidelines.md) | Conventions for contributors |
