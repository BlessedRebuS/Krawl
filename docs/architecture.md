# Krawl Architecture

## Overview

Krawl is a cloud-native deception honeypot server built on **FastAPI**. It creates realistic fake web applications (admin panels, login pages, fake credentials) to attract, detect, and analyze malicious crawlers and attackers while wasting their resources with infinite spider-trap pages.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI, Uvicorn, Python 3.11 |
| **ORM / DB** | SQLAlchemy 2.0, SQLite (WAL mode) |
| **Templating** | Jinja2 (server-side rendering) |
| **Reactivity** | Alpine.js 3.14 |
| **Partial Updates** | HTMX 2.0 |
| **Charts** | Chart.js 3.9 (doughnut), custom SVG radar |
| **Maps** | Leaflet 1.9 + CartoDB dark tiles |
| **Scheduling** | APScheduler |
| **Container** | Docker (python:3.11-slim), Helm/K8s ready |

## Directory Structure

```
Krawl/
├── src/
│   ├── app.py                    # FastAPI app factory + lifespan
│   ├── config.py                 # YAML + env config loader
│   ├── dependencies.py           # DI providers (templates, DB, client IP)
│   ├── database.py               # DatabaseManager singleton
│   ├── models.py                 # SQLAlchemy ORM models
│   ├── tracker.py                # In-memory + DB access tracking
│   ├── logger.py                 # Rotating file log handlers
│   ├── deception_responses.py    # Attack detection + fake responses
│   ├── sanitizer.py              # Input sanitization
│   ├── generators.py             # Random content generators
│   ├── wordlists.py              # JSON wordlist loader
│   ├── geo_utils.py              # IP geolocation API
│   ├── ip_utils.py               # IP validation
│   │
│   ├── routes/
│   │   ├── honeypot.py           # Trap pages, credential capture, catch-all
│   │   ├── dashboard.py          # Dashboard page (Jinja2 SSR)
│   │   ├── api.py                # JSON API endpoints
│   │   └── htmx.py               # HTMX HTML fragment endpoints
│   │
│   ├── middleware/
│   │   ├── deception.py          # Path traversal / XXE / cmd injection detection
│   │   └── ban_check.py          # Banned IP enforcement
│   │
│   ├── tasks/                    # APScheduler background jobs
│   │   ├── analyze_ips.py        # IP categorization scoring
│   │   ├── fetch_ip_rep.py       # Geolocation + blocklist enrichment
│   │   ├── db_dump.py            # Database export
│   │   ├── memory_cleanup.py     # In-memory list trimming
│   │   └── top_attacking_ips.py  # Top attacker caching
│   │
│   ├── tasks_master.py           # Task discovery + APScheduler orchestrator
│   ├── firewall/                 # Banlist export (iptables, raw)
│   ├── migrations/               # Schema migrations (auto-run)
│   │
│   └── templates/
│       ├── jinja2/
│       │   ├── base.html                     # Layout + CDN scripts
│       │   └── dashboard/
│       │       ├── index.html                # Main dashboard page
│       │       └── partials/                 # 13 HTMX fragment templates
│       ├── html/                             # Deceptive trap page templates
│       └── static/
│           ├── css/dashboard.css
│           └── js/
│               ├── dashboard.js              # Alpine.js app controller
│               ├── map.js                    # Leaflet map
│               ├── charts.js                 # Chart.js doughnut
│               └── radar.js                  # SVG radar chart
│
├── config.yaml               # Application configuration
├── wordlists.json             # Attack patterns + fake credentials
├── Dockerfile                 # Container build
├── docker-compose.yaml        # Local orchestration
├── entrypoint.sh              # Container startup (gosu privilege drop)
├── kubernetes/                # K8s manifests
└── helm/                      # Helm chart
```

## Application Entry Point

`src/app.py` uses the **FastAPI application factory** pattern with an async lifespan manager:

```
Startup                              Shutdown
  │                                    │
  ├─ Initialize logging                └─ Log shutdown
  ├─ Initialize SQLite DB
  ├─ Create AccessTracker
  ├─ Load webpages file (optional)
  ├─ Store config + tracker in app.state
  ├─ Start APScheduler background tasks
  └─ Log dashboard URL
```

## Request Pipeline

```
        Request
          │
          ▼
┌──────────────────────┐
│  BanCheckMiddleware  │──→ IP banned? → Return 500
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ DeceptionMiddleware  │──→ Attack detected? → Fake error response
└──────────┬───────────┘
           ▼
┌───────────────────────┐
│ ServerHeaderMiddleware│──→ Add random Server header
└──────────┬────────────┘
           ▼
┌───────────────────────┐
│     Route Matching    │
│  (ordered by priority)│
│                       │
│  1. Static files      │  /{secret}/static/*
│  2. Dashboard router  │  /{secret}/          (prefix-based)
│  3. API router        │  /{secret}/api/*     (prefix-based)
│  4. HTMX router       │  /{secret}/htmx/*   (prefix-based)
│  5. Honeypot router   │  /* (catch-all)
└───────────────────────┘
```

### Prefix-Based Routing

Dashboard, API, and HTMX routers are mounted with `prefix=f"/{secret}"` in `app.py`. This means:
- Route handlers define paths **without** the secret (e.g., `@router.get("/api/all-ips")`)
- FastAPI prepends the secret automatically (e.g., `GET /a1b2c3/api/all-ips`)
- The honeypot catch-all `/{path:path}` only matches paths that **don't** start with the secret
- No `_is_dashboard_path()` checks needed — the prefix handles access scoping

## Route Architecture

### Honeypot Routes (`routes/honeypot.py`)

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/{path:path}` | Trap page with random links (catch-all) |
| `HEAD` | `/{path:path}` | 200 OK |
| `POST` | `/{path:path}` | Credential capture |
| `GET` | `/admin`, `/login` | Fake login form |
| `GET` | `/wp-admin`, `/wp-login.php` | Fake WordPress login |
| `GET` | `/phpmyadmin` | Fake phpMyAdmin |
| `GET` | `/robots.txt` | Honeypot paths advertised |
| `GET/POST` | `/api/search`, `/api/sql` | SQL injection honeypot |
| `POST` | `/api/contact` | XSS detection endpoint |
| `GET` | `/.env`, `/credentials.txt` | Fake sensitive files |

### Dashboard Routes (`routes/dashboard.py`)

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/` | Server-rendered dashboard (Jinja2) |

### API Routes (`routes/api.py`)

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/api/all-ips` | Paginated IP list with stats |
| `GET` | `/api/attackers` | Paginated attacker IPs |
| `GET` | `/api/ip-stats/{ip}` | Single IP detail |
| `GET` | `/api/credentials` | Captured credentials |
| `GET` | `/api/honeypot` | Honeypot trigger counts |
| `GET` | `/api/top-ips` | Top requesting IPs |
| `GET` | `/api/top-paths` | Most requested paths |
| `GET` | `/api/top-user-agents` | Top user agents |
| `GET` | `/api/attack-types-stats` | Attack type distribution |
| `GET` | `/api/attack-types` | Paginated attack log |
| `GET` | `/api/raw-request/{id}` | Full HTTP request |
| `GET` | `/api/get_banlist` | Export ban rules |

### HTMX Fragment Routes (`routes/htmx.py`)

Each returns a server-rendered Jinja2 partial (`hx-swap="innerHTML"`):

| Path | Template |
|------|----------|
| `/htmx/honeypot` | `honeypot_table.html` |
| `/htmx/top-ips` | `top_ips_table.html` |
| `/htmx/top-paths` | `top_paths_table.html` |
| `/htmx/top-ua` | `top_ua_table.html` |
| `/htmx/attackers` | `attackers_table.html` |
| `/htmx/credentials` | `credentials_table.html` |
| `/htmx/attacks` | `attack_types_table.html` |
| `/htmx/patterns` | `patterns_table.html` |
| `/htmx/ip-detail/{ip}` | `ip_detail.html` |

## Database Schema

```
┌─────────────────┐     ┌──────────────────┐
│   AccessLog     │     │ AttackDetection   │
├─────────────────┤     ├──────────────────┤
│ id (PK)         │◄────│ access_log_id(FK)│
│ ip (indexed)    │     │ attack_type      │
│ path            │     │ matched_pattern  │
│ user_agent      │     └──────────────────┘
│ method          │
│ is_suspicious   │     ┌──────────────────┐
│ is_honeypot     │     │CredentialAttempt │
│ timestamp       │     ├──────────────────┤
│ raw_request     │     │ id (PK)          │
└─────────────────┘     │ ip (indexed)     │
                        │ path, username   │
┌─────────────────┐     │ password         │
│    IpStats      │     │ timestamp        │
├─────────────────┤     └──────────────────┘
│ ip (PK)         │
│ total_requests  │     ┌──────────────────┐
│ first/last_seen │     │ CategoryHistory  │
│ country_code    │     ├──────────────────┤
│ city, lat, lon  │     │ id (PK)          │
│ asn, asn_org    │     │ ip (indexed)     │
│ isp, reverse    │     │ old_category     │
│ is_proxy        │     │ new_category     │
│ is_hosting      │     │ timestamp        │
│ list_on (JSON)  │     └──────────────────┘
│ category        │
│ category_scores │
│ analyzed_metrics│
│ manual_category │
└─────────────────┘
```

**SQLite config:** WAL mode, 30s busy timeout, file permissions 600.

## Frontend Architecture

```
base.html
  ├── CDN: Leaflet, Chart.js, HTMX, Alpine.js (deferred)
  ├── Static: dashboard.css
  │
  └── dashboard/index.html (extends base)
      │
      ├── Stats cards ──────────── Server-rendered on page load
      ├── Suspicious table ─────── Server-rendered on page load
      │
      ├── Overview tab (Alpine.js x-show)
      │   ├── Honeypot table ───── HTMX hx-get on load
      │   ├── Top IPs table ────── HTMX hx-get on load
      │   ├── Top Paths table ──── HTMX hx-get on load
      │   ├── Top UA table ─────── HTMX hx-get on load
      │   └── Credentials table ── HTMX hx-get on load
      │
      └── Attacks tab (Alpine.js x-show, lazy init)
          ├── Attackers table ──── HTMX hx-get on load
          ├── Map ──────────────── Leaflet (init on tab switch)
          ├── Chart ────────────── Chart.js (init on tab switch)
          ├── Attack types table ─ HTMX hx-get on load
          └── Patterns table ───── HTMX hx-get on load
```

**Responsibility split:**
- **Alpine.js** — Tab state, modals, dropdowns, lazy initialization
- **HTMX** — Table pagination, sorting, IP detail expansion
- **Leaflet** — Interactive map with category-colored markers
- **Chart.js** — Doughnut chart for attack type distribution
- **Custom SVG** — Radar charts for IP category scores

## Background Tasks

Managed by `TasksMaster` (APScheduler). Tasks are auto-discovered from `src/tasks/`.

| Task | Schedule | Purpose |
|------|----------|---------|
| `analyze_ips` | Every 1 min | Score IPs into categories (attacker, crawler, user) |
| `fetch_ip_rep` | Every 5 min | Enrich IPs with geolocation + blocklist data |
| `db_dump` | Configurable | Export database backups |
| `memory_cleanup` | Periodic | Trim in-memory lists |
| `top_attacking_ips` | Periodic | Cache top attackers |

### IP Categorization Model

Each IP is scored across 4 categories based on:
- HTTP method distribution (risky methods ratio)
- Robots.txt violations
- Request timing anomalies (coefficient of variation)
- User-Agent diversity
- Attack URL detection

Categories: `attacker`, `bad_crawler`, `good_crawler`, `regular_user`, `unknown`

## Configuration

`config.yaml` with environment variable overrides (`KRAWL_{FIELD}`):

```yaml
server:
  port: 5000
  delay: 100                    # Response delay (ms)

dashboard:
  secret_path: "test"           # Auto-generates if null

database:
  path: "data/krawl.db"
  retention_days: 30

crawl:
  infinite_pages_for_malicious: true
  max_pages_limit: 250
  ban_duration_seconds: 600

behavior:
  probability_error_codes: 0    # 0-100%

canary:
  token_url: null               # External canary alert URL
```

## Logging

Three rotating log files (1MB max, 5 backups each):

| Logger | File | Content |
|--------|------|---------|
| `krawl.app` | `logs/krawl.log` | Application events, errors |
| `krawl.access` | `logs/access.log` | HTTP access, attack detections |
| `krawl.credentials` | `logs/credentials.log` | Captured login attempts |

## Docker

```dockerfile
FROM python:3.11-slim
# Non-root user: krawl:1000
# Volumes: /app/logs, /app/data, /app/exports
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000", "--app-dir", "src"]
```

## Key Data Flows

### Honeypot Request

```
Client → BanCheck → DeceptionMiddleware → HoneypotRouter
                                              │
                                    ┌─────────┴──────────┐
                                    │ tracker.record()    │
                                    │   ├─ in-memory ++   │
                                    │   ├─ detect attacks │
                                    │   └─ DB persist     │
                                    └────────────────────┘
```

### Dashboard Load

```
Browser → GET /{secret}/ → SSR initial stats + Jinja2 render
       → Alpine.js init → HTMX fires hx-get for each table
       → User clicks Attacks tab → setTimeout → init Leaflet + Chart.js
       → Leaflet fetches /api/all-ips → plots markers
       → Chart.js fetches /api/attack-types-stats → renders doughnut
```

### IP Enrichment Pipeline

```
APScheduler (every 5 min)
  └─ fetch_ip_rep.main()
       ├─ DB: get unenriched IPs (limit 50)
       ├─ ip-api.com → geolocation (country, city, ASN, coords)
       ├─ iprep.lcrawl.com → blocklist memberships
       └─ DB: update IpStats with enriched data
```
